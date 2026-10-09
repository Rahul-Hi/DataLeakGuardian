import io
import os
import pytest
from pathlib import Path
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from app import create_app
from app.services.storage_service import (
    LocalStorageBackend,
    R2StorageBackend,
    get_storage,
    validate_category,
    validate_filename,
)


def test_validate_category_and_filename():
    assert validate_category("uploads") == "uploads"
    assert validate_category("reports") == "reports"
    with pytest.raises(ValueError):
        validate_category("system")
    with pytest.raises(ValueError):
        validate_category("../../etc")

    assert validate_filename("scan_123.pdf") == "scan_123.pdf"
    with pytest.raises(ValueError):
        validate_filename("../scan.pdf")
    with pytest.raises(ValueError):
        validate_filename("/root/scan.pdf")
    with pytest.raises(ValueError):
        validate_filename("uploads/scan.pdf")
    with pytest.raises(ValueError):
        validate_filename("scan\0.pdf")
    with pytest.raises(ValueError):
        validate_filename("")


def test_local_storage_save_get_and_stream(tmp_path):
    uploads_dir = tmp_path / "uploads"
    reports_dir = tmp_path / "reports"
    storage = LocalStorageBackend(upload_folder=uploads_dir, report_folder=reports_dir)

    # Save and read bytes in uploads
    stored_key = storage.save("uploads", "sample.pdf", b"%PDF-1.4 dummy content")
    assert stored_key == "uploads/sample.pdf"
    assert (uploads_dir / "sample.pdf").is_file()
    assert storage.get_bytes("uploads", "sample.pdf") == b"%PDF-1.4 dummy content"

    # Streaming
    chunks = list(storage.get_stream("uploads", "sample.pdf"))
    assert b"".join(chunks) == b"%PDF-1.4 dummy content"

    # Exists and Delete
    assert storage.exists("uploads", "sample.pdf")
    assert storage.delete("uploads", "sample.pdf")
    assert not storage.exists("uploads", "sample.pdf")
    assert not (uploads_dir / "sample.pdf").exists()


def test_local_storage_missing_file_raises(tmp_path):
    storage = LocalStorageBackend(upload_folder=tmp_path / "uploads", report_folder=tmp_path / "reports")
    with pytest.raises(FileNotFoundError):
        storage.get_bytes("uploads", "nonexistent.pdf")
    with pytest.raises(FileNotFoundError):
        list(storage.get_stream("reports", "nonexistent.pdf"))


def test_local_storage_traversal_prevention(tmp_path):
    storage = LocalStorageBackend(upload_folder=tmp_path / "uploads", report_folder=tmp_path / "reports")
    with pytest.raises(ValueError):
        storage.save("uploads", "../evil.pdf", b"malicious")


def test_r2_storage_backend_with_mock_client():
    mock_s3 = MagicMock()
    storage = R2StorageBackend(
        bucket_name="guardian-bucket",
        access_key_id="dummy_key",
        secret_access_key="dummy_secret",
        endpoint_url="https://dummy.r2.cloudflarestorage.com",
        s3_client=mock_s3,
    )

    # Save
    key = storage.save("uploads", "document.pdf", b"%PDF data")
    assert key == "uploads/document.pdf"
    mock_s3.put_object.assert_called_once_with(
        Bucket="guardian-bucket", Key="uploads/document.pdf", Body=b"%PDF data"
    )

    # Get bytes
    mock_body = MagicMock()
    mock_body.read.return_value = b"%PDF downloaded"
    mock_s3.get_object.return_value = {"Body": mock_body}
    data = storage.get_bytes("uploads", "document.pdf")
    assert data == b"%PDF downloaded"

    # Get stream
    mock_stream_body = MagicMock()
    mock_stream_body.iter_chunks.return_value = [b"%PDF ", b"streamed"]
    mock_s3.get_object.return_value = {"Body": mock_stream_body}
    streamed = list(storage.get_stream("uploads", "document.pdf"))
    assert streamed == [b"%PDF ", b"streamed"]

    # Exists
    mock_s3.head_object.return_value = {}
    assert storage.exists("uploads", "document.pdf")

    # Delete
    assert storage.delete("uploads", "document.pdf")
    mock_s3.delete_object.assert_called_once_with(
        Bucket="guardian-bucket", Key="uploads/document.pdf"
    )


def test_r2_storage_missing_object_handling():
    mock_s3 = MagicMock()
    err_response = {"Error": {"Code": "NoSuchKey", "Message": "The specified key does not exist."}}
    mock_s3.get_object.side_effect = ClientError(err_response, "GetObject")
    mock_s3.head_object.side_effect = ClientError(err_response, "HeadObject")

    storage = R2StorageBackend(
        bucket_name="guardian-bucket",
        s3_client=mock_s3,
    )

    with pytest.raises(FileNotFoundError):
        storage.get_bytes("reports", "missing_report.pdf")

    assert not storage.exists("reports", "missing_report.pdf")

    # Verify that non-404 service error (e.g. 403 AccessDenied) is propagated
    forbidden_response = {"Error": {"Code": "AccessDenied", "Message": "Access Denied."}}
    mock_s3.head_object.side_effect = ClientError(forbidden_response, "HeadObject")
    with pytest.raises(ClientError):
        storage.exists("reports", "forbidden.pdf")


def test_get_storage_selection_and_partial_config_failure(monkeypatch):
    # Default to LocalStorageBackend when no R2 vars are set
    for key in ["R2_BUCKET_NAME", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_ENDPOINT_URL", "R2_ACCOUNT_ID"]:
        monkeypatch.delenv(key, raising=False)

    storage = get_storage()
    assert isinstance(storage, LocalStorageBackend)

    # Partial configuration fails loudly
    monkeypatch.setenv("R2_BUCKET_NAME", "guardian-bucket")
    with pytest.raises(ValueError) as excinfo:
        get_storage()
    assert "Incomplete Cloudflare R2 configuration" in str(excinfo.value)

    # Full configuration selects R2StorageBackend (mock boto3 client to prevent network call)
    monkeypatch.setenv("R2_ACCESS_KEY_ID", "key123")
    monkeypatch.setenv("R2_SECRET_ACCESS_KEY", "sec123")
    monkeypatch.setenv("R2_ENDPOINT_URL", "https://account.r2.cloudflarestorage.com")

    monkeypatch.setattr(
        "boto3.client",
        lambda *args, **kwargs: MagicMock(),
    )
    r2_storage = get_storage()
    assert isinstance(r2_storage, R2StorageBackend)


def test_report_service_and_web_route_integration_with_storage(tmp_path):
    custom_reports = tmp_path / "reports"
    custom_uploads = tmp_path / "uploads"
    app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "REPORT_FOLDER": str(custom_reports),
        "UPLOAD_FOLDER": str(custom_uploads),
    })

    with app.app_context():
        from app.services.report_service import generate_privacy_report

        report_name = generate_privacy_report(
            "test_doc.pdf",
            "PDF",
            {"total_score": 10, "risk_level": "Low", "detected_category_summary": {}, "explanations": []},
            [],
        )
        storage = get_storage()
        assert storage.exists("reports", report_name)
        pdf_bytes = storage.get_bytes("reports", report_name)
        assert pdf_bytes.startswith(b"%PDF")


def test_database_failure_cleans_up_storage_artifacts(tmp_path, monkeypatch):
    custom_reports = tmp_path / "reports"
    custom_uploads = tmp_path / "uploads"
    app = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "REPORT_FOLDER": str(custom_reports),
        "UPLOAD_FOLDER": str(custom_uploads),
    })

    with app.test_request_context():
        from flask import session
        from app.routes.web import _process_findings_and_save
        from app.database import get_db

        session["user_id"] = 1
        storage = get_storage()
        storage.save("uploads", "fail_test.pdf", b"dummy")

        real_db = get_db()

        class FaultyDb:
            def execute(self, sql, *args, **kwargs):
                if "INSERT INTO documents" in sql:
                    raise RuntimeError("Simulated DB Insert Failure")
                return real_db.execute(sql, *args, **kwargs)

            def rollback(self):
                return real_db.rollback()

            def commit(self):
                return real_db.commit()

        monkeypatch.setattr("app.routes.web.get_db", lambda: FaultyDb())

        with pytest.raises(RuntimeError):
            _process_findings_and_save(
                original_name="fail_test.pdf",
                file_name="fail_test.pdf",
                file_type="pdf",
                file_size=5,
                stored_path="uploads/fail_test.pdf",
                text_content="Sample text",
            )

        # Confirm that uploaded file was cleaned up on failure
        assert not storage.exists("uploads", "fail_test.pdf")
