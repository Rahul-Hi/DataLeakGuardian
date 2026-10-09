import os
from pathlib import Path
import pytest


@pytest.fixture(scope="session", autouse=True)
def isolated_test_suite_environment(tmp_path_factory):
    """
    Session-level autouse fixture to guarantee that all automated tests execute in an
    isolated temporary environment. Protects database/app.db and local user files
    from being accessed, modified, or polluted by test runs.
    """
    test_session_dir = tmp_path_factory.mktemp("dlg_isolated_test_env")
    test_db_path = test_session_dir / "isolated_test_app.db"
    test_uploads_path = test_session_dir / "test_uploads"
    test_reports_path = test_session_dir / "test_reports"

    test_uploads_path.mkdir(parents=True, exist_ok=True)
    test_reports_path.mkdir(parents=True, exist_ok=True)

    keys_to_manage = [
        "DATABASE_PATH",
        "DATABASE_URL",
        "UPLOAD_FOLDER",
        "REPORT_FOLDER",
        "STORAGE_BACKEND",
    ]
    original_env = {key: os.environ.get(key) for key in keys_to_manage}

    os.environ["DATABASE_PATH"] = str(test_db_path)
    os.environ["UPLOAD_FOLDER"] = str(test_uploads_path)
    os.environ["REPORT_FOLDER"] = str(test_reports_path)
    os.environ.pop("STORAGE_BACKEND", None)
    # Ensure tests do not accidentally target external PostgreSQL
    os.environ.pop("DATABASE_URL", None)

    yield {
        "dir": test_session_dir,
        "db": test_db_path,
        "uploads": test_uploads_path,
        "reports": test_reports_path,
    }

    # Restore original environment
    for key, val in original_env.items():
        if val is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = val
