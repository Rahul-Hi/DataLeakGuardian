import os
import time
import uuid
from pathlib import Path

from flask import current_app
from werkzeug.utils import secure_filename

from app.database import get_db
from app.services.storage_service import LocalStorageBackend, get_storage

MAX_FILE_SIZE = 4 * 1024 * 1024


def get_max_file_size():
    if current_app:
        return current_app.config.get("MAX_CONTENT_LENGTH", MAX_FILE_SIZE)
    return int(os.environ.get("MAX_CONTENT_LENGTH", MAX_FILE_SIZE))


def _file_has_valid_signature(file_name, file_bytes):
    suffix = Path(file_name).suffix.lower()
    if suffix == ".pdf":
        return file_bytes.startswith(b"%PDF")
    if suffix == ".png":
        return file_bytes.startswith(b"\x89PNG\r\n\x1a\n")
    if suffix in {".jpg", ".jpeg"}:
        return file_bytes.startswith(b"\xff\xd8\xff")
    return False


def is_allowed_file(filename):
    if not filename:
        return False
    ext = Path(filename).suffix.lower().lstrip(".")
    return ext in current_app.config["ALLOWED_EXTENSIONS"]


def cleanup_stale_files(max_age_hours=24):
    if not current_app:
        return

    storage = get_storage()
    if not isinstance(storage, LocalStorageBackend):
        # Cloud object storage lifecycle policies handle remote bucket expiration
        return

    referenced = get_db().execute(
        "SELECT file_name, report_name FROM documents WHERE status = 'completed'"
    ).fetchall()
    retained_names = {name for row in referenced for name in (row["file_name"], row["report_name"]) if name}

    for folder_name in ["UPLOAD_FOLDER", "REPORT_FOLDER"]:
        folder_path = current_app.config.get(folder_name)
        if not folder_path:
            continue
        try:
            base = Path(os.path.abspath(folder_path))
            if not base.exists():
                continue
            for existing in base.iterdir():
                if not existing.is_file() or existing.name in retained_names:
                    continue
                age_seconds = time.time() - existing.stat().st_mtime
                if age_seconds > max_age_hours * 3600:
                    existing.unlink(missing_ok=True)
        except OSError:
            continue


def save_uploaded_file(file_storage):
    if file_storage is None or not hasattr(file_storage, "filename"):
        raise ValueError("No file was uploaded.")

    original_name = secure_filename(file_storage.filename)
    if not original_name:
        raise ValueError("Invalid file name.")

    if not is_allowed_file(original_name):
        raise ValueError("Only PDF, PNG, JPG, and JPEG files are allowed.")

    file_storage.seek(0, os.SEEK_END)
    file_size = file_storage.tell()
    file_storage.seek(0)

    max_size = get_max_file_size()
    max_mb = max_size // (1024 * 1024)

    if file_size <= 0:
        raise ValueError("Uploaded file is empty.")
    if file_size > max_size:
        raise ValueError(f"File size exceeds the {max_mb} MB limit.")

    signature_bytes = file_storage.read(4096)
    file_storage.seek(0)
    if not _file_has_valid_signature(original_name, signature_bytes):
        raise ValueError("The uploaded file is corrupted or invalid.")

    file_bytes = file_storage.read()
    file_storage.seek(0)

    file_ext = Path(original_name).suffix.lower()
    safe_name = f"{uuid.uuid4().hex}{file_ext}"

    storage = get_storage()
    stored_path = storage.save("uploads", safe_name, file_bytes)

    return {
        "original_name": original_name,
        "file_name": safe_name,
        "file_type": file_ext.lstrip("."),
        "file_size": file_size,
        "stored_path": stored_path,
        "file_bytes": file_bytes,
    }
