import io
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import BinaryIO, Generator, Optional, Union

from flask import current_app, has_app_context

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    boto3 = None
    ClientError = None


def _is_production_environment() -> bool:
    """Detect a production environment without importing the app factory (avoids circular imports)."""
    if has_app_context():
        try:
            from app import is_production
            return is_production()
        except Exception:
            pass
    env_indicators = [
        os.environ.get("FLASK_ENV", "").strip().lower(),
        os.environ.get("ENV", "").strip().lower(),
        os.environ.get("ENVIRONMENT", "").strip().lower(),
        os.environ.get("VERCEL_ENV", "").strip().lower(),
    ]
    if "production" in env_indicators:
        return True
    if os.environ.get("VERCEL") == "1":
        return True
    return False


ALLOWED_CATEGORIES = {"uploads", "reports"}


def validate_category(category: str) -> str:
    if category not in ALLOWED_CATEGORIES:
        raise ValueError(f"Invalid storage category: '{category}'. Allowed categories: {sorted(ALLOWED_CATEGORIES)}")
    return category


def validate_filename(filename: str) -> str:
    if not filename or not isinstance(filename, str):
        raise ValueError("Filename must be a non-empty string.")

    base = os.path.basename(filename)
    if base != filename or filename in {".", ".."} or "/" in filename or "\\" in filename:
        raise ValueError(f"Invalid or unsafe filename: '{filename}'")

    if "\0" in filename:
        raise ValueError(f"Invalid filename containing null bytes: '{filename}'")

    return filename


class StorageBackend(ABC):
    @abstractmethod
    def save(self, category: str, filename: str, data: Union[bytes, BinaryIO]) -> str:
        """Saves data to the given category and filename. Returns stored key/path."""
        pass

    @abstractmethod
    def get_bytes(self, category: str, filename: str) -> bytes:
        """Retrieves raw bytes for an object. Raises FileNotFoundError if missing."""
        pass

    @abstractmethod
    def get_stream(self, category: str, filename: str) -> Generator[bytes, None, None]:
        """Yields chunks of bytes for streaming. Raises FileNotFoundError if missing."""
        pass

    @abstractmethod
    def delete(self, category: str, filename: str) -> bool:
        """Deletes object. Returns True if deleted or successfully absent."""
        pass

    @abstractmethod
    def exists(self, category: str, filename: str) -> bool:
        """Checks if object exists."""
        pass


class LocalStorageBackend(StorageBackend):
    def __init__(
        self,
        upload_folder: Optional[Union[str, Path]] = None,
        report_folder: Optional[Union[str, Path]] = None,
    ):
        self._upload_folder = Path(upload_folder).resolve() if upload_folder else None
        self._report_folder = Path(report_folder).resolve() if report_folder else None

    def _get_base_dir(self, category: str) -> Path:
        validate_category(category)
        if category == "uploads":
            if self._upload_folder:
                base = self._upload_folder
            elif has_app_context() and current_app.config.get("UPLOAD_FOLDER"):
                base = Path(current_app.config["UPLOAD_FOLDER"]).resolve()
            else:
                base = Path(os.environ.get("UPLOAD_FOLDER", "instance/uploads")).resolve()
        else:
            if self._report_folder:
                base = self._report_folder
            elif has_app_context() and current_app.config.get("REPORT_FOLDER"):
                base = Path(current_app.config["REPORT_FOLDER"]).resolve()
            else:
                base = Path(os.environ.get("REPORT_FOLDER", "instance/reports")).resolve()

        base.mkdir(parents=True, exist_ok=True)
        return base

    def _resolve_path(self, category: str, filename: str) -> Path:
        validate_category(category)
        safe_name = validate_filename(filename)
        base = self._get_base_dir(category)
        target = (base / safe_name).resolve()

        try:
            target.relative_to(base)
        except ValueError:
            raise ValueError(f"Path traversal detected: '{filename}' outside base directory.")

        return target

    def save(self, category: str, filename: str, data: Union[bytes, BinaryIO]) -> str:
        target = self._resolve_path(category, filename)
        if isinstance(data, (bytes, bytearray)):
            target.write_bytes(data)
        else:
            with open(target, "wb") as f:
                f.write(data.read())
        return f"{category}/{filename}"

    def get_bytes(self, category: str, filename: str) -> bytes:
        target = self._resolve_path(category, filename)
        if not target.is_file():
            raise FileNotFoundError(f"File not found in local storage: {category}/{filename}")
        return target.read_bytes()

    def get_stream(self, category: str, filename: str) -> Generator[bytes, None, None]:
        target = self._resolve_path(category, filename)
        if not target.is_file():
            raise FileNotFoundError(f"File not found in local storage: {category}/{filename}")
        with open(target, "rb") as f:
            while chunk := f.read(64 * 1024):
                yield chunk

    def delete(self, category: str, filename: str) -> bool:
        target = self._resolve_path(category, filename)
        if target.is_file():
            target.unlink(missing_ok=True)
            return True
        return False

    def exists(self, category: str, filename: str) -> bool:
        target = self._resolve_path(category, filename)
        return target.is_file()


class R2StorageBackend(StorageBackend):
    def __init__(
        self,
        bucket_name: Optional[str] = None,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        account_id: Optional[str] = None,
        s3_client: Optional[object] = None,
    ):
        self.bucket_name = bucket_name or os.environ.get("R2_BUCKET_NAME")
        access_key = access_key_id or os.environ.get("R2_ACCESS_KEY_ID")
        secret_key = secret_access_key or os.environ.get("R2_SECRET_ACCESS_KEY")
        endpoint = endpoint_url or os.environ.get("R2_ENDPOINT_URL")
        acct_id = account_id or os.environ.get("R2_ACCOUNT_ID")

        if not endpoint and acct_id:
            endpoint = f"https://{acct_id}.r2.cloudflarestorage.com"

        if s3_client is not None:
            self._client = s3_client
            if not self.bucket_name:
                raise ValueError("R2_BUCKET_NAME is required.")
        else:
            if not (self.bucket_name and access_key and secret_key and endpoint):
                missing = []
                if not self.bucket_name:
                    missing.append("R2_BUCKET_NAME")
                if not access_key:
                    missing.append("R2_ACCESS_KEY_ID")
                if not secret_key:
                    missing.append("R2_SECRET_ACCESS_KEY")
                if not endpoint:
                    missing.append("R2_ENDPOINT_URL or R2_ACCOUNT_ID")
                raise ValueError(f"Incomplete Cloudflare R2 configuration. Missing: {', '.join(missing)}")

            if boto3 is None:
                raise RuntimeError("boto3 is required for R2StorageBackend.")

            self._client = boto3.client(
                "s3",
                endpoint_url=endpoint,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name="auto",
            )

    def _get_key(self, category: str, filename: str) -> str:
        validate_category(category)
        safe_name = validate_filename(filename)
        return f"{category}/{safe_name}"

    def save(self, category: str, filename: str, data: Union[bytes, BinaryIO]) -> str:
        key = self._get_key(category, filename)
        body = data if isinstance(data, (bytes, bytearray)) else data.read()
        self._client.put_object(Bucket=self.bucket_name, Key=key, Body=body)
        return f"{category}/{filename}"

    def get_bytes(self, category: str, filename: str) -> bytes:
        key = self._get_key(category, filename)
        try:
            response = self._client.get_object(Bucket=self.bucket_name, Key=key)
            return response["Body"].read()
        except Exception as exc:
            if hasattr(exc, "response") and exc.response.get("Error", {}).get("Code") in ("404", "NoSuchKey"):
                raise FileNotFoundError(f"File not found in R2: {key}") from exc
            raise

    def get_stream(self, category: str, filename: str) -> Generator[bytes, None, None]:
        key = self._get_key(category, filename)
        try:
            response = self._client.get_object(Bucket=self.bucket_name, Key=key)
            body = response["Body"]
            try:
                if hasattr(body, "iter_chunks"):
                    for chunk in body.iter_chunks(chunk_size=64 * 1024):
                        yield chunk
                else:
                    yield body.read()
            finally:
                if hasattr(body, "close"):
                    body.close()
        except Exception as exc:
            if hasattr(exc, "response") and exc.response.get("Error", {}).get("Code") in ("404", "NoSuchKey"):
                raise FileNotFoundError(f"File not found in R2: {key}") from exc
            raise

    def delete(self, category: str, filename: str) -> bool:
        key = self._get_key(category, filename)
        self._client.delete_object(Bucket=self.bucket_name, Key=key)
        return True

    def exists(self, category: str, filename: str) -> bool:
        key = self._get_key(category, filename)
        try:
            self._client.head_object(Bucket=self.bucket_name, Key=key)
            return True
        except Exception as exc:
            if hasattr(exc, "response") and str(exc.response.get("Error", {}).get("Code")) in ("404", "NoSuchKey"):
                return False
            raise


class EphemeralStorageBackend(StorageBackend):
    """
    Zero-storage backend for serverless environments (e.g. Vercel) where external
    object storage is deferred. Does not write to disk, /tmp, or cloud buckets.
    """
    def save(self, category: str, filename: str, data: Union[bytes, BinaryIO]) -> str:
        validate_category(category)
        safe_name = validate_filename(filename)
        # Returns a non-persistent indicator key; does not store bytes anywhere
        return f"{category}/ephemeral_{safe_name}"

    def get_bytes(self, category: str, filename: str) -> bytes:
        validate_category(category)
        raise FileNotFoundError(f"File not available in ephemeral zero-storage mode: {category}/{filename}")

    def get_stream(self, category: str, filename: str) -> Generator[bytes, None, None]:
        validate_category(category)
        raise FileNotFoundError(f"File not available in ephemeral zero-storage mode: {category}/{filename}")

    def delete(self, category: str, filename: str) -> bool:
        validate_category(category)
        return True

    def exists(self, category: str, filename: str) -> bool:
        validate_category(category)
        return False


def get_storage(custom_backend: Optional[StorageBackend] = None) -> StorageBackend:
    if custom_backend is not None:
        return custom_backend

    configured_backend = None
    if has_app_context() and current_app.config.get("STORAGE_BACKEND"):
        backend = current_app.config["STORAGE_BACKEND"]
        if isinstance(backend, StorageBackend):
            return backend
        if isinstance(backend, str):
            configured_backend = backend.lower()

    if not configured_backend and os.environ.get("STORAGE_BACKEND"):
        configured_backend = os.environ.get("STORAGE_BACKEND").lower()

    if configured_backend == "r2":
        return R2StorageBackend()
    if configured_backend == "local":
        return LocalStorageBackend()
    if configured_backend == "ephemeral":
        return EphemeralStorageBackend()
    if configured_backend is not None:
        raise ValueError(
            f"Unknown storage backend configured: '{configured_backend}'. Allowed: 'local', 'r2', 'ephemeral'."
        )

    r2_keys = ["R2_BUCKET_NAME", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY"]
    present_keys = [k for k in r2_keys if os.environ.get(k)]
    has_endpoint = bool(os.environ.get("R2_ENDPOINT_URL") or os.environ.get("R2_ACCOUNT_ID"))

    if present_keys or has_endpoint:
        missing = [k for k in r2_keys if not os.environ.get(k)]
        if not has_endpoint:
            missing.append("R2_ENDPOINT_URL or R2_ACCOUNT_ID")
        if missing:
            raise ValueError(
                f"Incomplete Cloudflare R2 configuration: missing {', '.join(missing)}. "
                "All R2 variables must be configured or none to use local storage."
            )
        return R2StorageBackend()

    # In production environments (Vercel, etc.) the local filesystem is read-only.
    # Silently selecting LocalStorageBackend would cause uploads to fail with OSError.
    # Require an explicit STORAGE_BACKEND (e.g. 'r2' with credentials, or 'ephemeral' for zero-storage).
    if _is_production_environment():
        raise ValueError(
            "STORAGE_BACKEND environment variable is not configured. "
            "In production environments, configure STORAGE_BACKEND=r2 with Cloudflare R2 credentials, "
            "or STORAGE_BACKEND=ephemeral for serverless zero-storage mode."
        )

    return LocalStorageBackend()
