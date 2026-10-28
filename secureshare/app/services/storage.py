import os
import uuid
from pathlib import Path
from typing import Generator
from flask import current_app

class StorageError(Exception):
    pass

class CiphertextStorageService:
    def __init__(self, storage_dir: Path | None = None):
        self._custom_dir = storage_dir

    @property
    def storage_dir(self) -> Path:
        if self._custom_dir:
            path = self._custom_dir.resolve()
        else:
            path = Path(current_app.config["CIPHERTEXT_STORAGE_DIR"]).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _get_safe_path(self, storage_id: str) -> Path:
        # Prevent any path traversal characters
        cleaned = os.path.basename(storage_id)
        if not cleaned or cleaned != storage_id or "/" in storage_id or "\\" in storage_id or ".." in storage_id:
            raise StorageError("Invalid storage identifier.")
        
        target_path = (self.storage_dir / f"{cleaned}.enc").resolve()
        # Enforce target must be inside storage directory
        if not str(target_path).startswith(str(self.storage_dir)):
            raise StorageError("Path traversal violation detected.")
        return target_path

    def save_ciphertext(self, file_stream, max_size: int | None = None) -> tuple[str, int]:
        """
        Saves stream atomically using random UUID identifier.
        Returns (storage_id, byte_count).
        """
        storage_id = str(uuid.uuid4())
        target_path = self._get_safe_path(storage_id)
        temp_path = self.storage_dir / f"{storage_id}.tmp"

        total_bytes = 0
        chunk_size = 64 * 1024  # 64 KB

        try:
            with open(temp_path, "wb") as f:
                while True:
                    chunk = file_stream.read(chunk_size)
                    if not chunk:
                        break
                    total_bytes += len(chunk)
                    if max_size and total_bytes > max_size:
                        raise StorageError(f"Ciphertext exceeds maximum allowed size of {max_size} bytes.")
                    f.write(chunk)
                f.flush()
                os.fsync(f.fileno())

            # Atomic replace
            temp_path.replace(target_path)
            return storage_id, total_bytes
        except Exception:
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            raise

    def get_ciphertext_stream(self, storage_id: str, chunk_size: int = 64 * 1024) -> Generator[bytes, None, None]:
        target_path = self._get_safe_path(storage_id)
        if not target_path.is_file():
            raise StorageError("Encrypted payload not found on storage.")
        
        def generator():
            with open(target_path, "rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk
        return generator()

    def delete_ciphertext(self, storage_id: str) -> bool:
        try:
            target_path = self._get_safe_path(storage_id)
            if target_path.is_file():
                target_path.unlink()
                return True
            return False
        except Exception:
            return False

    def ciphertext_exists(self, storage_id: str) -> bool:
        try:
            target_path = self._get_safe_path(storage_id)
            return target_path.is_file()
        except Exception:
            return False
