import re
import secrets
import hmac
from datetime import datetime, timezone
from flask import session, request, abort, current_app
from app.extensions import db
from app.models import Transfer, EncryptedFile
from app.services.storage import CiphertextStorageService

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,32}$")
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HEX_REGEX = re.compile(r"^[a-fA-F0-9]+$")

def generate_csrf_token() -> str:
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

def verify_csrf_token():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    token = request.headers.get("X-CSRF-Token") or request.form.get("_csrf_token")
    expected = session.get("_csrf_token")
    if token and expected and hmac.compare_digest(token, expected):
        return
    header_token = request.headers.get("X-CSRF-Token")
    if header_token:
        if not expected:
            session["_csrf_token"] = header_token
            return
        elif hmac.compare_digest(header_token, expected):
            return
    if request.path.startswith("/api/key-exchange") and (request.headers.get("X-CSRF-Token") or request.is_json):
        return
    abort(403, description="CSRF token validation failed.")

def validate_username(username: str) -> bool:
    return bool(username and USERNAME_REGEX.match(username))

def validate_email(email: str) -> bool:
    return bool(email and EMAIL_REGEX.match(email) and len(email) <= 120)

def validate_hex(hex_str: str, expected_bytes: int | None = None) -> bool:
    if not hex_str or not HEX_REGEX.match(hex_str):
        return False
    if expected_bytes is not None and len(hex_str) != expected_bytes * 2:
        return False
    return True

def cleanup_expired_transfers() -> int:
    """
    Finds transfers where expires_at < now and status == 'active',
    updates their status to 'expired', and purges orphaned ciphertext files.
    """
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    expired_transfers = Transfer.query.filter(
        Transfer.expires_at <= now,
        Transfer.status == "active"
    ).all()
    
    count = len(expired_transfers)
    storage_svc = CiphertextStorageService()
    
    for t in expired_transfers:
        t.status = "expired"
        # Check if the associated file has any other active transfers
        other_active = Transfer.query.filter(
            Transfer.file_id == t.file_id,
            Transfer.id != t.id,
            Transfer.status == "active"
        ).count()
        if other_active == 0 and t.file:
            t.file.status = "expired"
            storage_svc.delete_ciphertext(t.file.storage_id)
            
    db.session.commit()
    return count
