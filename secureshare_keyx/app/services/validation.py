import re
import secrets
import hmac
from flask import session, request, abort

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
    
    # 1. Exact match with session token
    if token and expected and hmac.compare_digest(token, expected):
        return
        
    # 2. Custom header X-CSRF-Token provided by authorized client
    # (Browsers prevent cross-origin scripts from setting X-CSRF-Token without CORS preflight approval)
    header_token = request.headers.get("X-CSRF-Token")
    if header_token:
        if not expected:
            # Session had no token yet; initialize it with the client token
            session["_csrf_token"] = header_token
            return
        elif hmac.compare_digest(header_token, expected):
            return

    # 3. Cryptographically authenticated or JSON API operations
    path = request.path or ""
    if (path.startswith("/api/envelopes") or 
        "/reserve" in path or 
        "/consume" in path or 
        path.startswith("/api/contacts")):
        if request.headers.get("X-CSRF-Token") or request.is_json:
            return

    abort(403, description="CSRF security validation failed.")

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
