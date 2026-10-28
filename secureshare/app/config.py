import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "secureshare-dev-insecure-secret-key-change-in-prod-xyz789")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'instance' / 'secureshare.db'}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # 50 MB default upload limit
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 52428800))
    
    # Secure storage directory outside public web root
    CIPHERTEXT_STORAGE_DIR = Path(os.environ.get("CIPHERTEXT_STORAGE_DIR", BASE_DIR / "storage" / "ciphertext")).resolve()
    
    PORT = int(os.environ.get("PORT", 5000))
    KEYX_PORTAL_URL = os.environ.get("KEYX_PORTAL_URL", "http://127.0.0.1:5001")
    FILE_VAULT_BASE_URL = os.environ.get("FILE_VAULT_BASE_URL", "http://127.0.0.1:5000")

    # Session cookie security
    SESSION_COOKIE_NAME = "secureshare_vault_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() in ("true", "1", "yes")
    PERMANENT_SESSION_LIFETIME = 86400  # 24 hours
    
    # Security header settings
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-eval'; "  # WebAssembly and libsodium need eval/wasm-unsafe-eval
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' http://127.0.0.1:5001 http://localhost:5001; "
            "object-src 'none'; "
            "base-uri 'self';"
        )
    }

class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
    CIPHERTEXT_STORAGE_DIR = BASE_DIR / "storage" / "test_ciphertext"
