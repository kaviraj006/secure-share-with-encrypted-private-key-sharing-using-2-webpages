import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "secureshare-keyx-rugged-red-secret-key-9988776655")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'instance' / 'secureshare_keyx.db'}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    PORT = int(os.environ.get("PORT", 5001))
    
    # Session cookie security
    SESSION_COOKIE_NAME = "secureshare_keyx_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() in ("true", "1", "yes")
    PERMANENT_SESSION_LIFETIME = 86400  # 24 hours
    
    # CORS origins for cross-portal integration with file-sharing website (port 5000)
    CORS_ALLOWED_ORIGINS = [
        origin.strip() for origin in os.environ.get(
            "CORS_ALLOWED_ORIGINS",
            "http://127.0.0.1:5000,http://localhost:5000,http://127.0.0.1:5001,http://localhost:5001"
        ).split(",") if origin.strip()
    ]
    
    # Security header settings
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-eval'; "  # WebAssembly and libsodium require eval/wasm-unsafe-eval
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' http://127.0.0.1:5000 http://localhost:5000 http://127.0.0.1:5001 http://localhost:5001 ws:; "
            "object-src 'none'; "
            "base-uri 'self';"
        )
    }

class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
