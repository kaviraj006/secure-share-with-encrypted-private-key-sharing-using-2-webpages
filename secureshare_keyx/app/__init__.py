import os
from flask import Flask, render_template, jsonify, request
from app.config import Config
from app.extensions import db, login_manager, cors
from app.models import User
from app.routes.auth import auth_bp
from app.routes.identity import identity_bp
from app.routes.contacts import contacts_bp
from app.routes.prekeys import prekeys_bp
from app.routes.envelopes import envelopes_bp
from app.routes.history import history_bp
from app.routes.security import security_bp
from app.routes.integration import integration_bp

def create_app(config_class=Config):
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static"
    )
    app.config.from_object(config_class)
    
    # Ensure instance directory exists
    instance_path = os.path.dirname(app.config["SQLALCHEMY_DATABASE_URI"].replace("sqlite:///", ""))
    if instance_path and not instance_path.startswith(":"):
        os.makedirs(instance_path, exist_ok=True)
        
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    cors.init_app(
        app,
        resources={r"/api/*": {"origins": app.config.get("CORS_ALLOWED_ORIGINS", "*")}},
        supports_credentials=True
    )
    
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, user_id)
        
    @login_manager.unauthorized_handler
    def unauthorized():
        if request.path.startswith("/api/"):
            return jsonify({"error": "AUTHENTICATION REQUIRED. ACCESS RESTRICTED.", "code": "UNAUTHORIZED"}), 401
        return render_template("index.html")

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(identity_bp)
    app.register_blueprint(contacts_bp)
    app.register_blueprint(prekeys_bp)
    app.register_blueprint(envelopes_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(security_bp)
    app.register_blueprint(integration_bp)

    # Health and Readiness check
    @app.route("/api/health", methods=["GET"])
    def health_check():
        from app.models import utc_now
        return jsonify({
            "status": "ONLINE",
            "service": "SecureShare // KEY EXCHANGE",
            "version": "1.0.0",
            "port": app.config.get("PORT", 5001),
            "timestamp": utc_now().isoformat()
        }), 200

    # Unified Dashboard Statistics
    @app.route("/api/dashboard/stats", methods=["GET"])
    def dashboard_stats():
        from flask_login import current_user
        from app.models import PublicPrekey, KeyEnvelope, TrustedContact, utc_now
        
        if not current_user.is_authenticated:
            return jsonify({
                "authenticated": False,
                "stats": {
                    "identity_status": "UNAUTHENTICATED",
                    "available_prekeys": 0,
                    "inbox_count": 0,
                    "contacts_count": 0,
                    "verified_contacts_count": 0
                },
                "pending_envelopes": []
            }), 200

        now = utc_now()
        avail_pk = PublicPrekey.query.filter(
            PublicPrekey.user_id == current_user.id,
            PublicPrekey.status == "AVAILABLE",
            (PublicPrekey.expires_at.is_(None)) | (PublicPrekey.expires_at > now)
        ).count()

        pending_envs = KeyEnvelope.query.filter_by(
            recipient_id=current_user.id,
            status="PENDING"
        ).order_by(KeyEnvelope.created_at.desc()).all()

        contacts = TrustedContact.query.filter_by(owner_id=current_user.id).all()
        verified_contacts = [c for c in contacts if c.verification_status == "VERIFIED"]

        identity_status = "UNINITIALIZED"
        fingerprint = None
        if current_user.identity:
            identity_status = "ACTIVE" if current_user.identity.status == "active" else current_user.identity.status.upper()
            fingerprint = current_user.identity.fingerprint

        return jsonify({
            "authenticated": True,
            "username": current_user.username,
            "stats": {
                "identity_status": identity_status,
                "fingerprint": fingerprint,
                "available_prekeys": avail_pk,
                "inbox_count": len(pending_envs),
                "contacts_count": len(contacts),
                "verified_contacts_count": len(verified_contacts)
            },
            "pending_envelopes": [e.to_dict() for e in pending_envs[:5]]
        }), 200
    
    # File Vault connectivity probe alias
    @app.route("/api/probe/filevault", methods=["GET"])
    def probe_filevault_alias():
        import urllib.request
        try:
            req = urllib.request.Request("http://127.0.0.1:5000/api/auth/csrf", headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                return jsonify({"online": resp.status in (200, 401), "status": resp.status, "url": "http://127.0.0.1:5000"}), 200
        except Exception as e:
            return jsonify({"online": False, "error": str(e), "url": "http://127.0.0.1:5000"}), 200

    # SPA Routes
    @app.route("/")
    @app.route("/overview")
    @app.route("/identity")
    @app.route("/contacts")
    @app.route("/keys")
    @app.route("/prekeys")
    @app.route("/exchange")
    @app.route("/envelopes")
    @app.route("/inbox")
    @app.route("/history")
    @app.route("/logs")
    @app.route("/settings")
    @app.route("/login")
    @app.route("/register")
    def spa_entrypoint():
        return render_template("index.html")
        
    # Security headers
    @app.after_request
    def set_security_headers(response):
        for header, value in app.config.get("SECURITY_HEADERS", {}).items():
            response.headers[header] = value
        return response

    # Error handlers
    @app.errorhandler(400)
    def bad_request(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": str(e.description or "BAD REQUEST"), "code": "BAD_REQUEST"}), 400
        return e

    @app.errorhandler(403)
    def forbidden(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": str(e.description or "FORBIDDEN"), "code": "FORBIDDEN"}), 403
        return e

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": str(e.description or "NOT FOUND"), "code": "NOT_FOUND"}), 404
        return render_template("index.html")

    @app.errorhandler(410)
    def gone(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": str(e.description or "RESOURCE EXPIRED"), "code": "GONE"}), 410
        return e

    @app.errorhandler(500)
    def internal_error(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "INTERNAL SERVER FAULT.", "code": "INTERNAL_SERVER_ERROR"}), 500
        return e

    with app.app_context():
        db.create_all()

    return app
