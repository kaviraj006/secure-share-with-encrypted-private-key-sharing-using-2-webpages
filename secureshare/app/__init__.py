import os
from flask import Flask, render_template, jsonify, send_from_directory, request
from app.config import Config
from app.extensions import db, login_manager
from app.models import User
from app.routes.auth import auth_bp
from app.routes.users import users_bp
from app.routes.key_exchange import key_exchange_bp
from app.routes.files import files_bp
from app.routes.transfers import transfers_bp

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
        
    # Ensure ciphertext storage directory exists
    os.makedirs(app.config["CIPHERTEXT_STORAGE_DIR"], exist_ok=True)
    
    # Init extensions
    db.init_app(app)
    login_manager.init_app(app)
    
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, user_id)
        
    @login_manager.unauthorized_handler
    def unauthorized():
        if request.path.startswith("/api/"):
            return jsonify({"error": "Authentication required.", "code": "UNAUTHORIZED"}), 401
        return render_template("index.html")

    # Register API blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(key_exchange_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(transfers_bp)
    
    # SPA frontend catch-all routes
    @app.route("/")
    @app.route("/login")
    @app.route("/register")
    @app.route("/dashboard")
    @app.route("/upload")
    @app.route("/receive")
    @app.route("/receive/<path:subpath>")
    @app.route("/history")
    @app.route("/settings")
    def spa_index(subpath=None):
        return render_template("index.html")
        
    # Security headers on every response
    @app.after_request
    def set_security_headers(response):
        for header, value in app.config.get("SECURITY_HEADERS", {}).items():
            response.headers[header] = value
        return response

    # API error handlers
    @app.errorhandler(400)
    def bad_request(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": str(e.description or "Bad request"), "code": "BAD_REQUEST"}), 400
        return e

    @app.errorhandler(403)
    def forbidden(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": str(e.description or "Forbidden"), "code": "FORBIDDEN"}), 403
        return e

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": str(e.description or "Not found"), "code": "NOT_FOUND"}), 404
        return render_template("index.html")

    @app.errorhandler(410)
    def gone(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": str(e.description or "Resource expired"), "code": "GONE"}), 410
        return e

    @app.errorhandler(500)
    def internal_error(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "An unexpected error occurred on the server.", "code": "INTERNAL_SERVER_ERROR"}), 500
        return e

    # Create tables
    with app.app_context():
        db.create_all()

    return app
