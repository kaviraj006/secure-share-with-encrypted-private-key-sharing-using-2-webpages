from flask import Blueprint, request, jsonify, session
from flask_login import login_user, logout_user, current_user, login_required
from app.extensions import db
from app.models import User
from app.services.security import (
    validate_username,
    validate_email,
    generate_csrf_token,
    verify_csrf_token
)
from app.utils.rate_limit import rate_limit

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

@auth_bp.route("/csrf", methods=["GET"])
def get_csrf():
    return jsonify({"csrf_token": generate_csrf_token()})

@auth_bp.route("/register", methods=["POST"])
@rate_limit(max_requests=10, window_seconds=60)
def register():
    # If session has CSRF token already, verify it
    if "_csrf_token" in session:
        verify_csrf_token()
        
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    
    if not validate_username(username):
        return jsonify({"error": "Username must be 3-32 alphanumeric characters or underscores.", "code": "INVALID_USERNAME"}), 400
        
    if not validate_email(email):
        return jsonify({"error": "A valid email address is required.", "code": "INVALID_EMAIL"}), 400
        
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long.", "code": "PASSWORD_TOO_SHORT"}), 400
        
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username is already registered.", "code": "USERNAME_TAKEN"}), 409
        
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email address is already registered.", "code": "EMAIL_TAKEN"}), 409
        
    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    login_user(user, remember=False)
    session.permanent = True
    csrf_token = generate_csrf_token()
    
    return jsonify({
        "message": "User registered successfully.",
        "user": user.to_dict(),
        "csrf_token": csrf_token
    }), 201

@auth_bp.route("/login", methods=["POST"])
@rate_limit(max_requests=10, window_seconds=60)
def login():
    if "_csrf_token" in session:
        verify_csrf_token()
        
    data = request.get_json(silent=True) or {}
    identifier = (data.get("identifier") or data.get("username") or data.get("email") or "").strip()
    password = data.get("password") or ""
    
    if not identifier or not password:
        return jsonify({"error": "Invalid username or password.", "code": "INVALID_CREDENTIALS"}), 401
        
    # Generic failure message to prevent user enumeration
    user = User.query.filter(
        (User.username == identifier) | (User.email == identifier.lower())
    ).first()
    
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid username or password.", "code": "INVALID_CREDENTIALS"}), 401
        
    if user.account_status != "active":
        return jsonify({"error": "Account is suspended or inactive.", "code": "ACCOUNT_INACTIVE"}), 403
        
    login_user(user, remember=False)
    session.permanent = True
    csrf_token = generate_csrf_token()
    
    return jsonify({
        "message": "Logged in successfully.",
        "user": user.to_dict(),
        "csrf_token": csrf_token
    })

@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    verify_csrf_token()
    logout_user()
    session.clear()
    return jsonify({"message": "Logged out successfully."})

@auth_bp.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json(silent=True) or {}
    identifier = (data.get("identifier") or data.get("username") or data.get("email") or "").strip()
    new_password = data.get("new_password") or data.get("password") or ""
    
    if not identifier or not new_password:
        return jsonify({"error": "Identifier and new password are required.", "code": "MISSING_FIELDS"}), 400
    if len(new_password) < 8:
        return jsonify({"error": "New password must be at least 8 characters long.", "code": "PASSWORD_TOO_SHORT"}), 400
        
    user = User.query.filter(
        (User.username == identifier) | (User.email == identifier.lower())
    ).first()
    if not user:
        return jsonify({"error": f"User '{identifier}' not found.", "code": "USER_NOT_FOUND"}), 404
        
    user.set_password(new_password)
    db.session.commit()
    return jsonify({"message": f"Password for '{user.username}' successfully reset.", "user": user.to_dict()}), 200

@auth_bp.route("/me", methods=["GET"])
def me():
    csrf_token = generate_csrf_token()
    if not current_user.is_authenticated:
        return jsonify({"authenticated": False, "csrf_token": csrf_token}), 200
        
    return jsonify({
        "authenticated": True,
        "user": current_user.to_dict(),
        "csrf_token": csrf_token
    })
