from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from app.models import User, PublicIdentity

users_bp = Blueprint("users", __name__, url_prefix="/api")

@users_bp.route("/users/search", methods=["GET"])
def search_users():
    query = (request.args.get("q") or "").strip()
    current_uid = current_user.id if current_user.is_authenticated else None
    filters = [User.account_status == "active"]
    if current_uid:
        filters.append(User.id != current_uid)
    if query:
        filters.append(
            (User.username.ilike(f"%{query}%")) |
            (User.id.ilike(f"%{query}%")) |
            (User.email.ilike(f"%{query}%"))
        )
    
    # Prioritize users with active identities, then username alphabetical
    matched_users = User.query.filter(*filters).order_by(User.username.asc()).limit(50).all()
    
    results = []
    for u in matched_users:
        identity = u.identity
        results.append({
            "id": u.id,
            "username": u.username,
            "has_identity": identity is not None,
            "fingerprint": identity.fingerprint if identity else None,
            "signing_public_key": identity.signing_public_key if identity else None,
            "x25519_prekey": identity.x25519_prekey if identity else None,
            "prekey_id": identity.prekey_id if identity else None
        })
        
    return jsonify({"users": results})

@users_bp.route("/users/<user_id>", methods=["GET"])
def get_user_profile(user_id: str):
    user_id = user_id.strip()
    user = User.query.filter(
        (User.id == user_id) |
        (User.username == user_id)
    ).first_or_404(description="User not found.")
    return jsonify({
        "id": user.id,
        "username": user.username,
        "created_at": user.created_at.isoformat(),
        "has_identity": user.identity is not None,
        "fingerprint": user.identity.fingerprint if user.identity else None
    })

@users_bp.route("/identities/<user_id>", methods=["GET"])
def get_identity(user_id: str):
    user_id = user_id.strip()
    user = User.query.filter(
        (User.id == user_id) |
        (User.username == user_id)
    ).first()
    if user and user.identity:
        return jsonify(user.identity.to_dict())
    identity = PublicIdentity.query.filter_by(user_id=user_id).first_or_404(description="Public identity not found.")
    return jsonify(identity.to_dict())
