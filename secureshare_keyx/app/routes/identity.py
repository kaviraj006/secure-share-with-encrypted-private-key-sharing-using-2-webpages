from flask import Blueprint, request, jsonify
from flask_login import current_user
from sqlalchemy import func
from app.extensions import db
from app.models import User, PublicIdentity, utc_now
from app.services.validation import verify_csrf_token, validate_hex
from app.services.security_logger import log_security_event

identity_bp = Blueprint("identity", __name__, url_prefix="/api")

def _get_caller_user_id(data: dict = None):
    if current_user.is_authenticated:
        return current_user.id
    header_uid = request.headers.get("X-User-ID")
    if header_uid:
        return header_uid.strip()
    if data:
        body_uid = data.get("user_id") or data.get("owner_id")
        if body_uid:
            return str(body_uid).strip()
    return None

@identity_bp.route("/identities", methods=["POST"])
def publish_identity():
    verify_csrf_token()
    data = request.get_json(silent=True) or {}
    
    user_id = _get_caller_user_id(data)
    if not user_id:
        return jsonify({"error": "Authentication required to publish identity.", "code": "UNAUTHORIZED"}), 401

    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User account not found.", "code": "USER_NOT_FOUND"}), 404

    ed25519_pk = (data.get("ed25519_public_key") or "").strip().lower()
    fingerprint = (data.get("fingerprint") or "").strip()
    
    if not validate_hex(ed25519_pk, expected_bytes=32):
        return jsonify({"error": "Invalid Ed25519 public key. Must be 32 bytes (64 hex characters).", "code": "INVALID_KEY"}), 400
        
    if not fingerprint or len(fingerprint) < 16:
        return jsonify({"error": "Invalid identity fingerprint.", "code": "INVALID_FINGERPRINT"}), 400
        
    identity = PublicIdentity.query.filter_by(user_id=user.id).first()
    if identity:
        # Check if key is being rotated
        if identity.ed25519_public_key != ed25519_pk:
            old_fp = identity.fingerprint
            identity.ed25519_public_key = ed25519_pk
            identity.fingerprint = fingerprint
            identity.status = "rotated"
            identity.created_at = utc_now()
            log_security_event(
                event_type="KEY_CHANGE_DETECTED",
                message=f"User {user.username} rotated Ed25519 identity key. Old FP: {old_fp[:16]}..., New FP: {fingerprint[:16]}...",
                result="WARNING",
                related_public_id=fingerprint
            )
        else:
            identity.status = "active"
    else:
        identity = PublicIdentity(
            user_id=user.id,
            ed25519_public_key=ed25519_pk,
            fingerprint=fingerprint,
            created_at=utc_now(),
            status="active"
        )
        db.session.add(identity)
        log_security_event(
            event_type="PUBLIC_KEY_PUBLISHED",
            message=f"User {user.username} published initial Ed25519 identity key.",
            result="SUCCESS",
            related_public_id=fingerprint
        )
        
    db.session.commit()
    return jsonify({
        "message": "Cryptographic public identity active.",
        "identity": identity.to_dict()
    })

@identity_bp.route("/identities/me", methods=["GET"])
def get_my_identity():
    user_id = _get_caller_user_id()
    if not user_id:
        return jsonify({"has_identity": False}), 200
        
    identity = PublicIdentity.query.filter_by(user_id=user_id).first()
    if not identity:
        return jsonify({"has_identity": False}), 200
    return jsonify({"has_identity": True, "identity": identity.to_dict()})

@identity_bp.route("/identities/<target>", methods=["GET"])
def get_user_identity(target: str):
    target = target.strip()
    user = User.query.filter(
        (User.id == target) |
        (func.lower(User.username) == target.lower()) |
        (func.lower(User.email) == target.lower())
    ).first()
    if not user:
        return jsonify({"error": f"User '{target}' not found.", "code": "USER_NOT_FOUND"}), 404
    if not user.identity:
        return jsonify({"error": f"User '{user.username}' has not published a cryptographic identity.", "code": "NO_IDENTITY", "user_id": user.id, "username": user.username}), 404
    return jsonify({
        "user_id": user.id,
        "username": user.username,
        "identity": user.identity.to_dict()
    })

@identity_bp.route("/identities/<target>/fingerprint", methods=["GET"])
def get_user_fingerprint(target: str):
    target = target.strip()
    user = User.query.filter(
        (User.id == target) |
        (func.lower(User.username) == target.lower()) |
        (func.lower(User.email) == target.lower())
    ).first()
    if not user:
        return jsonify({"error": f"User '{target}' not found.", "code": "USER_NOT_FOUND"}), 404
    if not user.identity:
        return jsonify({"error": "User has no active fingerprint.", "code": "NO_IDENTITY"}), 404
    return jsonify({
        "user_id": user.id,
        "username": user.username,
        "fingerprint": user.identity.fingerprint
    })

@identity_bp.route("/users/search", methods=["GET"])
def search_users():
    q = (request.args.get("q") or "").strip()
    current_uid = _get_caller_user_id()

    filters = [User.account_status == "active"]
    if current_uid:
        filters.append(User.id != current_uid)
    if q:
        filters.append(
            (User.username.ilike(f"%{q}%")) |
            (User.id.ilike(f"%{q}%")) |
            (User.email.ilike(f"%{q}%")) |
            (User.identity.has(PublicIdentity.fingerprint.ilike(f"%{q}%"))) |
            (User.identity.has(PublicIdentity.ed25519_public_key.ilike(f"%{q}%")))
        )

    users = User.query.filter(*filters).order_by(User.username.asc()).limit(50).all()
    
    results = []
    for u in users:
        results.append({
            "id": u.id,
            "username": u.username,
            "has_identity": u.identity is not None,
            "fingerprint": u.identity.fingerprint if u.identity else None,
            "ed25519_public_key": u.identity.ed25519_public_key if u.identity else None
        })
    return jsonify({"users": results})
