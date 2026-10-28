from flask import Blueprint, request, jsonify
from flask_login import current_user
from sqlalchemy import func
from app.extensions import db
from app.models import User, PublicPrekey, utc_now
from app.services.prekey_service import PrekeyService
from app.services.validation import verify_csrf_token, validate_hex

prekeys_bp = Blueprint("prekeys", __name__, url_prefix="/api/prekeys")

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

@prekeys_bp.route("", methods=["POST"])
def publish_prekeys():
    verify_csrf_token()
    data = request.get_json(silent=True) or {}
    
    user_id = _get_caller_user_id(data)
    if not user_id:
        return jsonify({"error": "Authentication required to publish prekeys.", "code": "UNAUTHORIZED"}), 401

    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "User account not found.", "code": "USER_NOT_FOUND"}), 404
        
    # Support single prekey or batch
    prekeys_list = data.get("prekeys") or [data]
    published = []
    
    for item in prekeys_list:
        prekey_id = (item.get("prekey_id") or item.get("id") or "").strip()
        x25519_pk = (item.get("x25519_public_key") or "").strip().lower()
        signature = (item.get("signature") or "").strip()
        days_valid = int(item.get("days_valid") or 30)
        
        if not prekey_id:
            continue
        if not validate_hex(x25519_pk, expected_bytes=32):
            return jsonify({"error": f"Invalid X25519 public key format for prekey {prekey_id}.", "code": "INVALID_KEY"}), 400
        if not signature:
            return jsonify({"error": f"Signed identity signature required for prekey {prekey_id}.", "code": "MISSING_SIGNATURE"}), 400
            
        pk_obj = PrekeyService.publish_prekey(
            user_id=user.id,
            prekey_id=prekey_id,
            x25519_pk=x25519_pk,
            signature=signature,
            days_valid=days_valid
        )
        published.append(pk_obj.to_dict())
        
    return jsonify({
        "message": f"Successfully published {len(published)} prekey(s).",
        "prekeys": published
    }), 201

@prekeys_bp.route("/me", methods=["GET"])
def get_my_prekeys():
    user_id = _get_caller_user_id()
    if not user_id:
        summary_data = {
            "total": 0,
            "available": 0,
            "reserved": 0,
            "consumed": 0,
            "expired": 0,
            "needs_replenishment": True
        }
        return jsonify({"prekeys": [], "summary": summary_data, "stats": summary_data}), 200

    now = utc_now()
    # Check for expired prekeys
    prekeys = PublicPrekey.query.filter_by(user_id=user_id).order_by(PublicPrekey.created_at.desc()).all()
    expired_changed = False
    for p in prekeys:
        if p.status == "AVAILABLE" and p.expires_at and p.expires_at <= now:
            p.status = "EXPIRED"
            expired_changed = True
            
    if expired_changed:
        db.session.commit()
            
    available_count = sum(1 for p in prekeys if p.status == "AVAILABLE")
    reserved_count = sum(1 for p in prekeys if p.status == "RESERVED")
    consumed_count = sum(1 for p in prekeys if p.status == "CONSUMED")
    expired_count = sum(1 for p in prekeys if p.status == "EXPIRED")
    
    summary_data = {
        "total": len(prekeys),
        "available": available_count,
        "reserved": reserved_count,
        "consumed": consumed_count,
        "expired": expired_count,
        "needs_replenishment": available_count < 3
    }
    
    return jsonify({
        "prekeys": [p.to_dict() for p in prekeys],
        "summary": summary_data,
        "stats": summary_data
    })

@prekeys_bp.route("/<target>", methods=["GET"])
def get_recipient_prekey(target: str):
    target = target.strip()
    user = User.query.filter(
        (User.id == target) |
        (func.lower(User.username) == target.lower()) |
        (func.lower(User.email) == target.lower())
    ).first()
    if not user:
        return jsonify({"error": f"Recipient '{target}' not found.", "code": "USER_NOT_FOUND"}), 404

    prekey = PrekeyService.get_available_prekey(user.id)
    if not prekey:
        return jsonify({
            "error": "No available unexpired prekeys for this recipient. Replenishment required.",
            "code": "NO_PREKEYS_AVAILABLE",
            "recipient_id": user.id,
            "recipient_username": user.username
        }), 404
        
    return jsonify({
        "recipient_id": user.id,
        "recipient_username": user.username,
        "prekey": prekey.to_dict()
    })

@prekeys_bp.route("/<prekey_id>/reserve", methods=["POST"])
def reserve_prekey(prekey_id: str):
    verify_csrf_token()
    success = PrekeyService.reserve_prekey(prekey_id)
    if not success:
        return jsonify({"error": "Prekey is no longer available or already reserved/consumed.", "code": "PREKEY_UNAVAILABLE"}), 409
    return jsonify({"message": f"Prekey {prekey_id} reserved successfully."})

@prekeys_bp.route("/<prekey_id>/consume", methods=["POST"])
def consume_prekey(prekey_id: str):
    verify_csrf_token()
    success = PrekeyService.consume_prekey(prekey_id)
    if not success:
        return jsonify({"error": "Prekey could not be consumed (already consumed or invalid).", "code": "DOUBLE_CONSUMPTION_REJECTED"}), 409
    return jsonify({"message": f"Prekey {prekey_id} consumed permanently."})
