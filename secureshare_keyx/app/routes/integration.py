import json
import urllib.request
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from sqlalchemy import func
from app.extensions import db
from app.models import User, PublicIdentity, PublicPrekey, KeyEnvelope, utc_now
from app.services.prekey_service import PrekeyService
from app.services.validation import verify_csrf_token

integration_bp = Blueprint("integration", __name__, url_prefix="/api/key-exchange")

@integration_bp.route("/status", methods=["GET"])
def key_exchange_portal_status():
    return jsonify({
        "status": "ONLINE",
        "online": True,
        "service": "SecureShare Key Exchange Portal",
        "port": 5001,
        "adapter": "FileVault-KeyX-Adapter-v1"
    }), 200

@integration_bp.route("/probe/filevault", methods=["GET"])
def probe_filevault():
    try:
        req = urllib.request.Request("http://127.0.0.1:5000/api/auth/csrf", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            return jsonify({"online": resp.status in (200, 401), "status": resp.status, "url": "http://127.0.0.1:5000"}), 200
    except Exception as e:
        return jsonify({"online": False, "error": str(e), "url": "http://127.0.0.1:5000"}), 200

@integration_bp.route("/identities/<target>", methods=["GET"])
def discover_identity(target: str):
    """
    Public discovery endpoint queried by SecureShare file-sharing website.
    Returns recipient public keys, prekey, and fingerprint.
    """
    target = target.strip()
    user = User.query.filter(
        (User.id == target) |
        (func.lower(User.username) == target.lower()) |
        (func.lower(User.email) == target.lower())
    ).first()
    if not user:
        return jsonify({"error": f"Recipient '{target}' not found.", "code": "USER_NOT_FOUND"}), 404
    if not user.identity:
        return jsonify({"error": f"Recipient '{user.username}' has not published an identity bundle.", "code": "NO_IDENTITY", "user_id": user.id, "username": user.username}), 404
        
    prekey = PrekeyService.get_available_prekey(user.id)
    if not prekey:
        return jsonify({"error": f"No available unexpired prekey found for recipient '{user.username}'.", "code": "NO_PREKEYS_AVAILABLE", "user_id": user.id, "username": user.username}), 404
        
    return jsonify({
        "recipient_id": user.id,
        "recipient_username": user.username,
        "signing_public_key": user.identity.ed25519_public_key,
        "fingerprint": user.identity.fingerprint,
        "x25519_prekey": prekey.x25519_public_key,
        "prekey_id": prekey.id,
        "prekey_signature": prekey.signature,
        "created_at": user.identity.created_at.isoformat()
    })

@integration_bp.route("/envelopes", methods=["POST"])
def submit_envelope_integration():
    """
    Integration endpoint to submit signed key envelopes from the file-sharing app.
    Accepts JSON envelope with sender_id and recipient_id.
    """
    data = request.get_json(silent=True) or {}
    transfer_id = (data.get("transfer_id") or "").strip()
    sender_id = (data.get("sender_id") or (current_user.id if current_user.is_authenticated else "")).strip()
    recipient_id = (data.get("recipient_id") or "").strip()
    envelope_payload = data.get("envelope")
    
    if not transfer_id or not recipient_id or not envelope_payload:
        return jsonify({"error": "transfer_id, recipient_id, and envelope payload required.", "code": "INVALID_PARAMS"}), 400
        
    if not sender_id:
        return jsonify({"error": "sender_id is required.", "code": "MISSING_SENDER"}), 400
        
    if isinstance(envelope_payload, dict):
        recipient_prekey_id = envelope_payload.get("recipient_prekey_id", "default")
        signature = envelope_payload.get("signature", "")
        envelope_str = json.dumps(envelope_payload)
    else:
        recipient_prekey_id = "default"
        signature = ""
        envelope_str = str(envelope_payload)
        
    # Mark prekey consumed if specified
    if recipient_prekey_id and recipient_prekey_id != "default":
        PrekeyService.consume_prekey(recipient_prekey_id)
        
    # Resolve recipient on Key Exchange Portal
    sender_username = (data.get("sender_username") or "").strip()
    recipient_username = (data.get("recipient_username") or "").strip()
    envelope = KeyEnvelope.query.filter_by(transfer_id=transfer_id).first()

    target_rec = None
    if recipient_username:
        target_rec = User.query.filter(func.lower(User.username) == recipient_username.lower()).first()
    if not target_rec and recipient_id:
        target_rec = User.query.filter((User.id == recipient_id) | (func.lower(User.username) == str(recipient_id).lower())).first()

    if target_rec:
        resolved_recipient_id = target_rec.id
    elif envelope and envelope.recipient_id:
        resolved_recipient_id = envelope.recipient_id
    else:
        resolved_recipient_id = recipient_id

    target_sender = None
    if sender_username:
        target_sender = User.query.filter(func.lower(User.username) == sender_username.lower()).first()
    if not target_sender and sender_id:
        target_sender = User.query.filter((User.id == sender_id) | (func.lower(User.username) == str(sender_id).lower())).first()

    if target_sender:
        resolved_sender_id = target_sender.id
    elif envelope and envelope.sender_id:
        resolved_sender_id = envelope.sender_id
    else:
        resolved_sender_id = sender_id

    if not envelope:
        from datetime import timedelta
        envelope = KeyEnvelope(
            transfer_id=transfer_id,
            sender_id=resolved_sender_id,
            recipient_id=resolved_recipient_id,
            recipient_prekey_id=recipient_prekey_id,
            encrypted_envelope=envelope_str,
            sender_signature=signature,
            protocol_version=1,
            created_at=utc_now(),
            expires_at=utc_now() + timedelta(days=2),
            status="PENDING"
        )
        db.session.add(envelope)
    else:
        from datetime import timedelta
        envelope.sender_id = resolved_sender_id
        envelope.recipient_id = resolved_recipient_id
        envelope.recipient_prekey_id = recipient_prekey_id
        envelope.encrypted_envelope = envelope_str
        envelope.sender_signature = signature
        envelope.status = "PENDING"
        envelope.created_at = utc_now()
        envelope.expires_at = utc_now() + timedelta(days=2)
    db.session.commit()
        
    return jsonify({
        "message": "Key envelope integrated successfully.",
        "envelope_id": envelope.id,
        "transfer_id": transfer_id
    }), 201

@integration_bp.route("/envelopes/<transfer_id>", methods=["GET"])
def get_envelope_integration(transfer_id: str):
    """
    Integration endpoint to retrieve signed key envelope by transfer_id.
    """
    envelope = KeyEnvelope.query.filter_by(transfer_id=transfer_id).first_or_404(description="Envelope not found.")
    
    now = utc_now()
    if envelope.expires_at <= now:
        envelope.status = "EXPIRED"
        db.session.commit()
        return jsonify({"error": "Transfer has expired.", "code": "ENVELOPE_EXPIRED"}), 410
        
    return jsonify({
        "transfer_id": envelope.transfer_id,
        "sender_id": envelope.sender_id,
        "recipient_id": envelope.recipient_id,
        "envelope": json.loads(envelope.encrypted_envelope) if envelope.encrypted_envelope.startswith("{") else envelope.encrypted_envelope,
        "created_at": envelope.created_at.isoformat(),
        "status": envelope.status
    })
