import json
from datetime import timedelta
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from sqlalchemy import func
from app.extensions import db
from app.models import User, KeyEnvelope, PublicIdentity, utc_now
from app.services.prekey_service import PrekeyService
from app.services.validation import verify_csrf_token
from app.services.security_logger import log_security_event

envelopes_bp = Blueprint("envelopes", __name__, url_prefix="/api/envelopes")

@envelopes_bp.route("", methods=["POST"])
def submit_envelope():
    verify_csrf_token()
    data = request.get_json(silent=True) or {}
    
    transfer_id = (data.get("transfer_id") or "").strip()
    recipient_identifier = (data.get("recipient_id") or data.get("recipient") or "").strip()
    recipient_prekey_id = (data.get("recipient_prekey_id") or "").strip()
    envelope_payload = data.get("encrypted_envelope") or data.get("envelope")
    sender_signature = (data.get("sender_signature") or (envelope_payload.get("signature") if isinstance(envelope_payload, dict) else "") or "").strip()
    protocol_version = int(data.get("protocol_version") or 1)
    expires_in_hours = min(max(int(data.get("expires_in_hours") or 24), 1), 168)
    
    if not transfer_id:
        return jsonify({"error": "transfer_id is required.", "code": "MISSING_TRANSFER_ID"}), 400
    if not recipient_identifier:
        return jsonify({"error": "recipient_id is required.", "code": "MISSING_RECIPIENT"}), 400
    if not recipient_prekey_id:
        return jsonify({"error": "recipient_prekey_id is required.", "code": "MISSING_PREKEY_ID"}), 400
    if not envelope_payload:
        return jsonify({"error": "encrypted_envelope is required.", "code": "MISSING_ENVELOPE"}), 400
    if not sender_signature:
        return jsonify({"error": "sender_signature is required.", "code": "MISSING_SIGNATURE"}), 400
        
    # Find recipient user
    recipient_user = User.query.filter(
        (User.id == recipient_identifier) | (func.lower(User.username) == recipient_identifier.lower())
    ).first()
    if not recipient_user:
        return jsonify({"error": "Recipient user not found.", "code": "RECIPIENT_NOT_FOUND"}), 404

    # Determine sender_id
    sender_id = (data.get("sender_id") or "").strip()
    if not sender_id and current_user.is_authenticated:
        sender_id = current_user.id

    if not sender_id and isinstance(envelope_payload, dict):
        sender_pk = (envelope_payload.get("sender_identity_key") or "").strip().lower()
        if sender_pk:
            pub_ident = PublicIdentity.query.filter(func.lower(PublicIdentity.ed25519_public_key) == sender_pk).first()
            if pub_ident:
                sender_id = pub_ident.user_id

    if not sender_id:
        sender_id = "external_sender"
        
    if (current_user.is_authenticated and recipient_user.id == current_user.id) or (sender_id and sender_id == recipient_user.id):
        return jsonify({"error": "Cannot address envelope to self.", "code": "SELF_ENVELOPE"}), 400
        
    # Format envelope JSON
    if isinstance(envelope_payload, dict):
        envelope_str = json.dumps(envelope_payload)
    else:
        envelope_str = str(envelope_payload)
        
    now = utc_now()
    expires_at = now + timedelta(hours=expires_in_hours)
    
    # Consume prekey
    PrekeyService.consume_prekey(recipient_prekey_id)

    # Check for existing envelope on this transfer_id
    existing_envelope = KeyEnvelope.query.filter_by(transfer_id=transfer_id).first()
    if existing_envelope:
        # Exact replay defense: if identical signature/payload is resent without force_update, reject with 409
        if existing_envelope.sender_signature == sender_signature and not data.get("force_update"):
            log_security_event(
                event_type="REPLAY_ATTEMPT_REJECTED",
                message=f"Duplicate envelope transfer_id {transfer_id} rejected.",
                related_public_id=transfer_id,
                result="FAILURE"
            )
            return jsonify({
                "error": "Replay attempt detected: transfer_id already exists.",
                "code": "DUPLICATE_TRANSFER_ID"
            }), 409

        # Update existing envelope with fresh key seal
        existing_envelope.sender_id = sender_id or existing_envelope.sender_id
        existing_envelope.recipient_id = recipient_user.id
        existing_envelope.recipient_prekey_id = recipient_prekey_id
        existing_envelope.encrypted_envelope = envelope_str
        existing_envelope.sender_signature = sender_signature
        existing_envelope.protocol_version = protocol_version
        existing_envelope.status = "PENDING"
        existing_envelope.created_at = now
        existing_envelope.expires_at = expires_at
        db.session.commit()
        
        log_security_event(
            event_type="ENVELOPE_UPDATED",
            message=f"Key envelope for transfer {transfer_id} updated with fresh key by sender {sender_id}.",
            related_public_id=transfer_id,
            result="SUCCESS"
        )
        return jsonify({
            "message": "Key envelope updated with fresh file key.",
            "envelope": existing_envelope.to_dict(),
            "envelope_id": existing_envelope.id
        }), 200
    
    envelope = KeyEnvelope(
        transfer_id=transfer_id,
        sender_id=sender_id,
        recipient_id=recipient_user.id,
        recipient_prekey_id=recipient_prekey_id,
        encrypted_envelope=envelope_str,
        sender_signature=sender_signature,
        protocol_version=protocol_version,
        created_at=now,
        expires_at=expires_at,
        status="PENDING"
    )
    db.session.add(envelope)
    db.session.commit()
    
    log_security_event(
        event_type="ENVELOPE_SUBMITTED",
        message=f"Protected key envelope dispatched to {recipient_user.username} for transfer {transfer_id}.",
        related_public_id=transfer_id,
        result="SUCCESS"
    )
    
    return jsonify({
        "message": "Key envelope stored and prekey consumed.",
        "envelope": envelope.to_dict()
    }), 201

def _get_caller_id():
    if current_user.is_authenticated:
        return current_user.id
    header_uid = request.headers.get("X-User-ID")
    if header_uid:
        return header_uid.strip()
    param_uid = request.args.get("user_id") or request.args.get("owner_id")
    if param_uid:
        return param_uid.strip()
    return None

@envelopes_bp.route("/inbox", methods=["GET"])
def get_inbox():
    user_id = _get_caller_id()
    if not user_id:
        return jsonify({"inbox": []}), 200

    caller = db.session.get(User, user_id)
    caller_username = caller.username.lower() if caller else ""

    now = utc_now()
    all_envelopes = KeyEnvelope.query.order_by(KeyEnvelope.created_at.desc()).all()
    
    inbox_items = []
    for env in all_envelopes:
        rec_match = (env.recipient_id == user_id)
        if not rec_match and env.recipient:
            rec_match = (env.recipient.username.lower() == caller_username)
        if not rec_match and caller_username and (env.recipient_id == caller_username):
            rec_match = True

        if rec_match:
            if env.status == "PENDING" and env.expires_at <= now:
                env.status = "EXPIRED"
                db.session.commit()
            inbox_items.append(env.to_dict())
        
    return jsonify({"inbox": inbox_items})

@envelopes_bp.route("/<transfer_id>", methods=["GET"])
def get_envelope(transfer_id: str):
    envelope = KeyEnvelope.query.filter_by(transfer_id=transfer_id).first_or_404(description="Envelope not found.")
    user_id = _get_caller_id()
    
    # Per-object authorization: only recipient or sender if caller is identifiable
    if user_id:
        caller = db.session.get(User, user_id)
        c_name = caller.username.lower() if caller else ""
        is_recip = (user_id == envelope.recipient_id) or \
                   (caller and envelope.recipient and c_name == envelope.recipient.username.lower()) or \
                   (c_name and envelope.recipient_id == c_name)
        is_sender = (user_id == envelope.sender_id) or \
                    (caller and envelope.sender and c_name == envelope.sender.username.lower()) or \
                    (c_name and envelope.sender_id == c_name)
        if not is_recip and not is_sender:
            log_security_event(
                event_type="UNAUTHORIZED_ACCESS",
                message=f"Unauthorized access attempt to envelope {transfer_id} by {user_id}.",
                related_public_id=transfer_id,
                result="FAILURE"
            )
            return jsonify({"error": "Access forbidden: you are not authorized to view this key envelope.", "code": "FORBIDDEN"}), 403
        
    now = utc_now()
    if envelope.expires_at <= now:
        envelope.status = "EXPIRED"
        db.session.commit()
        log_security_event(
            event_type="EXPIRED_TRANSFER_REJECTED",
            message=f"Attempt to retrieve expired envelope {transfer_id} rejected.",
            related_public_id=transfer_id,
            result="WARNING"
        )
        return jsonify({"error": "Key envelope has expired.", "code": "ENVELOPE_EXPIRED"}), 410
        
    log_security_event(
        event_type="ENVELOPE_RETRIEVED",
        message=f"Key envelope {transfer_id} retrieved.",
        related_public_id=transfer_id,
        result="SUCCESS"
    )
    
    return jsonify({"envelope": envelope.to_dict()})

@envelopes_bp.route("/<transfer_id>/accept", methods=["POST"])
def accept_envelope(transfer_id: str):
    verify_csrf_token()
    envelope = KeyEnvelope.query.filter_by(transfer_id=transfer_id).first_or_404(description="Envelope not found.")
    user_id = _get_caller_id()
    if user_id:
        caller = db.session.get(User, user_id)
        c_name = caller.username.lower() if caller else ""
        is_recip = (user_id == envelope.recipient_id) or \
                   (caller and envelope.recipient and c_name == envelope.recipient.username.lower()) or \
                   (c_name and envelope.recipient_id == c_name)
        if not is_recip:
            return jsonify({"error": "Forbidden.", "code": "FORBIDDEN"}), 403
        
    envelope.status = "ACCEPTED"
    db.session.commit()
    log_security_event(
        event_type="ENVELOPE_ACCEPTED",
        message=f"Recipient verified and accepted envelope {transfer_id}.",
        related_public_id=transfer_id,
        result="SUCCESS"
    )
    return jsonify({"message": f"Envelope {transfer_id} marked as ACCEPTED.", "status": "ACCEPTED"})

@envelopes_bp.route("/<transfer_id>/reject", methods=["POST"])
def reject_envelope(transfer_id: str):
    verify_csrf_token()
    envelope = KeyEnvelope.query.filter_by(transfer_id=transfer_id).first_or_404(description="Envelope not found.")
    user_id = _get_caller_id()
    if user_id:
        caller = db.session.get(User, user_id)
        c_name = caller.username.lower() if caller else ""
        is_recip = (user_id == envelope.recipient_id) or \
                   (caller and envelope.recipient and c_name == envelope.recipient.username.lower()) or \
                   (c_name and envelope.recipient_id == c_name)
        if not is_recip:
            return jsonify({"error": "Forbidden.", "code": "FORBIDDEN"}), 403
        
    envelope.status = "REJECTED"
    db.session.commit()
    log_security_event(
        event_type="SIGNATURE_VERIFICATION_FAILED",
        message=f"Recipient rejected envelope {transfer_id} (signature verification failed or rejected).",
        related_public_id=transfer_id,
        result="FAILURE"
    )
    return jsonify({"message": f"Envelope {transfer_id} marked as REJECTED.", "status": "REJECTED"})
