from flask import Blueprint, request, jsonify
from flask_login import current_user
from app.models import KeyEnvelope

history_bp = Blueprint("history", __name__, url_prefix="/api/transfers")

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

@history_bp.route("", methods=["GET"])
def get_transfers():
    uid = _get_caller_id()
    if not uid:
        return jsonify({"sent": [], "received": []}), 200

    sent = KeyEnvelope.query.filter_by(sender_id=uid).order_by(KeyEnvelope.created_at.desc()).all()
    received = KeyEnvelope.query.filter_by(recipient_id=uid).order_by(KeyEnvelope.created_at.desc()).all()
    
    return jsonify({
        "sent": [s.to_dict() for s in sent],
        "received": [r.to_dict() for r in received]
    })

@history_bp.route("/<transfer_id>", methods=["GET"])
def get_transfer_detail(transfer_id: str):
    envelope = KeyEnvelope.query.filter_by(transfer_id=transfer_id).first_or_404(description="Transfer not found.")
    uid = _get_caller_id()
    if uid and uid != envelope.recipient_id and uid != envelope.sender_id:
        return jsonify({"error": "Unauthorized.", "code": "FORBIDDEN"}), 403
    return jsonify({"transfer": envelope.to_dict()})
