import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import func
from flask import Blueprint, request, jsonify, Response, current_app
from flask_login import login_required, current_user
from app.extensions import db
from app.models import Transfer, EncryptedFile, User, FileRecipient, KeyEnvelope
from app.services.storage import CiphertextStorageService
from app.services.security import verify_csrf_token, cleanup_expired_transfers

transfers_bp = Blueprint("transfers", __name__, url_prefix="/api/transfers")

@transfers_bp.route("", methods=["POST"])
@login_required
def create_transfer():
    """Create a new transfer. Envelope is optional at creation; it can be attached later via PATCH.
    Expected JSON payload:
        {
            "recipient": "username_or_id",
            "file_id": "<encrypted_file_id>",
            "envelope_id": "<optional_envelope_id>",
            "expires_in_hours": <int>
        }
    """
    verify_csrf_token()
    data = request.get_json(silent=True) or {}

    recipient_identifier = (data.get("recipient") or "").strip()
    file_id = (data.get("file_id") or "").strip()
    envelope_id = (data.get("envelope_id") or "").strip()
    hours = min(max(int(data.get("expires_in_hours") or 24), 1), 168)  # 1 hour to 7 days

    if not recipient_identifier:
        return jsonify({"error": "Recipient username or ID is required.", "code": "MISSING_RECIPIENT"}), 400

    recipient = User.query.filter(
        (User.id == recipient_identifier) | 
        (func.lower(User.username) == recipient_identifier.lower())
    ).first()
    if not recipient:
        # Check if recipient exists on Key Exchange Portal
        from app.routes.key_exchange import _call_keyx_portal
        try:
            status, keyx_user = _call_keyx_portal("GET", f"/api/key-exchange/identities/{recipient_identifier}")
            if status == 200 and keyx_user.get("recipient_username"):
                recip_uname = keyx_user.get("recipient_username")
                # Check if user already exists locally by username
                recipient = User.query.filter(func.lower(User.username) == recip_uname.lower()).first()
                if not recipient:
                    recipient = User(
                        id=keyx_user.get("recipient_id") or str(uuid.uuid4()),
                        username=recip_uname,
                        email=f"{recip_uname}@secureshare.keyx",
                        password_hash="stub_managed_by_keyx"
                    )
                    db.session.add(recipient)
                    db.session.commit()
        except Exception:
            pass

    if not recipient:
        return jsonify({"error": "Recipient user not found.", "code": "RECIPIENT_NOT_FOUND"}), 404

    if recipient.id == current_user.id:
        return jsonify({"error": "Cannot address transfer to yourself.", "code": "INVALID_RECIPIENT"}), 400

    file_record = EncryptedFile.query.filter_by(id=file_id, owner_id=current_user.id, status="active").first()
    if not file_record:
        return jsonify({"error": "Encrypted file record not found or inaccessible.", "code": "FILE_NOT_FOUND"}), 404

    # Envelope is optional at this stage. If provided, validate it belongs to the sender and recipient.
    envelope = None
    if envelope_id:
        envelope = KeyEnvelope.query.filter_by(id=envelope_id, sender_id=current_user.id, recipient_id=recipient.id).first()
        if not envelope:
            return jsonify({"error": "Key envelope not found or not bound to this recipient.", "code": "INVALID_ENVELOPE"}), 400

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    expires_at = now + timedelta(hours=hours)

    transfer_id = str(uuid.uuid4())
    transfer = Transfer(
        id=transfer_id,
        sender_id=current_user.id,
        recipient_id=recipient.id,
        file_id=file_record.id,
        envelope_id=envelope.id if envelope else None,
        created_at=now,
        expires_at=expires_at,
        status="active"
    )

    # If an envelope was supplied, bind its transfer_id to the newly generated UUID.
    if envelope:
        envelope.transfer_id = transfer_id

    # Record recipient permission for the file.
    perm = FileRecipient(
        file_id=file_record.id,
        recipient_id=recipient.id,
        permission="download",
        access_status="pending"
    )

    db.session.add(transfer)
    db.session.add(perm)
    db.session.commit()

    return jsonify({
        "message": "Transfer created successfully.",
        "transfer": transfer.to_dict()
    }), 201

@transfers_bp.route("/<transfer_id>", methods=["PATCH"])
@login_required
def update_transfer_envelope(transfer_id: str):
    """Attach an existing key envelope to a transfer after the envelope has been created.
    Expected JSON payload: {"envelope_id": "<envelope-id>"}
    """
    verify_csrf_token()
    transfer = Transfer.query.filter_by(id=transfer_id).first_or_404(description="Transfer not found.")
    data = request.get_json(silent=True) or {}
    envelope_id = (data.get("envelope_id") or "").strip()
    if not envelope_id:
        return jsonify({"error": "envelope_id is required.", "code": "MISSING_ENVELOPE_ID"}), 400

    envelope = KeyEnvelope.query.filter_by(id=envelope_id, sender_id=current_user.id).first()
    if not envelope or (envelope.recipient_id != transfer.recipient_id and envelope.transfer_id != transfer.id):
        return jsonify({"error": "Key envelope not found or not bound to this recipient.", "code": "INVALID_ENVELOPE"}), 400

    # Ensure recipient matches transfer
    envelope.recipient_id = transfer.recipient_id

    # Bind envelope to the transfer.
    envelope.transfer_id = transfer.id
    transfer.envelope_id = envelope.id
    db.session.commit()

    return jsonify({"message": "Envelope attached to transfer.", "transfer": transfer.to_dict()})

@transfers_bp.route("/<transfer_id>", methods=["GET"])
@login_required
def get_transfer(transfer_id: str):
    transfer = Transfer.query.filter_by(id=transfer_id).first_or_404(description="Transfer not found.")

    # Access control: Must be sender or recipient
    if current_user.id != transfer.recipient_id and current_user.id != transfer.sender_id:
        return jsonify({"error": "Unauthorized access to transfer.", "code": "FORBIDDEN"}), 403

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if transfer.expires_at <= now and transfer.status == "active":
        transfer.status = "expired"
        db.session.commit()
        return jsonify({"error": "Transfer has expired.", "code": "TRANSFER_EXPIRED"}), 410

    if transfer.status == "deleted":
        return jsonify({"error": "Transfer has been deleted.", "code": "TRANSFER_DELETED"}), 404

    return jsonify({
        "transfer": transfer.to_dict(),
        "file": transfer.file.to_dict() if transfer.file else None
    })

@transfers_bp.route("/<transfer_id>/download", methods=["GET"])
@login_required
def download_ciphertext(transfer_id: str):
    transfer = Transfer.query.filter_by(id=transfer_id).first_or_404(description="Transfer not found.")

    # Authorization: Must be sender or recipient
    if current_user.id != transfer.recipient_id and current_user.id != transfer.sender_id:
        return jsonify({"error": "Unauthorized. You are not the intended recipient of this transfer.", "code": "FORBIDDEN"}), 403

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if transfer.expires_at <= now or transfer.status == "expired":
        transfer.status = "expired"
        db.session.commit()
        return jsonify({"error": "This transfer has expired and is no longer available.", "code": "TRANSFER_EXPIRED"}), 410

    if transfer.status == "deleted" or not transfer.file or transfer.file.status != "active":
        return jsonify({"error": "This file is no longer available.", "code": "FILE_UNAVAILABLE"}), 404

    storage_svc = CiphertextStorageService()
    try:
        stream = storage_svc.get_ciphertext_stream(transfer.file.storage_id)
    except Exception:
        return jsonify({"error": "Encrypted payload missing on storage.", "code": "STORAGE_MISSING"}), 404

    transfer.download_count += 1
    # Update recipient access status
    rec_perm = FileRecipient.query.filter_by(file_id=transfer.file_id, recipient_id=current_user.id).first()
    if rec_perm:
        rec_perm.access_status = "downloaded"
    db.session.commit()

    return Response(
        stream,
        mimetype="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="payload_{transfer.id}.enc"',
            "X-Encryption-Nonce": transfer.file.nonce,
            "X-Encryption-Algorithm": transfer.file.algorithm,
            "X-Protocol-Version": str(transfer.file.protocol_version),
            "Content-Length": str(transfer.file.encrypted_size),
            "Access-Control-Expose-Headers": "Content-Disposition, Content-Length, X-Encryption-Nonce, X-Encryption-Algorithm, X-Protocol-Version"
        }
    )

@transfers_bp.route("/<transfer_id>", methods=["DELETE"])
@login_required
def delete_transfer(transfer_id: str):
    verify_csrf_token()
    transfer = Transfer.query.filter_by(id=transfer_id).first_or_404(description="Transfer not found.")

    # Only sender or recipient can delete
    if current_user.id != transfer.sender_id and current_user.id != transfer.recipient_id:
        return jsonify({"error": "Unauthorized.", "code": "FORBIDDEN"}), 403

    transfer.status = "deleted"

    # If file has no other active transfers, purge ciphertext
    other_active = Transfer.query.filter(
        Transfer.file_id == transfer.file_id,
        Transfer.id != transfer.id,
        Transfer.status == "active"
    ).count()

    if other_active == 0 and transfer.file:
        transfer.file.status = "deleted"
        storage_svc = CiphertextStorageService()
        storage_svc.delete_ciphertext(transfer.file.storage_id)

    db.session.commit()
    return jsonify({"message": "Transfer and associated storage deleted successfully."})

@transfers_bp.route("/history", methods=["GET"])
@login_required
def transfer_history():
    sent = Transfer.query.filter_by(sender_id=current_user.id).order_by(Transfer.created_at.desc()).all()
    received = Transfer.query.filter_by(recipient_id=current_user.id).order_by(Transfer.created_at.desc()).all()

    return jsonify({
        "sent": [t.to_dict() for t in sent],
        "received": [t.to_dict() for t in received]
    })

@transfers_bp.route("/cleanup-expired", methods=["POST"])
@login_required
def trigger_cleanup():
    cleaned_count = cleanup_expired_transfers()
    return jsonify({"message": f"Pruned {cleaned_count} expired transfers."})
