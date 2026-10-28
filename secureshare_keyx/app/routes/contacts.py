from flask import Blueprint, request, jsonify
from flask_login import current_user
from sqlalchemy import func
from app.extensions import db
from app.models import User, TrustedContact, PublicIdentity, utc_now
from app.services.validation import verify_csrf_token
from app.services.security_logger import log_security_event

contacts_bp = Blueprint("contacts", __name__, url_prefix="/api/contacts")

def _resolve_owner_id(data: dict = None):
    """
    Resolve the caller's owner ID from Flask session, X-User-ID header,
    query parameters, or JSON body.
    """
    if current_user.is_authenticated:
        return current_user.id
    header_uid = request.headers.get("X-User-ID")
    if header_uid:
        return header_uid.strip()
    param_uid = request.args.get("owner_id") or request.args.get("user_id")
    if param_uid:
        return param_uid.strip()
    username = request.args.get("username")
    if username:
        u = User.query.filter(func.lower(User.username) == username.strip().lower()).first()
        if u:
            return u.id
    if data:
        body_uid = data.get("owner_id") or data.get("user_id")
        if body_uid:
            return str(body_uid).strip()
        body_uname = data.get("current_username")
        if body_uname:
            u = User.query.filter(func.lower(User.username) == body_uname.strip().lower()).first()
            if u:
                return u.id
    return None

@contacts_bp.route("", methods=["GET"])
def list_contacts():
    owner_id = _resolve_owner_id()
    if not owner_id:
        # If user is not yet logged in and no owner specified, return empty contacts list safely
        return jsonify({"contacts": []}), 200

    contacts = TrustedContact.query.filter_by(owner_id=owner_id).order_by(TrustedContact.created_at.desc()).all()
    
    results = []
    for c in contacts:
        contact_user = c.contact_user
        current_fp = contact_user.identity.fingerprint if contact_user and contact_user.identity else None
        
        # Check if remote key changed unexpectedly or was uninitialized
        status = c.verification_status
        if c.trusted_fingerprint == "UNINITIALIZED" and current_fp:
            c.trusted_fingerprint = current_fp
            status = "UNVERIFIED"
            c.verification_status = "UNVERIFIED"
            db.session.commit()
        elif current_fp and current_fp != c.trusted_fingerprint and c.trusted_fingerprint != "UNINITIALIZED":
            status = "KEY CHANGED"
            # Update status in db
            if c.verification_status != "KEY CHANGED":
                c.verification_status = "KEY CHANGED"
                db.session.commit()
                log_security_event(
                    event_type="KEY_CHANGE_DETECTED",
                    message=f"Contact {c.contact_username} key fingerprint changed! Expected {c.trusted_fingerprint[:16]}..., Live {current_fp[:16]}...",
                    result="WARNING",
                    related_public_id=c.contact_id
                )
                
        results.append({
            "id": c.id,
            "contact_id": c.contact_id,
            "contact_username": c.contact_username,
            "trusted_fingerprint": c.trusted_fingerprint,
            "current_fingerprint": current_fp,
            "verification_status": status,
            "created_at": c.created_at.isoformat(),
            "verified_at": c.verified_at.isoformat() if c.verified_at else None
        })
        
    return jsonify({"contacts": results})

@contacts_bp.route("", methods=["POST"])
def add_contact():
    verify_csrf_token()
    data = request.get_json(silent=True) or {}
    
    owner_id = _resolve_owner_id(data)
    if not owner_id:
        return jsonify({"error": "Authentication required to add contacts.", "code": "UNAUTHORIZED"}), 401

    owner = db.session.get(User, owner_id)
    if not owner:
        return jsonify({"error": "Owner user account not found.", "code": "OWNER_NOT_FOUND"}), 404
        
    contact_username = (data.get("username") or data.get("identifier") or data.get("id") or "").strip()
    if not contact_username:
        return jsonify({"error": "Contact username, ID, or fingerprint is required.", "code": "MISSING_USERNAME"}), 400
        
    target_user = User.query.filter(
        (User.id == contact_username) |
        (func.lower(User.username) == contact_username.lower()) |
        (func.lower(User.email) == contact_username.lower())
    ).first()

    # Also match by public identity fingerprint or Ed25519 public key
    if not target_user:
        target_identity = PublicIdentity.query.filter(
            (PublicIdentity.fingerprint == contact_username) |
            (PublicIdentity.ed25519_public_key == contact_username.lower())
        ).first()
        if target_identity and target_identity.user:
            target_user = target_identity.user

    if not target_user:
        return jsonify({"error": f"User '{contact_username}' does not exist.", "code": "USER_NOT_FOUND"}), 404
        
    if target_user.id == owner.id or contact_username.lower() == owner.username.lower():
        return jsonify({"error": "Cannot add yourself as a contact.", "code": "SELF_CONTACT"}), 400
        
    live_fp = target_user.identity.fingerprint if target_user.identity else "UNINITIALIZED"
    status = "UNVERIFIED" if target_user.identity else "NO_IDENTITY"
    
    existing = TrustedContact.query.filter_by(owner_id=owner.id, contact_id=target_user.id).first()
    if existing:
        existing.trusted_fingerprint = live_fp
        existing.verification_status = status
        existing.verified_at = None
        db.session.commit()
        contact = existing
    else:
        contact = TrustedContact(
            owner_id=owner.id,
            contact_id=target_user.id,
            contact_username=target_user.username,
            trusted_fingerprint=live_fp,
            verification_status=status,
            created_at=utc_now()
        )
        db.session.add(contact)
        db.session.commit()
        
    return jsonify({
        "message": f"Contact {contact.contact_username} added. Verification required.",
        "contact": contact.to_dict()
    }), 201

@contacts_bp.route("/<contact_id>/verify", methods=["POST"])
def verify_contact(contact_id: str):
    verify_csrf_token()
    data = request.get_json(silent=True) or {}
    owner_id = _resolve_owner_id(data)

    query = TrustedContact.query.filter_by(id=contact_id)
    if owner_id:
        query = query.filter_by(owner_id=owner_id)
    contact = query.first()
    
    # Fallback search if contact_id was passed as target user ID or username
    if not contact and owner_id:
        contact = TrustedContact.query.filter(
            (TrustedContact.owner_id == owner_id) &
            ((TrustedContact.contact_id == contact_id) | (TrustedContact.contact_username == contact_id))
        ).first()
        
    if not contact:
        return jsonify({"error": "Contact not found.", "code": "CONTACT_NOT_FOUND"}), 404
    
    confirmed_fp = (data.get("fingerprint") or "").strip()
    
    # Check if target user has active identity
    target_user = contact.contact_user
    if not target_user or not target_user.identity:
        return jsonify({"error": "Target user has no active cryptographic identity.", "code": "NO_IDENTITY"}), 400
        
    live_fp = target_user.identity.fingerprint
    if confirmed_fp and confirmed_fp != live_fp:
        return jsonify({"error": "Submitted fingerprint does not match target user's current identity key.", "code": "FINGERPRINT_MISMATCH"}), 400
        
    contact.trusted_fingerprint = live_fp
    contact.verification_status = "VERIFIED"
    contact.verified_at = utc_now()
    db.session.commit()
    
    log_security_event(
        event_type="FINGERPRINT_VERIFIED",
        message=f"Contact {contact.contact_username} verified (Fingerprint: {live_fp[:16]}...).",
        result="SUCCESS",
        related_public_id=contact.contact_id
    )
    
    return jsonify({
        "message": f"Contact {contact.contact_username} marked as VERIFIED.",
        "contact": contact.to_dict()
    })

@contacts_bp.route("/<contact_id>", methods=["DELETE"])
def delete_contact(contact_id: str):
    verify_csrf_token()
    owner_id = _resolve_owner_id()
    
    query = TrustedContact.query.filter_by(id=contact_id)
    if owner_id:
        query = query.filter_by(owner_id=owner_id)
    contact = query.first()
    
    if not contact and owner_id:
        contact = TrustedContact.query.filter(
            (TrustedContact.owner_id == owner_id) &
            ((TrustedContact.contact_id == contact_id) | (TrustedContact.contact_username == contact_id))
        ).first()

    if not contact:
        return jsonify({"error": "Contact not found.", "code": "CONTACT_NOT_FOUND"}), 404

    username = contact.contact_username
    db.session.delete(contact)
    db.session.commit()
    
    return jsonify({"message": f"Contact {username} removed."})
