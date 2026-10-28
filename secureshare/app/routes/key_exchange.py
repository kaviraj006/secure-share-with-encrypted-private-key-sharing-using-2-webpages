import json
import urllib.request
import urllib.error
import urllib.parse
from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from sqlalchemy import func
from app.extensions import db
from app.models import User, PublicIdentity, KeyEnvelope, Transfer
from app.services.security import verify_csrf_token, validate_hex

key_exchange_bp = Blueprint("key_exchange", __name__, url_prefix="/api/key-exchange")

def _call_keyx_portal(method: str, endpoint: str, json_data: dict = None, timeout: float = 3.0):
    """
    Adapter call to the SecureShare Key Exchange Portal service.
    Raises ConnectionError if the Key Exchange Portal is unreachable.
    """
    if request and request.headers.get("X-KeyX-Simulate-Offline") == "1" and current_app.config.get("DEBUG"):
        raise ConnectionError("Simulated Key Exchange Portal offline")

    base_url = current_app.config.get("KEYX_PORTAL_URL", "http://127.0.0.1:5001").rstrip("/")
    url = f"{base_url}{endpoint}"
    
    headers = {"Accept": "application/json"}
    body = None
    if json_data is not None:
        body = json.dumps(json_data).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            return resp.status, json.loads(data.decode("utf-8")) if data else {}
    except urllib.error.HTTPError as e:
        err_body = e.read()
        try:
            parsed = json.loads(err_body.decode("utf-8"))
        except Exception:
            parsed = {"error": f"Key Exchange HTTP error ({e.code})"}
        return e.code, parsed
    except (urllib.error.URLError, ConnectionError, OSError, TimeoutError) as e:
        raise ConnectionError(f"Key Exchange Portal is unreachable at {base_url}: {e}")

@key_exchange_bp.route("/identities", methods=["POST"])
@login_required
def publish_identity():
    """
    Publish or rotate authenticated user's public identity and X25519 prekey.
    Never receives or stores private keys.
    """
    verify_csrf_token()
    data = request.get_json(silent=True) or {}
    
    signing_pk = (data.get("signing_public_key") or "").strip().lower()
    x25519_pk = (data.get("x25519_prekey") or "").strip().lower()
    fingerprint = (data.get("fingerprint") or "").strip()
    prekey_id = (data.get("prekey_id") or "").strip()
    
    # Ed25519 and X25519 public keys are 32 bytes (64 hex characters)
    if not validate_hex(signing_pk, expected_bytes=32):
        return jsonify({"error": "Invalid signing public key. Must be 32 bytes (64 hex characters).", "code": "INVALID_SIGNING_KEY"}), 400
        
    if not validate_hex(x25519_pk, expected_bytes=32):
        return jsonify({"error": "Invalid X25519 prekey. Must be 32 bytes (64 hex characters).", "code": "INVALID_PREKEY"}), 400
        
    if not fingerprint or len(fingerprint) < 16:
        return jsonify({"error": "Invalid identity fingerprint.", "code": "INVALID_FINGERPRINT"}), 400
        
    if not prekey_id:
        return jsonify({"error": "Prekey ID is required.", "code": "MISSING_PREKEY_ID"}), 400
        
    identity = PublicIdentity.query.filter_by(user_id=current_user.id).first()
    if not identity:
        identity = PublicIdentity(user_id=current_user.id)
        db.session.add(identity)
        
    identity.signing_public_key = signing_pk
    identity.fingerprint = fingerprint
    identity.x25519_prekey = x25519_pk
    identity.prekey_id = prekey_id
    identity.verification_status = "active"
    
    db.session.commit()
    
    return jsonify({
        "message": "Public cryptographic identity bundle updated.",
        "identity": identity.to_dict()
    })

@key_exchange_bp.route("/users/search", methods=["GET"])
def search_keyx_users():
    """
    Search registered users on Key Exchange Portal to assist recipient selection.
    """
    q = request.args.get("q", "").strip()
    try:
        status, portal_data = _call_keyx_portal("GET", f"/api/users/search?q={urllib.parse.quote(q)}")
        return jsonify(portal_data), status
    except ConnectionError:
        filters = [User.account_status == "active"]
        if current_user.is_authenticated:
            filters.append(User.id != current_user.id)
        if q:
            filters.append(User.username.ilike(f"%{q}%"))
        users = User.query.filter(*filters).all()
        return jsonify({
            "users": [{
                "id": u.id,
                "username": u.username,
                "has_identity": u.identity is not None,
                "fingerprint": u.identity.fingerprint if u.identity else None
            } for u in users]
        }), 200

@key_exchange_bp.route("/identities/<target>", methods=["GET"])
def get_recipient_bundle(target: str):
    """
    Retrieve public prekey bundle and fingerprint for a recipient by username or user ID.
    Queries Key Exchange Portal first (authoritative source for cryptographic identities),
    falling back to local registry if Key Exchange Portal is unreachable or for local test users.
    """
    target = target.strip()
    
    # 1. Query Key Exchange Portal first (authority on identities & prekeys)
    portal_failed = False
    portal_data = None
    try:
        status, portal_data = _call_keyx_portal("GET", f"/api/key-exchange/identities/{urllib.parse.quote(target)}")
        if status == 200 and portal_data:
            recip_uname = portal_data.get("recipient_username")
            if recip_uname:
                local_u = User.query.filter(func.lower(User.username) == recip_uname.lower()).first()
                if local_u:
                    portal_data["local_user_id"] = local_u.id
            return jsonify(portal_data), 200
        elif status != 404:
            return jsonify(portal_data), status
    except ConnectionError:
        portal_failed = True

    # 2. Check local registry as fallback if not found in portal or portal is offline
    user = User.query.filter(
        (User.id == target) |
        (func.lower(User.username) == target.lower()) |
        (func.lower(User.email) == target.lower())
    ).first()
    if user and user.identity:
        return jsonify({
            "recipient_id": user.id,
            "recipient_username": user.username,
            "signing_public_key": user.identity.signing_public_key,
            "fingerprint": user.identity.fingerprint,
            "x25519_prekey": user.identity.x25519_prekey,
            "prekey_id": user.identity.prekey_id,
            "created_at": user.identity.created_at.isoformat()
        })

    # 3. If 404 on Port 5001, check if similar active identities exist on Port 5001 (e.g. kaviraj1 when typing kaviraj)
    suggestions = []
    if not portal_failed:
        try:
            _, search_res = _call_keyx_portal("GET", f"/api/users/search?q={urllib.parse.quote(target)}")
            if search_res and "users" in search_res:
                suggestions = [u["username"] for u in search_res["users"] if u.get("has_identity") and u.get("username").lower() != target.lower()][:3]
        except Exception:
            pass

    if portal_failed:
        return jsonify({
            "error": "Key Exchange Portal is unavailable at http://127.0.0.1:5001. Recipient key discovery failed.",
            "code": "KEY_EXCHANGE_PORTAL_UNAVAILABLE"
        }), 503

    err_msg = (portal_data.get("error") if portal_data else None) or f"Recipient '{target}' not found or has not published an identity bundle on Key Exchange Portal."
    resp_obj = {"error": err_msg, "code": "USER_NOT_FOUND"}
    if suggestions:
        resp_obj["suggestions"] = suggestions
        resp_obj["error"] = f"{err_msg} Available active recipient(s): {', '.join(suggestions)}."
    return jsonify(resp_obj), 404

@key_exchange_bp.route("/envelopes", methods=["POST"])
@login_required
def submit_envelope():
    """
    Store signed key envelope associated with a transfer.
    Submits to Key Exchange Portal and syncs to local transfer association.
    """
    verify_csrf_token()
    data = request.get_json(silent=True) or {}
    
    transfer_id = (data.get("transfer_id") or "").strip()
    recipient_id = (data.get("recipient_id") or "").strip()
    recipient_username = (data.get("recipient_username") or "").strip()
    envelope_data = data.get("envelope")
    sender_id = (data.get("sender_id") or current_user.id).strip()
    
    if not transfer_id or not recipient_id or not envelope_data:
        return jsonify({"error": "transfer_id, recipient_id, and envelope payload are required.", "code": "INVALID_ENVELOPE_DATA"}), 400

    # Format envelope string
    if isinstance(envelope_data, dict):
        envelope_str = json.dumps(envelope_data)
    elif isinstance(envelope_data, str):
        envelope_str = envelope_data
    else:
        return jsonify({"error": "Envelope must be a JSON object or string.", "code": "INVALID_FORMAT"}), 400

    # 1. Forward to Key Exchange Portal
    envelope_id = None
    sender_user = db.session.get(User, sender_id) if sender_id else current_user
    recipient_user = db.session.get(User, recipient_id) if recipient_id else None
    transfer = Transfer.query.filter_by(id=transfer_id).first()
    if not recipient_user and transfer and transfer.recipient_id:
        recipient_user = db.session.get(User, transfer.recipient_id)

    resolved_recip_username = recipient_username or (recipient_user.username if recipient_user else None) or (transfer.recipient.username if transfer and transfer.recipient else None)

    try:
        status, portal_res = _call_keyx_portal("POST", "/api/key-exchange/envelopes", {
            "transfer_id": transfer_id,
            "sender_id": sender_id,
            "sender_username": sender_user.username if sender_user else None,
            "recipient_id": recipient_id,
            "recipient_username": resolved_recip_username,
            "envelope": envelope_data
        })
        if status in (200, 201):
            envelope_id = portal_res.get("envelope_id")
        else:
            return jsonify({
                "error": portal_res.get("error", "Key Exchange Portal rejected envelope."),
                "code": portal_res.get("code", "KEY_EXCHANGE_SUBMISSION_FAILED")
            }), status
    except ConnectionError:
        return jsonify({
            "error": "Key Exchange Portal is unavailable at http://127.0.0.1:5001. Envelope could not be submitted.",
            "code": "KEY_EXCHANGE_PORTAL_UNAVAILABLE"
        }), 503

    # 2. Sync to local database
    local_env = KeyEnvelope.query.filter_by(transfer_id=transfer_id).first()
    transfer = Transfer.query.filter_by(id=transfer_id).first()
    resolved_rec_id = transfer.recipient_id if transfer else recipient_id

    if not local_env:
        local_env = KeyEnvelope(
            id=envelope_id,
            transfer_id=transfer_id,
            sender_id=current_user.id,
            recipient_id=resolved_rec_id,
            envelope_json=envelope_str
        )
        db.session.add(local_env)
    else:
        local_env.envelope_json = envelope_str
        if resolved_rec_id:
            local_env.recipient_id = resolved_rec_id
    db.session.commit()
    
    return jsonify({
        "message": "Key envelope stored successfully in Key Exchange Portal.",
        "envelope_id": local_env.id
    }), 201

@key_exchange_bp.route("/envelopes/<transfer_id>", methods=["GET"])
@login_required
def get_envelope(transfer_id: str):
    """
    Retrieve protected key envelope for a transfer.
    Enforces authorization: Only intended recipient or sender may retrieve.
    Retrieves from Key Exchange Portal.
    """
    transfer = Transfer.query.filter_by(id=transfer_id).first_or_404(description="Transfer not found.")
    
    # Access control: Must be sender or recipient
    if current_user.id != transfer.recipient_id and current_user.id != transfer.sender_id:
        return jsonify({"error": "Unauthorized access to transfer key envelope.", "code": "FORBIDDEN"}), 403
        
    if transfer.status == "expired":
        return jsonify({"error": "Transfer has expired.", "code": "TRANSFER_EXPIRED"}), 410
        
    if transfer.status == "deleted":
        return jsonify({"error": "Transfer has been deleted.", "code": "TRANSFER_DELETED"}), 404

    # 1. Fetch from Key Exchange Portal
    try:
        status, portal_data = _call_keyx_portal("GET", f"/api/key-exchange/envelopes/{transfer_id}")
        if status == 200:
            return jsonify(portal_data), 200
        elif status == 410:
            return jsonify({"error": "Transfer key envelope has expired.", "code": "ENVELOPE_EXPIRED"}), 410
        elif status != 404:
            return jsonify(portal_data), status
    except ConnectionError:
        return jsonify({
            "error": "Key Exchange Portal is unavailable at http://127.0.0.1:5001. Decryption cannot proceed.",
            "code": "KEY_EXCHANGE_PORTAL_UNAVAILABLE"
        }), 503

    # 2. Local fallback if not found in portal
    envelope = KeyEnvelope.query.filter_by(transfer_id=transfer_id).first()
    if not envelope:
        return jsonify({"error": "No key envelope found for this transfer.", "code": "ENVELOPE_NOT_FOUND"}), 404
        
    return jsonify({
        "transfer_id": transfer_id,
        "sender_id": envelope.sender_id,
        "recipient_id": envelope.recipient_id,
        "envelope": json.loads(envelope.envelope_json) if envelope.envelope_json.startswith("{") else envelope.envelope_json,
        "created_at": envelope.created_at.isoformat()
    })

@key_exchange_bp.route("/status", methods=["GET"])
def key_exchange_status():
    """
    Check live connectivity status with the Key Exchange Portal.
    """
    base_url = current_app.config.get("KEYX_PORTAL_URL", "http://127.0.0.1:5001").rstrip("/")
    try:
        status, data = _call_keyx_portal("GET", "/api/auth/csrf", timeout=2.0)
        online = (status == 200)
    except Exception:
        online = False
    return jsonify({
        "portal_url": base_url,
        "online": online,
        "adapter": "FileVault-KeyX-Adapter-v1"
    })

