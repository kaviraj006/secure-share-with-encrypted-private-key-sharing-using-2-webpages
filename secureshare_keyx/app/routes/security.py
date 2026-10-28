from flask import Blueprint, request, jsonify
from flask_login import current_user
from app.models import SecurityEvent, User

security_bp = Blueprint("security", __name__, url_prefix="/api")

def _get_caller_info():
    if current_user.is_authenticated:
        return current_user.id, current_user.username
    header_uid = request.headers.get("X-User-ID")
    if header_uid:
        u = User.query.get(header_uid.strip())
        return header_uid.strip(), (u.username if u else None)
    return None, None

@security_bp.route("/security-events", methods=["GET"])
def get_security_events():
    limit = min(max(int(request.args.get("limit") or 50), 1), 200)
    event_type = request.args.get("type")
    
    uid, uname = _get_caller_info()
    if not uid and not uname:
        return jsonify({"events": []}), 200

    filters = []
    if uid:
        filters.append(SecurityEvent.actor_id == uid)
    if uname:
        filters.append(SecurityEvent.actor_username == uname)
        
    query = SecurityEvent.query.filter(*filters)
    if event_type:
        query = query.filter_by(event_type=event_type)
        
    events = query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
    return jsonify({"events": [e.to_dict() for e in events]})
