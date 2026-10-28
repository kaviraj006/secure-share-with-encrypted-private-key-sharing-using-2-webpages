from flask import request
from flask_login import current_user
from app.extensions import db
from app.models import SecurityEvent, utc_now

def log_security_event(event_type: str, message: str, result: str = "SUCCESS", actor_id: str = None, actor_username: str = None, related_public_id: str = None):
    """
    Records safe operational security event.
    NEVER logs passwords, private keys, shared secrets, or session tokens.
    """
    try:
        if not actor_id and current_user and current_user.is_authenticated:
            actor_id = current_user.id
            actor_username = current_user.username
            
        event = SecurityEvent(
            actor_id=actor_id,
            actor_username=actor_username,
            event_type=event_type,
            related_public_id=related_public_id,
            result=result,
            message=message[:255],
            timestamp=utc_now()
        )
        db.session.add(event)
        db.session.commit()
    except Exception as e:
        # Avoid masking exceptions during database rollbacks
        try:
            db.session.rollback()
        except Exception:
            pass
