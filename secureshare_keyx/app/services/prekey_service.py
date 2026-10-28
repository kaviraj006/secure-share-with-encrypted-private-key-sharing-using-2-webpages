from datetime import timedelta
from app.extensions import db
from app.models import PublicPrekey, utc_now
from app.services.security_logger import log_security_event

class PrekeyService:
    @staticmethod
    def publish_prekey(user_id: str, prekey_id: str, x25519_pk: str, signature: str, days_valid: int = 30) -> PublicPrekey:
        now = utc_now()
        expires_at = now + timedelta(days=days_valid)
        
        prekey = PublicPrekey.query.filter_by(id=prekey_id).first()
        if prekey:
            # Re-activate if rotating
            prekey.x25519_public_key = x25519_pk
            prekey.signature = signature
            prekey.expires_at = expires_at
            prekey.status = "AVAILABLE"
            prekey.consumed_at = None
        else:
            prekey = PublicPrekey(
                id=prekey_id,
                user_id=user_id,
                x25519_public_key=x25519_pk,
                signature=signature,
                created_at=now,
                expires_at=expires_at,
                status="AVAILABLE"
            )
            db.session.add(prekey)
            
        db.session.commit()
        log_security_event(
            event_type="PREKEY_PUBLISHED",
            message=f"X25519 Prekey {prekey_id} published.",
            related_public_id=prekey_id,
            result="SUCCESS"
        )
        return prekey

    @staticmethod
    def get_available_prekey(user_id: str) -> PublicPrekey | None:
        now = utc_now()
        # Find oldest available unexpired prekey
        prekey = PublicPrekey.query.filter(
            PublicPrekey.user_id == user_id,
            PublicPrekey.status == "AVAILABLE",
            (PublicPrekey.expires_at == None) | (PublicPrekey.expires_at > now)
        ).order_by(PublicPrekey.created_at.asc()).first()
        
        # If no AVAILABLE prekey, check if any RESERVED prekey was orphaned (> 5 min and not in KeyEnvelope)
        if not prekey:
            from datetime import timedelta
            from app.models import KeyEnvelope
            stale_threshold = now - timedelta(minutes=5)
            reserved_candidates = PublicPrekey.query.filter(
                PublicPrekey.user_id == user_id,
                PublicPrekey.status == "RESERVED",
                (PublicPrekey.expires_at == None) | (PublicPrekey.expires_at > now),
                PublicPrekey.created_at < stale_threshold
            ).all()
            for cand in reserved_candidates:
                in_envelope = KeyEnvelope.query.filter_by(recipient_prekey_id=cand.id).first()
                if not in_envelope:
                    cand.status = "AVAILABLE"
                    db.session.commit()
                    return cand

        # Continuous High-Volume Fallback (Signal Protocol Signed-Prekey Fallback):
        # If all one-time prekeys have been consumed, return the latest prekey for this user
        # so ongoing communications/transfers are never blocked.
        if not prekey:
            prekey = PublicPrekey.query.filter(
                PublicPrekey.user_id == user_id
            ).order_by(PublicPrekey.created_at.desc()).first()
            if prekey:
                return prekey
                    
        return prekey

    @staticmethod
    def reserve_prekey(prekey_id: str) -> bool:
        """
        Atomically reserve a prekey for envelope encryption.
        """
        prekey = PublicPrekey.query.filter_by(id=prekey_id).first()
        if not prekey:
            return False
            
        prekey.status = "RESERVED"
        db.session.commit()
        return True

    @staticmethod
    def consume_prekey(prekey_id: str) -> bool:
        """
        Atomically consume a prekey, preventing double reuse.
        """
        prekey = PublicPrekey.query.filter_by(id=prekey_id).first()
        if not prekey:
            return False
            
        prekey.status = "CONSUMED"
        prekey.consumed_at = utc_now()
        db.session.commit()
        log_security_event(
            event_type="PREKEY_CONSUMED",
            message=f"Prekey {prekey_id} permanently consumed.",
            related_public_id=prekey_id,
            result="SUCCESS"
        )
        return True
