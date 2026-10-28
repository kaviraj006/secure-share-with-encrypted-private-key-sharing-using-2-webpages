import uuid
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app.extensions import db

def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)

class User(UserMixin, db.Model):
    __tablename__ = "users"
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    account_status = db.Column(db.String(20), default="active", nullable=False)
    
    # Relationships
    identity = db.relationship("PublicIdentity", backref="user", uselist=False, cascade="all, delete-orphan")
    prekeys = db.relationship("PublicPrekey", backref="user", lazy="dynamic", cascade="all, delete-orphan")
    trusted_contacts = db.relationship("TrustedContact", backref="owner", foreign_keys="TrustedContact.owner_id", lazy="dynamic", cascade="all, delete-orphan")
    sent_envelopes = db.relationship("KeyEnvelope", backref="sender", foreign_keys="KeyEnvelope.sender_id", lazy="dynamic")
    received_envelopes = db.relationship("KeyEnvelope", backref="recipient", foreign_keys="KeyEnvelope.recipient_id", lazy="dynamic")
    
    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password, method="scrypt")
        
    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)
        
    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "created_at": self.created_at.isoformat(),
            "has_identity": self.identity is not None,
            "fingerprint": self.identity.fingerprint if self.identity else None
        }


class PublicIdentity(db.Model):
    __tablename__ = "public_identities"
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True)
    ed25519_public_key = db.Column(db.String(128), nullable=False)  # Ed25519 public key hex (32 bytes = 64 chars)
    fingerprint = db.Column(db.String(128), nullable=False, index=True)  # Formatted SHA-256 fingerprint
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    status = db.Column(db.String(20), default="active", nullable=False)  # active, revoked, rotated
    
    def to_dict(self):
        return {
            "user_id": self.user_id,
            "ed25519_public_key": self.ed25519_public_key,
            "fingerprint": self.fingerprint,
            "created_at": self.created_at.isoformat(),
            "status": self.status
        }


class PublicPrekey(db.Model):
    __tablename__ = "public_prekeys"
    
    id = db.Column(db.String(64), primary_key=True)  # Unique prekey identifier e.g. prekey_xyz
    user_id = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    x25519_public_key = db.Column(db.String(128), nullable=False)  # X25519 public key hex
    signature = db.Column(db.Text, nullable=False)  # Ed25519 signature of the prekey public key
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True, index=True)
    consumed_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default="AVAILABLE", nullable=False, index=True)  # AVAILABLE, RESERVED, CONSUMED, EXPIRED
    
    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "x25519_public_key": self.x25519_public_key,
            "signature": self.signature,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "consumed_at": self.consumed_at.isoformat() if self.consumed_at else None,
            "status": self.status
        }


class TrustedContact(db.Model):
    __tablename__ = "trusted_contacts"
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    contact_id = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    contact_username = db.Column(db.String(64), nullable=False)
    trusted_fingerprint = db.Column(db.String(128), nullable=False)
    verification_status = db.Column(db.String(32), default="UNVERIFIED", nullable=False)  # UNVERIFIED, VERIFICATION REQUIRED, VERIFIED, KEY CHANGED
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    verified_at = db.Column(db.DateTime, nullable=True)
    
    # Relationship to target user
    contact_user = db.relationship("User", foreign_keys=[contact_id])
    
    def to_dict(self):
        return {
            "id": self.id,
            "owner_id": self.owner_id,
            "contact_id": self.contact_id,
            "contact_username": self.contact_username,
            "trusted_fingerprint": self.trusted_fingerprint,
            "verification_status": self.verification_status,
            "created_at": self.created_at.isoformat(),
            "verified_at": self.verified_at.isoformat() if self.verified_at else None
        }


class KeyEnvelope(db.Model):
    __tablename__ = "key_envelopes"
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    transfer_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    sender_id = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    recipient_id = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    recipient_prekey_id = db.Column(db.String(64), nullable=False)
    encrypted_envelope = db.Column(db.Text, nullable=False)  # Versioned envelope JSON string
    sender_signature = db.Column(db.Text, nullable=False)  # Ed25519 detached signature
    protocol_version = db.Column(db.Integer, default=1, nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    status = db.Column(db.String(20), default="PENDING", nullable=False)  # PENDING, ACCEPTED, REJECTED, EXPIRED
    
    def to_dict(self):
        s_name = self.sender.username if self.sender else None
        if not s_name and self.sender_id:
            s_cand = User.query.filter((User.id == self.sender_id) | (User.username == self.sender_id)).first()
            if s_cand:
                s_name = s_cand.username
            else:
                s_name = self.sender_id[:8] if len(self.sender_id) > 8 else self.sender_id

        r_name = self.recipient.username if self.recipient else None
        if not r_name and self.recipient_id:
            r_cand = User.query.filter((User.id == self.recipient_id) | (User.username == self.recipient_id)).first()
            if r_cand:
                r_name = r_cand.username
            else:
                r_name = self.recipient_id[:8] if len(self.recipient_id) > 8 else self.recipient_id

        return {
            "id": self.id,
            "transfer_id": self.transfer_id,
            "sender_id": self.sender_id,
            "sender_username": s_name,
            "recipient_id": self.recipient_id,
            "recipient_username": r_name,
            "recipient_prekey_id": self.recipient_prekey_id,
            "encrypted_envelope": self.encrypted_envelope,
            "sender_signature": self.sender_signature,
            "protocol_version": self.protocol_version,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "status": self.status
        }


class SecurityEvent(db.Model):
    __tablename__ = "security_events"
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    actor_id = db.Column(db.String(36), nullable=True, index=True)
    actor_username = db.Column(db.String(64), nullable=True)
    event_type = db.Column(db.String(48), nullable=False, index=True)
    related_public_id = db.Column(db.String(64), nullable=True)
    result = db.Column(db.String(20), default="SUCCESS", nullable=False)  # SUCCESS, WARNING, FAILURE
    message = db.Column(db.String(256), nullable=False)
    timestamp = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)
    
    def to_dict(self):
        return {
            "id": self.id,
            "actor_id": self.actor_id,
            "actor_username": self.actor_username or "ANONYMOUS",
            "event_type": self.event_type,
            "related_public_id": self.related_public_id,
            "result": self.result,
            "message": self.message,
            "timestamp": self.timestamp.isoformat()
        }
