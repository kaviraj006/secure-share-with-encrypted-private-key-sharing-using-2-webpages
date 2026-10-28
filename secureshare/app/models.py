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
    owned_files = db.relationship("EncryptedFile", backref="owner", lazy="dynamic", cascade="all, delete-orphan")
    sent_transfers = db.relationship("Transfer", backref="sender", foreign_keys="Transfer.sender_id", lazy="dynamic")
    received_transfers = db.relationship("Transfer", backref="recipient", foreign_keys="Transfer.recipient_id", lazy="dynamic")
    
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
            "identity_fingerprint": self.identity.fingerprint if self.identity else None
        }


class PublicIdentity(db.Model):
    __tablename__ = "public_identities"
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True)
    signing_public_key = db.Column(db.String(128), nullable=False)  # Ed25519 public key hex
    fingerprint = db.Column(db.String(128), nullable=False, index=True)  # Formatted SHA-256 fingerprint
    x25519_prekey = db.Column(db.String(128), nullable=False)  # X25519 prekey public key hex
    prekey_id = db.Column(db.String(64), nullable=False)  # Unique prekey identifier
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    verification_status = db.Column(db.String(32), default="unverified", nullable=False)
    
    def to_dict(self):
        return {
            "user_id": self.user_id,
            "signing_public_key": self.signing_public_key,
            "fingerprint": self.fingerprint,
            "x25519_prekey": self.x25519_prekey,
            "prekey_id": self.prekey_id,
            "verification_status": self.verification_status,
            "created_at": self.created_at.isoformat()
        }


class EncryptedFile(db.Model):
    __tablename__ = "encrypted_files"
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    storage_id = db.Column(db.String(64), unique=True, nullable=False, index=True)  # Random storage filename
    encrypted_size = db.Column(db.BigInteger, nullable=False)
    nonce = db.Column(db.String(64), nullable=False)  # Base64 nonce for AES-GCM
    algorithm = db.Column(db.String(32), default="AES-256-GCM", nullable=False)
    protocol_version = db.Column(db.Integer, default=1, nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True, index=True)
    status = db.Column(db.String(20), default="active", nullable=False)  # active, deleted, expired
    
    transfers = db.relationship("Transfer", backref="file", lazy="dynamic", cascade="all, delete-orphan")
    recipients = db.relationship("FileRecipient", backref="file", lazy="dynamic", cascade="all, delete-orphan")
    
    def to_dict(self):
        return {
            "id": self.id,
            "owner_id": self.owner_id,
            "storage_id": self.storage_id,
            "encrypted_size": self.encrypted_size,
            "nonce": self.nonce,
            "algorithm": self.algorithm,
            "protocol_version": self.protocol_version,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "status": self.status
        }


class FileRecipient(db.Model):
    __tablename__ = "file_recipients"
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    file_id = db.Column(db.String(36), db.ForeignKey("encrypted_files.id", ondelete="CASCADE"), nullable=False, index=True)
    recipient_id = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    permission = db.Column(db.String(20), default="download", nullable=False)
    access_status = db.Column(db.String(20), default="pending", nullable=False)  # pending, downloaded, revoked
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)


class Transfer(db.Model):
    __tablename__ = "transfers"
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    sender_id = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    recipient_id = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    file_id = db.Column(db.String(36), db.ForeignKey("encrypted_files.id", ondelete="CASCADE"), nullable=False, index=True)
    envelope_id = db.Column(db.String(36), db.ForeignKey("key_envelopes.id", ondelete="SET NULL"), nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    status = db.Column(db.String(20), default="active", nullable=False)  # active, completed, expired, deleted
    download_count = db.Column(db.Integer, default=0, nullable=False)
    
    envelope = db.relationship("KeyEnvelope", backref="transfers", foreign_keys=[envelope_id])
    
    def to_dict(self):
        return {
            "id": self.id,
            "sender_id": self.sender_id,
            "sender_username": self.sender.username if self.sender else None,
            "recipient_id": self.recipient_id,
            "recipient_username": self.recipient.username if self.recipient else None,
            "file_id": self.file_id,
            "encrypted_size": self.file.encrypted_size if self.file else 0,
            "algorithm": self.file.algorithm if self.file else "AES-256-GCM",
            "protocol_version": self.file.protocol_version if self.file else 1,
            "nonce": self.file.nonce if self.file else None,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "status": self.status,
            "download_count": self.download_count
        }


class KeyEnvelope(db.Model):
    __tablename__ = "key_envelopes"
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    transfer_id = db.Column(db.String(36), nullable=False, index=True)
    sender_id = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    recipient_id = db.Column(db.String(36), db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    envelope_json = db.Column(db.Text, nullable=False)  # Protected envelope JSON string
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    
    def to_dict(self):
        return {
            "id": self.id,
            "transfer_id": self.transfer_id,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "envelope": self.envelope_json,
            "created_at": self.created_at.isoformat()
        }
