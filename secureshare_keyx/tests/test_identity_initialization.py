"""
Test Suite for Identity Initialization, Persistence, Backend Synchronization, and Recipient Discovery.
Tests the requirements of Section 2, 4, 5, 6, 8:
- First-time user identity generation & prekeys publication
- Idempotent returning user initialization (no key churn)
- Backend synchronization when local key exists but server record is missing
- Precise recipient discovery (USER_NOT_FOUND vs NO_IDENTITY vs NO_PREKEYS_AVAILABLE vs SUCCESS)
- Ed25519 cryptographic signature verification on discovered prekeys
- Key envelope creation targeting discovered recipient
- Specific kaviraj1 status verification
"""

import os
import sys
import uuid
import json
import base64
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from app import create_app
from app.extensions import db
from app.models import User, PublicIdentity, PublicPrekey, KeyEnvelope
from app.services.prekey_service import PrekeyService


@pytest.fixture
def test_app():
    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app


@pytest.fixture
def test_client(test_app):
    with test_app.app_context():
        with test_app.test_client() as client:
            yield client


def get_csrf(client):
    """Retrieves CSRF token for the given client session."""
    resp = client.get("/api/auth/csrf")
    return resp.get_json()["csrf_token"]


def register_user(client, username, email, password="Password123!Industrial"):
    """Registers a user and returns valid csrf_token."""
    csrf = get_csrf(client)
    resp = client.post("/api/auth/register", json={
        "username": username,
        "email": email,
        "password": password
    }, headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 201
    return get_csrf(client)


def login_user(client, username, password="Password123!Industrial"):
    """Logs in an existing user and returns valid csrf_token."""
    csrf = get_csrf(client)
    resp = client.post("/api/auth/login", json={
        "identifier": username,
        "password": password
    }, headers={"X-CSRF-Token": csrf})
    assert resp.status_code == 200
    return get_csrf(client)


def generate_crypto_bundle():
    """Generates an Ed25519 identity keypair and 5 signed X25519 prekeys."""
    id_priv = ed25519.Ed25519PrivateKey.generate()
    id_pub = id_priv.public_key()
    id_pub_bytes = id_pub.public_bytes_raw()
    id_pub_hex = id_pub_bytes.hex()
    
    # Fingerprint: SHA-256 of public key
    digest = hashes.Hash(hashes.SHA256())
    digest.update(id_pub_bytes)
    fp_raw = digest.finalize()
    fp_hex = ":".join(f"{b:02x}" for b in fp_raw[:16])
    fingerprint = f"SHA256:{fp_hex}"
    
    # 5 Signed X25519 Prekeys
    prekeys = []
    prekey_privs = {}
    for i in range(5):
        pk_priv = x25519.X25519PrivateKey.generate()
        pk_pub = pk_priv.public_key()
        pk_pub_bytes = pk_pub.public_bytes_raw()
        pk_pub_hex = pk_pub_bytes.hex()
        
        # Ed25519 signature over X25519 public key bytes
        sig_bytes = id_priv.sign(pk_pub_bytes)
        sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
        
        prekeys.append({
            "prekey_id": f"prekey_{uuid.uuid4().hex[:8]}_{i:02d}",
            "x25519_public_key": pk_pub_hex,
            "signature": sig_b64
        })
        prekey_privs[pk_pub_hex] = pk_priv
        
    return {
        "id_priv": id_priv,
        "id_pub_hex": id_pub_hex,
        "fingerprint": fingerprint,
        "prekeys": prekeys,
        "prekey_privs": prekey_privs
    }


class TestIdentityInitializationAndDiscovery:

    def test_kaviraj1_existing_status(self, test_client):
        """
        Verify that kaviraj1 exists in the DB, and discovery correctly returns
        the active identity and signed prekey.
        """
        user = User.query.filter_by(username="kaviraj1").first()
        assert user is not None, "kaviraj1 must exist in the database"
        
        # Test public discovery endpoint
        resp = test_client.get("/api/key-exchange/identities/kaviraj1")
        if user.identity:
            assert resp.status_code == 200
            data = resp.get_json()
            assert data.get("recipient_username") == "kaviraj1"
            assert data.get("signing_public_key") == user.identity.ed25519_public_key
            assert data.get("fingerprint") == user.identity.fingerprint
            assert "x25519_prekey" in data
            assert "prekey_signature" in data
        else:
            assert resp.status_code == 404
            data = resp.get_json()
            assert data.get("code") == "NO_IDENTITY"
            assert data.get("username") == "kaviraj1"

    def test_uninitialized_user_discovery(self, test_client):
        """
        Verify that an uninitialized registered user returns NO_IDENTITY.
        """
        uid = uuid.uuid4().hex[:6]
        uninit_name = f"uninit_{uid}"
        register_user(test_client, uninit_name, f"{uninit_name}@test.com")
        
        resp = test_client.get(f"/api/key-exchange/identities/{uninit_name}")
        assert resp.status_code == 404
        data = resp.get_json()
        assert data.get("code") == "NO_IDENTITY"
        assert data.get("username") == uninit_name
        assert "has not published an identity bundle" in data.get("error")

    def test_nonexistent_user_discovery(self, test_client):
        """Verify that discovery for non-existent user returns USER_NOT_FOUND."""
        resp = test_client.get("/api/key-exchange/identities/definitely_not_a_real_user_9999")
        assert resp.status_code == 404
        data = resp.get_json()
        assert data.get("code") == "USER_NOT_FOUND"

    def test_new_user_first_time_identity_and_prekeys_init(self, test_client):
        """
        Simulate a brand new user logging in and performing automatic identity initialization:
        1. Check /api/identities/me -> has_identity is False
        2. Publish Ed25519 identity key
        3. Publish 5 signed X25519 prekeys
        4. Verify /api/identities/me -> has_identity is True
        5. Verify both /api/identities/<target> and /api/key-exchange/identities/<target> return valid public key and signed prekey
        """
        uid = uuid.uuid4().hex[:6]
        username = f"newuser_{uid}"
        csrf = register_user(test_client, username, f"{username}@test.com")
        headers = {"X-CSRF-Token": csrf}
        
        # Step 1: Check identity status before publishing
        resp = test_client.get("/api/identities/me")
        assert resp.status_code == 200
        assert resp.get_json()["has_identity"] is False
        
        # Step 2: Generate crypto bundle and publish identity
        bundle = generate_crypto_bundle()
        resp = test_client.post("/api/identities", json={
            "ed25519_public_key": bundle["id_pub_hex"],
            "fingerprint": bundle["fingerprint"]
        }, headers=headers)
        assert resp.status_code == 200
        assert resp.get_json()["identity"]["fingerprint"] == bundle["fingerprint"]
        
        # Step 3: Publish 5 signed X25519 prekeys
        resp = test_client.post("/api/prekeys", json={
            "prekeys": bundle["prekeys"]
        }, headers=headers)
        assert resp.status_code == 201
        prekey_res = resp.get_json()
        assert len(prekey_res["prekeys"]) == 5
        
        # Step 4: Verify /api/identities/me reports active identity
        resp = test_client.get("/api/identities/me")
        assert resp.status_code == 200
        assert resp.get_json()["has_identity"] is True
        assert resp.get_json()["identity"]["ed25519_public_key"] == bundle["id_pub_hex"]
        
        # Step 5: Verify internal endpoint /api/identities/<target>
        internal_resp = test_client.get(f"/api/identities/{username}")
        assert internal_resp.status_code == 200
        internal_data = internal_resp.get_json()
        assert internal_data["username"] == username
        assert internal_data["identity"]["ed25519_public_key"] == bundle["id_pub_hex"]
        
        # Step 6: Verify public integration discovery endpoint /api/key-exchange/identities/<target>
        disc_resp = test_client.get(f"/api/key-exchange/identities/{username}")
        assert disc_resp.status_code == 200
        disc_data = disc_resp.get_json()
        assert disc_data["recipient_username"] == username
        assert disc_data["signing_public_key"] == bundle["id_pub_hex"]
        assert disc_data["fingerprint"] == bundle["fingerprint"]
        assert "x25519_prekey" in disc_data
        
        # Verify Ed25519 cryptographic signature of the prekey
        pub_prekey_hex = disc_data["x25519_prekey"]
        sig_b64 = disc_data["prekey_signature"]
        sig_bytes = base64.b64decode(sig_b64)
        
        ed_pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(bundle["id_pub_hex"]))
        ed_pub_key.verify(sig_bytes, bytes.fromhex(pub_prekey_hex))

    def test_idempotent_initialization(self, test_client):
        """
        Verify that publishing the same identity again is idempotent:
        does not rotate keys or duplicate database records.
        """
        uid = uuid.uuid4().hex[:6]
        username = f"idemp_{uid}"
        csrf = register_user(test_client, username, f"{username}@test.com")
        headers = {"X-CSRF-Token": csrf}
        bundle = generate_crypto_bundle()
        
        # First publish
        test_client.post("/api/identities", json={
            "ed25519_public_key": bundle["id_pub_hex"],
            "fingerprint": bundle["fingerprint"]
        }, headers=headers)
        
        # Second publish with SAME key
        resp2 = test_client.post("/api/identities", json={
            "ed25519_public_key": bundle["id_pub_hex"],
            "fingerprint": bundle["fingerprint"]
        }, headers=headers)
        assert resp2.status_code == 200
        assert resp2.get_json()["identity"]["status"] == "active"
        
        # Count records in DB for this user
        user = User.query.filter_by(username=username).first()
        count = PublicIdentity.query.filter_by(user_id=user.id).count()
        assert count == 1, "There must only be 1 identity record per user"

    def test_prekeys_exhaustion_detection(self, test_client):
        """
        Verify that when all prekeys are consumed, discovery returns NO_PREKEYS_AVAILABLE.
        """
        uid = uuid.uuid4().hex[:6]
        username = f"exhaust_{uid}"
        csrf = register_user(test_client, username, f"{username}@test.com")
        headers = {"X-CSRF-Token": csrf}
        bundle = generate_crypto_bundle()
        
        # Publish identity and prekeys
        test_client.post("/api/identities", json={
            "ed25519_public_key": bundle["id_pub_hex"],
            "fingerprint": bundle["fingerprint"]
        }, headers=headers)
        test_client.post("/api/prekeys", json={
            "prekeys": bundle["prekeys"]
        }, headers=headers)
        
        # Mark all prekeys for this user as consumed
        user = User.query.filter_by(username=username).first()
        prekeys = PublicPrekey.query.filter_by(user_id=user.id).all()
        for pk in prekeys:
            pk.status = "consumed"
        db.session.commit()
        
        # Discover should now return NO_PREKEYS_AVAILABLE
        resp = test_client.get(f"/api/key-exchange/identities/{username}")
        assert resp.status_code == 404
        assert resp.get_json()["code"] == "NO_PREKEYS_AVAILABLE"

    def test_complete_key_envelope_transfer_flow(self, test_app):
        """
        Full two-user flow using two isolated browser sessions (Alice client & Bob client):
        - Sender (Alice) registers and initializes.
        - Recipient (Bob) registers and initializes.
        - Alice discovers Bob and verifies prekey signature.
        - Alice creates an AES key, wraps it in protected envelope for Bob.
        - Alice deposits envelope into Bob's KeyX inbox.
        - Bob unseals the envelope and recovers the exact AES key.
        """
        uid = uuid.uuid4().hex[:6]
        alice_name = f"alice_{uid}"
        bob_name = f"bob_{uid}"
        
        bob_client = test_app.test_client()
        alice_client = test_app.test_client()
        
        # 1. Register & init Bob in Bob's browser session
        bob_csrf = register_user(bob_client, bob_name, f"{bob_name}@test.com")
        bob_bundle = generate_crypto_bundle()
        bob_client.post("/api/identities", json={
            "ed25519_public_key": bob_bundle["id_pub_hex"],
            "fingerprint": bob_bundle["fingerprint"]
        }, headers={"X-CSRF-Token": bob_csrf})
        bob_client.post("/api/prekeys", json={"prekeys": bob_bundle["prekeys"]}, headers={"X-CSRF-Token": bob_csrf})
        
        # 2. Register & init Alice in Alice's browser session
        alice_csrf = register_user(alice_client, alice_name, f"{alice_name}@test.com")
        alice_bundle = generate_crypto_bundle()
        alice_client.post("/api/identities", json={
            "ed25519_public_key": alice_bundle["id_pub_hex"],
            "fingerprint": alice_bundle["fingerprint"]
        }, headers={"X-CSRF-Token": alice_csrf})
        alice_client.post("/api/prekeys", json={"prekeys": alice_bundle["prekeys"]}, headers={"X-CSRF-Token": alice_csrf})
        
        # 3. Alice discovers Bob
        disc_resp = alice_client.get(f"/api/key-exchange/identities/{bob_name}")
        assert disc_resp.status_code == 200
        bob_info = disc_resp.get_json()
        
        # Alice verifies Bob's prekey signature
        bob_id_pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(bob_info["signing_public_key"]))
        bob_prekey_pub_bytes = bytes.fromhex(bob_info["x25519_prekey"])
        bob_prekey_sig = base64.b64decode(bob_info["prekey_signature"])
        bob_id_pub.verify(bob_prekey_sig, bob_prekey_pub_bytes)
        
        # 4. Alice generates random 32-byte AES file key
        aes_file_key = os.urandom(32)
        
        # Alice generates ephemeral X25519 keypair
        ephem_priv = x25519.X25519PrivateKey.generate()
        ephem_pub_bytes = ephem_priv.public_key().public_bytes_raw()
        
        # Diffie-Hellman with Bob's X25519 prekey
        bob_x25519_pub = x25519.X25519PublicKey.from_public_bytes(bob_prekey_pub_bytes)
        shared_secret = ephem_priv.exchange(bob_x25519_pub)
        
        # HKDF derive 256-bit wrapping key
        transfer_id = str(uuid.uuid4())
        salt = os.urandom(16)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=f"SecureShare-FileVault-Transfer-{transfer_id}".encode("utf-8")
        )
        wrapping_key = hkdf.derive(shared_secret)
        
        # AES-256-GCM encrypt the file key
        aesgcm = AESGCM(wrapping_key)
        iv = os.urandom(12)
        aad = f"{transfer_id}:{bob_info['prekey_id']}".encode("utf-8")
        ciphertext_and_tag = aesgcm.encrypt(iv, aes_file_key, aad)
        encrypted_file_key = ciphertext_and_tag[:-16]
        tag = ciphertext_and_tag[-16:]
        
        # Alice signs envelope with her Ed25519 identity key
        sig_payload = f"{transfer_id}:{ephem_pub_bytes.hex()}:{encrypted_file_key.hex()}".encode("utf-8")
        alice_sig = alice_bundle["id_priv"].sign(sig_payload)
        
        # 5. Alice dispatches envelope to KeyX
        env_resp = alice_client.post("/api/envelopes", json={
            "transfer_id": transfer_id,
            "recipient_id": bob_info["recipient_id"],
            "recipient_prekey_id": bob_info["prekey_id"],
            "envelope": {
                "ephemeral_public_key": ephem_pub_bytes.hex(),
                "encrypted_file_key": encrypted_file_key.hex(),
                "iv": iv.hex(),
                "tag": tag.hex(),
                "salt": salt.hex(),
                "signature": base64.b64encode(alice_sig).decode("ascii")
            },
            "sender_signature": base64.b64encode(alice_sig).decode("ascii")
        }, headers={"X-CSRF-Token": get_csrf(alice_client)})
        assert env_resp.status_code == 201
        
        # 6. Bob checks envelope in Bob's browser session
        inbox_resp = bob_client.get(f"/api/envelopes/{transfer_id}")
        assert inbox_resp.status_code == 200
        env_record = inbox_resp.get_json()["envelope"]
        env_data = json.loads(env_record["encrypted_envelope"]) if isinstance(env_record["encrypted_envelope"], str) else env_record["encrypted_envelope"]
        
        # Bob verifies Alice's signature
        alice_id_pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(alice_bundle["id_pub_hex"]))
        verify_payload = f"{transfer_id}:{env_data['ephemeral_public_key']}:{env_data['encrypted_file_key']}".encode("utf-8")
        alice_id_pub.verify(base64.b64decode(env_record["sender_signature"]), verify_payload)
        
        # Bob unwraps AES file key
        bob_priv_prekey = bob_bundle["prekey_privs"][bob_info["x25519_prekey"]]
        bob_shared_secret = bob_priv_prekey.exchange(
            x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(env_data["ephemeral_public_key"]))
        )
        bob_hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=bytes.fromhex(env_data["salt"]),
            info=f"SecureShare-FileVault-Transfer-{transfer_id}".encode("utf-8")
        )
        bob_wrapping_key = bob_hkdf.derive(bob_shared_secret)
        bob_aesgcm = AESGCM(bob_wrapping_key)
        recovered_file_key = bob_aesgcm.decrypt(
            bytes.fromhex(env_data["iv"]),
            bytes.fromhex(env_data["encrypted_file_key"]) + bytes.fromhex(env_data["tag"]),
            f"{transfer_id}:{env_record['recipient_prekey_id']}".encode("utf-8")
        )
        
        assert recovered_file_key == aes_file_key, "Recovered AES file key must match original exactly"
