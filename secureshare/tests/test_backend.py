import io
import json
import time
from datetime import datetime, timezone, timedelta
from app.extensions import db
from app.models import User, EncryptedFile, Transfer, PublicIdentity, KeyEnvelope
from app.services.storage import CiphertextStorageService, StorageError
import pytest

def test_user_registration_and_login(client):
    # 1. Register Alice
    resp = client.post("/api/auth/register", json={
        "username": "alice_test",
        "email": "alice@example.com",
        "password": "Password123!Secure"
    })
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["user"]["username"] == "alice_test"
    csrf_token = data["csrf_token"]

    # Reject duplicate username
    dup_resp = client.post("/api/auth/register", json={
        "username": "alice_test",
        "email": "another@example.com",
        "password": "Password123!Secure"
    }, headers={"X-CSRF-Token": csrf_token})
    assert dup_resp.status_code == 409

    # 2. Check /api/auth/me
    me_resp = client.get("/api/auth/me")
    assert me_resp.status_code == 200
    assert me_resp.get_json()["authenticated"] is True

    # 3. Logout
    logout_resp = client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_token})
    assert logout_resp.status_code == 200

    # 4. Login with invalid password
    bad_login = client.post("/api/auth/login", json={
        "identifier": "alice_test",
        "password": "WrongPassword!"
    })
    assert bad_login.status_code == 401

    # 5. Login with correct credentials
    good_login = client.post("/api/auth/login", json={
        "identifier": "alice_test",
        "password": "Password123!Secure"
    })
    assert good_login.status_code == 200
    assert good_login.get_json()["user"]["username"] == "alice_test"

def test_public_identity_publish_and_search(client):
    # Register Alice
    reg = client.post("/api/auth/register", json={
        "username": "alice_crypto",
        "email": "alice_crypto@example.com",
        "password": "Password123!Secure"
    })
    csrf = reg.get_json()["csrf_token"]

    # Publish public identity
    fake_signing_pk = "01" * 32  # 64 hex characters
    fake_x25519_pk = "02" * 32
    pub_resp = client.post("/api/key-exchange/identities", json={
        "signing_public_key": fake_signing_pk,
        "x25519_prekey": fake_x25519_pk,
        "fingerprint": "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99",
        "prekey_id": "prekey_001"
    }, headers={"X-CSRF-Token": csrf})
    assert pub_resp.status_code == 200

    # Register Bob and search for Alice
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    client.post("/api/auth/register", json={
        "username": "bob_crypto",
        "email": "bob_crypto@example.com",
        "password": "Password123!Secure"
    })
    
    search_resp = client.get("/api/users/search?q=alice")
    assert search_resp.status_code == 200
    results = search_resp.get_json()["users"]
    assert len(results) == 1
    assert results[0]["username"] == "alice_crypto"
    assert results[0]["signing_public_key"] == fake_signing_pk

def test_encrypted_file_upload_and_storage_guarantees(client, app):
    # Register and login Alice
    reg = client.post("/api/auth/register", json={
        "username": "alice_sender",
        "email": "alice_sender@example.com",
        "password": "Password123!Secure"
    })
    csrf = reg.get_json()["csrf_token"]

    # Upload encrypted bytes
    ciphertext_bytes = b"\xde\xad\xbe\xef" * 1024  # 4 KB of mock ciphertext
    data = {
        "file": (io.BytesIO(ciphertext_bytes), "payload.enc"),
        "nonce": "dGVzdF9ub25jZV8xMjM0",
        "algorithm": "AES-256-GCM",
        "protocol_version": 1
    }

    upload_resp = client.post("/api/files/upload", data=data, content_type="multipart/form-data", headers={"X-CSRF-Token": csrf})
    assert upload_resp.status_code == 201
    file_info = upload_resp.get_json()["file"]
    file_id = file_info["id"]
    storage_id = file_info["storage_id"]
    assert file_info["encrypted_size"] == len(ciphertext_bytes)

    # VERIFY: Ciphertext file exists in storage and matches exact encrypted bytes
    storage_svc = CiphertextStorageService(app.config["CIPHERTEXT_STORAGE_DIR"])
    stored_path = storage_svc._get_safe_path(storage_id)
    assert stored_path.is_file()
    with open(stored_path, "rb") as f:
        stored_bytes = f.read()
    assert stored_bytes == ciphertext_bytes

def test_transfer_creation_authorization_and_expiry(client, app):
    # 1. Register Alice (Sender)
    reg_alice = client.post("/api/auth/register", json={
        "username": "sender_alice",
        "email": "alice_s@example.com",
        "password": "Password123!Secure"
    })
    alice_id = reg_alice.get_json()["user"]["id"]
    csrf_alice = reg_alice.get_json()["csrf_token"]

    # 2. Register Bob (Recipient)
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_alice})
    reg_bob = client.post("/api/auth/register", json={
        "username": "receiver_bob",
        "email": "bob_r@example.com",
        "password": "Password123!Secure"
    })
    bob_id = reg_bob.get_json()["user"]["id"]
    csrf_bob = reg_bob.get_json()["csrf_token"]

    # 3. Register Charlie (Unauthorized third party)
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_bob})
    reg_charlie = client.post("/api/auth/register", json={
        "username": "eve_eavesdropper",
        "email": "eve@example.com",
        "password": "Password123!Secure"
    })
    csrf_charlie = reg_charlie.get_json()["csrf_token"]

    # 4. Login as Alice and upload file
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_charlie})
    login_alice = client.post("/api/auth/login", json={"identifier": "sender_alice", "password": "Password123!Secure"})
    csrf_alice = login_alice.get_json()["csrf_token"]

    ciphertext = b"SecretCiphertextBytes" * 20
    upload = client.post("/api/files/upload", data={
        "file": (io.BytesIO(ciphertext), "secret.enc"),
        "nonce": "dGVzdF9ub25jZV8xMg==",
        "algorithm": "AES-256-GCM"
    }, content_type="multipart/form-data", headers={"X-CSRF-Token": csrf_alice})
    file_id = upload.get_json()["file"]["id"]

    # 5. Create Transfer addressed to Bob (no envelope yet — get the real UUID first)
    tx_resp = client.post("/api/transfers", json={
        "recipient": "receiver_bob",
        "file_id": file_id,
        "expires_in_hours": 24
    }, headers={"X-CSRF-Token": csrf_alice})
    assert tx_resp.status_code == 201
    transfer_id = tx_resp.get_json()["transfer"]["id"]

    # 6. Submit signed envelope bound to Bob using REAL transfer UUID
    env_resp = client.post("/api/key-exchange/envelopes", json={
        "transfer_id": transfer_id,
        "recipient_id": bob_id,
        "envelope": {"version": 1, "mock": "signed_envelope_payload"}
    }, headers={"X-CSRF-Token": csrf_alice})
    assert env_resp.status_code == 201
    envelope_id = env_resp.get_json()["envelope_id"]

    # Attach envelope to transfer via PATCH
    patch_resp = client.patch(f"/api/transfers/{transfer_id}", json={
        "envelope_id": envelope_id
    }, headers={"X-CSRF-Token": csrf_alice})
    assert patch_resp.status_code == 200

    # 7. Charlie tries to download Bob's file -> REJECTED (HTTP 403 Forbidden)
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_alice})
    login_charlie = client.post("/api/auth/login", json={"identifier": "eve_eavesdropper", "password": "Password123!Secure"})
    csrf_charlie = login_charlie.get_json()["csrf_token"]

    charlie_dl = client.get(f"/api/transfers/{transfer_id}/download")
    assert charlie_dl.status_code == 403

    # Charlie tries to get envelope -> REJECTED (HTTP 403 Forbidden)
    charlie_env = client.get(f"/api/key-exchange/envelopes/{transfer_id}")
    assert charlie_env.status_code == 403

    # 8. Bob logs in and downloads file -> AUTHORIZED (HTTP 200)
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_charlie})
    login_bob = client.post("/api/auth/login", json={"identifier": "receiver_bob", "password": "Password123!Secure"})
    csrf_bob = login_bob.get_json()["csrf_token"]

    bob_dl = client.get(f"/api/transfers/{transfer_id}/download")
    assert bob_dl.status_code == 200
    assert bob_dl.data == ciphertext

    bob_env = client.get(f"/api/key-exchange/envelopes/{transfer_id}")
    assert bob_env.status_code == 200

    # 9. Test expiration behavior
    with app.app_context():
        tx = db.session.get(Transfer, transfer_id)
        # Fast-forward expiration to the past
        tx.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        app.extensions["sqlalchemy"].session.commit()

    # Now download should return 410 Gone
    expired_dl = client.get(f"/api/transfers/{transfer_id}/download")
    assert expired_dl.status_code == 410

def test_path_traversal_protection(app):
    storage_svc = CiphertextStorageService(app.config["CIPHERTEXT_STORAGE_DIR"])
    
    with pytest.raises(StorageError):
        storage_svc._get_safe_path("../../etc/passwd")

    with pytest.raises(StorageError):
        storage_svc._get_safe_path("..\\windows\\system32")

    with pytest.raises(StorageError):
        storage_svc._get_safe_path("valid_id/../../attack")
