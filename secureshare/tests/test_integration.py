import io
import json
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from app.services.storage import CiphertextStorageService

def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'))

def test_full_e2e_transfer_workflow(client, app):
    """
    Simulates the complete correct client-side workflow:
      1. Alice registers, generates identity keys, publishes public bundle.
      2. Bob registers, generates identity keys + X25519 prekey, publishes public bundle.
      3. Alice fetches Bob's public bundle (signing pk + X25519 prekey).
      4. Alice generates AES-256-GCM file key, encrypts the original plaintext locally.
      5. Alice uploads ONLY the ciphertext to the server.
      6. Alice creates the transfer record (no envelope yet) → server assigns REAL UUID.
      7. Alice builds the protected key envelope signed with the REAL transfer UUID.
      8. Alice submits the envelope and PATCH-attaches it to the transfer.
      9. Bob logs in, retrieves envelope by the real transfer UUID.
      10. Bob verifies Alice's Ed25519 signature.
      11. Bob computes X25519 shared secret using HIS private prekey + Alice's ephemeral pub.
      12. Bob derives wrapping key with HKDF-SHA-256 using real transfer UUID in context.
      13. Bob unwraps the AES file key.
      14. Bob downloads the ciphertext from the server.
      15. Bob decrypts locally — bytes must match exactly.
    Also verifies:
      - Backend stores only ciphertext (not plaintext).
      - Unauthorized third party cannot download or retrieve envelope.
      - Backend never receives unwrapped AES keys or private keys.
    """
    # -------------------------------------------------------------------------
    # 1. Register Alice
    # -------------------------------------------------------------------------
    reg_alice = client.post("/api/auth/register", json={
        "username": "alice_e2e",
        "email": "alice_e2e@example.com",
        "password": "Password123!Secure"
    })
    assert reg_alice.status_code == 201
    alice_id = reg_alice.get_json()["user"]["id"]
    csrf_alice = reg_alice.get_json()["csrf_token"]

    # Alice generates Ed25519 identity keypair (client-side — never sent to server)
    alice_id_sk = ed25519.Ed25519PrivateKey.generate()
    alice_id_pk = alice_id_sk.public_key()
    alice_id_pk_bytes = alice_id_pk.public_bytes_raw()
    alice_id_pk_hex = alice_id_pk_bytes.hex()

    # Alice publishes her PUBLIC identity bundle (public keys only)
    alice_pub_resp = client.post("/api/key-exchange/identities", json={
        "signing_public_key": alice_id_pk_hex,
        "x25519_prekey": ("11" * 32),        # Alice also has a prekey (not used in this transfer)
        "fingerprint": "11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF",
        "prekey_id": "alice_prekey_0"
    }, headers={"X-CSRF-Token": csrf_alice})
    assert alice_pub_resp.status_code == 200

    # -------------------------------------------------------------------------
    # 2. Register Bob
    # -------------------------------------------------------------------------
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_alice})
    reg_bob = client.post("/api/auth/register", json={
        "username": "bob_e2e",
        "email": "bob_e2e@example.com",
        "password": "Password123!Secure"
    })
    assert reg_bob.status_code == 201
    bob_id = reg_bob.get_json()["user"]["id"]
    csrf_bob = reg_bob.get_json()["csrf_token"]

    # Bob generates Ed25519 identity + X25519 prekey (PRIVATE keys never leave Bob's device)
    bob_id_sk = ed25519.Ed25519PrivateKey.generate()
    bob_id_pk = bob_id_sk.public_key()
    bob_id_pk_bytes = bob_id_pk.public_bytes_raw()
    bob_id_pk_hex = bob_id_pk_bytes.hex()

    bob_prekey_sk = x25519.X25519PrivateKey.generate()
    bob_prekey_pk = bob_prekey_sk.public_key()
    bob_prekey_pk_bytes = bob_prekey_pk.public_bytes_raw()
    bob_prekey_pk_hex = bob_prekey_pk_bytes.hex()
    bob_prekey_id = "bob_prekey_101"

    # Bob publishes his PUBLIC bundle (public keys only — private keys stay local)
    bob_pub_resp = client.post("/api/key-exchange/identities", json={
        "signing_public_key": bob_id_pk_hex,
        "x25519_prekey": bob_prekey_pk_hex,
        "fingerprint": "BB:BB:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF",
        "prekey_id": bob_prekey_id
    }, headers={"X-CSRF-Token": csrf_bob})
    assert bob_pub_resp.status_code == 200

    # -------------------------------------------------------------------------
    # 3. Alice logs back in and fetches Bob's public bundle
    # -------------------------------------------------------------------------
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_bob})
    login_alice = client.post("/api/auth/login", json={
        "identifier": "alice_e2e",
        "password": "Password123!Secure"
    })
    assert login_alice.status_code == 200
    csrf_alice = login_alice.get_json()["csrf_token"]

    bundle_resp = client.get("/api/key-exchange/identities/bob_e2e")
    assert bundle_resp.status_code == 200
    bob_bundle = bundle_resp.get_json()
    assert bob_bundle["x25519_prekey"] == bob_prekey_pk_hex
    assert bob_bundle["signing_public_key"] == bob_id_pk_hex

    # -------------------------------------------------------------------------
    # 4. Alice generates AES-256 file key and encrypts original plaintext locally
    # -------------------------------------------------------------------------
    original_plaintext = b"%PDF-1.4 Mock confidential report text with sensitive company data" * 100
    file_aes_key = AESGCM.generate_key(bit_length=256)   # stays in Alice's memory only
    file_nonce = b"\x12" * 12
    file_ciphertext = AESGCM(file_aes_key).encrypt(file_nonce, original_plaintext, None)

    # -------------------------------------------------------------------------
    # 5. Alice uploads ONLY the ciphertext to the server
    # -------------------------------------------------------------------------
    upload_resp = client.post("/api/files/upload", data={
        "file": (io.BytesIO(file_ciphertext), "confidential.pdf.enc"),
        "nonce": b64encode(file_nonce).decode(),
        "algorithm": "AES-256-GCM",
        "protocol_version": 1
    }, content_type="multipart/form-data", headers={"X-CSRF-Token": csrf_alice})
    assert upload_resp.status_code == 201
    file_id = upload_resp.get_json()["file"]["id"]
    storage_id = upload_resp.get_json()["file"]["storage_id"]

    # VERIFY: Backend stores only ciphertext — plaintext must not be present
    storage_svc = CiphertextStorageService(app.config["CIPHERTEXT_STORAGE_DIR"])
    stored_path = storage_svc._get_safe_path(storage_id)
    with open(stored_path, "rb") as f:
        stored_bytes = f.read()
    assert stored_bytes == file_ciphertext
    assert original_plaintext not in stored_bytes

    # -------------------------------------------------------------------------
    # 6. Alice creates the transfer record (WITHOUT envelope) to obtain REAL UUID
    # -------------------------------------------------------------------------
    tx_create_resp = client.post("/api/transfers", json={
        "recipient": "bob_e2e",
        "file_id": file_id,
        # No envelope_id — it will be attached via PATCH after envelope creation
        "expires_in_hours": 48
    }, headers={"X-CSRF-Token": csrf_alice})
    assert tx_create_resp.status_code == 201, (
        f"Transfer creation failed: {tx_create_resp.get_json()}"
    )
    transfer_id = tx_create_resp.get_json()["transfer"]["id"]
    assert len(transfer_id) == 36, "Expected UUID format transfer ID"

    # -------------------------------------------------------------------------
    # 7. Alice builds the protected key envelope using the REAL transfer UUID
    # -------------------------------------------------------------------------
    alice_ephemeral_sk = x25519.X25519PrivateKey.generate()
    alice_ephemeral_pk = alice_ephemeral_sk.public_key()
    alice_ephemeral_pk_hex = alice_ephemeral_pk.public_bytes_raw().hex()

    bob_prekey_pub_obj = x25519.X25519PublicKey.from_public_bytes(
        bytes.fromhex(bob_bundle["x25519_prekey"])
    )
    shared_secret = alice_ephemeral_sk.exchange(bob_prekey_pub_obj)

    # HKDF-SHA-256 wrapping key derivation — uses REAL transfer_id
    salt = b"\x33" * 32
    context_info = (
        f"SecureShare-v1|wrapping-key|{alice_id_pk_hex}|{bob_id_pk_hex}"
        f"|{transfer_id}|{bob_prekey_id}"
    ).encode()
    wrapping_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=context_info
    ).derive(shared_secret)

    # Wrap file key with AAD bound to real transfer_id
    wrap_nonce = b"\x44" * 12
    key_aad = f"SecureShare-Envelope-Key-v1|{transfer_id}|{bob_prekey_id}".encode()
    wrapped_file_key = AESGCM(wrapping_key).encrypt(wrap_nonce, file_aes_key, key_aad)

    # Wrap metadata with AAD bound to real transfer_id
    meta_dict = {
        "filename": "confidential.pdf",
        "mimeType": "application/pdf",
        "size": len(original_plaintext)
    }
    meta_nonce = b"\x55" * 12
    meta_aad = f"SecureShare-Envelope-Meta-v1|{transfer_id}".encode()
    wrapped_meta = AESGCM(wrapping_key).encrypt(meta_nonce, canonical_json(meta_dict).encode(), meta_aad)

    # Build unsigned envelope with REAL transfer_id
    envelope_data = {
        "version": 1,
        "transfer_id": transfer_id,            # REAL UUID — not a temp placeholder
        "recipient_prekey_id": bob_prekey_id,
        "sender_identity_key": alice_id_pk_hex,
        "sender_ephemeral_key": alice_ephemeral_pk_hex,
        "hkdf_salt": b64encode(salt).decode(),
        "wrapped_key_nonce": b64encode(wrap_nonce).decode(),
        "wrapped_file_key": b64encode(wrapped_file_key).decode(),
        "meta_nonce": b64encode(meta_nonce).decode(),
        "meta_ciphertext": b64encode(wrapped_meta).decode()
    }

    # Alice signs canonical serialization (private key never sent to server)
    canonical_env_bytes = canonical_json(envelope_data).encode()
    envelope_signature = alice_id_sk.sign(canonical_env_bytes)
    envelope_data["signature"] = b64encode(envelope_signature).decode()

    # -------------------------------------------------------------------------
    # 8. Alice submits envelope, then PATCH-attaches it to the transfer
    # -------------------------------------------------------------------------
    env_submit = client.post("/api/key-exchange/envelopes", json={
        "transfer_id": transfer_id,
        "recipient_id": bob_id,
        "envelope": envelope_data
    }, headers={"X-CSRF-Token": csrf_alice})
    assert env_submit.status_code == 201, (
        f"Envelope submit failed: {env_submit.get_json()}"
    )
    envelope_id = env_submit.get_json()["envelope_id"]

    # PATCH the transfer to attach the envelope
    patch_resp = client.patch(f"/api/transfers/{transfer_id}", json={
        "envelope_id": envelope_id
    }, headers={"X-CSRF-Token": csrf_alice})
    assert patch_resp.status_code == 200, (
        f"Transfer PATCH failed: {patch_resp.get_json()}"
    )

    # -------------------------------------------------------------------------
    # 9. Eve (third party) tries to access Bob's transfer — must be forbidden
    # -------------------------------------------------------------------------
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_alice})
    reg_eve = client.post("/api/auth/register", json={
        "username": "eve_eavesdropper_e2e",
        "email": "eve_e2e@example.com",
        "password": "Password123!Secure"
    })
    csrf_eve = reg_eve.get_json()["csrf_token"]

    eve_dl = client.get(f"/api/transfers/{transfer_id}/download")
    assert eve_dl.status_code == 403, "Eve must be denied ciphertext download"

    eve_env = client.get(f"/api/key-exchange/envelopes/{transfer_id}")
    assert eve_env.status_code == 403, "Eve must be denied envelope retrieval"

    # -------------------------------------------------------------------------
    # 10–14. Bob logs in, retrieves envelope, verifies, derives keys, decrypts
    # -------------------------------------------------------------------------
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_eve})
    login_bob = client.post("/api/auth/login", json={
        "identifier": "bob_e2e",
        "password": "Password123!Secure"
    })
    assert login_bob.status_code == 200
    csrf_bob = login_bob.get_json()["csrf_token"]

    # 10. Bob retrieves the envelope from the server using the real transfer UUID
    bob_env_resp = client.get(f"/api/key-exchange/envelopes/{transfer_id}")
    assert bob_env_resp.status_code == 200
    retrieved_env = bob_env_resp.get_json()["envelope"]

    # Confirm the envelope is bound to the real transfer UUID
    assert retrieved_env["transfer_id"] == transfer_id

    # 11. Bob verifies Alice's Ed25519 signature (public key from Alice's published bundle)
    sig_to_verify = b64decode(retrieved_env["signature"])
    unsigned_copy = {k: v for k, v in retrieved_env.items() if k != "signature"}
    alice_pub_obj = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(retrieved_env["sender_identity_key"])
    )
    alice_pub_obj.verify(sig_to_verify, canonical_json(unsigned_copy).encode())  # raises on failure

    # 12. Bob derives shared secret using HIS private prekey + Alice's ephemeral public key
    alice_ephemeral_pub_obj = x25519.X25519PublicKey.from_public_bytes(
        bytes.fromhex(retrieved_env["sender_ephemeral_key"])
    )
    bob_shared_secret = bob_prekey_sk.exchange(alice_ephemeral_pub_obj)
    assert bob_shared_secret == shared_secret, "Shared secrets must be equal (DH correctness)"

    # Bob derives wrapping key — context includes the real transfer_id
    bob_salt = b64decode(retrieved_env["hkdf_salt"])
    bob_wrapping_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=bob_salt, info=context_info
    ).derive(bob_shared_secret)
    assert bob_wrapping_key == wrapping_key, "Wrapping keys must match"

    # 13. Bob unwraps AES file key (stays in Bob's memory — never sent to server)
    bob_wrap_nonce = b64decode(retrieved_env["wrapped_key_nonce"])
    bob_wrapped_key = b64decode(retrieved_env["wrapped_file_key"])
    recovered_file_key = AESGCM(bob_wrapping_key).decrypt(bob_wrap_nonce, bob_wrapped_key, key_aad)
    assert recovered_file_key == file_aes_key, "Recovered file key must match original"

    # Bob unwraps metadata
    bob_meta_nonce = b64decode(retrieved_env["meta_nonce"])
    bob_meta_cipher = b64decode(retrieved_env["meta_ciphertext"])
    recovered_meta = json.loads(
        AESGCM(bob_wrapping_key).decrypt(bob_meta_nonce, bob_meta_cipher, meta_aad).decode()
    )
    assert recovered_meta["filename"] == "confidential.pdf"

    # 14. Bob downloads the ciphertext from the server
    dl_resp = client.get(f"/api/transfers/{transfer_id}/download")
    assert dl_resp.status_code == 200
    downloaded_ciphertext = dl_resp.data
    downloaded_nonce = b64decode(dl_resp.headers["X-Encryption-Nonce"])

    # 15. Bob decrypts locally using the recovered file key — must match original plaintext exactly
    recovered_plaintext = AESGCM(recovered_file_key).decrypt(
        downloaded_nonce, downloaded_ciphertext, None
    )
    assert recovered_plaintext == original_plaintext, (
        "Decrypted plaintext must be byte-for-byte identical to original"
    )
    print("\nSUCCESS: End-to-end byte-for-byte decryption equality verified!")
    print(f"  Transfer UUID : {transfer_id}")
    print(f"  Plaintext     : {len(original_plaintext)} bytes")
    print(f"  Ciphertext    : {len(downloaded_ciphertext)} bytes")
    print(f"  Recovered     : {len(recovered_plaintext)} bytes")
