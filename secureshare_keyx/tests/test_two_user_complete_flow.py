import json
import uuid
import hashlib
import urllib.request
import http.cookiejar
from io import BytesIO
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import base64

FILE_VAULT_URL = "http://127.0.0.1:5000"
KEYX_PORTAL_URL = "http://127.0.0.1:5001"

def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'))

class HttpClient:
    def __init__(self, base_url):
        self.base_url = base_url
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))

    def request(self, method, path, data=None, json_data=None, headers=None, files=None):
        url = self.base_url + path
        h = headers or {}
        req_body = None

        if json_data is not None:
            req_body = json.dumps(json_data).encode("utf-8")
            h["Content-Type"] = "application/json"
        elif files:
            boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"
            h["Content-Type"] = f"multipart/form-data; boundary={boundary}"
            parts = []
            if data:
                for k, v in data.items():
                    parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
            for name, (fname, fstream, ctype) in files.items():
                content = fstream.read()
                parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{fname}\"\r\nContent-Type: {ctype}\r\n\r\n".encode() + content + b"\r\n")
            parts.append(f"--{boundary}--\r\n".encode())
            req_body = b"".join(parts)

        req = urllib.request.Request(url, data=req_body, headers=h, method=method)
        try:
            resp = self.opener.open(req)
            body = resp.read()
            return resp.status, body, resp.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read(), e.headers


def test_complete_e2e_flow():
    print("=" * 80)
    print("STARTING COMPLETE END-TO-END WORKFLOW TEST: ALICE -> BOB")
    print("File Vault (Port 5000) <---> Key Exchange Portal (Port 5001)")
    print("=" * 80)

    suffix = uuid.uuid4().hex[:6]
    alice_name = f"alice_{suffix}"
    bob_name = f"bob_{suffix}"
    password = "CorrectHorseBatteryStaple123!"

    # -------------------------------------------------------------
    # 0. Health Probes
    # -------------------------------------------------------------
    print("\n[Step 0] Probing services connectivity...")
    keyx_client = HttpClient(KEYX_PORTAL_URL)
    status, body, _ = keyx_client.request("GET", "/api/probe/filevault")
    assert status == 200, f"KeyX probe failed: {body.decode()}"
    probe_data = json.loads(body)
    assert probe_data.get("online") is True, f"File Vault reported offline by KeyX: {probe_data}"
    print(f"  [+] KeyX -> File Vault probe successful: {probe_data}")

    # -------------------------------------------------------------
    # 1. Initialize Identities: Bob & Alice on Key Exchange Portal
    # -------------------------------------------------------------
    print("\n[Step 1] Initializing Bob's identity and vault on Key Exchange Portal (Port 5001)...")
    status, body, _ = keyx_client.request("GET", "/api/auth/csrf")
    assert status == 200
    csrf_bob_keyx = json.loads(body)["csrf_token"]

    status, body, _ = keyx_client.request("POST", "/api/auth/register", json_data={
        "username": bob_name,
        "email": f"{bob_name}@keyx.internal",
        "password": password
    }, headers={"X-CSRF-Token": csrf_bob_keyx})
    assert status == 201, f"Bob register on KeyX failed: {body.decode()}"
    bob_keyx_user = json.loads(body)["user"]
    bob_keyx_id = bob_keyx_user["id"]
    csrf_bob_keyx = json.loads(body).get("csrf_token", csrf_bob_keyx)

    # Bob's local keys (generated in browser)
    bob_identity_sk = ed25519.Ed25519PrivateKey.generate()
    bob_identity_pk = bob_identity_sk.public_key()
    bob_identity_pk_hex = bob_identity_pk.public_bytes_raw().hex()
    bob_fp = f"SHA256:{hashlib.sha256(bob_identity_pk.public_bytes_raw()).hexdigest()[:32]}"

    # Publish Bob's identity
    status, body, _ = keyx_client.request("POST", "/api/identities", json_data={
        "ed25519_public_key": bob_identity_pk_hex,
        "fingerprint": bob_fp
    }, headers={"X-CSRF-Token": csrf_bob_keyx})
    assert status in (200, 201), f"Bob identity publish failed: {body.decode()}"
    print(f"  [+] Bob published Ed25519 identity key: {bob_identity_pk_hex[:16]}... (FP: {bob_fp[:24]}...)")

    # -------------------------------------------------------------
    # 2. Publish Bob's signed X25519 prekey pool
    # -------------------------------------------------------------
    print("\n[Step 2] Publishing Bob's signed X25519 prekeys...")
    bob_prekey_sk = x25519.X25519PrivateKey.generate()
    bob_prekey_pk = bob_prekey_sk.public_key()
    bob_prekey_pk_hex = bob_prekey_pk.public_bytes_raw().hex()
    bob_prekey_id = f"prekey_{suffix}_01"

    # Sign prekey public key with Bob's Ed25519 identity key
    prekey_sig = bob_identity_sk.sign(bob_prekey_pk.public_bytes_raw())
    bob_prekey_sig_b64 = base64.b64encode(prekey_sig).decode("ascii")

    status, body, _ = keyx_client.request("POST", "/api/prekeys", json_data={
        "prekey_id": bob_prekey_id,
        "x25519_public_key": bob_prekey_pk_hex,
        "signature": bob_prekey_sig_b64,
        "days_valid": 30
    }, headers={"X-CSRF-Token": csrf_bob_keyx})
    assert status == 201, f"Bob prekey publish failed: {body.decode()}"
    print(f"  [+] Bob published signed X25519 prekey {bob_prekey_id} (Signature: {bob_prekey_sig_b64[:20]}...)")

    # Verify Bob's prekey pool status
    status, body, _ = keyx_client.request("GET", "/api/prekeys/me")
    assert status == 200
    pk_me = json.loads(body)
    assert pk_me["summary"]["available"] >= 1
    assert "stats" in pk_me
    print(f"  [+] Bob prekey telemetry: available={pk_me['summary']['available']}, total={pk_me['summary']['total']}")

    # -------------------------------------------------------------
    # 3. Initialize Alice's Identity & Verify Bob
    # -------------------------------------------------------------
    print("\n[Step 3] Initializing Alice on Key Exchange Portal and verifying Bob...")
    alice_keyx = HttpClient(KEYX_PORTAL_URL)
    status, body, _ = alice_keyx.request("GET", "/api/auth/csrf")
    assert status == 200
    csrf_alice_keyx = json.loads(body)["csrf_token"]

    status, body, _ = alice_keyx.request("POST", "/api/auth/register", json_data={
        "username": alice_name,
        "email": f"{alice_name}@keyx.internal",
        "password": password
    }, headers={"X-CSRF-Token": csrf_alice_keyx})
    assert status == 201, f"Alice register failed: {body.decode()}"
    alice_keyx_user = json.loads(body)["user"]
    alice_keyx_id = alice_keyx_user["id"]
    csrf_alice_keyx = json.loads(body).get("csrf_token", csrf_alice_keyx)

    # Alice's local Ed25519 keys
    alice_identity_sk = ed25519.Ed25519PrivateKey.generate()
    alice_identity_pk = alice_identity_sk.public_key()
    alice_identity_pk_hex = alice_identity_pk.public_bytes_raw().hex()
    alice_fp = f"SHA256:{hashlib.sha256(alice_identity_pk.public_bytes_raw()).hexdigest()[:32]}"

    status, body, _ = alice_keyx.request("POST", "/api/identities", json_data={
        "ed25519_public_key": alice_identity_pk_hex,
        "fingerprint": alice_fp
    }, headers={"X-CSRF-Token": csrf_alice_keyx})
    assert status in (200, 201)
    print(f"  [+] Alice registered and published Ed25519 identity: {alice_identity_pk_hex[:16]}...")

    # Alice adds Bob as a trusted contact
    status, body, _ = alice_keyx.request("POST", "/api/contacts", json_data={
        "username": bob_name
    }, headers={"X-CSRF-Token": csrf_alice_keyx})
    assert status == 201, f"Add contact failed: {body.decode()}"
    contact_data = json.loads(body)["contact"]
    contact_id = contact_data["id"]
    print(f"  [+] Alice added {bob_name} as contact (Status: {contact_data['verification_status']})")

    # Alice verifies Bob's fingerprint out-of-band
    status, body, _ = alice_keyx.request("POST", f"/api/contacts/{contact_id}/verify", json_data={
        "fingerprint": bob_fp
    }, headers={"X-CSRF-Token": csrf_alice_keyx})
    assert status == 200, f"Verify contact failed: {body.decode()}"
    print(f"  [+] Alice verified Bob's fingerprint out-of-band (Status: VERIFIED)")

    # -------------------------------------------------------------
    # 4. Discover Bob's valid public prekey
    # -------------------------------------------------------------
    print("\n[Step 4] Alice discovers Bob's public identity & signed prekey...")
    status, body, _ = alice_keyx.request("GET", f"/api/identities/{bob_name}")
    assert status == 200, f"Discover identity failed: {body.decode()}"
    discovered_id = json.loads(body)
    assert discovered_id["identity"]["ed25519_public_key"] == bob_identity_pk_hex

    status, body, _ = alice_keyx.request("GET", f"/api/prekeys/{bob_name}")
    assert status == 200, f"Discover prekey failed: {body.decode()}"
    discovered_pk = json.loads(body)
    assert discovered_pk["prekey"]["id"] == bob_prekey_id
    assert discovered_pk["prekey"]["x25519_public_key"] == bob_prekey_pk_hex

    # Verify Bob's prekey signature using Bob's published Ed25519 public key
    bob_id_pk_obj = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(discovered_id["identity"]["ed25519_public_key"]))
    prekey_raw_bytes = bytes.fromhex(discovered_pk["prekey"]["x25519_public_key"])
    prekey_sig_bytes = base64.b64decode(discovered_pk["prekey"]["signature"])
    bob_id_pk_obj.verify(prekey_sig_bytes, prekey_raw_bytes)
    print("  [+] Alice verified Bob's prekey signature cryptographically [PASS]")

    # -------------------------------------------------------------
    # 5. Create real file transfer using File Vault (Port 5000)
    # -------------------------------------------------------------
    print("\n[Step 5] Creating real encrypted file transfer on File Vault (Port 5000)...")
    # Register Alice and Bob on File Vault (Port 5000)
    vault_alice = HttpClient(FILE_VAULT_URL)
    status, body, _ = vault_alice.request("GET", "/api/auth/csrf")
    assert status == 200
    csrf_vault_alice = json.loads(body)["csrf_token"]

    status, body, _ = vault_alice.request("POST", "/api/auth/register", json_data={
        "username": alice_name,
        "email": f"{alice_name}@vault.internal",
        "password": password
    }, headers={"X-CSRF-Token": csrf_vault_alice})
    assert status == 201
    alice_vault_id = json.loads(body)["user"]["id"]

    vault_bob = HttpClient(FILE_VAULT_URL)
    status, body, _ = vault_bob.request("GET", "/api/auth/csrf")
    assert status == 200
    csrf_vault_bob = json.loads(body)["csrf_token"]

    status, body, _ = vault_bob.request("POST", "/api/auth/register", json_data={
        "username": bob_name,
        "email": f"{bob_name}@vault.internal",
        "password": password
    }, headers={"X-CSRF-Token": csrf_vault_bob})
    assert status == 201
    bob_vault_id = json.loads(body)["user"]["id"]

    # Alice syncs her public identity to File Vault as well
    status, body, _ = vault_alice.request("POST", "/api/key-exchange/identities", json_data={
        "signing_public_key": alice_identity_pk_hex,
        "fingerprint": alice_fp,
        "x25519_prekey": "00" * 32,
        "prekey_id": "temp_prekey"
    }, headers={"X-CSRF-Token": csrf_vault_alice})
    assert status in (200, 201)

    # Bob syncs his identity bundle to File Vault
    status, body, _ = vault_bob.request("POST", "/api/key-exchange/identities", json_data={
        "signing_public_key": bob_identity_pk_hex,
        "fingerprint": bob_fp,
        "x25519_prekey": bob_prekey_pk_hex,
        "prekey_id": bob_prekey_id
    }, headers={"X-CSRF-Token": csrf_vault_bob})
    assert status in (200, 201)

    # Generate real sample PDF
    pdf_content = b"%PDF-1.4\n%SecureShare Encrypted Contract\n" + (b"CONFIDENTIAL TRANSACTION DATA // DEEP ENCRYPTION\n" * 1500) + b"\n%%EOF"
    pdf_sha256 = hashlib.sha256(pdf_content).hexdigest()
    print(f"  [+] Original file created: {len(pdf_content)} bytes | SHA-256: {pdf_sha256}")

    # Generate raw 256-bit AES file key in Alice's memory
    raw_aes_file_key = AESGCM.generate_key(bit_length=256)
    file_nonce = bytes([i % 256 for i in range(12)])  # 12-byte nonce
    aesgcm = AESGCM(raw_aes_file_key)
    ciphertext_bytes = aesgcm.encrypt(file_nonce, pdf_content, None)

    # Alice uploads ciphertext to File Vault
    status, body, _ = vault_alice.request("POST", "/api/files/upload", data={
        "original_filename": "financial_contract.pdf",
        "mime_type": "application/pdf",
        "original_size": str(len(pdf_content)),
        "nonce": base64.b64encode(file_nonce).decode("ascii")
    }, files={
        "file": ("financial_contract.pdf.enc", BytesIO(ciphertext_bytes), "application/octet-stream")
    }, headers={"X-CSRF-Token": csrf_vault_alice})
    assert status == 201, f"Ciphertext upload failed: {body.decode()}"
    uploaded_file_id = json.loads(body)["file"]["id"]
    print(f"  [+] Ciphertext uploaded to File Vault (File ID: {uploaded_file_id})")

    # Alice creates transfer record
    status, body, _ = vault_alice.request("POST", "/api/transfers", json_data={
        "recipient": bob_name,
        "file_id": uploaded_file_id,
        "expiry_hours": 24
    }, headers={"X-CSRF-Token": csrf_vault_alice})
    assert status == 201, f"Create transfer failed: {body.decode()}"
    transfer_record = json.loads(body)["transfer"]
    transfer_id = transfer_record["id"]
    print(f"  [+] Transfer created! Transfer ID: {transfer_id}")

    # -------------------------------------------------------------
    # 6. Seal protected envelope bound to Transfer ID & Bob
    # -------------------------------------------------------------
    print("\n[Step 6] Alice creates and seals protected envelope for Bob...")
    # Alice generates ephemeral X25519 keypair
    alice_ephemeral_sk = x25519.X25519PrivateKey.generate()
    alice_ephemeral_pk = alice_ephemeral_sk.public_key()
    alice_ephemeral_pk_hex = alice_ephemeral_pk.public_bytes_raw().hex()

    # X25519 DH Agreement: Alice ephemeral sk + Bob prekey pk
    bob_prekey_pk_obj = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(bob_prekey_pk_hex))
    shared_secret = alice_ephemeral_sk.exchange(bob_prekey_pk_obj)

    # HKDF Derivation with exact canonical context
    hkdf_salt = bytes([k % 256 for k in range(32)])
    context_info = f"SecureShare-v1|wrapping-key|{alice_identity_pk_hex.lower()}|{bob_identity_pk_hex.lower()}|{transfer_id}|{bob_prekey_id}".encode("utf-8")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hkdf_salt,
        info=context_info
    )
    wrapping_key = hkdf.derive(shared_secret)

    # Wrap raw AES file key
    wrap_nonce = bytes([(k * 3) % 256 for k in range(12)])
    wrap_aad = f"SecureShare-Envelope-Key-v1|{transfer_id}|{bob_prekey_id}".encode("utf-8")
    wrap_aes = AESGCM(wrapping_key)
    wrapped_file_key_bytes = wrap_aes.encrypt(wrap_nonce, raw_aes_file_key, wrap_aad)

    # Metadata wrapping
    meta_dict = {"filename": "financial_contract.pdf", "size": len(pdf_content)}
    meta_bytes = canonical_json(meta_dict).encode("utf-8")
    meta_nonce = bytes([(k * 7) % 256 for k in range(12)])
    meta_aad = f"SecureShare-Envelope-Meta-v1|{transfer_id}".encode("utf-8")
    wrapped_meta_bytes = wrap_aes.encrypt(meta_nonce, meta_bytes, meta_aad)

    # Envelope object
    unsigned_envelope = {
        "version": 1,
        "transfer_id": transfer_id,
        "recipient_prekey_id": bob_prekey_id,
        "sender_identity_key": alice_identity_pk_hex.lower(),
        "sender_ephemeral_key": alice_ephemeral_pk_hex.lower(),
        "hkdf_salt": base64.b64encode(hkdf_salt).decode("ascii"),
        "wrapped_key_nonce": base64.b64encode(wrap_nonce).decode("ascii"),
        "wrapped_file_key": base64.b64encode(wrapped_file_key_bytes).decode("ascii"),
        "meta_nonce": base64.b64encode(meta_nonce).decode("ascii"),
        "meta_ciphertext": base64.b64encode(wrapped_meta_bytes).decode("ascii")
    }

    # Alice signs canonical JSON with Ed25519 identity key
    canonical_env_str = canonical_json(unsigned_envelope)
    alice_signature = alice_identity_sk.sign(canonical_env_str.encode("utf-8"))
    alice_sig_b64 = base64.b64encode(alice_signature).decode("ascii")

    envelope_payload = dict(unsigned_envelope)
    envelope_payload["signature"] = alice_sig_b64

    # -------------------------------------------------------------
    # 7. Alice dispatches envelope to Key Exchange Portal (Port 5001)
    # -------------------------------------------------------------
    print("\n[Step 7] Alice dispatches envelope to Key Exchange Portal...")
    status, body, _ = alice_keyx.request("POST", "/api/envelopes", json_data={
        "transfer_id": transfer_id,
        "recipient_id": bob_keyx_id,
        "recipient_prekey_id": bob_prekey_id,
        "encrypted_envelope": envelope_payload,
        "sender_signature": alice_sig_b64
    }, headers={"X-CSRF-Token": csrf_alice_keyx})
    assert status == 201, f"Envelope dispatch failed: {body.decode()}"
    print("  [+] Key envelope successfully stored in Key Exchange Portal!")

    # Also submit to File Vault's integration endpoint to verify cross-portal submission
    status, body, _ = vault_alice.request("POST", "/api/key-exchange/envelopes", json_data={
        "transfer_id": transfer_id,
        "sender_id": alice_vault_id,
        "recipient_id": bob_vault_id,
        "envelope": envelope_payload
    }, headers={"X-CSRF-Token": csrf_vault_alice})
    assert status in (200, 201), f"File Vault integration envelope submit failed: {body.decode()}"
    vault_env_id = json.loads(body)["envelope_id"]

    # Attach envelope to File Vault transfer record
    status, body, _ = vault_alice.request("PATCH", f"/api/transfers/{transfer_id}", json_data={
        "envelope_id": vault_env_id
    }, headers={"X-CSRF-Token": csrf_vault_alice})
    assert status == 200, f"Attach envelope to transfer failed: {body.decode()}"
    print("  [+] Key envelope successfully attached to File Vault transfer record via KeyX adapter!")

    # -------------------------------------------------------------
    # 8. Bob checks Inbox & Retrieves Envelope on Port 5001
    # -------------------------------------------------------------
    print("\n[Step 8] Bob checks Inbox on Key Exchange Portal (Port 5001)...")
    status, body, _ = keyx_client.request("GET", "/api/envelopes/inbox")
    assert status == 200
    inbox_items = json.loads(body)["inbox"]
    assert len(inbox_items) >= 1
    target_env_rec = next((item for item in inbox_items if item["transfer_id"] == transfer_id), None)
    assert target_env_rec is not None, "Target envelope not found in Bob's inbox!"
    print(f"  [+] Found envelope in Bob's inbox: Sender={target_env_rec['sender_username']}, Prekey={target_env_rec['recipient_prekey_id']}")

    status, body, _ = keyx_client.request("GET", f"/api/envelopes/{transfer_id}")
    assert status == 200
    retrieved_env_data = json.loads(body)["envelope"]

    # -------------------------------------------------------------
    # 9. Bob verifies Alice's digital signature
    # -------------------------------------------------------------
    print("\n[Step 9] Bob cryptographically verifies Alice's Ed25519 digital signature...")
    env_content = json.loads(retrieved_env_data["encrypted_envelope"]) if isinstance(retrieved_env_data["encrypted_envelope"], str) else retrieved_env_data["encrypted_envelope"]
    sig_to_verify = retrieved_env_data.get("sender_signature") or env_content.get("signature")

    unsigned_check = dict(env_content)
    unsigned_check.pop("signature", None)
    canonical_check_str = canonical_json(unsigned_check)

    alice_id_pk_obj = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(env_content["sender_identity_key"]))
    alice_id_pk_obj.verify(base64.b64decode(sig_to_verify), canonical_check_str.encode("utf-8"))
    print("  [+] Alice's Ed25519 digital signature verified authentic! [PASS]")

    # -------------------------------------------------------------
    # 10. Bob recovers AES file key using Bob's local private prekey
    # -------------------------------------------------------------
    print("\n[Step 10] Bob unwrap the 256-bit AES file key using local private prekey...")
    ephemeral_pk_obj = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(env_content["sender_ephemeral_key"]))
    # Bob computes shared secret: Bob private prekey + Alice ephemeral public key
    bob_shared_secret = bob_prekey_sk.exchange(ephemeral_pk_obj)
    assert bob_shared_secret == shared_secret, "ECDH shared secret mismatch between Alice and Bob!"

    bob_context_info = f"SecureShare-v1|wrapping-key|{env_content['sender_identity_key'].lower()}|{bob_identity_pk_hex.lower()}|{transfer_id}|{env_content['recipient_prekey_id']}".encode("utf-8")
    bob_hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base64.b64decode(env_content["hkdf_salt"]),
        info=bob_context_info
    )
    bob_wrapping_key = bob_hkdf.derive(bob_shared_secret)
    assert bob_wrapping_key == wrapping_key, "Wrapping key derivation mismatch!"

    bob_wrap_aes = AESGCM(bob_wrapping_key)
    bob_wrap_nonce = base64.b64decode(env_content["wrapped_key_nonce"])
    bob_wrap_aad = f"SecureShare-Envelope-Key-v1|{transfer_id}|{env_content['recipient_prekey_id']}".encode("utf-8")
    recovered_aes_key = bob_wrap_aes.decrypt(bob_wrap_nonce, base64.b64decode(env_content["wrapped_file_key"]), bob_wrap_aad)

    assert recovered_aes_key == raw_aes_file_key, "Recovered AES key does not match original AES file key!"
    print(f"  [+] 256-bit AES file key successfully recovered in Bob's browser: {recovered_aes_key.hex()[:16]}... [PASS]")

    # Bob marks envelope as ACCEPTED
    status, body, _ = keyx_client.request("POST", f"/api/envelopes/{transfer_id}/accept", headers={"X-CSRF-Token": csrf_bob_keyx})
    assert status == 200

    # -------------------------------------------------------------
    # 11 & 12. Bob decrypts file in File Vault & verifies SHA-256
    # -------------------------------------------------------------
    print("\n[Step 11 & 12] Bob retrieves ciphertext from File Vault (Port 5000) and decrypts in browser...")
    status, dl_ciphertext, dl_headers = vault_bob.request("GET", f"/api/transfers/{transfer_id}/download")
    assert status == 200, f"Download ciphertext failed: {dl_ciphertext[:200]}"
    dl_nonce = base64.b64decode(dl_headers["X-Encryption-Nonce"])

    bob_file_aes = AESGCM(recovered_aes_key)
    decrypted_pdf_bytes = bob_file_aes.decrypt(dl_nonce, dl_ciphertext, None)
    decrypted_sha256 = hashlib.sha256(decrypted_pdf_bytes).hexdigest()

    assert decrypted_pdf_bytes == pdf_content, "Decrypted content does not match original file!"
    assert decrypted_sha256 == pdf_sha256, "Decrypted SHA-256 checksum mismatch!"
    print(f"  [+] Byte-for-byte SHA-256 match verified: {decrypted_sha256} == {pdf_sha256} [PASS]")

    # -------------------------------------------------------------
    # 13. Test Edge Cases & Negative Scenarios
    # -------------------------------------------------------------
    print("\n[Step 13] Testing Negative Edge Cases & Defensive Measures...")

    # Edge Case A: Prekey consumed cannot be consumed again
    print("  [A] Prekey consumption verification...")
    # Attempt to discover Bob's prekey again
    status, body, _ = alice_keyx.request("GET", f"/api/prekeys/{bob_name}")
    assert status == 404, "Consumed prekey was improperly served again!"
    assert json.loads(body).get("code") == "NO_PREKEYS_AVAILABLE"
    print("      -> Consumed prekey successfully purged from available pool [PASS]")

    # Edge Case B: Replay / duplicate transfer_id rejection
    print("  [B] Duplicate Transfer ID rejection...")
    status, body, _ = alice_keyx.request("POST", "/api/envelopes", json_data={
        "transfer_id": transfer_id,
        "recipient_id": bob_keyx_id,
        "recipient_prekey_id": "different_prekey",
        "encrypted_envelope": envelope_payload,
        "sender_signature": alice_sig_b64
    }, headers={"X-CSRF-Token": csrf_alice_keyx})
    assert status == 409, f"Duplicate transfer ID should return 409, got {status}"
    print("      -> Duplicate Transfer ID correctly rejected with 409 [PASS]")

    # Edge Case C: Unauthorized envelope retrieval
    print("  [C] Unauthorized access control...")
    mallory_client = HttpClient(KEYX_PORTAL_URL)
    status, body, _ = mallory_client.request("GET", "/api/auth/csrf")
    csrf_mallory = json.loads(body)["csrf_token"]
    status, body, _ = mallory_client.request("POST", "/api/auth/register", json_data={
        "username": f"mallory_{suffix}",
        "email": f"mallory_{suffix}@keyx.internal",
        "password": password
    }, headers={"X-CSRF-Token": csrf_mallory})
    assert status == 201

    status, body, _ = mallory_client.request("GET", f"/api/envelopes/{transfer_id}")
    assert status == 403, f"Mallory access should be forbidden, got {status}"
    print("      -> Third-party actor access to key envelope rejected with 403 [PASS]")

    # Edge Case D: Tampered Ed25519 signature
    print("  [D] Tampered signature detection...")
    tampered_sig = bytearray(base64.b64decode(alice_sig_b64))
    tampered_sig[0] ^= 0xFF
    threw_on_sig = False
    try:
        alice_id_pk_obj.verify(bytes(tampered_sig), canonical_check_str.encode("utf-8"))
    except Exception:
        threw_on_sig = True
    assert threw_on_sig, "Tampered signature was not rejected!"
    print("      -> Tampered Ed25519 signature fails verification [PASS]")

    # Edge Case E: Tampered Ciphertext Authentication Tag
    print("  [E] AES-GCM Authentication Tag tampering detection...")
    tampered_ct = bytearray(dl_ciphertext)
    tampered_ct[15] ^= 0xFF
    threw_on_tag = False
    try:
        bob_file_aes.decrypt(dl_nonce, bytes(tampered_ct), None)
    except Exception:
        threw_on_tag = True
    assert threw_on_tag, "Tampered ciphertext did not fail authentication!"
    print("      -> AES-GCM authentication tag verifies integrity and rejects tampering [PASS]")

    # Edge Case F: Wrong recipient lookup
    print("  [F] Non-existent recipient discovery...")
    status, body, _ = alice_keyx.request("GET", "/api/identities/non_existent_ghost_user_999")
    assert status == 404
    print("      -> Non-existent recipient correctly returns 404 [PASS]")

    print("\n" + "=" * 80)
    print("ALL 12 WORKFLOW STEPS + ALL 6 EDGE CASES PASSED WITH 100% SUCCESS!")
    print("=" * 80)

if __name__ == "__main__":
    test_complete_e2e_flow()
