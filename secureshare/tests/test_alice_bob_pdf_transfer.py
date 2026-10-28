import json
import uuid
import hashlib
import urllib.request
import http.cookiejar
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

FILE_VAULT_URL = "http://127.0.0.1:5000"
KEYX_PORTAL_URL = "http://127.0.0.1:5001"

def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'))

class HttpClient:
    def __init__(self, base_url=FILE_VAULT_URL):
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

def run_pdf_transfer_test():
    print("=" * 70)
    print("REAL TWO-USER E2E FILE TRANSFER TEST: ALICE -> BOB (SAMPLE PDF)")
    print("=" * 70)

    # 1. Generate real sample PDF bytes (128 KB simulated PDF structure)
    pdf_header = b"%PDF-1.4\n%Binary Header\n"
    pdf_body = b"CONFIDENTIAL SETTLEMENT AGREEMENT // SECURESHARE\n" * 2500
    pdf_trailer = b"\nxref\n0 5\ntrailer\n<< /Root 1 0 R >>\nstartxref\n%%EOF\n"
    original_pdf_bytes = pdf_header + pdf_body + pdf_trailer
    original_sha256 = hashlib.sha256(original_pdf_bytes).hexdigest()
    print(f"[+] Created original sample PDF: {len(original_pdf_bytes)} bytes | SHA-256: {original_sha256}")

    # Unique test usernames
    suffix = uuid.uuid4().hex[:6]
    alice_name = f"alice_user_{suffix}"
    bob_name = f"bob_user_{suffix}"
    password = "CorrectHorseBatteryStaple123!"

    # 2. Bob registers on Key Exchange Portal (Port 5001) & publishes prekey
    bob_keyx = HttpClient(KEYX_PORTAL_URL)
    status, body, _ = bob_keyx.request("GET", "/api/auth/csrf")
    assert status == 200
    csrf_keyx = json.loads(body)["csrf_token"]

    status, body, _ = bob_keyx.request("POST", "/api/auth/register", json_data={
        "username": bob_name,
        "email": f"{bob_name}@test.portal",
        "password": password
    }, headers={"X-CSRF-Token": csrf_keyx})
    assert status == 201, f"Bob KeyX register failed: {body.decode()}"
    bob_keyx_id = json.loads(body)["user"]["id"]
    csrf_keyx = json.loads(body).get("csrf_token", csrf_keyx)

    # Bob's private cryptographic keys (stored locally in his device keystore)
    bob_identity_sk = ed25519.Ed25519PrivateKey.generate()
    bob_identity_pk_hex = bob_identity_sk.public_key().public_bytes_raw().hex()
    bob_prekey_sk = x25519.X25519PrivateKey.generate()
    bob_prekey_pk_hex = bob_prekey_sk.public_key().public_bytes_raw().hex()
    bob_prekey_id = f"prekey_{suffix}"
    bob_fp = f"F0:F1:{suffix[:2]}:{suffix[2:4]}:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55"

    # Bob publishes Identity on Port 5001
    status, body, _ = bob_keyx.request("POST", "/api/identities", json_data={
        "ed25519_public_key": bob_identity_pk_hex,
        "fingerprint": bob_fp
    }, headers={"X-CSRF-Token": csrf_keyx})
    assert status in (200, 201)

    # Bob publishes Signed Prekey on Port 5001
    prekey_sig = bob_identity_sk.sign(bytes.fromhex(bob_prekey_pk_hex))
    status, body, _ = bob_keyx.request("POST", "/api/prekeys", json_data={
        "x25519_public_key": bob_prekey_pk_hex,
        "signature": b64encode(prekey_sig).decode("utf-8"),
        "prekey_id": bob_prekey_id
    }, headers={"X-CSRF-Token": csrf_keyx})
    assert status in (200, 201)
    print(f"[PASS] Bob registered on Key Exchange Portal (Port 5001) with Prekey ID: {bob_prekey_id}")

    # Register Bob on File Vault (Port 5000)
    bob_init_client = HttpClient(FILE_VAULT_URL)
    status, body, _ = bob_init_client.request("GET", "/api/auth/csrf")
    assert status == 200
    csrf_bob_reg = json.loads(body)["csrf_token"]
    status, body, _ = bob_init_client.request("POST", "/api/auth/register", json_data={
        "username": bob_name,
        "email": f"{bob_name}@vault.local",
        "password": password
    }, headers={"X-CSRF-Token": csrf_bob_reg})
    assert status == 201, f"Bob Vault register failed: {body.decode()}"
    bob_vault_id = json.loads(body)["user"]["id"]
    csrf_bob_reg = json.loads(body).get("csrf_token", csrf_bob_reg)
    status, body, _ = bob_init_client.request("POST", "/api/key-exchange/identities", json_data={
        "signing_public_key": bob_identity_pk_hex,
        "x25519_prekey": bob_prekey_pk_hex,
        "fingerprint": bob_fp,
        "prekey_id": bob_prekey_id
    }, headers={"X-CSRF-Token": csrf_bob_reg})
    assert status == 200
    print(f"[PASS] Bob registered on File Vault (Port 5000)")

    # 3. Register Alice and Bob on File Vault (Port 5000)
    alice_client = HttpClient(FILE_VAULT_URL)
    status, body, _ = alice_client.request("GET", "/api/auth/csrf")
    assert status == 200
    csrf_alice = json.loads(body)["csrf_token"]

    status, body, _ = alice_client.request("POST", "/api/auth/register", json_data={
        "username": alice_name,
        "email": f"{alice_name}@vault.local",
        "password": password
    }, headers={"X-CSRF-Token": csrf_alice})
    assert status == 201, f"Alice register failed: {body.decode()}"
    alice_vault_id = json.loads(body)["user"]["id"]
    csrf_alice = json.loads(body).get("csrf_token", csrf_alice)

    # Alice publishes her identity on File Vault
    alice_identity_sk = ed25519.Ed25519PrivateKey.generate()
    alice_identity_pk_hex = alice_identity_sk.public_key().public_bytes_raw().hex()
    alice_prekey_sk = x25519.X25519PrivateKey.generate()
    alice_prekey_pk_hex = alice_prekey_sk.public_key().public_bytes_raw().hex()
    alice_fp = f"A1:A2:{suffix[:2]}:{suffix[2:4]}:11:22:33:44:55:66:77:88:99:00:11:22"

    status, body, _ = alice_client.request("POST", "/api/key-exchange/identities", json_data={
        "signing_public_key": alice_identity_pk_hex,
        "x25519_prekey": alice_prekey_pk_hex,
        "fingerprint": alice_fp,
        "prekey_id": f"alice_pre_{suffix}"
    }, headers={"X-CSRF-Token": csrf_alice})
    assert status == 200
    print(f"[PASS] Alice registered on File Vault (Port 5000)")

    # 4. Alice discovers Bob's prekey bundle from Key Exchange Portal
    status, body, _ = alice_client.request("GET", f"/api/key-exchange/identities/{bob_name}")
    assert status == 200, f"Alice lookup of Bob failed: {body.decode()}"
    bob_discovered = json.loads(body)
    assert bob_discovered["x25519_prekey"] == bob_prekey_pk_hex
    assert bob_discovered["prekey_id"] == bob_prekey_id
    print(f"[PASS] Alice discovered Bob's prekey bundle from Port 5001")

    # 5. Alice generates random AES-256 file key & encrypts PDF locally
    raw_aes_key = AESGCM.generate_key(bit_length=256)
    file_nonce = b"\x10\x20\x30\x40\x50\x60\x70\x80\x90\xA0\xB0\xC0" # 12 bytes
    aesgcm = AESGCM(raw_aes_key)
    ciphertext_bytes = aesgcm.encrypt(file_nonce, original_pdf_bytes, None)
    print(f"[PASS] Alice encrypted PDF with AES-256-GCM locally ({len(ciphertext_bytes)} bytes)")

    # 6. Alice uploads ciphertext ONLY to File Vault backend
    import io
    status, body, _ = alice_client.request("POST", "/api/files/upload", data={
        "nonce": b64encode(file_nonce).decode("utf-8"),
        "algorithm": "AES-256-GCM"
    }, files={
        "file": ("contract.enc", io.BytesIO(ciphertext_bytes), "application/octet-stream")
    }, headers={"X-CSRF-Token": csrf_alice})
    assert status == 201, f"Ciphertext upload failed: {body.decode()}"
    file_record_id = json.loads(body)["file"]["id"]

    # 7. Alice creates transfer record to obtain real Transfer ID UUID
    status, body, _ = alice_client.request("POST", "/api/transfers", json_data={
        "recipient": bob_name,
        "file_id": file_record_id,
        "expires_in_hours": 24
    }, headers={"X-CSRF-Token": csrf_alice})
    assert status == 201, f"Create transfer failed: {body.decode()}"
    transfer_record = json.loads(body)["transfer"]
    real_transfer_id = transfer_record["id"]
    print(f"[PASS] Transfer created with real UUID: {real_transfer_id}")

    # 8. Alice creates protected key envelope bound to real UUID & Bob's prekey
    alice_ephemeral_sk = x25519.X25519PrivateKey.generate()
    alice_ephemeral_pk_bytes = alice_ephemeral_sk.public_key().public_bytes_raw()
    alice_ephemeral_pk_hex = alice_ephemeral_pk_bytes.hex()

    bob_pre_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(bob_prekey_pk_hex))
    shared_secret = alice_ephemeral_sk.exchange(bob_pre_pub)
    hkdf_salt = b"\x01" * 32
    context_info = f"SecureShare-v1|wrapping-key|{alice_identity_pk_hex.lower()}|{bob_identity_pk_hex.lower()}|{real_transfer_id}|{bob_prekey_id}".encode("utf-8")
    wrapping_key_bytes = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hkdf_salt,
        info=context_info
    ).derive(shared_secret)

    # Wrap raw AES key
    wrap_cipher = AESGCM(wrapping_key_bytes)
    key_nonce = b"\xaa" * 12
    key_aad = f"SecureShare-Envelope-Key-v1|{real_transfer_id}|{bob_prekey_id}".encode("utf-8")
    wrapped_file_key = wrap_cipher.encrypt(key_nonce, raw_aes_key, key_aad)

    # Wrap metadata
    file_metadata = {
        "filename": "sample_confidential_contract.pdf",
        "size": len(original_pdf_bytes),
        "mimeType": "application/pdf"
    }
    meta_nonce = b"\xbb" * 12
    meta_aad = f"SecureShare-Envelope-Meta-v1|{real_transfer_id}".encode("utf-8")
    wrapped_meta = wrap_cipher.encrypt(meta_nonce, canonical_json(file_metadata).encode("utf-8"), meta_aad)

    unsigned_envelope = {
        "version": 1,
        "transfer_id": real_transfer_id,
        "recipient_prekey_id": bob_prekey_id,
        "sender_identity_key": alice_identity_pk_hex.lower(),
        "sender_ephemeral_key": alice_ephemeral_pk_hex.lower(),
        "hkdf_salt": b64encode(hkdf_salt).decode("utf-8"),
        "wrapped_key_nonce": b64encode(key_nonce).decode("utf-8"),
        "wrapped_file_key": b64encode(wrapped_file_key).decode("utf-8"),
        "meta_nonce": b64encode(meta_nonce).decode("utf-8"),
        "meta_ciphertext": b64encode(wrapped_meta).decode("utf-8")
    }

    # Alice signs canonical envelope with Ed25519
    canonical_env_bytes = canonical_json(unsigned_envelope).encode("utf-8")
    envelope_signature = alice_identity_sk.sign(canonical_env_bytes)
    unsigned_envelope["signature"] = b64encode(envelope_signature).decode("utf-8")
    full_envelope = unsigned_envelope

    # 9. Alice submits envelope to Key Exchange Portal via adapter
    status, body, _ = alice_client.request("POST", "/api/key-exchange/envelopes", json_data={
        "transfer_id": real_transfer_id,
        "sender_id": alice_vault_id,
        "recipient_id": bob_discovered["recipient_id"],
        "envelope": full_envelope
    }, headers={"X-CSRF-Token": csrf_alice})
    assert status == 201, f"Envelope submit failed: {body.decode()}"
    envelope_id = json.loads(body)["envelope_id"]

    # Alice attaches envelope to transfer
    status, body, _ = alice_client.request("PATCH", f"/api/transfers/{real_transfer_id}", json_data={
        "envelope_id": envelope_id
    }, headers={"X-CSRF-Token": csrf_alice})
    assert status == 200, f"Attach envelope failed: {body.decode()}"
    print(f"[PASS] Key envelope submitted to Key Exchange Portal and attached to transfer")

    # =========================================================================
    # 10. RECIPIENT DECRYPTION WORKFLOW (BOB'S SEPARATE BROWSER CONTEXT)
    # =========================================================================
    bob_vault_client = HttpClient(FILE_VAULT_URL)
    status, body, _ = bob_vault_client.request("GET", "/api/auth/csrf")
    assert status == 200
    csrf_bob = json.loads(body)["csrf_token"]

    status, body, _ = bob_vault_client.request("POST", "/api/auth/login", json_data={
        "identifier": bob_name,
        "password": password
    }, headers={"X-CSRF-Token": csrf_bob})
    assert status == 200, f"Bob Vault login failed: {body.decode()}"
    csrf_bob = json.loads(body).get("csrf_token", csrf_bob)

    # Bob inspects transfer metadata
    status, body, _ = bob_vault_client.request("GET", f"/api/transfers/{real_transfer_id}")
    assert status == 200
    bob_tx_info = json.loads(body)["transfer"]
    assert bob_tx_info["recipient_username"] == bob_name
    print(f"[PASS] Bob inspected transfer record: addressed to {bob_tx_info['recipient_username']}, size {bob_tx_info['encrypted_size']} bytes")

    # Bob retrieves key envelope from Key Exchange Portal via adapter
    status, body, _ = bob_vault_client.request("GET", f"/api/key-exchange/envelopes/{real_transfer_id}")
    assert status == 200, f"Bob envelope retrieval failed: {body.decode()}"
    bob_retrieved_env = json.loads(body)["envelope"]
    assert bob_retrieved_env["transfer_id"] == real_transfer_id
    print(f"[PASS] Bob retrieved key envelope bound to transfer UUID {real_transfer_id}")

    # Bob verifies Alice's Ed25519 digital signature
    env_sig = b64decode(bob_retrieved_env["signature"])
    unsigned_copy = dict(bob_retrieved_env)
    del unsigned_copy["signature"]
    alice_ed_pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(bob_retrieved_env["sender_identity_key"]))
    alice_ed_pk.verify(env_sig, canonical_json(unsigned_copy).encode("utf-8"))
    print(f"[PASS] Bob verified Alice's Ed25519 digital signature successfully")

    # Bob derives wrapping key using his private X25519 prekey
    alice_eph_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(bob_retrieved_env["sender_ephemeral_key"]))
    bob_shared_secret = bob_prekey_sk.exchange(alice_eph_pub)
    bob_wrapping_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b64decode(bob_retrieved_env["hkdf_salt"]),
        info=context_info
    ).derive(bob_shared_secret)

    # Bob unwraps raw AES file key
    bob_wrap_cipher = AESGCM(bob_wrapping_key)
    bob_recovered_aes_key = bob_wrap_cipher.decrypt(
        b64decode(bob_retrieved_env["wrapped_key_nonce"]),
        b64decode(bob_retrieved_env["wrapped_file_key"]),
        key_aad
    )
    assert bob_recovered_aes_key == raw_aes_key, "Recovered AES key mismatch!"
    print(f"[PASS] Bob unwrapped 256-bit AES file key in browser memory")

    # Bob downloads ciphertext
    status, body, headers = bob_vault_client.request("GET", f"/api/transfers/{real_transfer_id}/download")
    assert status == 200
    retrieved_ciphertext = body
    retrieved_nonce = b64decode(headers["X-Encryption-Nonce"])
    print(f"[PASS] Bob downloaded ciphertext ({len(retrieved_ciphertext)} bytes)")

    # Bob decrypts ciphertext with AES-256-GCM & verifies 128-bit authentication tag
    bob_file_cipher = AESGCM(bob_recovered_aes_key)
    decrypted_pdf_bytes = bob_file_cipher.decrypt(retrieved_nonce, retrieved_ciphertext, None)
    decrypted_sha256 = hashlib.sha256(decrypted_pdf_bytes).hexdigest()
    print(f"[PASS] Bob decrypted PDF locally: {len(decrypted_pdf_bytes)} bytes | SHA-256: {decrypted_sha256}")

    # Bit-for-bit check
    assert decrypted_pdf_bytes == original_pdf_bytes, "Decrypted bytes do not match original PDF!"
    assert decrypted_sha256 == original_sha256, "SHA-256 checksum mismatch!"
    print("\n" + "=" * 70)
    print("SUCCESS: 100% BIT-FOR-BIT IDENTICAL PDF TRANSFERRED AND DECRYPTED!")
    print("=" * 70)

if __name__ == "__main__":
    run_pdf_transfer_test()
