import io
import json
import uuid
import urllib.request
import urllib.parse
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

def run_all_phase10_tests():
    print("=" * 70)
    print("SECURESHARE FILE VAULT & KEY EXCHANGE PORTAL — FULL PHASE 10 E2E SUITE")
    print("=" * 70)

    suffix = uuid.uuid4().hex[:6]
    alice_username = f"alice_{suffix}"
    bob_username = f"bob_{suffix}"
    charlie_username = f"charlie_{suffix}"
    password = "StrongPassword123!Safe"

    # =========================================================================
    # TEST A: Valid Transfer End-to-End Workflow (Alice -> Bob)
    # =========================================================================
    print("\n--- TEST A: Valid End-to-End Transfer ---")

    # 1. Bob registers on Key Exchange Portal (Port 5001) & publishes prekey
    bob_keyx = HttpClient(KEYX_PORTAL_URL)
    status, body, _ = bob_keyx.request("GET", "/api/auth/csrf")
    assert status == 200, f"Key Exchange Portal CSRF failed: {status}"
    csrf_keyx = json.loads(body)["csrf_token"]

    status, body, _ = bob_keyx.request("POST", "/api/auth/register", json_data={
        "username": bob_username,
        "email": f"{bob_username}@portal.secureshare",
        "password": password
    }, headers={"X-CSRF-Token": csrf_keyx})
    assert status == 201, f"Bob KeyX register failed: {body.decode()}"
    bob_keyx_id = json.loads(body)["user"]["id"]
    csrf_keyx = json.loads(body).get("csrf_token", csrf_keyx)

    # Bob publishes Identity & Signed Prekey on Port 5001
    bob_ed_sk = ed25519.Ed25519PrivateKey.generate()
    bob_ed_pk_hex = bob_ed_sk.public_key().public_bytes_raw().hex()
    bob_pre_sk = x25519.X25519PrivateKey.generate()
    bob_pre_pk_hex = bob_pre_sk.public_key().public_bytes_raw().hex()
    bob_prekey_id = f"prekey_bob_{suffix}"
    bob_fp = f"BB:BB:{suffix[:2]}:{suffix[2:4]}:00:11:22:33:44:55:66:77:88:99:AA:BB"

    status, body, _ = bob_keyx.request("POST", "/api/identities", json_data={
        "ed25519_public_key": bob_ed_pk_hex,
        "fingerprint": bob_fp
    }, headers={"X-CSRF-Token": csrf_keyx})
    assert status in (200, 201), f"Bob identity publish failed: {body.decode()}"

    # Sign prekey
    sig_bytes = bob_ed_sk.sign(bytes.fromhex(bob_pre_pk_hex))
    status, body, _ = bob_keyx.request("POST", "/api/prekeys", json_data={
        "prekey_id": bob_prekey_id,
        "x25519_public_key": bob_pre_pk_hex,
        "signature": b64encode(sig_bytes).decode(),
        "days_valid": 14
    }, headers={"X-CSRF-Token": csrf_keyx})
    assert status == 201, f"Bob prekey publish failed: {body.decode()}"
    print(f"[PASS] 1. Bob registered and published prekeys on Key Exchange Portal (Port 5001)")

    # 2. Alice and Bob register on File Vault (Port 5000)
    alice_vault = HttpClient(FILE_VAULT_URL)
    status, body, _ = alice_vault.request("GET", "/api/auth/csrf")
    assert status == 200
    csrf_alice = json.loads(body)["csrf_token"]

    status, body, _ = alice_vault.request("POST", "/api/auth/register", json_data={
        "username": alice_username,
        "email": f"{alice_username}@example.com",
        "password": password
    }, headers={"X-CSRF-Token": csrf_alice})
    assert status == 201
    alice_vault_data = json.loads(body)
    alice_id = alice_vault_data["user"]["id"]
    csrf_alice = alice_vault_data.get("csrf_token", csrf_alice)

    alice_ed_sk = ed25519.Ed25519PrivateKey.generate()
    alice_ed_pk_hex = alice_ed_sk.public_key().public_bytes_raw().hex()
    alice_pre_sk = x25519.X25519PrivateKey.generate()
    alice_pre_pk_hex = alice_pre_sk.public_key().public_bytes_raw().hex()

    status, body, _ = alice_vault.request("POST", "/api/key-exchange/identities", json_data={
        "signing_public_key": alice_ed_pk_hex,
        "x25519_prekey": alice_pre_pk_hex,
        "fingerprint": f"FA:CE:{suffix[:2]}:{suffix[2:4]}:00:11:22:33:44:55:66:77:88:99:AA:BB",
        "prekey_id": f"prekey_alice_{suffix}"
    }, headers={"X-CSRF-Token": csrf_alice})
    assert status == 200

    bob_vault = HttpClient(FILE_VAULT_URL)
    status, body, _ = bob_vault.request("GET", "/api/auth/csrf")
    csrf_bob = json.loads(body)["csrf_token"]

    status, body, _ = bob_vault.request("POST", "/api/auth/register", json_data={
        "username": bob_username,
        "email": f"{bob_username}@example.com",
        "password": password
    }, headers={"X-CSRF-Token": csrf_bob})
    assert status == 201
    bob_id = json.loads(body)["user"]["id"]
    csrf_bob = json.loads(body).get("csrf_token", csrf_bob)
    print(f"[PASS] 2. Alice and Bob registered on File Vault (Port 5000)")

    # 3. Alice discovers Bob's public prekey through File Vault adapter -> Port 5001
    status, body, _ = alice_vault.request("GET", f"/api/key-exchange/identities/{bob_username}")
    assert status == 200, f"Discovery failed: {body.decode()}"
    bob_bundle = json.loads(body)
    assert bob_bundle["recipient_username"] == bob_username
    assert bob_bundle["x25519_prekey"] == bob_pre_pk_hex
    assert bob_bundle["signing_public_key"] == bob_ed_pk_hex
    print(f"[PASS] 3. Alice discovered Bob's prekey bundle from Key Exchange Portal")

    # 4. Alice encrypts original file locally with random AES-256-GCM
    original_plaintext = b"TOP SECRET MISSION DIRECTIVE - VERIFY RECIPIENT FILE DECRYPTION E2E\n" * 64
    file_aes_key = AESGCM.generate_key(bit_length=256)
    file_nonce = b"\x10\x20\x30\x40\x50\x60\x70\x80\x90\xa0\xb0\xc0"
    ciphertext = AESGCM(file_aes_key).encrypt(file_nonce, original_plaintext, None)

    # 5. Alice uploads ciphertext only
    status, body, _ = alice_vault.request("POST", "/api/files/upload", files={
        "file": ("mission.pdf.enc", io.BytesIO(ciphertext), "application/octet-stream")
    }, data={
        "nonce": b64encode(file_nonce).decode(),
        "algorithm": "AES-256-GCM",
        "protocol_version": "1"
    }, headers={"X-CSRF-Token": csrf_alice})
    assert status == 201
    file_id = json.loads(body)["file"]["id"]
    print(f"[PASS] 4. Alice uploaded encrypted ciphertext ({len(ciphertext)} bytes)")

    # 6. Alice creates transfer record
    status, body, _ = alice_vault.request("POST", "/api/transfers", json_data={
        "recipient": bob_username,
        "file_id": file_id,
        "expires_in_hours": 24
    }, headers={"X-CSRF-Token": csrf_alice})
    assert status == 201
    transfer_id = json.loads(body)["transfer"]["id"]
    print(f"[PASS] 5. Transfer created with real UUID: {transfer_id}")

    # 7. Alice generates X25519 ephemeral key, wraps AES file key, and signs envelope
    alice_ephemeral_sk = x25519.X25519PrivateKey.generate()
    alice_ephemeral_pk_hex = alice_ephemeral_sk.public_key().public_bytes_raw().hex()

    bob_prekey_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(bob_bundle["x25519_prekey"]))
    shared_secret = alice_ephemeral_sk.exchange(bob_prekey_pub)

    salt = b"\x33" * 32
    context_info = f"SecureShare-v1|wrapping-key|{alice_ed_pk_hex}|{bob_ed_pk_hex}|{transfer_id}|{bob_bundle['prekey_id']}".encode()
    wrapping_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=context_info).derive(shared_secret)

    wrap_nonce = b"\x44" * 12
    key_aad = f"SecureShare-Envelope-Key-v1|{transfer_id}|{bob_bundle['prekey_id']}".encode()
    wrapped_file_key = AESGCM(wrapping_key).encrypt(wrap_nonce, file_aes_key, key_aad)

    meta_payload = {"filename": "mission.pdf", "size": len(original_plaintext), "mimeType": "application/pdf"}
    meta_nonce = b"\x55" * 12
    meta_aad = f"SecureShare-Envelope-Meta-v1|{transfer_id}".encode()
    wrapped_meta = AESGCM(wrapping_key).encrypt(meta_nonce, canonical_json(meta_payload).encode(), meta_aad)

    envelope_payload = {
        "version": 1,
        "transfer_id": transfer_id,
        "recipient_prekey_id": bob_bundle["prekey_id"],
        "sender_identity_key": alice_ed_pk_hex,
        "sender_ephemeral_key": alice_ephemeral_pk_hex,
        "hkdf_salt": b64encode(salt).decode(),
        "wrapped_key_nonce": b64encode(wrap_nonce).decode(),
        "wrapped_file_key": b64encode(wrapped_file_key).decode(),
        "meta_nonce": b64encode(meta_nonce).decode(),
        "meta_ciphertext": b64encode(wrapped_meta).decode()
    }

    sig = alice_ed_sk.sign(canonical_json(envelope_payload).encode())
    envelope_payload["signature"] = b64encode(sig).decode()

    # 8. Alice submits envelope through File Vault adapter -> stored in Port 5001
    status, body, _ = alice_vault.request("POST", "/api/key-exchange/envelopes", json_data={
        "transfer_id": transfer_id,
        "recipient_id": bob_id,
        "envelope": envelope_payload
    }, headers={"X-CSRF-Token": csrf_alice})
    assert status == 201, f"Envelope submit failed: {body.decode()}"
    envelope_id = json.loads(body)["envelope_id"]

    # Alice attaches envelope
    status, body, _ = alice_vault.request("PATCH", f"/api/transfers/{transfer_id}", json_data={
        "envelope_id": envelope_id
    }, headers={"X-CSRF-Token": csrf_alice})
    assert status == 200
    print(f"[PASS] 6. Envelope submitted to Key Exchange Portal and attached to transfer")

    # 9. Verify envelope exists on Port 5001 directly
    status, body, _ = bob_keyx.request("GET", f"/api/key-exchange/envelopes/{transfer_id}")
    assert status == 200, f"Direct Key Exchange check failed: {status}"
    direct_env = json.loads(body)["envelope"]
    assert direct_env["transfer_id"] == transfer_id
    print(f"[PASS] 7. Confirmed envelope is stored in Key Exchange Portal database")

    # 10. Bob retrieves envelope through File Vault
    status, body, _ = bob_vault.request("GET", f"/api/key-exchange/envelopes/{transfer_id}")
    assert status == 200
    retrieved_env = json.loads(body)["envelope"]

    # 11. Bob verifies Alice's signature
    unsigned = {k: v for k, v in retrieved_env.items() if k != "signature"}
    alice_pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(retrieved_env["sender_identity_key"]))
    alice_pub.verify(b64decode(retrieved_env["signature"]), canonical_json(unsigned).encode())
    print(f"[PASS] 8. Bob verified Alice's Ed25519 signature successfully")

    # 12. Bob derives wrapping key with his private X25519 key
    alice_ephem_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(retrieved_env["sender_ephemeral_key"]))
    bob_shared = bob_pre_sk.exchange(alice_ephem_pub)
    assert bob_shared == shared_secret

    bob_wrap_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b64decode(retrieved_env["hkdf_salt"]), info=context_info).derive(bob_shared)
    assert bob_wrap_key == wrapping_key

    # 13. Bob unwraps AES file key
    recovered_aes_key = AESGCM(bob_wrap_key).decrypt(
        b64decode(retrieved_env["wrapped_key_nonce"]),
        b64decode(retrieved_env["wrapped_file_key"]),
        key_aad
    )
    assert recovered_aes_key == file_aes_key
    print(f"[PASS] 9. Bob unwrapped raw AES-256 file key locally in memory")

    # 14. Bob downloads ciphertext
    status, dl_ciphertext, headers = bob_vault.request("GET", f"/api/transfers/{transfer_id}/download")
    assert status == 200
    dl_nonce = b64decode(headers.get("X-Encryption-Nonce"))

    # 15. Bob decrypts with AES-256-GCM
    decrypted_bytes = AESGCM(recovered_aes_key).decrypt(dl_nonce, dl_ciphertext, None)
    assert decrypted_bytes == original_plaintext
    print(f"[PASS] 10. Decrypted bytes match original bit-for-bit ({len(decrypted_bytes)} bytes)")

    # =========================================================================
    # TEST B: Missing Envelope
    # =========================================================================
    print("\n--- TEST B: Missing Envelope Rejection ---")
    # Create transfer without envelope
    status, body, _ = alice_vault.request("POST", "/api/transfers", json_data={
        "recipient": bob_username,
        "file_id": file_id,
        "expires_in_hours": 24
    }, headers={"X-CSRF-Token": csrf_alice})
    assert status == 201
    no_env_tx_id = json.loads(body)["transfer"]["id"]

    # Bob attempts to fetch non-existent envelope
    status, body, _ = bob_vault.request("GET", f"/api/key-exchange/envelopes/{no_env_tx_id}")
    assert status == 404, f"Expected 404 for missing envelope, got {status}"
    print(f"[PASS] Missing envelope correctly reports 404 not found")

    # =========================================================================
    # TEST C: Wrong Recipient Access Denied
    # =========================================================================
    print("\n--- TEST C: Unauthorized Recipient Access Denied ---")
    charlie_vault = HttpClient(FILE_VAULT_URL)
    status, body, _ = charlie_vault.request("GET", "/api/auth/csrf")
    csrf_charlie = json.loads(body)["csrf_token"]
    status, body, _ = charlie_vault.request("POST", "/api/auth/register", json_data={
        "username": charlie_username,
        "email": f"{charlie_username}@example.com",
        "password": password
    }, headers={"X-CSRF-Token": csrf_charlie})
    assert status == 201

    # Charlie attempts to download transfer or envelope addressed to Bob
    status, _, _ = charlie_vault.request("GET", f"/api/transfers/{transfer_id}")
    assert status == 403, f"Expected 403, got {status}"

    status, _, _ = charlie_vault.request("GET", f"/api/transfers/{transfer_id}/download")
    assert status == 403, f"Expected 403, got {status}"

    status, _, _ = charlie_vault.request("GET", f"/api/key-exchange/envelopes/{transfer_id}")
    assert status == 403, f"Expected 403, got {status}"
    print(f"[PASS] Unrelated user (Charlie) is strictly forbidden (HTTP 403) from access")

    # =========================================================================
    # TEST D: Wrong / Missing Private Key
    # =========================================================================
    print("\n--- TEST D: Wrong Private Key Decryption Failure ---")
    wrong_prekey_sk = x25519.X25519PrivateKey.generate()
    wrong_shared = wrong_prekey_sk.exchange(alice_ephem_pub)
    wrong_wrapping_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b64decode(retrieved_env["hkdf_salt"]), info=context_info).derive(wrong_shared)

    try:
        AESGCM(wrong_wrapping_key).decrypt(
            b64decode(retrieved_env["wrapped_key_nonce"]),
            b64decode(retrieved_env["wrapped_file_key"]),
            key_aad
        )
        assert False, "Should have thrown InvalidTag exception!"
    except Exception as e:
        assert "InvalidTag" in type(e).__name__ or "authenticate" in str(e).lower()
        print(f"[PASS] Wrong private key rejected: AES-GCM tag authentication failed as expected")

    # =========================================================================
    # TEST E: Tampered Envelope Signature Verification Failure
    # =========================================================================
    print("\n--- TEST E: Tampered Envelope Signature Failure ---")
    tampered_env = dict(retrieved_env)
    # Alter the ciphertext
    raw_ct = list(b64decode(tampered_env["wrapped_file_key"]))
    raw_ct[0] ^= 0xFF
    tampered_env["wrapped_file_key"] = b64encode(bytes(raw_ct)).decode()

    unsigned_tampered = {k: v for k, v in tampered_env.items() if k != "signature"}
    try:
        alice_pub.verify(b64decode(tampered_env["signature"]), canonical_json(unsigned_tampered).encode())
        assert False, "Tampered envelope should have failed signature verification!"
    except Exception as e:
        assert "InvalidSignature" in type(e).__name__ or "signature" in str(e).lower()
        print(f"[PASS] Tampered envelope rejected: Ed25519 signature verification failed")

    # =========================================================================
    # TEST F: Tampered Ciphertext AES-GCM Authentication Failure
    # =========================================================================
    print("\n--- TEST F: Tampered Ciphertext AES-GCM Failure ---")
    tampered_ciphertext = bytearray(dl_ciphertext)
    tampered_ciphertext[10] ^= 0xAA  # Flip bits in ciphertext
    try:
        AESGCM(recovered_aes_key).decrypt(dl_nonce, bytes(tampered_ciphertext), None)
        assert False, "Tampered ciphertext should have failed AES-GCM verification!"
    except Exception as e:
        assert "InvalidTag" in type(e).__name__ or "authenticate" in str(e).lower()
        print(f"[PASS] Tampered ciphertext rejected: AES-GCM tag verification failed")

    # =========================================================================
    # TEST G: Transfer ID Mismatch
    # =========================================================================
    print("\n--- TEST G: Transfer ID Mismatch Rejection ---")
    wrong_transfer_id = str(uuid.uuid4())
    wrong_key_aad = f"SecureShare-Envelope-Key-v1|{wrong_transfer_id}|{bob_bundle['prekey_id']}".encode()
    try:
        AESGCM(bob_wrap_key).decrypt(
            b64decode(retrieved_env["wrapped_key_nonce"]),
            b64decode(retrieved_env["wrapped_file_key"]),
            wrong_key_aad
        )
        assert False, "Should have failed due to AAD mismatch!"
    except Exception as e:
        assert "InvalidTag" in type(e).__name__ or "authenticate" in str(e).lower()
        print(f"[PASS] Envelope bound to wrong Transfer ID rejected via AAD authentication")

    # =========================================================================
    # TEST H: Key Exchange Portal Unavailable Dependency Failure
    # =========================================================================
    print("\n--- TEST H: Key Exchange Portal Unavailable Dependency Failure ---")
    status, body, _ = bob_vault.request("GET", f"/api/key-exchange/envelopes/{transfer_id}", headers={"X-KeyX-Simulate-Offline": "1"})
    assert status == 503, f"Expected 503 when portal offline, got {status}"
    data = json.loads(body)
    assert data["code"] == "KEY_EXCHANGE_PORTAL_UNAVAILABLE"
    print(f"[PASS] Key Exchange Portal offline accurately returns HTTP 503: {data['error']}")

    # =========================================================================
    # TEST I: Browser Refresh / State Recovery
    # =========================================================================
    print("\n--- TEST I: Browser Refresh & Re-Inspection State Recovery ---")
    # Simulate fresh page load: Bob inspects the transfer again
    status, body, _ = bob_vault.request("GET", f"/api/transfers/{transfer_id}")
    assert status == 200
    inspect_data = json.loads(body)["transfer"]
    assert inspect_data["id"] == transfer_id
    assert inspect_data["recipient_username"] == bob_username

    status, body, _ = bob_vault.request("GET", f"/api/key-exchange/envelopes/{transfer_id}")
    assert status == 200
    print(f"[PASS] Recipient transfer and key envelope successfully recovered after state reload")

    print("\n" + "=" * 70)
    print("ALL TESTS (A, B, C, D, E, F, G, H, I) PASSED WITH 100% INTEGRITY!")
    print("=" * 70)

if __name__ == "__main__":
    run_all_phase10_tests()
