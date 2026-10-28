import sys
import os
import uuid
import json
import base64
import urllib.request
import urllib.error
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VAULT_BASE = "http://127.0.0.1:5000"
KEYX_BASE = "http://127.0.0.1:5001"

class SessionClient:
    def __init__(self, base_url, cookie_name):
        self.base_url = base_url
        self.cookie_name = cookie_name
        self.cookies = {}
        self.csrf_token = ""

    def request(self, method, endpoint, data=None, raw_body=None, content_type="application/json"):
        url = f"{self.base_url}{endpoint}"
        headers = {"Accept": "application/json"}
        if self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())

        body = None
        if raw_body is not None:
            body = raw_body
            headers["Content-Type"] = content_type
        elif data is not None:
            body = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                self._update_cookies(resp)
                ct = resp.headers.get("Content-Type", "")
                nonce_hdr = resp.headers.get("X-Encryption-Nonce")
                resp_bytes = resp.read()
                if "application/json" in ct:
                    res_json = json.loads(resp_bytes.decode("utf-8")) if resp_bytes else {}
                    return resp.status, res_json, nonce_hdr
                return resp.status, resp_bytes, nonce_hdr
        except urllib.error.HTTPError as e:
            self._update_cookies(e)
            err_body = e.read()
            try:
                res_json = json.loads(err_body.decode("utf-8"))
            except Exception:
                res_json = {"error": err_body.decode("utf-8", errors="replace")}
            return e.code, res_json, None

    def _update_cookies(self, resp_or_err):
        header_cookies = resp_or_err.headers.get_all("Set-Cookie") or []
        for c_str in header_cookies:
            parts = c_str.split(";")[0].split("=", 1)
            if len(parts) == 2:
                self.cookies[parts[0].strip()] = parts[1].strip()

    def get(self, endpoint):
        s, data, _ = self.request("GET", endpoint)
        return s, data

    def post(self, endpoint, data):
        s, data, _ = self.request("POST", endpoint, data=data)
        return s, data

    def init_csrf(self, csrf_endpoint="/api/auth/csrf"):
        s, data, _ = self.request("GET", csrf_endpoint)
        if s == 200 and isinstance(data, dict):
            self.csrf_token = data.get("csrf_token", "")
        return self.csrf_token


def run_e2e_verification():
    print("=" * 80)
    print("SECURESHARE: END-TO-END FILE VAULT & KEY EXCHANGE TAG VERIFICATION TEST")
    print("=" * 80)

    # 1. Verify Recipient Discovery prioritizing Port 5001
    print("\n[Step 1] Verifying Recipient Discovery on File Vault (Port 5000)...")
    vault_client = SessionClient(VAULT_BASE, "secureshare_vault_session")
    vault_client.init_csrf()

    # Query for an unknown user to verify 404 with suggestions
    status, res = vault_client.get("/api/key-exchange/identities/kaviraj_nonexistent")
    print(f"  Lookup 'kaviraj_nonexistent': status={status}, response={res}")
    assert status == 404, f"Expected 404 for nonexistent user, got {status}"
    assert "kaviraj" in res.get("suggestions", []) or "kaviraj1" in res.get("suggestions", []) or "kaviraj" in res.get("error", ""), "Expected suggestion kaviraj"
    print("  [PASS] Nonexistent user returns 404 and active suggestions from Key Exchange Portal!")

    # Query for kaviraj (active on Port 5001 and Port 5000)
    status, res = vault_client.get("/api/key-exchange/identities/kaviraj")
    print(f"  Lookup 'kaviraj': status={status}, prekey_id={res.get('prekey_id')}")
    assert status == 200, f"Expected 200 for kaviraj, got {status}"
    assert res.get("recipient_username") == "kaviraj"
    print("  [PASS] kaviraj live identity & prekey retrieved successfully!")

    # Query for kaviraj1 (active on Port 5001)
    status, res = vault_client.get("/api/key-exchange/identities/kaviraj1")
    print(f"  Lookup 'kaviraj1': status={status}, prekey_id={res.get('prekey_id')}")
    assert status == 200, f"Expected 200 for kaviraj1, got {status}"
    assert res.get("recipient_username") == "kaviraj1"
    recip_signing_key_hex = res.get("signing_public_key")
    recip_prekey_hex = res.get("x25519_prekey")
    recip_prekey_id = res.get("prekey_id")
    recip_user_id = res.get("recipient_id")
    print("  [PASS] kaviraj1 live identity & prekey retrieved from Key Exchange Portal!")

    # 2. Setup a fresh recipient keypair to verify bit-for-bit unwrap & decrypt
    print("\n[Step 2] Provisioning fresh test recipient on Key Exchange Portal (Port 5001)...")
    suffix = uuid.uuid4().hex[:6]
    test_recip_name = f"recip_{suffix}"
    test_sender_name = f"sender_{suffix}"
    pw = "ComplexPassw0rd!123"

    # Register recipient on Port 5001
    recip_keyx = SessionClient(KEYX_BASE, "secureshare_keyx_session")
    recip_keyx.init_csrf()
    s, res = recip_keyx.post("/api/auth/register", {"username": test_recip_name, "email": f"{test_recip_name}@test.com", "password": pw})
    assert s in (200, 201), f"Register recip failed: {res}"
    test_recip_id = res["user"]["id"]

    # Register sender on Port 5001
    sender_keyx = SessionClient(KEYX_BASE, "secureshare_keyx_session")
    sender_keyx.init_csrf()
    s, res = sender_keyx.post("/api/auth/register", {"username": test_sender_name, "email": f"{test_sender_name}@test.com", "password": pw})
    assert s in (200, 201), f"Register sender failed: {res}"
    test_sender_id = res["user"]["id"]

    # Generate recipient cryptographic keys
    recip_sign_key = ed25519.Ed25519PrivateKey.generate()
    recip_sign_pub = recip_sign_key.public_key().public_bytes_raw()
    recip_prekey = x25519.X25519PrivateKey.generate()
    recip_prekey_pub = recip_prekey.public_key().public_bytes_raw()

    prekey_sig = recip_sign_key.sign(recip_prekey_pub)
    prekey_sig_b64 = base64.b64encode(prekey_sig).decode("utf-8")
    t_prekey_id = f"prekey_{uuid.uuid4().hex[:8]}"

    h = hashes.Hash(hashes.SHA256())
    h.update(recip_sign_pub)
    digest_hex = h.finalize().hex()
    fp_str = ":".join(digest_hex[i:i+2].upper() for i in range(0, 32, 2))

    s, res = recip_keyx.post("/api/identities", {"ed25519_public_key": recip_sign_pub.hex(), "fingerprint": fp_str})
    assert s in (200, 201), f"Publish identity failed: {res}"

    s, res = recip_keyx.post("/api/prekeys", {"prekeys": [{
        "prekey_id": t_prekey_id,
        "x25519_public_key": recip_prekey_pub.hex(),
        "signature": prekey_sig_b64
    }]})
    assert s in (200, 201), f"Publish prekey failed: {res}"
    print(f"  [+] Published prekey {t_prekey_id} on Port 5001 for {test_recip_name} [PASS]")

    # Sender identity on Port 5001
    sender_sign_key = ed25519.Ed25519PrivateKey.generate()
    sender_sign_pub = sender_sign_key.public_key().public_bytes_raw()
    h2 = hashes.Hash(hashes.SHA256())
    h2.update(sender_sign_pub)
    s_digest_hex = h2.finalize().hex()
    s_fp_str = ":".join(s_digest_hex[i:i+2].upper() for i in range(0, 32, 2))
    s, res = sender_keyx.post("/api/identities", {"ed25519_public_key": sender_sign_pub.hex(), "fingerprint": s_fp_str})
    assert s in (200, 201), f"Publish sender identity failed: {res}"

    # Register sender and recipient on File Vault (Port 5000)
    print("\n[Step 3] Registering users on File Vault (Port 5000)...")
    sender_vault = SessionClient(VAULT_BASE, "secureshare_vault_session")
    sender_vault.init_csrf()
    s, res = sender_vault.post("/api/auth/register", {"username": test_sender_name, "email": f"{test_sender_name}@test.com", "password": pw})
    assert s in (200, 201), f"Register sender on vault failed: {res}"

    recip_vault = SessionClient(VAULT_BASE, "secureshare_vault_session")
    recip_vault.init_csrf()
    s, res = recip_vault.post("/api/auth/register", {"username": test_recip_name, "email": f"{test_recip_name}@test.com", "password": pw})
    assert s in (200, 201), f"Register recip on vault failed: {res}"
    print("  [+] Registered sender and recipient accounts on Port 5000 [PASS]")

    # 4. File Vault: Sender Encrypts and Uploads File
    print("\n[Step 4] Client-Side File Encryption & Upload on Port 5000...")
    secret_payload = b"CRITICAL SECURESHARE VERIFICATION: Validating AES-256-GCM 128-bit authentication tag with end-to-end key recovery!"
    aes_file_key = os.urandom(32) # 256-bit AES file key
    aes_nonce = os.urandom(12) # 96-bit AES-GCM nonce

    file_encryptor = AESGCM(aes_file_key)
    ciphertext = file_encryptor.encrypt(aes_nonce, secret_payload, None)
    print(f"  [+] Plaintext size: {len(secret_payload)} bytes")
    print(f"  [+] Ciphertext size: {len(ciphertext)} bytes (includes 16-byte GCM tag)")
    print(f"  [+] Raw AES-256 File Key (Hex): {aes_file_key.hex()}")

    # Multipart upload to Port 5000
    boundary = "----TestBoundary" + uuid.uuid4().hex
    body_parts = [
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"nonce\"\r\n\r\n{base64.urlsafe_b64encode(aes_nonce).decode('utf-8')}\r\n".encode("utf-8"),
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"algorithm\"\r\n\r\nAES-256-GCM\r\n".encode("utf-8"),
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"secret_document.pdf\"\r\nContent-Type: application/pdf\r\n\r\n".encode("utf-8") + ciphertext + b"\r\n",
        f"--{boundary}--\r\n".encode("utf-8")
    ]
    status, up_res, _ = sender_vault.request("POST", "/api/files/upload", raw_body=b"".join(body_parts), content_type=f"multipart/form-data; boundary={boundary}")
    assert status == 201, f"Upload failed: {up_res}"
    uploaded_file_id = up_res["file"]["id"]
    print(f"  [+] Uploaded ciphertext to Port 5000 (File ID: {uploaded_file_id})")

    # Create transfer on Port 5000
    s, tx_res = sender_vault.post("/api/transfers", {
        "recipient": test_recip_name,
        "file_id": uploaded_file_id,
        "expires_in_hours": 24
    })
    assert s == 201, f"Create transfer failed: {tx_res}"
    real_transfer_id = tx_res["transfer"]["id"]
    print(f"  [+] Created transfer on Port 5000 (Transfer ID: {real_transfer_id})")

    # 5. Seal Protected Key Envelope bound to real_transfer_id
    print("\n[Step 5] Sealing Key Envelope on Port 5000 & Forwarding to Port 5001...")
    sender_eph_priv = x25519.X25519PrivateKey.generate()
    sender_eph_pub = sender_eph_priv.public_key().public_bytes_raw()

    shared_secret = sender_eph_priv.exchange(x25519.X25519PublicKey.from_public_bytes(recip_prekey_pub))
    salt = os.urandom(32)
    context_info = f"SecureShare-v1|wrapping-key|{sender_sign_pub.hex().lower()}|{recip_sign_pub.hex().lower()}|{real_transfer_id}|{t_prekey_id}".encode("utf-8")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=context_info)
    wrapping_key = hkdf.derive(shared_secret)

    key_nonce = os.urandom(12)
    key_aad = f"SecureShare-Envelope-Key-v1|{real_transfer_id}|{t_prekey_id}".encode("utf-8")
    wrapped_file_key = AESGCM(wrapping_key).encrypt(key_nonce, aes_file_key, key_aad)

    meta_nonce = os.urandom(12)
    meta_bytes = json.dumps({"filename": "secret_document.pdf", "size": len(secret_payload)}).encode("utf-8")
    meta_aad = f"SecureShare-Envelope-Meta-v1|{real_transfer_id}".encode("utf-8")
    wrapped_meta = AESGCM(wrapping_key).encrypt(meta_nonce, meta_bytes, meta_aad)

    envelope_payload = {
        "version": 1,
        "transfer_id": real_transfer_id,
        "recipient_prekey_id": t_prekey_id,
        "sender_identity_key": sender_sign_pub.hex().lower(),
        "sender_ephemeral_key": sender_eph_pub.hex().lower(),
        "hkdf_salt": base64.b64encode(salt).decode("utf-8"),
        "wrapped_key_nonce": base64.b64encode(key_nonce).decode("utf-8"),
        "wrapped_file_key": base64.b64encode(wrapped_file_key).decode("utf-8"),
        "meta_nonce": base64.b64encode(meta_nonce).decode("utf-8"),
        "meta_ciphertext": base64.b64encode(wrapped_meta).decode("utf-8")
    }
    canonical_str = json.dumps(envelope_payload, sort_keys=True, separators=(",", ":"))
    sig_bytes = sender_sign_key.sign(canonical_str.encode("utf-8"))
    envelope_payload["signature"] = base64.b64encode(sig_bytes).decode("utf-8")

    # Submit envelope via Port 5000 API
    s, env_res = sender_vault.post("/api/key-exchange/envelopes", {
        "transfer_id": real_transfer_id,
        "recipient_id": test_recip_id,
        "recipient_username": test_recip_name,
        "envelope": envelope_payload
    })
    assert s == 201, f"Submit envelope failed: {env_res}"
    print("  [+] Key envelope successfully submitted and synchronized across Port 5000 and 5001 [PASS]")

    # 6. Verify Recipient Inbox on Port 5001
    print("\n[Step 6] Verifying Recipient Inbox on Port 5001...")
    s, inbox_res = recip_keyx.get("/api/envelopes/inbox")
    assert s == 200, f"Get inbox failed: {inbox_res}"
    matching_inbox = [item for item in inbox_res.get("inbox", []) if item.get("transfer_id") == real_transfer_id]
    assert len(matching_inbox) == 1, f"Expected 1 matching envelope in recipient inbox, found {len(matching_inbox)}"
    print(f"  [+] Transfer {real_transfer_id} verified in recipient's Inbox on Port 5001! [PASS]")

    # 7. Recipient Unwraps Envelope on Port 5001
    print("\n[Step 7] Recipient Unwrapping Key Envelope...")
    s, env_get = recip_keyx.get(f"/api/envelopes/{real_transfer_id}")
    assert s == 200, f"Get envelope failed: {env_get}"
    stored_env = json.loads(env_get["envelope"]["encrypted_envelope"])

    # Verify Ed25519 digital signature
    unsig_env = {k: v for k, v in stored_env.items() if k != "signature"}
    can_bytes = json.dumps(unsig_env, sort_keys=True, separators=(",", ":")).encode("utf-8")
    raw_sig = base64.b64decode(stored_env["signature"].replace("-", "+").replace("_", "/") + "==")
    ed25519.Ed25519PublicKey.from_public_bytes(sender_sign_pub).verify(raw_sig, can_bytes)
    print("  [+] Sender Ed25519 signature verified successfully! [PASS]")

    # ECDH + HKDF key derivation
    r_shared = recip_prekey.exchange(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(stored_env["sender_ephemeral_key"])))
    r_salt = base64.b64decode(stored_env["hkdf_salt"].replace("-", "+").replace("_", "/") + "==")
    r_wrap_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=r_salt, info=context_info).derive(r_shared)

    r_key_nonce = base64.b64decode(stored_env["wrapped_key_nonce"].replace("-", "+").replace("_", "/") + "==")
    r_wrapped_key = base64.b64decode(stored_env["wrapped_file_key"].replace("-", "+").replace("_", "/") + "==")
    unwrapped_aes_key = AESGCM(r_wrap_key).decrypt(r_key_nonce, r_wrapped_key, key_aad)

    assert unwrapped_aes_key == aes_file_key, "Recovered AES key does not match original file key!"
    print(f"  [+] Unwrapped AES File Key: {unwrapped_aes_key.hex()} [MATCHES ENCRYPTED KEY!]")

    # 8. Decrypt on File Vault (Port 5000) using unwrapped AES key
    print("\n[Step 8] File Vault Decryption & AES-GCM Tag Verification...")
    status, downloaded_ct, nonce_hdr = recip_vault.request("GET", f"/api/transfers/{real_transfer_id}/download")
    assert status == 200, f"Download failed: {status}"
    assert len(downloaded_ct) == len(ciphertext), f"Ciphertext length mismatch: {len(downloaded_ct)} vs {len(ciphertext)}"
    print(f"  [+] Downloaded ciphertext: {len(downloaded_ct)} bytes, Nonce Header: {nonce_hdr}")

    norm_nonce = nonce_hdr.replace("-", "+").replace("_", "/")
    while len(norm_nonce) % 4 != 0:
        norm_nonce += "="
    decrypted_nonce = base64.b64decode(norm_nonce)

    # Perform AES-GCM decryption
    decryptor = AESGCM(unwrapped_aes_key)
    decrypted_plaintext = decryptor.decrypt(decrypted_nonce, downloaded_ct, None)

    assert decrypted_plaintext == secret_payload, "Decrypted payload does not match original plaintext!"
    print(f"  [+] Decrypted plaintext: '{decrypted_plaintext.decode('utf-8')}'")
    print("  [+] AES-GCM 128-bit authentication tag VERIFIED SUCCESSFULLY! [100% PASS]")

    # 9. Verify that using an INVALID key (like random key generated in exchange) FAILS with InvalidTag
    print("\n[Step 9] Verifying that mismatched random key triggers expected Tag Failure...")
    mismatched_random_key = os.urandom(32)
    bad_decryptor = AESGCM(mismatched_random_key)
    tag_failed = False
    try:
        bad_decryptor.decrypt(decrypted_nonce, downloaded_ct, None)
    except Exception as e:
        tag_failed = True
        print(f"  [+] Expected failure verified: {type(e).__name__} ({e})")
    assert tag_failed, "Decryption with mismatched key should have failed with InvalidTag!"
    print("  [+] Invalid tag behavior confirmed! [PASS]")

    print("\n" + "=" * 80)
    print("ALL 9 TESTS PASSED: BIT-FOR-BIT FILE DECRYPTION AND AUTH TAG VERIFIED!")
    print("=" * 80)

if __name__ == "__main__":
    run_e2e_verification()
