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

def test_unwrap_and_decrypt_workflow():
    print("=" * 70)
    print("TESTING FULL UNWRAP & DECRYPT WORKFLOW ACROSS BOTH SITES")
    print("=" * 70)

    # 1. Setup Sender & Recipient accounts
    suffix = uuid.uuid4().hex[:6]
    sender_name = f"sender_{suffix}"
    recip_name = f"recip_{suffix}"
    pw = "ComplexPassw0rd!123"

    print(f"\n[1] Registering users: {sender_name} and {recip_name}")
    sender_vault = SessionClient(VAULT_BASE, "secureshare_vault_session")
    sender_vault.init_csrf()
    s, res = sender_vault.post("/api/auth/register", {"username": sender_name, "email": f"{sender_name}@test.com", "password": pw})
    assert s in (200, 201), f"Register sender failed: {res}"
    sender_vault_uid = res.get("user", {}).get("id")

    recip_vault = SessionClient(VAULT_BASE, "secureshare_vault_session")
    recip_vault.init_csrf()
    s, res = recip_vault.post("/api/auth/register", {"username": recip_name, "email": f"{recip_name}@test.com", "password": pw})
    assert s in (200, 201), f"Register recip failed: {res}"
    recip_vault_uid = res.get("user", {}).get("id")

    # Key Exchange Portal accounts
    sender_keyx = SessionClient(KEYX_BASE, "secureshare_keyx_session")
    sender_keyx.init_csrf()
    s, res = sender_keyx.post("/api/auth/register", {"username": sender_name, "email": f"{sender_name}@test.com", "password": pw})
    assert s in (200, 201), f"Register sender keyx failed: {res}"
    sender_keyx_uid = res.get("user", {}).get("id")

    recip_keyx = SessionClient(KEYX_BASE, "secureshare_keyx_session")
    recip_keyx.init_csrf()
    s, res = recip_keyx.post("/api/auth/register", {"username": recip_name, "email": f"{recip_name}@test.com", "password": pw})
    assert s in (200, 201), f"Register recip keyx failed: {res}"
    recip_keyx_uid = res.get("user", {}).get("id")
    print("  [+] Users registered on Port 5000 and Port 5001 successfully!")

    # 2. Setup Recipient Cryptographic Identity & Prekey on Key Exchange Portal (Port 5001)
    recip_sign_key = ed25519.Ed25519PrivateKey.generate()
    recip_sign_pub = recip_sign_key.public_key().public_bytes_raw()
    recip_prekey = x25519.X25519PrivateKey.generate()
    recip_prekey_pub = recip_prekey.public_key().public_bytes_raw()

    # Prekey signature by recipient Ed25519 identity key
    prekey_sig = recip_sign_key.sign(recip_prekey_pub)
    prekey_sig_b64 = base64.b64encode(prekey_sig).decode("utf-8")
    prekey_id = f"prekey_{uuid.uuid4().hex[:8]}"

    # Calculate fingerprint
    h = hashes.Hash(hashes.SHA256())
    h.update(recip_sign_pub)
    digest = h.finalize().hex()
    fp_str = ":".join(digest[i:i+2].upper() for i in range(0, 32, 2))

    # Publish identity on Key Exchange Portal
    s, res = recip_keyx.post("/api/identities", {
        "ed25519_public_key": recip_sign_pub.hex(),
        "fingerprint": fp_str
    })
    assert s in (200, 201), f"Publish identity failed: {res}"

    # Publish prekey
    s, res = recip_keyx.post("/api/prekeys", {
        "prekeys": [{
            "prekey_id": prekey_id,
            "x25519_public_key": recip_prekey_pub.hex(),
            "signature": prekey_sig_b64
        }]
    })
    assert s in (200, 201), f"Publish prekey failed: {res}"
    print(f"  [+] Published recipient prekey {prekey_id} on Port 5001")

    # Also register sender identity
    sender_sign_key = ed25519.Ed25519PrivateKey.generate()
    sender_sign_pub = sender_sign_key.public_key().public_bytes_raw()
    h2 = hashes.Hash(hashes.SHA256())
    h2.update(sender_sign_pub)
    s_digest = h2.finalize().hex()
    s_fp_str = ":".join(s_digest[i:i+2].upper() for i in range(0, 32, 2))

    s, res = sender_keyx.post("/api/identities", {
        "ed25519_public_key": sender_sign_pub.hex(),
        "fingerprint": s_fp_str
    })
    assert s in (200, 201), f"Publish sender identity failed: {res}"

    # 3. Sender Encrypts and Uploads File on File Vault (Port 5000)
    original_plaintext = b"SECURESHARE CONFIDENTIAL DATA: Bit-for-bit decrypted content verification."
    raw_aes_key = os.urandom(32) # 256-bit AES file key
    nonce = os.urandom(12) # 96-bit AES-GCM nonce

    aesgcm = AESGCM(raw_aes_key)
    ciphertext = aesgcm.encrypt(nonce, original_plaintext, None)

    # Upload ciphertext multipart/form-data
    boundary = "----WebKitFormBoundary" + uuid.uuid4().hex
    body_parts = []
    body_parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"nonce\"\r\n\r\n{base64.urlsafe_b64encode(nonce).decode('utf-8')}\r\n".encode("utf-8"))
    body_parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"algorithm\"\r\n\r\nAES-256-GCM\r\n".encode("utf-8"))
    body_parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"confidential_doc.txt\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode("utf-8") + ciphertext + b"\r\n")
    body_parts.append(f"--{boundary}--\r\n".encode("utf-8"))
    multipart_body = b"".join(body_parts)

    status, upload_res, _ = sender_vault.request("POST", "/api/files/upload", raw_body=multipart_body, content_type=f"multipart/form-data; boundary={boundary}")
    assert status == 201, f"Upload ciphertext failed: {upload_res}"
    file_id = upload_res["file"]["id"]
    print(f"  [+] Uploaded ciphertext to Port 5000 (File ID: {file_id})")

    # Create transfer record on File Vault
    s, tx_res = sender_vault.post("/api/transfers", {
        "recipient": recip_name,
        "file_id": file_id,
        "expires_in_hours": 24
    })
    assert s == 201, f"Create transfer failed: {tx_res}"
    transfer_id = tx_res["transfer"]["id"]
    print(f"  [+] Created transfer record on Port 5000 (Transfer ID: {transfer_id})")

    # 4. Seal Protected Key Envelope on Key Exchange Portal (Port 5001)
    sender_eph_priv = x25519.X25519PrivateKey.generate()
    sender_eph_pub = sender_eph_priv.public_key().public_bytes_raw()

    shared_secret = sender_eph_priv.exchange(x25519.X25519PublicKey.from_public_bytes(recip_prekey_pub))
    salt = os.urandom(32)
    context_info = f"SecureShare-v1|wrapping-key|{sender_sign_pub.hex().lower()}|{recip_sign_pub.hex().lower()}|{transfer_id}|{prekey_id}".encode("utf-8")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=context_info)
    wrapping_key = hkdf.derive(shared_secret)

    # Wrap AES key with wrapping key
    key_nonce = os.urandom(12)
    key_aad = f"SecureShare-Envelope-Key-v1|{transfer_id}|{prekey_id}".encode("utf-8")
    wrapped_file_key = AESGCM(wrapping_key).encrypt(key_nonce, raw_aes_key, key_aad)

    # Wrap metadata
    meta_bytes = json.dumps({"filename": "confidential_doc.txt", "size": len(original_plaintext)}).encode("utf-8")
    meta_nonce = os.urandom(12)
    meta_aad = f"SecureShare-Envelope-Meta-v1|{transfer_id}".encode("utf-8")
    wrapped_meta = AESGCM(wrapping_key).encrypt(meta_nonce, meta_bytes, meta_aad)

    envelope_payload = {
        "version": 1,
        "transfer_id": transfer_id,
        "recipient_prekey_id": prekey_id,
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

    # Dispatch envelope on Port 5001
    s, seal_res = sender_keyx.post("/api/envelopes", {
        "transfer_id": transfer_id,
        "sender_id": sender_keyx_uid,
        "recipient_id": recip_keyx_uid,
        "recipient_prekey_id": prekey_id,
        "encrypted_envelope": json.dumps(envelope_payload),
        "sender_signature": envelope_payload["signature"],
        "force_update": True
    })
    assert s in (200, 201), f"Seal envelope failed: {seal_res}"
    print(f"  [+] Key envelope sealed and dispatched on Port 5001 [PASS]")

    # 5. Recipient Unwraps Envelope on Key Exchange Portal (Port 5001)
    s, env_res = recip_keyx.get(f"/api/envelopes/{transfer_id}")
    assert s == 200, f"Get envelope on keyx failed: {env_res}"
    retrieved_env = json.loads(env_res["envelope"]["encrypted_envelope"])

    # Verify Ed25519 signature
    unsigned_env = {k: v for k, v in retrieved_env.items() if k != "signature"}
    can_verify = json.dumps(unsigned_env, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig_to_verify = base64.b64decode(retrieved_env["signature"].replace("-", "+").replace("_", "/") + "==")
    ed25519.Ed25519PublicKey.from_public_bytes(sender_sign_pub).verify(sig_to_verify, can_verify)
    print("  [+] Recipient verified sender Ed25519 signature! [PASS]")

    # Recipient computes ECDH + HKDF unwrapping key
    eph_bytes = bytes.fromhex(retrieved_env["sender_ephemeral_key"])
    recip_shared_secret = recip_prekey.exchange(x25519.X25519PublicKey.from_public_bytes(eph_bytes))
    recip_salt = base64.b64decode(retrieved_env["hkdf_salt"].replace("-", "+").replace("_", "/") + "==")
    recip_hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=recip_salt, info=context_info)
    recip_wrapping_key = recip_hkdf.derive(recip_shared_secret)

    # Recipient unwraps raw AES file key
    recip_key_nonce = base64.b64decode(retrieved_env["wrapped_key_nonce"].replace("-", "+").replace("_", "/") + "==")
    recip_wrapped_key = base64.b64decode(retrieved_env["wrapped_file_key"].replace("-", "+").replace("_", "/") + "==")
    unwrapped_raw_key = AESGCM(recip_wrapping_key).decrypt(recip_key_nonce, recip_wrapped_key, key_aad)

    assert unwrapped_raw_key == raw_aes_key, "Unwrapped key does not match original AES key!"
    unwrapped_key_hex = unwrapped_raw_key.hex()
    print(f"  [+] Key unwrapped successfully on Port 5001: {unwrapped_key_hex[:16]}... [PASS]")

    # 6. Recipient Decrypts File on File Vault (Port 5000) using unwrapped AES Key
    print("\n[6] Testing File Vault Decryption with Unwrapped Key...")
    
    # Recipient inspects transfer record
    s, tx_get = recip_vault.get(f"/api/transfers/{transfer_id}")
    assert s == 200, f"Inspect transfer failed: {tx_get}"
    t_record = tx_get["transfer"]
    print(f"  [+] Inspected transfer on Port 5000: sender={t_record['sender_username']}, size={t_record['encrypted_size']}")

    # Recipient downloads ciphertext stream from Port 5000
    status, downloaded_ciphertext, nonce_header = recip_vault.request("GET", f"/api/transfers/{transfer_id}/download")
    assert status == 200, f"Download ciphertext failed: {status}"
    assert len(downloaded_ciphertext) > 0, "Downloaded ciphertext is empty!"
    print(f"  [+] Downloaded ciphertext: {len(downloaded_ciphertext)} bytes, Nonce Header: {nonce_header}")

    # Use nonce from header (or fallback to transfer record)
    nonce_to_use = nonce_header or t_record.get("nonce")
    assert nonce_to_use is not None, "Nonce is missing!"
    
    # Flexible base64 decode of nonce
    norm_nonce_str = nonce_to_use.replace("-", "+").replace("_", "/")
    while len(norm_nonce_str) % 4 != 0:
        norm_nonce_str += "="
    decrypted_nonce = base64.b64decode(norm_nonce_str)
    assert len(decrypted_nonce) == 12, f"Invalid nonce length: {len(decrypted_nonce)}"

    # Decrypt ciphertext using the unwrapped key (from Port 5001)
    file_decryptor = AESGCM(bytes.fromhex(unwrapped_key_hex))
    decrypted_bytes = file_decryptor.decrypt(decrypted_nonce, downloaded_ciphertext, None)

    assert decrypted_bytes == original_plaintext, "Decrypted bytes do not match original plaintext!"
    print(f"  [+] Decrypted content: '{decrypted_bytes.decode('utf-8')}'")
    print("  [+] BIT-FOR-BIT MATCH: 100% IDENTICAL [PASS]")

    print("\n" + "=" * 70)
    print("ALL UNWRAP & DECRYPT WORKFLOW TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 70)

if __name__ == "__main__":
    test_unwrap_and_decrypt_workflow()
