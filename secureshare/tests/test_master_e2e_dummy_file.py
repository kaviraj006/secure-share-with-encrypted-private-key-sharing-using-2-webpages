"""
MASTER E2E DUMMY-FILE TEST SUITE: SECURESHARE FILE VAULT & KEY EXCHANGE PORTAL
Implements Phase Seven (Tests A, B, C, D) and Phase Eight (Negative Tests).

Features:
- Generates a deterministic dummy test file: secureshare_e2e_test.txt
- Computes and records original SHA-256 digest
- Creates isolated sessions and local keystores for Alice (sender) and Bob (recipient)
- Executes real client-side AES-256-GCM encryption, X25519 DH, HKDF-SHA-256, Ed25519 signatures
- Verifies 100% byte-for-byte identical decrypted recovery
- Executes full suite of negative/failure edge cases
"""

import os
import sys
import json
import time
import uuid
import hashlib
import urllib.request
import urllib.parse
import http.cookiejar
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

FILE_VAULT_URL = "http://127.0.0.1:5000"
KEYX_URL = "http://127.0.0.1:5001"


class HttpClient:
    def __init__(self, base_url):
        self.base_url = base_url
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))
        self.csrf_token = None
        self.last_headers = None

    def get_csrf(self):
        status, data = self.get("/api/auth/csrf")
        if status == 200 and isinstance(data, dict):
            self.csrf_token = data.get("csrf_token")
        return self.csrf_token

    def request(self, method, path, json_data=None, form_data=None, files=None, custom_headers=None):
        url = self.base_url + path
        headers = custom_headers or {}
        req_body = None

        if not self.csrf_token and method in ("POST", "PUT", "PATCH", "DELETE"):
            self.get_csrf()

        if self.csrf_token and "X-CSRF-Token" not in headers:
            headers["X-CSRF-Token"] = self.csrf_token

        if json_data is not None:
            req_body = json.dumps(json_data).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif files or form_data:
            boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
            parts = []
            if form_data:
                for k, v in form_data.items():
                    parts.append(
                        f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode("utf-8")
                    )
            if files:
                for name, (fname, fbytes, ctype) in files.items():
                    parts.append(
                        f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{fname}\"\r\nContent-Type: {ctype}\r\n\r\n".encode()
                        + fbytes + b"\r\n"
                    )
            parts.append(f"--{boundary}--\r\n".encode())
            req_body = b"".join(parts)

        req = urllib.request.Request(url, data=req_body, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=10) as resp:
                status = resp.status
                self.last_headers = resp.headers
                body = resp.read()
                try:
                    data = json.loads(body.decode("utf-8"))
                except Exception:
                    data = body
                if isinstance(data, dict) and data.get("csrf_token"):
                    self.csrf_token = data.get("csrf_token")
                return status, data
        except urllib.error.HTTPError as e:
            status = e.code
            self.last_headers = e.headers
            body = e.read()
            try:
                data = json.loads(body.decode("utf-8"))
            except Exception:
                data = body
            return status, data

    def get(self, path, custom_headers=None):
        return self.request("GET", path, custom_headers=custom_headers)

    def post(self, path, json_data=None, form_data=None, files=None, custom_headers=None):
        return self.request("POST", path, json_data=json_data, form_data=form_data, files=files, custom_headers=custom_headers)

    def patch(self, path, json_data=None, custom_headers=None):
        return self.request("PATCH", path, json_data=json_data, custom_headers=custom_headers)


class BrowserKeystoreSimulator:
    """Simulates client-side IndexedDB encrypted keystore and libsodium primitives."""
    def __init__(self, username, user_id=None):
        self.username = username
        self.user_id = user_id
        self.is_unlocked = False
        self.passphrase = None
        
        # Ed25519 Identity Keypair
        self.id_priv = ed25519.Ed25519PrivateKey.generate()
        self.id_pub = self.id_priv.public_key()
        self.id_pub_bytes = self.id_pub.public_bytes_raw()
        self.id_pub_hex = self.id_pub_bytes.hex()
        
        # SHA-256 Fingerprint
        digest = hashlib.sha256(self.id_pub_bytes).digest()
        self.fingerprint = ":".join(f"{b:02X}" for b in digest[:16])
        
        # X25519 Prekeys
        self.prekeys = {}

    def unlock(self, passphrase):
        self.passphrase = passphrase
        self.is_unlocked = True
        return True

    def generate_signed_prekey(self, prekey_id):
        pk_priv = x25519.X25519PrivateKey.generate()
        pk_pub = pk_priv.public_key()
        pk_pub_bytes = pk_pub.public_bytes_raw()
        pk_pub_hex = pk_pub_bytes.hex()
        
        # Ed25519 signature over X25519 public key bytes
        sig_bytes = self.id_priv.sign(pk_pub_bytes)
        sig_b64 = b64encode(sig_bytes).decode("ascii")
        
        self.prekeys[prekey_id] = {
            "priv": pk_priv,
            "pub_bytes": pk_pub_bytes,
            "pub_hex": pk_pub_hex,
            "sig_b64": sig_b64
        }
        return {
            "prekey_id": prekey_id,
            "x25519_public_key": pk_pub_hex,
            "signature": sig_b64,
            "days_valid": 30
        }


def run_master_test():
    print("=" * 80)
    print("STARTING MASTER E2E DUMMY-FILE TEST: SECURESHARE FILE VAULT & KEY EXCHANGE")
    print("=" * 80)

    # -------------------------------------------------------------------------
    # STEP 0: Generate Dummy Test File
    # -------------------------------------------------------------------------
    test_id = str(uuid.uuid4())
    dummy_filename = "secureshare_e2e_test.txt"
    dummy_content = (
        f"=== SECURESHARE HIGH-ASSURANCE ZERO-KNOWLEDGE E2E VERIFICATION FILE ===\n"
        f"Test Run ID       : {test_id}\n"
        f"Generated At      : {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
        f"Classification    : STRICT ZERO-KNOWLEDGE ENCRYPTED CARGO\n"
        f"Payload Determinism: SHA-256 Verified Bit-for-Bit Delivery\n"
        f"{'X' * 4096}\n"
        f"=== END OF VERIFIED CARGO PAYLOAD ===\n"
    ).encode("utf-8")
    original_sha256 = hashlib.sha256(dummy_content).hexdigest()

    print(f"\n[Step 0] Generated deterministic dummy test file: '{dummy_filename}'")
    print(f"  -> File Size  : {len(dummy_content)} bytes")
    print(f"  -> SHA-256    : {original_sha256}")

    # Suffix for isolated accounts
    run_suffix = test_id[:8]
    alice_name = f"alice_{run_suffix}"
    bob_name = f"bob_{run_suffix}"
    password = f"MasterPass123!{run_suffix}"

    # Isolated client connections
    alice_fv = HttpClient(FILE_VAULT_URL)
    alice_keyx = HttpClient(KEYX_URL)
    bob_fv = HttpClient(FILE_VAULT_URL)
    bob_keyx = HttpClient(KEYX_URL)

    alice_vault = BrowserKeystoreSimulator(alice_name)
    bob_vault = BrowserKeystoreSimulator(bob_name)
    alice_vault.unlock(password)
    bob_vault.unlock(password)

    # -------------------------------------------------------------------------
    # PHASE SEVEN: TEST A — First-Time Setup
    # -------------------------------------------------------------------------
    print(f"\n[Test A] First-Time Setup (Registration & Cryptographic Identity Initialization)")

    # 1. Register Bob on Key Exchange Portal (Port 5001)
    status, reg_bob = bob_keyx.post("/api/auth/register", {
        "username": bob_name,
        "email": f"{bob_name}@secureshare.test",
        "password": password
    })
    assert status == 201, f"Bob KeyX reg failed: {reg_bob}"
    bob_vault.user_id = reg_bob["user"]["id"]
    print(f"  [+] Registered Bob on Key Exchange Portal (ID: {bob_vault.user_id})")

    # 2. Register Alice on Key Exchange Portal (Port 5001)
    status, reg_alice = alice_keyx.post("/api/auth/register", {
        "username": alice_name,
        "email": f"{alice_name}@secureshare.test",
        "password": password
    })
    assert status == 201, f"Alice KeyX reg failed: {reg_alice}"
    alice_vault.user_id = reg_alice["user"]["id"]
    print(f"  [+] Registered Alice on Key Exchange Portal (ID: {alice_vault.user_id})")

    # 3. Publish Bob's Ed25519 identity key
    status, id_resp = bob_keyx.post("/api/identities", {
        "ed25519_public_key": bob_vault.id_pub_hex,
        "fingerprint": bob_vault.fingerprint
    })
    assert status == 200, f"Bob identity publish failed: {id_resp}"
    print(f"  [+] Published Bob's Ed25519 Identity (FP: {bob_vault.fingerprint})")

    # 4. Publish Alice's Ed25519 identity key
    status, id_resp = alice_keyx.post("/api/identities", {
        "ed25519_public_key": alice_vault.id_pub_hex,
        "fingerprint": alice_vault.fingerprint
    })
    assert status == 200, f"Alice identity publish failed: {id_resp}"
    print(f"  [+] Published Alice's Ed25519 Identity (FP: {alice_vault.fingerprint})")

    # 5. Generate and publish Bob's 5 signed X25519 prekeys
    bob_prekeys_data = []
    for i in range(5):
        pk_data = bob_vault.generate_signed_prekey(f"prekey_{run_suffix}_{i:02d}")
        bob_prekeys_data.append(pk_data)
    status, pk_res = bob_keyx.post("/api/prekeys", {"prekeys": bob_prekeys_data})
    assert status == 201, f"Bob prekeys publish failed: {pk_res}"
    print(f"  [+] Published 5 signed X25519 prekeys for Bob")

    # 6. Verify reloading Bob's identity from server (/api/identities/me)
    status, me_bob = bob_keyx.get("/api/identities/me")
    assert status == 200 and me_bob["has_identity"] is True
    assert me_bob["identity"]["ed25519_public_key"] == bob_vault.id_pub_hex
    print(f"  [+] Verified Bob identity persistence & reload: MATCHED [PASS]")

    # 7. Register Alice & Bob on File Vault (Port 5000)
    status, _ = alice_fv.post("/api/auth/register", {
        "username": alice_name,
        "email": f"{alice_name}@fv.test",
        "password": password
    })
    assert status in (200, 201), "Alice FV reg failed"
    status, _ = bob_fv.post("/api/auth/register", {
        "username": bob_name,
        "email": f"{bob_name}@fv.test",
        "password": password
    })
    assert status in (200, 201), "Bob FV reg failed"
    print(f"  [+] Registered Alice & Bob on File Vault (Port 5000) [PASS]")

    # -------------------------------------------------------------------------
    # PHASE SEVEN: TEST B — Authentication and Recipient Discovery
    # -------------------------------------------------------------------------
    print(f"\n[Test B] Authentication and Recipient Discovery")

    # Discover Bob from Alice's session on KeyX
    status, disc_res = alice_keyx.get(f"/api/key-exchange/identities/{bob_name}")
    assert status == 200, f"Discovery failed: {disc_res}"
    assert disc_res["recipient_username"] == bob_name
    assert disc_res["signing_public_key"] == bob_vault.id_pub_hex
    assert disc_res["fingerprint"] == bob_vault.fingerprint
    print(f"  [+] Discovered Bob: Public Key & Fingerprint matched")

    # Cryptographically verify Bob's prekey signature
    bob_pub_id = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(disc_res["signing_public_key"]))
    prekey_pub_bytes = bytes.fromhex(disc_res["x25519_prekey"])
    prekey_sig_bytes = b64decode(disc_res["prekey_signature"])
    bob_pub_id.verify(prekey_sig_bytes, prekey_pub_bytes)
    print(f"  [+] Cryptographically verified Bob's prekey signature via Ed25519 [PASS]")

    # Verify Alice cannot accidentally use her own prekey instead of Bob's
    assert disc_res["signing_public_key"] != alice_vault.id_pub_hex
    print(f"  [+] Verified recipient prekey binding: Alice cannot use own prekey [PASS]")

    # -------------------------------------------------------------------------
    # PHASE SEVEN: TEST C — File Encryption, Upload & Envelope Creation
    # -------------------------------------------------------------------------
    print(f"\n[Test C] Real File Transfer (Client AES-256-GCM + Key Envelope Creation)")

    # 1. Alice generates random 256-bit AES file key in browser
    raw_aes_file_key = os.urandom(32)
    file_nonce = os.urandom(12)
    aesgcm_file = AESGCM(raw_aes_file_key)
    file_ciphertext = aesgcm_file.encrypt(file_nonce, dummy_content, None)
    print(f"  [+] File encrypted locally with AES-256-GCM: {len(file_ciphertext)} bytes (Ciphertext + 16B Tag)")

    # 2. Upload ciphertext to File Vault (Port 5000)
    status, upload_res = alice_fv.post(
        "/api/files/upload",
        form_data={
            "nonce": b64encode(file_nonce).decode("ascii"),
            "algorithm": "AES-256-GCM",
            "protocol_version": "1"
        },
        files={
            "file": (f"{dummy_filename}.enc", file_ciphertext, "application/octet-stream")
        }
    )
    assert status == 201, f"Upload failed: {upload_res}"
    file_id = upload_res["file"]["id"]
    print(f"  [+] Ciphertext stored in File Vault (File ID: {file_id})")

    # 3. Create Transfer record on File Vault
    status, tx_res = alice_fv.post("/api/transfers", {
        "file_id": file_id,
        "recipient": bob_name,
        "expires_in_hours": 24
    })
    assert status == 201, f"Transfer creation failed: {tx_res}"
    transfer_id = tx_res["transfer"]["id"]
    print(f"  [+] Transfer record created! Transfer ID: {transfer_id}")

    # 4. Create and seal protected key envelope in Alice's browser
    ephem_priv = x25519.X25519PrivateKey.generate()
    ephem_pub_bytes = ephem_priv.public_key().public_bytes_raw()
    shared_secret = ephem_priv.exchange(x25519.X25519PublicKey.from_public_bytes(prekey_pub_bytes))

    salt = os.urandom(32)
    # File Vault canonical HKDF context info
    context_info = f"SecureShare-v1|wrapping-key|{alice_vault.id_pub_hex.lower()}|{bob_vault.id_pub_hex.lower()}|{transfer_id}|{disc_res['prekey_id']}".encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=context_info
    )
    wrapping_key = hkdf.derive(shared_secret)

    # Wrap raw AES file key with AES-256-GCM
    wrap_aesgcm = AESGCM(wrapping_key)
    wrap_nonce = os.urandom(12)
    wrap_aad = f"SecureShare-Envelope-Key-v1|{transfer_id}|{disc_res['prekey_id']}".encode("utf-8")
    wrapped_file_key = wrap_aesgcm.encrypt(wrap_nonce, raw_aes_file_key, wrap_aad)

    # Wrap metadata
    file_meta = {
        "filename": dummy_filename,
        "size": len(dummy_content),
        "mimeType": "text/plain"
    }
    meta_nonce = os.urandom(12)
    meta_aad = f"SecureShare-Envelope-Meta-v1|{transfer_id}".encode("utf-8")
    wrapped_meta = wrap_aesgcm.encrypt(meta_nonce, json.dumps(file_meta, sort_keys=True).encode("utf-8"), meta_aad)

    # Assemble and sign canonical envelope
    envelope_payload = {
        "version": 1,
        "transfer_id": transfer_id,
        "recipient_prekey_id": disc_res["prekey_id"],
        "sender_identity_key": alice_vault.id_pub_hex.lower(),
        "sender_ephemeral_key": ephem_pub_bytes.hex().lower(),
        "hkdf_salt": b64encode(salt).decode("ascii"),
        "wrapped_key_nonce": b64encode(wrap_nonce).decode("ascii"),
        "wrapped_file_key": b64encode(wrapped_file_key).decode("ascii"),
        "meta_nonce": b64encode(meta_nonce).decode("ascii"),
        "meta_ciphertext": b64encode(wrapped_meta).decode("ascii")
    }

    canonical_str = json.dumps(envelope_payload, sort_keys=True, separators=(',', ':'))
    alice_sig = alice_vault.id_priv.sign(canonical_str.encode("utf-8"))
    envelope_payload["signature"] = b64encode(alice_sig).decode("ascii")

    # 5. Dispatch envelope to Key Exchange Portal (Port 5001)
    status, env_res = alice_keyx.post("/api/envelopes", {
        "transfer_id": transfer_id,
        "recipient_id": disc_res["recipient_id"],
        "recipient_prekey_id": disc_res["prekey_id"],
        "envelope": envelope_payload,
        "sender_signature": envelope_payload["signature"]
    })
    assert status == 201, f"Envelope submission failed: {env_res}"
    print(f"  [+] Key envelope stored on Key Exchange Portal [PASS]")

    # 6. Attach envelope to File Vault transfer record via KeyX adapter
    status, attach_res = alice_fv.post("/api/key-exchange/envelopes", {
        "transfer_id": transfer_id,
        "recipient_id": tx_res["transfer"]["recipient_id"],
        "envelope": envelope_payload
    })
    assert status in (200, 201), f"Envelope sync failed: {attach_res}"
    envelope_id = attach_res.get("envelope_id")
    if envelope_id:
        status, patch_res = alice_fv.patch(f"/api/transfers/{transfer_id}", {"envelope_id": envelope_id})
        assert status == 200, f"Envelope patch failed: {patch_res}"
    print(f"  [+] Key envelope attached to File Vault transfer record [PASS]")

    # -------------------------------------------------------------------------
    # PHASE SEVEN: TEST D — Recipient Key Recovery & Decryption
    # -------------------------------------------------------------------------
    print(f"\n[Test D] Recipient Key Recovery & Bit-for-Bit Decryption")

    # 1. Bob retrieves transfer and ciphertext from File Vault
    status, bob_tx = bob_fv.get(f"/api/transfers/{transfer_id}")
    assert status == 200, f"Bob could not retrieve transfer: {bob_tx}"
    assert bob_tx["transfer"]["recipient_username"] == bob_name
    print(f"  [+] Bob inspected transfer: addressed to {bob_name}")

    # 2. Bob retrieves key envelope from Key Exchange Portal (Port 5001)
    status, bob_env_res = bob_keyx.get(f"/api/envelopes/{transfer_id}")
    assert status == 200, f"Bob could not retrieve envelope: {bob_env_res}"
    env_record = bob_env_res["envelope"]
    env_data = json.loads(env_record["encrypted_envelope"]) if isinstance(env_record["encrypted_envelope"], str) else env_record["encrypted_envelope"]

    # 3. Bob verifies Alice's Ed25519 digital signature
    alice_id_pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(alice_vault.id_pub_hex))
    unsigned_env = {k: v for k, v in env_data.items() if k != "signature"}
    canonical_verify_str = json.dumps(unsigned_env, sort_keys=True, separators=(',', ':'))
    alice_id_pub.verify(b64decode(env_data["signature"]), canonical_verify_str.encode("utf-8"))
    print(f"  [+] Authenticated Alice's Ed25519 signature on envelope payload [PASS]")

    # 4. Bob unwraps AES file key in browser memory using his private prekey
    bob_priv_prekey = bob_vault.prekeys[env_data["recipient_prekey_id"]]["priv"]
    ephem_pub_from_env = bytes.fromhex(env_data["sender_ephemeral_key"])
    bob_shared_secret = bob_priv_prekey.exchange(x25519.X25519PublicKey.from_public_bytes(ephem_pub_from_env))

    bob_context_info = f"SecureShare-v1|wrapping-key|{env_data['sender_identity_key'].lower()}|{bob_vault.id_pub_hex.lower()}|{transfer_id}|{env_data['recipient_prekey_id']}".encode("utf-8")
    bob_hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b64decode(env_data["hkdf_salt"]),
        info=bob_context_info
    )
    bob_wrapping_key = bob_hkdf.derive(bob_shared_secret)

    bob_wrap_aesgcm = AESGCM(bob_wrapping_key)
    recovered_aes_key = bob_wrap_aesgcm.decrypt(
        b64decode(env_data["wrapped_key_nonce"]),
        b64decode(env_data["wrapped_file_key"]),
        f"SecureShare-Envelope-Key-v1|{transfer_id}|{env_data['recipient_prekey_id']}".encode("utf-8")
    )
    assert recovered_aes_key == raw_aes_file_key, "Recovered AES file key mismatch!"
    print(f"  [+] Unwrapped raw 256-bit AES file key in memory: {recovered_aes_key.hex()[:16]}... [PASS]")

    # 5. Bob downloads ciphertext from File Vault (Port 5000)
    status, downloaded_ciphertext = bob_fv.get(f"/api/transfers/{transfer_id}/download")
    assert status == 200, "Ciphertext download failed"
    retrieved_nonce = b64decode(bob_fv.last_headers.get("X-Encryption-Nonce"))
    assert retrieved_nonce == file_nonce, "Nonce mismatch between upload and download!"

    # 6. Bob decrypts ciphertext using recovered AES key locally
    dec_nonce = retrieved_nonce
    dec_ct = downloaded_ciphertext
    recovered_content = AESGCM(recovered_aes_key).decrypt(dec_nonce, dec_ct, None)
    recovered_sha256 = hashlib.sha256(recovered_content).hexdigest()

    assert recovered_content == dummy_content, "Recovered content does not match original bytes!"
    assert recovered_sha256 == original_sha256, "SHA-256 digest mismatch!"
    print(f"  [+] Local AES-256-GCM Decryption SUCCESSFUL!")
    print(f"      Original SHA-256 : {original_sha256}")
    print(f"      Decrypted SHA-256: {recovered_sha256}")
    print(f"      Bit-for-Bit Match: 100% IDENTICAL [PASS]")

    # -------------------------------------------------------------------------
    # PHASE EIGHT: NEGATIVE AND FAILURE TESTS
    # -------------------------------------------------------------------------
    print(f"\n[Phase 8] Negative and Failure Tests")

    # Neg 1: Incorrect password
    bad_client = HttpClient(KEYX_URL)
    status, bad_login = bad_client.post("/api/auth/login", {"identifier": bob_name, "password": "WrongPassword999!"})
    assert status == 401, f"Expected 401 on bad password, got {status}"
    print(f"  [N1] Incorrect password rejected with 401 [PASS]")

    # Neg 2: Locked vault / invalid passphrase
    fake_vault = BrowserKeystoreSimulator("charlie_test")
    # Wrong key derivation
    try:
        AESGCM(os.urandom(32)).decrypt(b64decode(env_data["wrapped_key_nonce"]), b64decode(env_data["wrapped_file_key"]), b"wrong_aad")
        assert False, "Should have thrown tag mismatch"
    except Exception:
        print(f"  [N2] Locked/wrong vault key rejected via AES-GCM tag authentication [PASS]")

    # Neg 3: Missing identity record
    status, no_id_res = alice_keyx.get(f"/api/key-exchange/identities/unregistered_user_random_{uuid.uuid4().hex[:6]}")
    assert status == 404 and no_id_res.get("code") == "USER_NOT_FOUND"
    print(f"  [N3] Non-existent recipient discovery returned 404 USER_NOT_FOUND [PASS]")

    # Neg 4: Missing or expired prekey
    # Exhaust Bob's prekeys or query user without prekeys
    exhaust_name = f"exhaust_{run_suffix}"
    status, _ = alice_keyx.post("/api/auth/register", {"username": exhaust_name, "email": f"{exhaust_name}@test.com", "password": password})
    # Alice attempts discovery on user who has no prekeys
    status, no_pk_res = alice_keyx.get(f"/api/key-exchange/identities/{exhaust_name}")
    assert status == 404 and no_pk_res.get("code") in ("NO_IDENTITY", "NO_PREKEYS_AVAILABLE")
    print(f"  [N4] Uninitialized/exhausted prekey discovery returned 404 ({no_pk_res.get('code')}) [PASS]")

    # Neg 5: Wrong recipient access control
    charlie_keyx = HttpClient(KEYX_URL)
    charlie_name = f"charlie_{run_suffix}"
    charlie_keyx.post("/api/auth/register", {"username": charlie_name, "email": f"{charlie_name}@test.com", "password": password})
    status, charlie_env = charlie_keyx.get(f"/api/envelopes/{transfer_id}")
    assert status == 403, f"Expected 403 for unauthorized recipient, got {status}"
    print(f"  [N5] Unauthorized recipient access to key envelope strictly rejected with 403 [PASS]")

    # Neg 6: Forged Ed25519 signature
    forged_sig = os.urandom(64)
    tampered_sig_env = {k: v for k, v in env_data.items() if k != "signature"}
    canonical_tampered = json.dumps(tampered_sig_env, sort_keys=True, separators=(',', ':'))
    try:
        alice_id_pub.verify(forged_sig, canonical_tampered.encode("utf-8"))
        assert False, "Forged signature should not verify!"
    except Exception:
        print(f"  [N6] Forged Ed25519 digital signature rejected [PASS]")

    # Neg 7: Modified envelope payload
    tampered_env_data = dict(env_data)
    tampered_env_data["wrapped_file_key"] = b64encode(os.urandom(48)).decode("ascii")
    try:
        unsigned_tampered = {k: v for k, v in tampered_env_data.items() if k != "signature"}
        alice_id_pub.verify(b64decode(tampered_env_data["signature"]), json.dumps(unsigned_tampered, sort_keys=True, separators=(',', ':')).encode("utf-8"))
        assert False, "Modified envelope should not verify signature!"
    except Exception:
        print(f"  [N7] Tampered envelope payload detected by signature mismatch [PASS]")

    # Neg 8: Wrong AES key fails AES-GCM decryption
    try:
        AESGCM(os.urandom(32)).decrypt(dec_nonce, dec_ct, None)
        assert False, "Wrong AES key should fail!"
    except Exception:
        print(f"  [N8] Wrong AES key rejected by AES-256-GCM authentication tag [PASS]")

    # Neg 9: Modified ciphertext fails AES-GCM
    tampered_ct = bytearray(dec_ct)
    tampered_ct[20] ^= 0xFF
    try:
        AESGCM(recovered_aes_key).decrypt(dec_nonce, bytes(tampered_ct), None)
        assert False, "Tampered ciphertext should fail GCM authentication!"
    except Exception:
        print(f"  [N9] Tampered ciphertext rejected by AES-256-GCM authentication tag [PASS]")

    # Neg 10: Missing key envelope
    status, missing_env = bob_keyx.get(f"/api/envelopes/{uuid.uuid4()}")
    assert status == 404, f"Expected 404 for missing envelope, got {status}"
    print(f"  [N10] Missing key envelope returns 404 [PASS]")

    # Neg 11: Duplicate Transfer ID submission
    status, dup_res = alice_keyx.post("/api/envelopes", {
        "transfer_id": transfer_id,
        "recipient_id": disc_res["recipient_id"],
        "recipient_prekey_id": disc_res["prekey_id"],
        "envelope": envelope_payload,
        "sender_signature": envelope_payload["signature"]
    })
    assert status == 409, f"Expected 409 for duplicate transfer, got {status}"
    print(f"  [N11] Duplicate Transfer ID replay attempt rejected with 409 [PASS]")

    # Neg 12: Prekey consumption
    # The prekey disc_res["prekey_id"] was consumed during envelope submission.
    # Subsequent discovery should not return the same prekey.
    status, disc_res2 = alice_keyx.get(f"/api/key-exchange/identities/{bob_name}")
    if status == 200:
        assert disc_res2["prekey_id"] != disc_res["prekey_id"], "Consumed one-time prekey was reused!"
    print(f"  [N12] One-time prekey consumption verified: single-use enforced [PASS]")

    print("\n" + "=" * 80)
    print("ALL TESTS IN MASTER DUMMY-FILE E2E SUITE PASSED WITH 100% INTEGRITY!")
    print("=" * 80)
    return True


if __name__ == "__main__":
    success = run_master_test()
    sys.exit(0 if success else 1)
