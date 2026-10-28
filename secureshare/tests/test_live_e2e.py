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

BASE_URL = "http://127.0.0.1:5000"

def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'))

class HttpClient:
    def __init__(self):
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))

    def request(self, method, path, data=None, json_data=None, headers=None, files=None):
        url = BASE_URL + path
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

def run_live_two_account_test():
    print("=== LIVE E2E SENDER-TO-RECIPIENT TWO-ACCOUNT TEST ===")
    alice = HttpClient()
    bob = HttpClient()

    suffix = uuid.uuid4().hex[:6]
    alice_username = f"alice_{suffix}"
    bob_username = f"bob_{suffix}"
    password = "StrongPassword123!Safe"

    # Step 1: Alice registers
    status, body, _ = alice.request("GET", "/api/auth/csrf")
    assert status == 200
    csrf_alice = json.loads(body)["csrf_token"]

    status, body, _ = alice.request("POST", "/api/auth/register", json_data={
        "username": alice_username,
        "email": f"{alice_username}@example.com",
        "password": password
    }, headers={"X-CSRF-Token": csrf_alice})
    assert status == 201, f"Alice register failed: {body.decode()}"
    alice_data = json.loads(body)
    alice_id = alice_data["user"]["id"]
    csrf_alice = alice_data.get("csrf_token", csrf_alice)
    print(f"[OK] 1. Alice registered: {alice_username} ({alice_id})")

    # Alice publishes public identity bundle
    alice_ed_sk = ed25519.Ed25519PrivateKey.generate()
    alice_ed_pk_hex = alice_ed_sk.public_key().public_bytes_raw().hex()
    alice_pre_sk = x25519.X25519PrivateKey.generate()
    alice_pre_pk_hex = alice_pre_sk.public_key().public_bytes_raw().hex()

    status, body, _ = alice.request("POST", "/api/key-exchange/identities", json_data={
        "signing_public_key": alice_ed_pk_hex,
        "x25519_prekey": alice_pre_pk_hex,
        "fingerprint": f"FA:CE:{suffix[:2]}:{suffix[2:4]}:00:11:22:33:44:55:66:77:88:99:AA:BB",
        "prekey_id": f"prekey_alice_{suffix}"
    }, headers={"X-CSRF-Token": csrf_alice})
    assert status == 200, f"Alice publish failed: {body.decode()}"
    print(f"[OK] 2. Alice published identity bundle (signing pk: {alice_ed_pk_hex[:16]}...)")

    # Step 2: Bob registers
    status, body, _ = bob.request("GET", "/api/auth/csrf")
    assert status == 200
    csrf_bob = json.loads(body)["csrf_token"]

    status, body, _ = bob.request("POST", "/api/auth/register", json_data={
        "username": bob_username,
        "email": f"{bob_username}@example.com",
        "password": password
    }, headers={"X-CSRF-Token": csrf_bob})
    assert status == 201, f"Bob register failed: {body.decode()}"
    bob_data = json.loads(body)
    bob_id = bob_data["user"]["id"]
    csrf_bob = bob_data.get("csrf_token", csrf_bob)
    print(f"[OK] 3. Bob registered: {bob_username} ({bob_id})")

    # Bob publishes public identity bundle with X25519 prekey
    bob_ed_sk = ed25519.Ed25519PrivateKey.generate()
    bob_ed_pk_hex = bob_ed_sk.public_key().public_bytes_raw().hex()
    bob_pre_sk = x25519.X25519PrivateKey.generate()
    bob_pre_pk_hex = bob_pre_sk.public_key().public_bytes_raw().hex()
    bob_prekey_id = f"prekey_bob_{suffix}"

    status, body, _ = bob.request("POST", "/api/key-exchange/identities", json_data={
        "signing_public_key": bob_ed_pk_hex,
        "x25519_prekey": bob_pre_pk_hex,
        "fingerprint": f"BB:BB:{suffix[:2]}:{suffix[2:4]}:00:11:22:33:44:55:66:77:88:99:AA:BB",
        "prekey_id": bob_prekey_id
    }, headers={"X-CSRF-Token": csrf_bob})
    assert status == 200, f"Bob publish failed: {body.decode()}"
    print(f"[OK] 4. Bob published prekey bundle (prekey: {bob_pre_pk_hex[:16]}...)")

    # Step 3: Alice discovers Bob's public bundle
    status, body, _ = alice.request("GET", f"/api/key-exchange/identities/{bob_username}")
    assert status == 200, f"Discovery failed: {body.decode()}"
    bob_bundle = json.loads(body)
    assert bob_bundle["x25519_prekey"] == bob_pre_pk_hex
    print(f"[OK] 5. Alice discovered Bob's prekey bundle")

    # Step 4: Alice encrypts file locally with random AES-256-GCM key
    original_plaintext = b"SECURESHARE TOP SECRET PAYLOAD DATA -- VERIFY CLIENT DECRYPTION" * 50
    file_aes_key = AESGCM.generate_key(bit_length=256)
    file_nonce = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
    ciphertext = AESGCM(file_aes_key).encrypt(file_nonce, original_plaintext, None)

    # Step 5: Alice uploads ciphertext only
    status, body, _ = alice.request("POST", "/api/files/upload", files={
        "file": ("confidential.pdf.enc", io.BytesIO(ciphertext), "application/octet-stream")
    }, data={
        "nonce": b64encode(file_nonce).decode(),
        "algorithm": "AES-256-GCM",
        "protocol_version": "1"
    }, headers={"X-CSRF-Token": csrf_alice})
    assert status == 201, f"Ciphertext upload failed: {body.decode()}"
    file_id = json.loads(body)["file"]["id"]
    print(f"[OK] 6. Ciphertext uploaded to server ({len(ciphertext)} bytes)")

    # Step 6: Alice creates transfer to obtain real Transfer ID
    status, body, _ = alice.request("POST", "/api/transfers", json_data={
        "recipient": bob_username,
        "file_id": file_id,
        "expires_in_hours": 24
    }, headers={"X-CSRF-Token": csrf_alice})
    assert status == 201, f"Transfer creation failed: {body.decode()}"
    transfer_id = json.loads(body)["transfer"]["id"]
    print(f"[OK] 7. Transfer created with real UUID: {transfer_id}")

    # Step 7: Alice creates protected key envelope with real transfer_id
    alice_ephemeral_sk = x25519.X25519PrivateKey.generate()
    alice_ephemeral_pk_hex = alice_ephemeral_sk.public_key().public_bytes_raw().hex()

    bob_prekey_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(bob_bundle["x25519_prekey"]))
    shared_secret = alice_ephemeral_sk.exchange(bob_prekey_pub)

    salt = b"\x99" * 32
    context_info = f"SecureShare-v1|wrapping-key|{alice_ed_pk_hex}|{bob_ed_pk_hex}|{transfer_id}|{bob_prekey_id}".encode()
    wrapping_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=context_info).derive(shared_secret)

    wrap_nonce = b"\x77" * 12
    key_aad = f"SecureShare-Envelope-Key-v1|{transfer_id}|{bob_prekey_id}".encode()
    wrapped_file_key = AESGCM(wrapping_key).encrypt(wrap_nonce, file_aes_key, key_aad)

    meta_payload = {"filename": "audit_report.pdf", "size": len(original_plaintext), "mimeType": "application/pdf"}
    meta_nonce = b"\x88" * 12
    meta_aad = f"SecureShare-Envelope-Meta-v1|{transfer_id}".encode()
    wrapped_meta = AESGCM(wrapping_key).encrypt(meta_nonce, canonical_json(meta_payload).encode(), meta_aad)

    envelope_payload = {
        "version": 1,
        "transfer_id": transfer_id,
        "recipient_prekey_id": bob_prekey_id,
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

    # Alice submits envelope
    status, body, _ = alice.request("POST", "/api/key-exchange/envelopes", json_data={
        "transfer_id": transfer_id,
        "recipient_id": bob_id,
        "envelope": envelope_payload
    }, headers={"X-CSRF-Token": csrf_alice})
    assert status == 201, f"Envelope submit failed: {body.decode()}"
    envelope_id = json.loads(body)["envelope_id"]

    # Alice attaches envelope to transfer
    status, body, _ = alice.request("PATCH", f"/api/transfers/{transfer_id}", json_data={
        "envelope_id": envelope_id
    }, headers={"X-CSRF-Token": csrf_alice})
    assert status == 200, f"Transfer patch failed: {body.decode()}"
    print(f"[OK] 8. Key envelope submitted and bound to transfer")

    # Step 8: Bob inspects transfer
    status, body, _ = bob.request("GET", f"/api/transfers/{transfer_id}")
    assert status == 200, f"Bob transfer lookup failed: {body.decode()}"
    tx_data = json.loads(body)["transfer"]
    assert tx_data["recipient_username"] == bob_username
    print(f"[OK] 9. Bob inspected transfer ({tx_data['id']})")

    # Step 9: Bob retrieves envelope
    status, body, _ = bob.request("GET", f"/api/key-exchange/envelopes/{transfer_id}")
    assert status == 200, f"Bob envelope fetch failed: {body.decode()}"
    retrieved_envelope = json.loads(body)["envelope"]
    assert retrieved_envelope["transfer_id"] == transfer_id
    print(f"[OK] 10. Bob retrieved encrypted key envelope")

    # Step 10: Bob verifies Alice's signature
    unsigned_env = {k: v for k, v in retrieved_envelope.items() if k != "signature"}
    alice_pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(retrieved_envelope["sender_identity_key"]))
    alice_pub_key.verify(b64decode(retrieved_envelope["signature"]), canonical_json(unsigned_env).encode())
    print(f"[OK] 11. Bob verified Alice's Ed25519 signature successfully")

    # Step 11: Bob derives wrapping key with his private X25519 prekey
    alice_ephem_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(retrieved_envelope["sender_ephemeral_key"]))
    bob_shared_secret = bob_pre_sk.exchange(alice_ephem_pub)
    assert bob_shared_secret == shared_secret

    bob_wrapping_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=b64decode(retrieved_envelope["hkdf_salt"]), info=context_info).derive(bob_shared_secret)
    assert bob_wrapping_key == wrapping_key
    print(f"[OK] 12. Bob derived HKDF-SHA-256 wrapping key using private prekey")

    # Step 12: Bob unwraps AES file key
    recovered_file_key = AESGCM(bob_wrapping_key).decrypt(
        b64decode(retrieved_envelope["wrapped_key_nonce"]),
        b64decode(retrieved_envelope["wrapped_file_key"]),
        key_aad
    )
    assert recovered_file_key == file_aes_key
    print(f"[OK] 13. Bob unwrapped AES file key (length: {len(recovered_file_key)*8} bits)")

    # Step 13: Bob downloads ciphertext
    status, downloaded_ciphertext, headers = bob.request("GET", f"/api/transfers/{transfer_id}/download")
    assert status == 200, f"Download failed: {status}"
    downloaded_nonce = b64decode(headers.get("X-Encryption-Nonce"))
    print(f"[OK] 14. Bob downloaded ciphertext ({len(downloaded_ciphertext)} bytes)")

    # Step 14: Bob decrypts locally with AES-256-GCM
    decrypted_plaintext = AESGCM(recovered_file_key).decrypt(downloaded_nonce, downloaded_ciphertext, None)
    assert decrypted_plaintext == original_plaintext, "Decrypted bytes mismatch!"
    print(f"[OK] 15. Decrypted bytes match original bit-for-bit!")
    print(f"       Original size : {len(original_plaintext)} bytes")
    print(f"       Decrypted size: {len(decrypted_plaintext)} bytes")

    print("\n=== ALL 15 LIVE VERIFICATION STEPS PASSED SUCCESSFULLY! ===")

if __name__ == "__main__":
    run_live_two_account_test()
