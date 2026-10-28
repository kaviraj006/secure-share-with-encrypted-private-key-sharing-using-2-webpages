import urllib.request
import urllib.parse
import http.cookiejar
import json
import os
import sys
import uuid
from base64 import b64encode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

KEYX_URL = "http://127.0.0.1:5001"

class HttpClient:
    def __init__(self, base_url):
        self.base_url = base_url
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))
        self.csrf_token = None

    def get_csrf(self):
        status, data = self.request("GET", "/api/auth/csrf")
        if status == 200 and isinstance(data, dict):
            self.csrf_token = data.get("csrf_token")
        return self.csrf_token

    def request(self, method, path, json_data=None):
        url = self.base_url + path
        headers = {"Accept": "application/json"}
        req_body = None

        if not self.csrf_token and method in ("POST", "PUT", "DELETE"):
            self.get_csrf()

        if self.csrf_token and "X-CSRF-Token" not in headers:
            headers["X-CSRF-Token"] = self.csrf_token

        if json_data is not None:
            req_body = json.dumps(json_data).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=req_body, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                if isinstance(data, dict) and data.get("csrf_token"):
                    self.csrf_token = data.get("csrf_token")
                return resp.status, data
        except urllib.error.HTTPError as e:
            try:
                data = json.loads(e.read().decode())
            except Exception:
                data = {"error": str(e)}
            return e.code, data

def run():
    print("=== Testing Unauthenticated Prekey Reservation & Envelope Dispatch ===")
    
    # 1. Discover recipient 'allen'
    anon_client = HttpClient(KEYX_URL)
    status, d_res = anon_client.request("GET", "/api/identities/allen")
    assert status == 200, f"Discovery failed: {d_res}"
    recipient_id = d_res["user_id"]
    recipient_ed_pk = d_res["identity"]["ed25519_public_key"]

    status, pk_res = anon_client.request("GET", f"/api/prekeys/{recipient_id}")
    assert status == 200, f"Prekey discovery failed: {pk_res}"
    prekey_id = pk_res["prekey"]["id"]
    prekey_pub_bytes = bytes.fromhex(pk_res["prekey"]["x25519_public_key"])
    print(f"[+] Discovered recipient 'allen' (ID: {recipient_id}, Prekey: {prekey_id})")

    # 2. Reserve recipient prekey WITHOUT being logged in!
    status, res_data = anon_client.request("POST", f"/api/prekeys/{prekey_id}/reserve")
    assert status == 200, f"Prekey reservation without login failed ({status}): {res_data}"
    print(f"[+] Successfully reserved prekey '{prekey_id}' without requiring login session! [PASS]")

    # 3. Create real cryptographic envelope
    sender_priv = ed25519.Ed25519PrivateKey.generate()
    sender_pub_bytes = sender_priv.public_key().public_bytes_raw()
    
    eph_priv = x25519.X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes_raw()
    
    shared_secret = eph_priv.exchange(x25519.X25519PublicKey.from_public_bytes(prekey_pub_bytes))
    
    transfer_id = str(uuid.uuid4())
    salt = os.urandom(32)
    raw_aes_key = os.urandom(32)
    
    context_info = f"SecureShare-v1|wrapping-key|{sender_pub_bytes.hex().lower()}|{recipient_ed_pk.lower()}|{transfer_id}|{prekey_id}".encode("utf-8")
    wrapping_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=context_info).derive(shared_secret)
    
    wrap_nonce = os.urandom(12)
    wrap_aad = f"SecureShare-Envelope-Key-v1|{transfer_id}|{prekey_id}".encode("utf-8")
    wrapped_file_key = AESGCM(wrapping_key).encrypt(wrap_nonce, raw_aes_key, wrap_aad)
    
    envelope_payload = {
        "version": 1,
        "transfer_id": transfer_id,
        "recipient_prekey_id": prekey_id,
        "sender_identity_key": sender_pub_bytes.hex().lower(),
        "sender_ephemeral_key": eph_pub_bytes.hex().lower(),
        "hkdf_salt": b64encode(salt).decode("ascii"),
        "wrapped_key_nonce": b64encode(wrap_nonce).decode("ascii"),
        "wrapped_file_key": b64encode(wrapped_file_key).decode("ascii"),
        "meta_nonce": b64encode(os.urandom(12)).decode("ascii"),
        "meta_ciphertext": b64encode(os.urandom(16)).decode("ascii")
    }
    
    canonical_str = json.dumps(envelope_payload, sort_keys=True, separators=(',', ':'))
    sig = sender_priv.sign(canonical_str.encode("utf-8"))
    envelope_payload["signature"] = b64encode(sig).decode("ascii")
    
    # 4. Submit envelope WITHOUT being logged in!
    status, env_res = anon_client.request("POST", "/api/envelopes", {
        "transfer_id": transfer_id,
        "recipient_id": recipient_id,
        "recipient_prekey_id": prekey_id,
        "envelope": envelope_payload,
        "sender_signature": envelope_payload["signature"]
    })
    assert status == 201, f"Envelope submission without login failed ({status}): {env_res}"
    print(f"[+] Successfully sealed and dispatched key envelope for transfer '{transfer_id}' without login! [PASS]")

    # 5. Replay attempt with same transfer_id returns 409
    status, dup_res = anon_client.request("POST", "/api/envelopes", {
        "transfer_id": transfer_id,
        "recipient_id": recipient_id,
        "recipient_prekey_id": prekey_id,
        "envelope": envelope_payload,
        "sender_signature": envelope_payload["signature"]
    })
    assert status == 409 and dup_res.get("code") == "DUPLICATE_TRANSFER_ID"
    print(f"[+] Replay attempt with duplicate transfer ID rejected with 409 [PASS]")

    print("\n" + "=" * 70)
    print("ALL PREKEY RESERVATION & ENVELOPE DISPATCH TESTS PASSED 100%!")
    print("=" * 70)
    return True

if __name__ == "__main__":
    success = run()
    sys.exit(0 if success else 1)
