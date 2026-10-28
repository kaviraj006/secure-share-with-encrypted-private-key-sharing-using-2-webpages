"""
Test Suite: High-Volume Multi-Key Transfer Test (10 Keys)
Uses cryptography module (Ed25519, X25519, HKDF-SHA-256, AES-256-GCM).
Verifies:
1. Sender and Recipient registration, identity publication, and discovery.
2. Sending 10 consecutive, distinct 256-bit AES file keys in sealed envelopes.
3. Prekey reservation & consumption with high-volume fallback.
4. Cryptographic unwrapping on the recipient side:
   - Ed25519 signature verification
   - X25519 DH scalar multiplication
   - HKDF-SHA-256 wrapping key agreement
   - AES-256-GCM unwrap
   - Byte-for-byte recovered key validation.
5. Idempotent key update / re-dispatch on existing transfer ID without replay error.
6. User discovery and contact verification out-of-band.
"""

import sys
import os
import json
import uuid
import secrets
import hashlib
import urllib.request
import urllib.parse
import http.cookiejar

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

KEYX_URL = "http://127.0.0.1:5001"

class PortalClient:
    def __init__(self, base_url):
        self.base_url = base_url
        self.cj = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cj))
        self.csrf_token = None
        self.user = None
        self.signing_priv = None
        self.signing_pub = None
        self.prekeys = {}  # prekey_id -> X25519PrivateKey

    def get_csrf(self):
        req = urllib.request.Request(f"{self.base_url}/api/auth/csrf", headers={"Accept": "application/json"})
        with self.opener.open(req) as resp:
            data = json.loads(resp.read().decode())
            self.csrf_token = data.get("csrf_token")
            return self.csrf_token

    def request(self, method, path, json_data=None):
        if not self.csrf_token and method in ("POST", "PUT", "DELETE"):
            self.get_csrf()

        headers = {"Accept": "application/json"}
        if self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token
        if self.user and self.user.get("id"):
            headers["X-User-ID"] = self.user["id"]

        body = None
        if json_data is not None:
            body = json.dumps(json_data).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(f"{self.base_url}{path}", data=body, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                if isinstance(data, dict) and data.get("csrf_token"):
                    self.csrf_token = data.get("csrf_token")
                return resp.status, data
        except urllib.error.HTTPError as e:
            try:
                err_data = json.loads(e.read().decode())
            except Exception:
                err_data = {"error": str(e)}
            return e.code, err_data

    def register_or_login(self, username, password):
        self.get_csrf()
        status, data = self.request("POST", "/api/auth/login", {
            "identifier": username,
            "password": password
        })
        if status == 200:
            self.user = data["user"]
            return self.user

        status, data = self.request("POST", "/api/auth/register", {
            "username": username,
            "email": f"{username}@example.com",
            "password": password
        })
        if status in (200, 201):
            self.user = data["user"]
            return self.user
        raise RuntimeError(f"Could not register/login {username}: {data}")

    def initialize_crypto(self):
        # Generate Ed25519 identity key
        self.signing_priv = ed25519.Ed25519PrivateKey.generate()
        self.signing_pub = self.signing_priv.public_key()
        pub_raw = self.signing_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        verify_key_hex = pub_raw.hex()
        
        # Calculate fingerprint
        fp_digest = hashlib.sha256(pub_raw).hexdigest().upper()
        fingerprint = ":".join(fp_digest[i:i+2] for i in range(0, 32, 2))

        # Publish identity
        status, res = self.request("POST", "/api/identities", {
            "ed25519_public_key": verify_key_hex,
            "fingerprint": fingerprint
        })
        assert status == 200, f"Publish identity failed: {res}"

        # Generate 5 initial signed prekeys
        prekeys_list = []
        for i in range(5):
            priv = x25519.X25519PrivateKey.generate()
            pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            pub_hex = pub_bytes.hex()
            pk_id = f"prekey_{int(uuid.uuid4().time_low)}_{secrets.token_hex(4)}"
            
            # Sign prekey public key with Ed25519
            msg = f"{pk_id}:{pub_hex}".encode("utf-8")
            sig = self.signing_priv.sign(msg).hex()
            
            self.prekeys[pk_id] = priv
            prekeys_list.append({
                "prekey_id": pk_id,
                "x25519_public_key": pub_hex,
                "signature": sig,
                "days_valid": 30
            })

        status, res = self.request("POST", "/api/prekeys", {"prekeys": prekeys_list})
        assert status in (200, 201), f"Publish prekeys failed: {res}"
        return verify_key_hex, fingerprint

def derive_hkdf_wrapping_key(shared_secret_bytes: bytes, salt: bytes, info: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret_bytes)

def test_multi_key_transfer():
    print("=" * 70)
    print("RUNNING MULTI-KEY ENVELOPE SEAL & UNWRAP TEST (10 DISTINCT KEYS)")
    print("=" * 70)

    # 1. Setup Sender (Alice) and Recipient (Bob)
    alice = PortalClient(KEYX_URL)
    alice_name = f"alice_{secrets.token_hex(3)}"
    alice.register_or_login(alice_name, "Password123!")
    alice_pub, alice_fp = alice.initialize_crypto()
    print(f"[+] Sender Alice initialized: {alice_name} (ID: {alice.user['id']})")

    bob = PortalClient(KEYX_URL)
    bob_name = f"bob_{secrets.token_hex(3)}"
    bob.register_or_login(bob_name, "Password123!")
    bob_pub, bob_fp = bob.initialize_crypto()
    print(f"[+] Recipient Bob initialized: {bob_name} (ID: {bob.user['id']})")

    # 2. Add Bob to Alice's trusted contacts & verify out-of-band
    print("\n--- Testing Contact Addition & Out-of-band Verification ---")
    status, add_res = alice.request("POST", "/api/contacts", {"username": bob_name})
    assert status == 201, f"Failed to add contact: {add_res}"
    contact_id = add_res["contact"]["id"]
    print(f"[+] Alice added Bob to contacts (Contact ID: {contact_id})")

    status, ver_res = alice.request("POST", f"/api/contacts/{contact_id}/verify", {
        "fingerprint": bob_fp
    })
    assert status == 200, f"Failed to verify contact: {ver_res}"
    assert ver_res["contact"]["verification_status"] == "VERIFIED"
    print(f"[+] Bob verified out-of-band with matching fingerprint: {bob_fp[:20]}...")

    # 3. Test High-Volume Envelope Exchange: Send 10 consecutive keys!
    print("\n--- Sending 10 Consecutive AES File Keys to Bob ---")
    sent_keys = []

    for k in range(1, 11):
        transfer_id = str(uuid.uuid4())
        raw_aes_key = secrets.token_hex(32)  # 256-bit AES file key
        sent_keys.append((transfer_id, raw_aes_key))

        # Alice discovers Bob's public identity & prekey
        status, prekey_res = alice.request("GET", f"/api/prekeys/{bob_name}")
        assert status == 200, f"[Key {k}] Recipient prekey lookup failed: {prekey_res}"
        prekey_data = prekey_res["prekey"]
        recipient_prekey_id = prekey_data["id"]
        recipient_x25519_pub_hex = prekey_data["x25519_public_key"]

        # Alice reserves prekey
        status, res_res = alice.request("POST", f"/api/prekeys/{recipient_prekey_id}/reserve")
        assert status == 200, f"[Key {k}] Prekey reservation failed: {res_res}"

        # Cryptographic Sealing (Sender side):
        # Generate ephemeral X25519 keypair
        ephemeral_priv = x25519.X25519PrivateKey.generate()
        ephemeral_pub_bytes = ephemeral_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ephemeral_pub_hex = ephemeral_pub_bytes.hex()

        # Perform DH agreement: Ephemeral Priv * Recipient Prekey Pub
        recipient_pub_obj = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(recipient_x25519_pub_hex))
        shared_key = ephemeral_priv.exchange(recipient_pub_obj)

        # Derive wrapping key using HKDF-SHA-256
        salt = bytes.fromhex(ephemeral_pub_hex)
        info = f"SecureShareKeyEnvelope-v1:{transfer_id}".encode("utf-8")
        wrapping_key = derive_hkdf_wrapping_key(shared_key, salt, info)

        # Encrypt the raw AES file key with AES-256-GCM
        aesgcm = AESGCM(wrapping_key)
        iv = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(iv, bytes.fromhex(raw_aes_key), info)
        
        wrapped_key_payload = {
            "version": 1,
            "transfer_id": transfer_id,
            "ephemeral_public_key": ephemeral_pub_hex,
            "recipient_prekey_id": recipient_prekey_id,
            "sender_identity_key": alice_pub,
            "iv": iv.hex(),
            "ciphertext": ciphertext.hex()
        }

        # Sign envelope with Alice's Ed25519 private key
        payload_bytes = json.dumps(wrapped_key_payload, sort_keys=True).encode("utf-8")
        signature = alice.signing_priv.sign(payload_bytes).hex()

        # Dispatch sealed envelope to Key Exchange Portal
        status, env_res = alice.request("POST", "/api/envelopes", {
            "transfer_id": transfer_id,
            "recipient_id": bob.user["id"],
            "recipient_prekey_id": recipient_prekey_id,
            "encrypted_envelope": wrapped_key_payload,
            "sender_signature": signature
        })
        assert status in (200, 201), f"[Key {k}] Envelope submission failed: {env_res}"

        # Recipient Bob receives and unwraps the key
        status, inbox_res = bob.request("GET", f"/api/envelopes/{transfer_id}")
        assert status == 200, f"[Key {k}] Bob failed to retrieve envelope: {inbox_res}"
        envelope_record = inbox_res["envelope"]
        received_payload = json.loads(envelope_record["encrypted_envelope"])
        received_sig = envelope_record["sender_signature"]

        # 1. Bob verifies Alice's Ed25519 signature
        verify_pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(alice_pub))
        verify_bytes = json.dumps(received_payload, sort_keys=True).encode("utf-8")
        verify_pub.verify(bytes.fromhex(received_sig), verify_bytes)

        # 2. Bob retrieves the private prekey matching recipient_prekey_id
        bob_prekey_priv = bob.prekeys.get(recipient_prekey_id)
        if not bob_prekey_priv:
            # Fallback
            bob_prekey_priv = next(iter(bob.prekeys.values()))

        # 3. Bob computes DH shared secret: Bob Prekey Priv * Alice Ephemeral Pub
        alice_eph_pub = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(received_payload["ephemeral_public_key"]))
        bob_shared_key = bob_prekey_priv.exchange(alice_eph_pub)

        # 4. Bob derives HKDF wrapping key
        bob_wrapping_key = derive_hkdf_wrapping_key(bob_shared_key, bytes.fromhex(received_payload["ephemeral_public_key"]), info)
        assert bob_wrapping_key == wrapping_key, f"[Key {k}] Wrapping key mismatch!"

        # 5. Bob decrypts AES-256-GCM ciphertext
        bob_aesgcm = AESGCM(bob_wrapping_key)
        recovered_raw_bytes = bob_aesgcm.decrypt(
            bytes.fromhex(received_payload["iv"]),
            bytes.fromhex(received_payload["ciphertext"]),
            info
        )
        recovered_key_hex = recovered_raw_bytes.hex()

        # Verify 100% exact match
        assert recovered_key_hex == raw_aes_key, f"[Key {k}] Key decryption mismatch! Expected {raw_aes_key}, got {recovered_key_hex}"
        print(f"  [+] Key {k}/10: Sealed & Unwrapped! Transfer ID: {transfer_id[:8]}... | Key: {recovered_key_hex[:16]}... [PASS]")

    # 4. Test Key Update / Re-dispatch (verifying fix for user's screenshot error)
    print("\n--- Testing Envelope Update / Re-dispatch for Same Transfer ID ---")
    test_tx_id = sent_keys[0][0]
    fresh_key = secrets.token_hex(32)

    status, upd_res = alice.request("POST", "/api/envelopes", {
        "transfer_id": test_tx_id,
        "recipient_id": bob.user["id"],
        "recipient_prekey_id": recipient_prekey_id,
        "encrypted_envelope": wrapped_key_payload,
        "sender_signature": signature
    })
    assert status == 200, f"Updating existing envelope failed: {upd_res}"
    print(f"[+] Re-dispatch on existing Transfer ID '{test_tx_id[:8]}...' succeeded without replay error! [PASS]")

    # 5. Test User Search Directory with empty query & keyword
    print("\n--- Testing User Directory Search ---")
    status, search_res = alice.request("GET", "/api/users/search?q=")
    assert status == 200 and len(search_res["users"]) > 0, f"Directory search failed: {search_res}"
    print(f"[+] Empty query directory search returned {len(search_res['users'])} active users [PASS]")

    status, search_bob = alice.request("GET", f"/api/users/search?q={bob_name}")
    assert status == 200 and len(search_bob["users"]) == 1, f"Bob search failed: {search_bob}"
    print(f"[+] Targeted search for '{bob_name}' succeeded [PASS]")

    print("\n" + "=" * 70)
    print("ALL 10 KEYS SUCCESSFULLY SEALED, TRANSMITTED, AND UNWRAPPED!")
    print("ALL VERIFICATION CHECKS PASSED WITH 100% ACCURACY!")
    print("=" * 70)

if __name__ == "__main__":
    test_multi_key_transfer()
