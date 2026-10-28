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

KEYX_BASE = "http://127.0.0.1:5001"

def http_req(url, method="GET", data=None, headers=None):
    hdrs = {"Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            resp_body = resp.read().decode("utf-8")
            return resp.status, json.loads(resp_body) if resp_body else {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(err_body)
        except Exception:
            return e.code, {"error": err_body}

def test_transfer_envelope_overwrite_and_idempotency():
    print("=== Testing Transfer ID Envelope Overwrite, Integration & Idempotency ===")
    
    # 1. Create a brand new Transfer ID
    test_transfer_id = str(uuid.uuid4())
    print(f"[1] Generated new transfer_id: {test_transfer_id}")

    # 2. Simulate File Vault adapter calling Port 5001 /api/key-exchange/envelopes
    # using Port 5000 user UUIDs and usernames
    status, res_adapter = http_req(f"{KEYX_BASE}/api/key-exchange/envelopes", method="POST", data={
        "transfer_id": test_transfer_id,
        "sender_id": "vault-uuid-allen",
        "sender_username": "allen",
        "recipient_id": "vault-uuid-kaviraj",
        "recipient_username": "kaviraj",
        "envelope": {"dummy": "file_vault_draft_payload"}
    })
    assert status in (200, 201), f"Adapter call failed: {status} {res_adapter}"
    print(f"[2] File Vault adapter successfully created envelope: {res_adapter}")

    # 3. Now simulate user opening Port 5001 /exchange to seal the key for that transfer ID
    sender_sign_key = ed25519.Ed25519PrivateKey.generate()
    sender_sign_pub = sender_sign_key.public_key()
    sender_pub_bytes = sender_sign_pub.public_bytes_raw()

    recip_priv = x25519.X25519PrivateKey.generate()
    recip_pub = recip_priv.public_key()
    recip_pub_bytes = recip_pub.public_bytes_raw()

    # Ephemeral key and shared secret
    sender_eph_priv = x25519.X25519PrivateKey.generate()
    sender_eph_pub = sender_eph_priv.public_key()
    sender_eph_pub_bytes = sender_eph_pub.public_bytes_raw()

    shared_secret = sender_eph_priv.exchange(recip_pub)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"secureshare_salt_v1",
        info=b"secureshare_envelope_wrapping"
    )
    wrapping_key = hkdf.derive(shared_secret)

    # 256-bit AES file key
    raw_aes_key = os.urandom(32)
    nonce = os.urandom(12)
    aesgcm = AESGCM(wrapping_key)
    enc_payload = aesgcm.encrypt(nonce, raw_aes_key, None)

    sealed_envelope = {
        "version": 1,
        "transfer_id": test_transfer_id,
        "recipient_prekey_id": "test_prekey_1",
        "ephemeral_public_key": sender_eph_pub_bytes.hex(),
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(enc_payload).decode("utf-8")
    }

    canonical_bytes = json.dumps(sealed_envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = sender_sign_key.sign(canonical_bytes)
    sig_b64 = base64.urlsafe_b64encode(signature).decode("utf-8").rstrip("=")

    # Look up kaviraj on Port 5001
    _, search_res = http_req(f"{KEYX_BASE}/api/users/search?q=kaviraj")
    assert "users" in search_res, f"Search failed: {search_res}"
    users = search_res.get("users", [])
    kaviraj_user = next((u for u in users if u["username"].lower() == "kaviraj"), users[0])
    recip_uid = kaviraj_user["id"]
    prekey_id = kaviraj_user.get("prekey_id") or "test_prekey_1"

    # User submits sealed envelope on Port 5001 /api/envelopes
    status, seal_res = http_req(f"{KEYX_BASE}/api/envelopes", method="POST", data={
        "transfer_id": test_transfer_id,
        "sender_id": "portal-sender-uid",
        "recipient_id": recip_uid,
        "recipient_prekey_id": prekey_id,
        "encrypted_envelope": json.dumps(sealed_envelope),
        "sender_signature": sig_b64,
        "force_update": True
    })

    print(f"[3] Port 5001 seal response status: {status}")
    print(f"    Body: {seal_res}")
    assert status in (200, 201), f"Sealing failed! {status} {seal_res}"
    assert "DUPLICATE_TRANSFER_ID" not in str(seal_res), "DUPLICATE_TRANSFER_ID error returned!"
    assert "Replay" not in str(seal_res), "Replay error returned!"
    print("[PASS] User can seal envelope on Port 5001 for a newly created transfer ID!")

    # 4. Test replay protection: resubmitting exact identical payload without force_update gets 409
    status_2, seal_res_2 = http_req(f"{KEYX_BASE}/api/envelopes", method="POST", data={
        "transfer_id": test_transfer_id,
        "sender_id": "portal-sender-uid",
        "recipient_id": recip_uid,
        "recipient_prekey_id": prekey_id,
        "encrypted_envelope": json.dumps(sealed_envelope),
        "sender_signature": sig_b64
    })
    print(f"[4] Replay protection check status: {status_2}")
    assert status_2 == 409, f"Expected 409 replay rejection, got: {status_2} {seal_res_2}"
    print("[PASS] Replay protection active: identical duplicate envelope rejected with 409!")

    # 4b. Test authorized update with force_update: true
    status_2b, seal_res_2b = http_req(f"{KEYX_BASE}/api/envelopes", method="POST", data={
        "transfer_id": test_transfer_id,
        "sender_id": "portal-sender-uid",
        "recipient_id": recip_uid,
        "recipient_prekey_id": prekey_id,
        "encrypted_envelope": json.dumps(sealed_envelope),
        "sender_signature": sig_b64,
        "force_update": True
    })
    print(f"[4b] Authorized update check status: {status_2b}")
    assert status_2b == 200, f"Expected 200 with force_update, got: {status_2b} {seal_res_2b}"
    print("[PASS] Authorized update with force_update succeeds with 200!")

    # 5. Retrieve envelope as recipient
    status_3, get_res = http_req(f"{KEYX_BASE}/api/envelopes/{test_transfer_id}", headers={"X-User-ID": recip_uid})
    print(f"[5] Envelope retrieval status: {status_3}")
    assert status_3 == 200, f"Get envelope failed: {status_3} {get_res}"
    env_data = get_res["envelope"]
    assert env_data["transfer_id"] == test_transfer_id
    print(f"    Envelope sender: {env_data.get('sender_username')}, recipient: {env_data.get('recipient_username')}")
    print("[PASS] Recipient retrieved envelope successfully!")

    print("\n=== ALL TRANSFER REPLAY & ENVELOPE INTEGRATION TESTS PASSED 100% ===")

if __name__ == "__main__":
    test_transfer_envelope_overwrite_and_idempotency()
