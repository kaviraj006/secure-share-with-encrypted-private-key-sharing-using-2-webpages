import pytest
from app.models import User, PublicIdentity, PublicPrekey, KeyEnvelope, TrustedContact

def test_full_exchange_lifecycle(client):
    # 1. Register Alice (Recipient)
    reg_alice = client.post("/api/auth/register", json={
        "username": "alice_keys",
        "email": "alice_keys@internal.secureshare",
        "password": "Password123!Industrial"
    })
    assert reg_alice.status_code == 201
    alice_id = reg_alice.get_json()["user"]["id"]
    csrf_alice = reg_alice.get_json()["csrf_token"]
    
    # 2. Alice publishes Identity Key
    alice_ed25519_pk = "a" * 64
    alice_fp = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
    res = client.post("/api/identities", json={
        "ed25519_public_key": alice_ed25519_pk,
        "fingerprint": alice_fp
    }, headers={"X-CSRF-Token": csrf_alice})
    assert res.status_code in (200, 201)
    
    # 3. Alice publishes Signed Prekey
    alice_prekey_id = "prekey_alice_001"
    res = client.post("/api/prekeys", json={
        "prekey_id": alice_prekey_id,
        "x25519_public_key": "b" * 64,
        "signature": "sig_prekey_alice_001",
        "days_valid": 14
    }, headers={"X-CSRF-Token": csrf_alice})
    assert res.status_code == 201
    
    # Alice logs out
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_alice})
    
    # 4. Register Bob (Sender)
    reg_bob = client.post("/api/auth/register", json={
        "username": "bob_sender",
        "email": "bob_sender@internal.secureshare",
        "password": "Password123!Industrial"
    })
    assert reg_bob.status_code == 201
    bob_id = reg_bob.get_json()["user"]["id"]
    csrf_bob = reg_bob.get_json()["csrf_token"]
    
    # Bob publishes Identity Key
    bob_ed25519_pk = "c" * 64
    bob_fp = "11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF"
    client.post("/api/identities", json={
        "ed25519_public_key": bob_ed25519_pk,
        "fingerprint": bob_fp
    }, headers={"X-CSRF-Token": csrf_bob})
    
    # 5. Bob searches for Alice & adds contact
    search_res = client.get("/api/users/search?q=alice")
    assert search_res.status_code == 200
    assert len(search_res.get_json()["users"]) == 1
    
    add_contact_res = client.post("/api/contacts", json={
        "username": "alice_keys"
    }, headers={"X-CSRF-Token": csrf_bob})
    assert add_contact_res.status_code == 201
    contact_data = add_contact_res.get_json()["contact"]
    assert contact_data["verification_status"] == "UNVERIFIED"
    assert contact_data["trusted_fingerprint"] == alice_fp
    contact_id = contact_data["id"]
    
    # 6. Bob performs out-of-band verification of Alice's fingerprint
    verify_res = client.post(f"/api/contacts/{contact_id}/verify", json={
        "fingerprint": alice_fp
    }, headers={"X-CSRF-Token": csrf_bob})
    assert verify_res.status_code == 200
    assert verify_res.get_json()["contact"]["verification_status"] == "VERIFIED"
    
    # 7. Bob fetches Alice's prekey for key agreement
    prekey_res = client.get(f"/api/prekeys/alice_keys")
    assert prekey_res.status_code == 200
    pk_info = prekey_res.get_json()["prekey"]
    assert pk_info["id"] == alice_prekey_id
    
    # Bob reserves the prekey
    reserve_res = client.post(f"/api/prekeys/{alice_prekey_id}/reserve", headers={"X-CSRF-Token": csrf_bob})
    assert reserve_res.status_code == 200
    
    # 8. Bob submits encrypted envelope
    transfer_id = "tx_e2e_889900"
    envelope_payload = {
        "transfer_id": transfer_id,
        "recipient_id": alice_id,
        "recipient_prekey_id": alice_prekey_id,
        "encrypted_envelope": {
            "version": 1,
            "ephemeral_x25519_public_key": "d" * 64,
            "wrapped_aes_key": "aabbccddeeff11223344",
            "nonce": "112233445566",
            "salt": "778899001122"
        },
        "sender_signature": "bob_valid_ed25519_signature"
    }
    env_post_res = client.post("/api/envelopes", json=envelope_payload, headers={"X-CSRF-Token": csrf_bob})
    assert env_post_res.status_code == 201
    
    # Verify prekey is now marked CONSUMED
    pk_after = client.get(f"/api/prekeys/alice_keys")
    assert pk_after.status_code == 404
    
    # 9. Alice logs back in, inspects inbox
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_bob})
    login_alice = client.post("/api/auth/login", json={
        "identifier": "alice_keys",
        "password": "Password123!Industrial"
    })
    csrf_alice = login_alice.get_json()["csrf_token"]
    
    inbox_res = client.get("/api/envelopes/inbox")
    assert inbox_res.status_code == 200
    inbox = inbox_res.get_json()["inbox"]
    assert len(inbox) == 1
    assert inbox[0]["transfer_id"] == transfer_id
    assert inbox[0]["sender_username"] == "bob_sender"
    assert inbox[0]["status"] == "PENDING"
    
    # Alice marks envelope accepted
    accept_res = client.post(f"/api/envelopes/{transfer_id}/accept", headers={"X-CSRF-Token": csrf_alice})
    assert accept_res.status_code == 200
    assert accept_res.get_json()["status"] == "ACCEPTED"
    
    # Verify transfer history
    hist_alice = client.get("/api/transfers")
    assert hist_alice.status_code == 200
    transfers = hist_alice.get_json()["received"]
    assert len(transfers) == 1
    assert transfers[0]["status"] == "ACCEPTED"

def test_cross_portal_integration_routes(client):
    # Setup user
    reg = client.post("/api/auth/register", json={
        "username": "portal_user",
        "email": "portal@secureshare.internal",
        "password": "Password123!Industrial"
    })
    csrf = reg.get_json()["csrf_token"]
    portal_id = reg.get_json()["user"]["id"]
    
    client.post("/api/identities", json={
        "ed25519_public_key": "8" * 64,
        "fingerprint": "88:88:88:88:88:88:88:88:88:88:88:88:88:88:88:88"
    }, headers={"X-CSRF-Token": csrf})
    
    client.post("/api/prekeys", json={
        "prekey_id": "portal_pk_1",
        "x25519_public_key": "9" * 64,
        "signature": "sig_pk_1",
        "days_valid": 7
    }, headers={"X-CSRF-Token": csrf})
    
    # Test cross-portal discovery route
    disc = client.get("/api/key-exchange/identities/portal_user")
    assert disc.status_code == 200
    data = disc.get_json()
    assert data["recipient_username"] == "portal_user"
    assert data["fingerprint"] == "88:88:88:88:88:88:88:88:88:88:88:88:88:88:88:88"
    assert data["x25519_prekey"] == "9" * 64
    
    # Test cross-portal envelope submission
    env_res = client.post("/api/key-exchange/envelopes", json={
        "transfer_id": "tx_cross_portal_99",
        "sender_id": portal_id,
        "recipient_id": portal_id,
        "envelope": {
            "version": 1,
            "wrapped_aes_key": "aabbcc112233",
            "signature": "sig_portal"
        }
    })
    assert env_res.status_code == 201
    
    # Test cross-portal envelope fetch
    fetch_res = client.get("/api/key-exchange/envelopes/tx_cross_portal_99")
    assert fetch_res.status_code == 200
    assert fetch_res.get_json()["transfer_id"] == "tx_cross_portal_99"
