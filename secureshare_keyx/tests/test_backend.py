import json
from datetime import datetime, timezone, timedelta
from app.extensions import db
from app.models import User, PublicIdentity, PublicPrekey, KeyEnvelope, TrustedContact, SecurityEvent

def test_auth_workflow(client):
    # 1. Register User
    reg = client.post("/api/auth/register", json={
        "username": "alice_op",
        "email": "alice_op@keyx.internal",
        "password": "Password123!Industrial"
    })
    assert reg.status_code == 201
    csrf = reg.get_json()["csrf_token"]
    
    # 2. Check /api/auth/me
    me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.get_json()["user"]["username"] == "alice_op"
    
    # 3. Duplicate registration rejected
    dup = client.post("/api/auth/register", json={
        "username": "alice_op",
        "email": "diff@keyx.internal",
        "password": "Password123!Industrial"
    }, headers={"X-CSRF-Token": csrf})
    assert dup.status_code == 409
    
    # 4. Logout
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    
    # 5. Invalid login rejected
    bad = client.post("/api/auth/login", json={"identifier": "alice_op", "password": "WrongPassword"})
    assert bad.status_code == 401
    
    # 6. Valid login
    good = client.post("/api/auth/login", json={"identifier": "alice_op", "password": "Password123!Industrial"})
    assert good.status_code == 200

def test_identity_and_prekey_lifecycle(client):
    reg = client.post("/api/auth/register", json={
        "username": "bob_crypto",
        "email": "bob@keyx.internal",
        "password": "Password123!Industrial"
    })
    csrf = reg.get_json()["csrf_token"]
    
    # Publish Identity
    signing_pk = "01" * 32
    fp = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
    id_resp = client.post("/api/identities", json={
        "ed25519_public_key": signing_pk,
        "fingerprint": fp
    }, headers={"X-CSRF-Token": csrf})
    assert id_resp.status_code == 200
    
    # Publish Prekey
    prekey_id = "prekey_001"
    x25519_pk = "02" * 32
    pk_resp = client.post("/api/prekeys", json={
        "prekey_id": prekey_id,
        "x25519_public_key": x25519_pk,
        "signature": "mock_sig_base64",
        "days_valid": 30
    }, headers={"X-CSRF-Token": csrf})
    assert pk_resp.status_code == 201
    
    # Reserve Prekey
    res_resp = client.post(f"/api/prekeys/{prekey_id}/reserve", headers={"X-CSRF-Token": csrf})
    assert res_resp.status_code == 200
    
    # Double reserve rejected
    res_dup = client.post(f"/api/prekeys/{prekey_id}/reserve", headers={"X-CSRF-Token": csrf})
    assert res_dup.status_code == 409
    
    # Consume Prekey
    cons_resp = client.post(f"/api/prekeys/{prekey_id}/consume", headers={"X-CSRF-Token": csrf})
    assert cons_resp.status_code == 200
    
    # Double consumption rejected
    cons_dup = client.post(f"/api/prekeys/{prekey_id}/consume", headers={"X-CSRF-Token": csrf})
    assert cons_dup.status_code == 409

def test_envelope_exchange_and_authorization(client, app):
    # Register Alice (Sender)
    reg_alice = client.post("/api/auth/register", json={
        "username": "sender_1",
        "email": "sender_1@keyx.internal",
        "password": "Password123!Industrial"
    })
    alice_id = reg_alice.get_json()["user"]["id"]
    csrf_alice = reg_alice.get_json()["csrf_token"]
    
    # Register Bob (Recipient)
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_alice})
    reg_bob = client.post("/api/auth/register", json={
        "username": "recipient_1",
        "email": "recipient_1@keyx.internal",
        "password": "Password123!Industrial"
    })
    bob_id = reg_bob.get_json()["user"]["id"]
    csrf_bob = reg_bob.get_json()["csrf_token"]
    
    # Bob publishes prekey
    client.post("/api/prekeys", json={
        "prekey_id": "bob_pk_99",
        "x25519_public_key": "03" * 32,
        "signature": "sig_mock",
        "days_valid": 10
    }, headers={"X-CSRF-Token": csrf_bob})
    
    # Login Alice
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_bob})
    log_a = client.post("/api/auth/login", json={"identifier": "sender_1", "password": "Password123!Industrial"})
    csrf_alice = log_a.get_json()["csrf_token"]
    
    # Alice submits envelope for Bob
    transfer_id = "tx_secure_1001"
    env_data = {
        "transfer_id": transfer_id,
        "recipient_id": bob_id,
        "recipient_prekey_id": "bob_pk_99",
        "encrypted_envelope": {"cipher": "AES_WRAPPED_KEY_MOCK"},
        "sender_signature": "mock_ed25519_sig"
    }
    sub_resp = client.post("/api/envelopes", json=env_data, headers={"X-CSRF-Token": csrf_alice})
    assert sub_resp.status_code == 201
    
    # Replay defense: duplicate transfer_id rejected
    replay_resp = client.post("/api/envelopes", json=env_data, headers={"X-CSRF-Token": csrf_alice})
    assert replay_resp.status_code == 409
    
    # Unauthorized third party cannot access envelope
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_alice})
    reg_eve = client.post("/api/auth/register", json={"username": "eve_hacker", "email": "eve@keyx.internal", "password": "Password123!Industrial"})
    csrf_eve = reg_eve.get_json()["csrf_token"]
    
    unauth = client.get(f"/api/envelopes/{transfer_id}")
    assert unauth.status_code == 403
    
    # Bob logs in and accesses envelope
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_eve})
    login_bob = client.post("/api/auth/login", json={"identifier": "recipient_1", "password": "Password123!Industrial"})
    csrf_bob = login_bob.get_json()["csrf_token"]
    inbox = client.get("/api/envelopes/inbox")
    assert inbox.status_code == 200
    assert len(inbox.get_json()["inbox"]) == 1
    
    bob_get = client.get(f"/api/envelopes/{transfer_id}")
    assert bob_get.status_code == 200
    assert bob_get.get_json()["envelope"]["sender_signature"] == "mock_ed25519_sig"

def test_contact_key_change_detection(client):
    # Register Alice
    reg_alice = client.post("/api/auth/register", json={
        "username": "alice_watch",
        "email": "alice_w@keyx.internal",
        "password": "Password123!Industrial"
    })
    csrf_alice = reg_alice.get_json()["csrf_token"]
    
    # Register Charlie & publish identity
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_alice})
    reg_charlie = client.post("/api/auth/register", json={
        "username": "charlie_target",
        "email": "charlie@keyx.internal",
        "password": "Password123!Industrial"
    })
    csrf_charlie = reg_charlie.get_json()["csrf_token"]
    client.post("/api/identities", json={
        "ed25519_public_key": "11" * 32,
        "fingerprint": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11"
    }, headers={"X-CSRF-Token": csrf_charlie})
    
    # Alice logs in and adds Charlie
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_charlie})
    log_a = client.post("/api/auth/login", json={"identifier": "alice_watch", "password": "Password123!Industrial"})
    csrf_alice = log_a.get_json()["csrf_token"]
    add_c = client.post("/api/contacts", json={"username": "charlie_target"}, headers={"X-CSRF-Token": csrf_alice})
    assert add_c.status_code == 201
    contact_id = add_c.get_json()["contact"]["id"]
    
    # Alice verifies Charlie's fingerprint
    client.post(f"/api/contacts/{contact_id}/verify", json={
        "fingerprint": "11:11:11:11:11:11:11:11:11:11:11:11:11:11:11:11"
    }, headers={"X-CSRF-Token": csrf_alice})
    
    # Charlie rotates key
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_alice})
    log_c = client.post("/api/auth/login", json={"identifier": "charlie_target", "password": "Password123!Industrial"})
    csrf_charlie = log_c.get_json()["csrf_token"]
    client.post("/api/identities", json={
        "ed25519_public_key": "22" * 32,
        "fingerprint": "22:22:22:22:22:22:22:22:22:22:22:22:22:22:22:22"
    }, headers={"X-CSRF-Token": csrf_charlie})
    
    # Alice checks contacts -> KEY CHANGED detected!
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf_charlie})
    log_a2 = client.post("/api/auth/login", json={"identifier": "alice_watch", "password": "Password123!Industrial"})
    csrf_alice = log_a2.get_json()["csrf_token"]
    c_list = client.get("/api/contacts")
    assert c_list.status_code == 200
    contact_entry = c_list.get_json()["contacts"][0]
    assert contact_entry["verification_status"] == "KEY CHANGED"

def test_security_events_logged(client):
    reg = client.post("/api/auth/register", json={
        "username": "sec_auditor",
        "email": "audit@keyx.internal",
        "password": "Password123!Industrial"
    })
    events_resp = client.get("/api/security-events")
    assert events_resp.status_code == 200
    events = events_resp.get_json()["events"]
    assert len(events) >= 1
    assert any(e["event_type"] == "IDENTITY_REGISTERED" for e in events)

def test_spa_and_static_routes(client):
    # Test SPA entrypoint returns 200 and loads HTML
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"SECURESHARE" in resp.data
    assert b"KEY EXCHANGE" in resp.data
    
    # Test other SPA routes also serve index.html
    for route in ["/identity", "/contacts", "/keys", "/exchange", "/envelopes", "/history", "/logs", "/settings"]:
        r = client.get(route)
        assert r.status_code == 200
        assert b"SECURESHARE" in r.data
        
    # Test static assets serve successfully
    css = client.get("/static/css/styles.css")
    assert css.status_code == 200
    assert b"--bg-core" in css.data
    
    favicon = client.get("/static/favicon.svg")
    assert favicon.status_code == 200
