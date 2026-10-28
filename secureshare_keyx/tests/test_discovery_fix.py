import urllib.request
import urllib.parse
import http.cookiejar
import json
import sys
import uuid

KEYX_URL = "http://127.0.0.1:5001"
FV_URL = "http://127.0.0.1:5000"

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

def run_tests():
    print("--- 1. Testing Unauthenticated Public Discovery ---")
    client = HttpClient(KEYX_URL)
    
    # 1. Discover by username
    status, d1 = client.request("GET", "/api/identities/allen")
    assert status == 200 and d1["username"] == "allen"
    print(f"  [+] Discovered 'allen' by username: ID={d1['user_id']}")
    allen_id = d1["user_id"]

    # 2. Discover by UUID
    status, d2 = client.request("GET", f"/api/identities/{allen_id}")
    assert status == 200 and d2["username"] == "allen"
    print(f"  [+] Discovered 'allen' by UUID ({allen_id})")

    # 3. Discover kaviraj1 by username & UUID
    status, d3 = client.request("GET", "/api/identities/kaviraj1")
    assert status == 200 and d3["username"] == "kaviraj1"
    kaviraj_id = d3["user_id"]
    print(f"  [+] Discovered 'kaviraj1' by username: ID={kaviraj_id}")

    status, d4 = client.request("GET", f"/api/identities/{kaviraj_id}")
    assert status == 200 and d4["username"] == "kaviraj1"
    print(f"  [+] Discovered 'kaviraj1' by UUID")

    # 4. Prekeys discovery without auth
    status, pk1 = client.request("GET", "/api/prekeys/allen")
    assert status == 200 and "prekey" in pk1
    print(f"  [+] Discovered prekey for 'allen': Prekey ID={pk1['prekey']['id']}")

    status, pk2 = client.request("GET", f"/api/prekeys/{allen_id}")
    assert status == 200 and "prekey" in pk2
    print(f"  [+] Discovered prekey for 'allen' by UUID")

    status, pk3 = client.request("GET", "/api/prekeys/kaviraj1")
    assert status == 200 and "prekey" in pk3
    print(f"  [+] Discovered prekey for 'kaviraj1': Prekey ID={pk3['prekey']['id']}")

    # 5. Search without auth
    status, s1 = client.request("GET", "/api/users/search?q=allen")
    assert status == 200 and len(s1["users"]) > 0
    print(f"  [+] User search by username 'allen' returned {len(s1['users'])} result(s)")

    status, s2 = client.request("GET", f"/api/users/search?q={allen_id[:8]}")
    assert status == 200 and len(s2["users"]) > 0
    print(f"  [+] User search by partial UUID prefix returned {len(s2['users'])} result(s)")

    print("\n--- 2. Testing Adding Contacts by Username and by ID ---")
    test_user = f"contact_tester_{uuid.uuid4().hex[:6]}"
    auth_client = HttpClient(KEYX_URL)
    status, reg = auth_client.request("POST", "/api/auth/register", {
        "username": test_user,
        "email": f"{test_user}@test.org",
        "password": "Password123!"
    })
    assert status == 201
    print(f"  [+] Registered active testing user: {test_user}")

    # Add contact by username
    status, c1 = auth_client.request("POST", "/api/contacts", {"username": "allen"})
    assert status == 201, f"Failed to add allen by username: {c1}"
    print(f"  [+] Added contact 'allen' by username: {c1['contact']['contact_username']}")

    # Add contact by ID
    status, c2 = auth_client.request("POST", "/api/contacts", {"username": kaviraj_id})
    assert status == 201, f"Failed to add kaviraj1 by ID: {c2}"
    assert c2["contact"]["contact_username"] == "kaviraj1"
    print(f"  [+] Added contact 'kaviraj1' by User ID ({kaviraj_id}): resolved to '{c2['contact']['contact_username']}'")

    # List contacts
    status, clist = auth_client.request("GET", "/api/contacts")
    assert status == 200 and len(clist["contacts"]) >= 2
    contact_names = [c["contact_username"] for c in clist["contacts"]]
    assert "allen" in contact_names and "kaviraj1" in contact_names
    print(f"  [+] Contact list verified: {contact_names}")

    print("\n" + "=" * 60)
    print("ALL DISCOVERY AND CONTACT ADD TESTS PASSED WITH 100% SUCCESS!")
    print("=" * 60)
    return True

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
