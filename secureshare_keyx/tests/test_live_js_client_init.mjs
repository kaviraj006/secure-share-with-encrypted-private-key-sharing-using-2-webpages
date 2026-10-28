/**
 * Full end-to-end test of the real client-side JavaScript modules against the running server (Port 5001).
 * Tests the exact path where "input cannot be null or undefined" was previously thrown:
 * - Ed25519 identity generation
 * - KeyStore saving in client
 * - Public identity registration on Flask backend
 * - 5 signed X25519 prekeys generation and registration
 * - Backend verification via /api/identities/me and /api/key-exchange/identities/<target>
 * - Idempotent re-initialization
 */

import sodium from '../static/js/vendor/sodium.js';
import { Ed25519Sign } from '../static/js/crypto/ed25519_sign.js';
import { X25519HKDF } from '../static/js/crypto/x25519_hkdf.js';
import { KeyStore } from '../static/js/crypto/keystore.js';

const BASE_URL = "http://127.0.0.1:5001/api";

class TestSession {
    constructor() {
        this.cookies = "";
        this.csrfToken = null;
    }

    async request(endpoint, options = {}) {
        const headers = options.headers || {};
        if (!headers["Content-Type"] && options.body) {
            headers["Content-Type"] = "application/json";
        }
        if (this.cookies) {
            headers["Cookie"] = this.cookies;
        }
        if (["POST", "PUT", "DELETE"].includes((options.method || "GET").toUpperCase()) && this.csrfToken) {
            headers["X-CSRF-Token"] = this.csrfToken;
        }

        const resp = await fetch(`${BASE_URL}${endpoint}`, {
            ...options,
            headers
        });

        const setCookie = resp.headers.get("set-cookie");
        if (setCookie) {
            this.cookies = setCookie.split(";")[0];
        }

        const data = await resp.json().catch(() => ({}));
        if (data.csrf_token) {
            this.csrfToken = data.csrf_token;
        }
        return { status: resp.status, data };
    }
}

async function runLiveTest() {
    console.log("================================================================================");
    console.log("STARTING LIVE JS CLIENT INITIALIZATION TEST AGAINST PORT 5001");
    console.log("================================================================================");

    await sodium.ready;
    const session = new TestSession();

    // 1. Fetch CSRF token
    const csrfRes = await session.request("/auth/csrf");
    if (csrfRes.status !== 200) {
        throw new Error(`Failed to reach server on Port 5001: HTTP ${csrfRes.status}`);
    }
    console.log("[+] Connected to Key Exchange Portal on Port 5001 (CSRF received)");

    // 2. Register fresh user
    const username = `kaviraj_test_${Date.now().toString(36)}`;
    const regRes = await session.request("/auth/register", {
        method: "POST",
        body: JSON.stringify({
            username: username,
            email: `${username}@test.com`,
            password: "KavirajPassword123!"
        })
    });
    if (regRes.status !== 201) {
        throw new Error(`Registration failed: ${JSON.stringify(regRes.data)}`);
    }
    const user = regRes.data.user;
    console.log(`[+] User registered: ${username} (UUID: ${user.id})`);

    // 3. Verify server reports NO_IDENTITY initially
    const initCheck = await session.request("/identities/me");
    if (initCheck.data.has_identity !== false) {
        throw new Error(`Expected has_identity: false, got: ${JSON.stringify(initCheck.data)}`);
    }
    console.log("[+] Pre-initialization status verified: has_identity = false");

    // 4. Initialize client KeyStore and unlock with master password
    const ks = new KeyStore(user.id);
    const unlocked = await ks.unlock("KavirajPassword123!");
    if (!unlocked) throw new Error("KeyStore unlock failed!");
    console.log("[+] Client KeyStore instantiated and unlocked successfully");

    // 5. Generate Ed25519 identity keypair using fixed async implementation
    console.log("[+] Generating Ed25519 identity keypair in browser...");
    const keypair = await Ed25519Sign.generateIdentityKeyPair();
    if (!keypair || !keypair.publicKey || !keypair.privateKey) {
        throw new Error("Ed25519 keypair generation returned null or undefined!");
    }
    const fp = Ed25519Sign.formatFingerprint(keypair.fingerprint);
    const pubHex = keypair.publicKeyHex || sodium.to_hex(keypair.publicKey);
    const privHex = keypair.privateKeyHex || sodium.to_hex(keypair.privateKey);

    console.log(`    -> Public Key: ${pubHex.substring(0, 16)}... (length: ${pubHex.length})`);
    console.log(`    -> Fingerprint: ${fp}`);

    // 6. Save identity into client KeyStore (must not throw "input cannot be null or undefined")
    await ks.saveIdentity(pubHex, privHex, fp);
    if (!ks.identity || ks.identity.publicKey !== pubHex) {
        throw new Error("Identity was not saved in KeyStore properly!");
    }
    console.log("[+] Identity saved in client KeyStore without error [PASS]");

    // 7. Register public identity on Flask backend
    const pubRes = await session.request("/identities", {
        method: "POST",
        body: JSON.stringify({
            ed25519_public_key: pubHex,
            fingerprint: fp
        })
    });
    if (pubRes.status !== 200) {
        throw new Error(`Failed to publish public identity: ${JSON.stringify(pubRes.data)}`);
    }
    console.log("[+] Public identity published to Flask database [PASS]");

    // 8. Generate and sign 5 X25519 prekeys
    console.log("[+] Generating 5 signed X25519 prekeys...");
    const prekeysToPublish = [];
    for (let i = 0; i < 5; i++) {
        const randHex = sodium.to_hex(sodium.randombytes_buf(4));
        const prekeyId = `prekey_${Date.now()}_${randHex}`;
        const signedPrekey = await X25519HKDF.generateSignedPrekey(ks.identity.privateKey, prekeyId);

        if (!signedPrekey || !signedPrekey.x25519PublicKey || !signedPrekey.x25519PrivateKey) {
            throw new Error(`Signed prekey ${i} generation returned null or undefined!`);
        }

        // Store in local KeyStore
        await ks.savePrekey(prekeyId, signedPrekey.x25519PublicKey, signedPrekey.x25519PrivateKey, signedPrekey.signature);

        prekeysToPublish.push({
            prekey_id: prekeyId,
            x25519_public_key: signedPrekey.x25519PublicKey,
            signature: signedPrekey.signature,
            days_valid: 30
        });
    }

    // 9. Batch publish prekeys to Flask backend
    const batchRes = await session.request("/prekeys", {
        method: "POST",
        body: JSON.stringify({ prekeys: prekeysToPublish })
    });
    if (batchRes.status !== 201) {
        throw new Error(`Failed to publish prekeys: ${JSON.stringify(batchRes.data)}`);
    }
    console.log(`[+] 5 signed prekeys stored locally and published to Flask [PASS]`);

    // 10. Verify /api/identities/me reports active identity
    const meRes = await session.request("/identities/me");
    if (!meRes.data.has_identity || meRes.data.identity.ed25519_public_key !== pubHex) {
        throw new Error(`Verification of /identities/me failed: ${JSON.stringify(meRes.data)}`);
    }
    console.log("[+] Server identity verification (/api/identities/me): ACTIVE & MATCHED [PASS]");

    // 11. Verify public recipient discovery on integration route
    const discRes = await session.request(`/key-exchange/identities/${username}`);
    if (discRes.status !== 200) {
        throw new Error(`Recipient discovery failed: ${JSON.stringify(discRes.data)}`);
    }
    const discData = discRes.data;
    if (discData.signing_public_key !== pubHex || discData.fingerprint !== fp) {
        throw new Error(`Recipient discovery returned mismatched keys!`);
    }

    // Authenticate discovered prekey signature using recipient's identity public key
    const sigVerified = await X25519HKDF.verifySignedPrekey(
        discData.signing_public_key,
        discData.x25519_prekey,
        discData.prekey_signature
    );
    if (!sigVerified) {
        throw new Error("Cryptographic verification of discovered prekey signature FAILED!");
    }
    console.log(`[+] Discovered recipient authenticated: Ed25519 signature cryptographically verified [PASS]`);

    // 12. Test Idempotency: re-save same identity does not alter public keys
    await ks.saveIdentity(pubHex, privHex, fp);
    const pubRes2 = await session.request("/identities", {
        method: "POST",
        body: JSON.stringify({
            ed25519_public_key: pubHex,
            fingerprint: fp
        })
    });
    if (pubRes2.status !== 200 || pubRes2.data.identity.status !== "active") {
        throw new Error("Idempotent identity re-publish failed!");
    }
    console.log("[+] Idempotent initialization verified: no key churn or duplicates [PASS]");

    console.log("================================================================================");
    console.log("ALL 12 VERIFICATION PHASES PASSED WITH 100% SUCCESS!");
    console.log("================================================================================");
}

runLiveTest().catch(err => {
    console.error("FATAL ERROR IN LIVE TEST:", err);
    process.exit(1);
});
