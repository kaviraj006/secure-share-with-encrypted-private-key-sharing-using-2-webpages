/**
 * SecureShare // KEY EXCHANGE - JavaScript Cryptographic Test Suite (Node.js ESM)
 */

import sodium from '../static/js/vendor/sodium.js';
import { generateAesKey, generateNonce, exportRawKey, encryptBytes, decryptBytes } from '../static/js/crypto/aes_gcm.js';
import { generateIdentityKeypair, signData, verifySignature, computeFingerprint } from '../static/js/crypto/ed25519_sign.js';
import { generateSignedPrekey, generateEphemeralKeypair, computeSharedSecret, deriveWrappingKey } from '../static/js/crypto/x25519_hkdf.js';
import { createKeyEnvelope, openKeyEnvelope, canonicalJson } from '../static/js/crypto/envelope.js';
import { KeyStore } from '../static/js/crypto/keystore.js';

let passed = 0;
let failed = 0;

function assert(cond, name) {
    if (cond) {
        console.log(`[PASS] ${name}`);
        passed++;
    } else {
        console.error(`[FAIL] ${name}`);
        failed++;
    }
}

async function runAll() {
    console.log("=== STARTING SECURESHARE KEY EXCHANGE CRYPTO TEST SUITE ===");
    await sodium.ready;

    // 1. X25519 Shared Secret Agreement
    try {
        const alice = sodium.crypto_box_keypair();
        const bob = sodium.crypto_box_keypair();
        const sharedA = await computeSharedSecret(alice.privateKey, bob.publicKey);
        const sharedB = await computeSharedSecret(bob.privateKey, alice.publicKey);
        assert(sodium.memcmp(sharedA, sharedB), "1. X25519 Shared Secret Agreement");
    } catch (e) {
        assert(false, `1. X25519 DH: ${e.message}`);
    }

    // 2. Reject Invalid/All-Zero Public Key
    try {
        const alice = sodium.crypto_box_keypair();
        const zeroPk = new Uint8Array(32);
        let threw = false;
        try {
            await computeSharedSecret(alice.privateKey, zeroPk);
        } catch {
            threw = true;
        }
        assert(threw, "2. Reject Invalid/All-Zero X25519 Public Key");
    } catch (e) {
        assert(false, `2. Zero PK: ${e.message}`);
    }

    // 3. HKDF Key Derivation Consistency
    try {
        const shared = sodium.randombytes_buf(32);
        const salt = sodium.randombytes_buf(32);
        const info = "SecureShare-v1|wrapping-key|alice|bob|tx123|prekey1";
        const key1 = await deriveWrappingKey(shared, salt, info);
        const key2 = await deriveWrappingKey(shared, salt, info);
        const raw1 = await exportRawKey(key1);
        const raw2 = await exportRawKey(key2);
        assert(sodium.memcmp(raw1, raw2), "3. HKDF Key Derivation Consistency");
    } catch (e) {
        assert(false, `3. HKDF: ${e.message}`);
    }

    // 4. Ed25519 Valid Signature Verification
    try {
        const idKey = await generateIdentityKeypair();
        const msg = new TextEncoder().encode("Canonical Security Protocol Context");
        const sig = await signData(msg, idKey.privateKey);
        const valid = await verifySignature(sig, msg, idKey.publicKey);
        assert(valid, "4. Valid Ed25519 Signature Verification");
    } catch (e) {
        assert(false, `4. Ed25519: ${e.message}`);
    }

    // 5. Reject Invalid / Tampered Signature
    try {
        const idKey = await generateIdentityKeypair();
        const msg = new TextEncoder().encode("Security Event Authentic");
        const sig = await signData(msg, idKey.privateKey);
        const tamperedSig = new Uint8Array(sig);
        tamperedSig[0] ^= 0xFF;
        const valid = await verifySignature(tamperedSig, msg, idKey.publicKey);
        assert(!valid, "5. Reject Tampered Ed25519 Signature");
    } catch (e) {
        assert(false, `5. Tampered Sig: ${e.message}`);
    }

    // 6. Prekey Signing and Authenticity Verification
    try {
        const idKey = await generateIdentityKeypair();
        const prekey = await generateSignedPrekey(idKey);
        const sigBytes = sodium.from_base64(prekey.signature);
        const valid = await verifySignature(sigBytes, prekey.publicKey, idKey.publicKey);
        assert(valid, "6. Prekey Signed by Identity Key Verification");
    } catch (e) {
        assert(false, `6. Signed Prekey: ${e.message}`);
    }

    // 7. AES-GCM Key Envelope Round Trip
    try {
        const senderId = await generateIdentityKeypair();
        const senderEphemeral = await generateEphemeralKeypair();
        const recipientId = await generateIdentityKeypair();
        const recipientPrekey = await generateSignedPrekey(recipientId);

        const originalFileKey = sodium.randombytes_buf(32);
        const transferId = "tx_audit_007";
        const meta = { filename: "classified_payload.tar.gz", size: 987654 };

        const envelope = await createKeyEnvelope({
            rawFileKey: originalFileKey,
            senderIdentity: senderId,
            senderEphemeral,
            recipientSigningKeyHex: recipientId.publicKeyHex,
            recipientPrekeyBytes: recipientPrekey.publicKey,
            transferId,
            prekeyId: recipientPrekey.prekeyId,
            fileMetadata: meta
        });

        const recovered = await openKeyEnvelope({
            envelope,
            recipientPrekeySecretBytes: recipientPrekey.privateKey,
            expectedSenderIdentityHex: senderId.publicKeyHex,
            recipientSigningKeyHex: recipientId.publicKeyHex,
            expectedTransferId: transferId,
            expectedPrekeyId: recipientPrekey.prekeyId
        });

        const keyMatches = sodium.memcmp(recovered.rawFileKey, originalFileKey);
        const metaMatches = recovered.fileMetadata.filename === "classified_payload.tar.gz";
        assert(keyMatches && metaMatches, "7. AES-GCM Key Envelope Create & Unwrap Round Trip");
    } catch (e) {
        assert(false, `7. Key Envelope Round Trip: ${e.message}`);
    }

    // 8. Rejection of Mismatched Transfer ID
    try {
        const senderId = await generateIdentityKeypair();
        const senderEphemeral = await generateEphemeralKeypair();
        const recipientId = await generateIdentityKeypair();
        const recipientPrekey = await generateSignedPrekey(recipientId);

        const envelope = await createKeyEnvelope({
            rawFileKey: sodium.randombytes_buf(32),
            senderIdentity: senderId,
            senderEphemeral,
            recipientSigningKeyHex: recipientId.publicKeyHex,
            recipientPrekeyBytes: recipientPrekey.publicKey,
            transferId: "tx_legit_111",
            prekeyId: recipientPrekey.prekeyId
        });

        let threw = false;
        try {
            await openKeyEnvelope({
                envelope,
                recipientPrekeySecretBytes: recipientPrekey.privateKey,
                expectedSenderIdentityHex: senderId.publicKeyHex,
                recipientSigningKeyHex: recipientId.publicKeyHex,
                expectedTransferId: "tx_MALICIOUS_SUBSTITUTE",
                expectedPrekeyId: recipientPrekey.prekeyId
            });
        } catch {
            threw = true;
        }
        assert(threw, "8. Rejection of Mismatched Transfer ID");
    } catch (e) {
        assert(false, `8. Transfer ID mismatch: ${e.message}`);
    }

    // 9. Rejection of Mismatched Prekey ID
    try {
        const senderId = await generateIdentityKeypair();
        const senderEphemeral = await generateEphemeralKeypair();
        const recipientId = await generateIdentityKeypair();
        const recipientPrekey = await generateSignedPrekey(recipientId);

        const envelope = await createKeyEnvelope({
            rawFileKey: sodium.randombytes_buf(32),
            senderIdentity: senderId,
            senderEphemeral,
            recipientSigningKeyHex: recipientId.publicKeyHex,
            recipientPrekeyBytes: recipientPrekey.publicKey,
            transferId: "tx_legit_222",
            prekeyId: recipientPrekey.prekeyId
        });

        let threw = false;
        try {
            await openKeyEnvelope({
                envelope,
                recipientPrekeySecretBytes: recipientPrekey.privateKey,
                expectedSenderIdentityHex: senderId.publicKeyHex,
                recipientSigningKeyHex: recipientId.publicKeyHex,
                expectedTransferId: "tx_legit_222",
                expectedPrekeyId: "prekey_WRONG_PREKEY_999"
            });
        } catch {
            threw = true;
        }
        assert(threw, "9. Rejection of Mismatched Recipient Prekey ID");
    } catch (e) {
        assert(false, `9. Prekey ID mismatch: ${e.message}`);
    }

    // 10. Rejection of Modified / Tampered Envelope Content
    try {
        const senderId = await generateIdentityKeypair();
        const senderEphemeral = await generateEphemeralKeypair();
        const recipientId = await generateIdentityKeypair();
        const recipientPrekey = await generateSignedPrekey(recipientId);

        const envelope = await createKeyEnvelope({
            rawFileKey: sodium.randombytes_buf(32),
            senderIdentity: senderId,
            senderEphemeral,
            recipientSigningKeyHex: recipientId.publicKeyHex,
            recipientPrekeyBytes: recipientPrekey.publicKey,
            transferId: "tx_legit_333",
            prekeyId: recipientPrekey.prekeyId
        });

        // Corrupt wrapped key ciphertext in envelope
        const tampered = JSON.parse(JSON.stringify(envelope));
        const chars = tampered.wrapped_file_key.split("");
        chars[chars.length - 1] = chars[chars.length - 1] === "A" ? "B" : "A";
        tampered.wrapped_file_key = chars.join("");

        let threw = false;
        try {
            await openKeyEnvelope({
                envelope: tampered,
                recipientPrekeySecretBytes: recipientPrekey.privateKey,
                expectedSenderIdentityHex: senderId.publicKeyHex,
                recipientSigningKeyHex: recipientId.publicKeyHex,
                expectedTransferId: "tx_legit_333",
                expectedPrekeyId: recipientPrekey.prekeyId
            });
        } catch {
            threw = true;
        }
        assert(threw, "10. Rejection of Tampered Envelope Fields (Signature Fails)");
    } catch (e) {
        assert(false, `10. Tampered Envelope: ${e.message}`);
    }

    // 11. Ed25519 Identity Keypair Generation & Serialization
    try {
        const id = await generateIdentityKeypair();
        const validPub = id.publicKey instanceof Uint8Array && id.publicKey.length === 32;
        const validPriv = id.privateKey instanceof Uint8Array && id.privateKey.length === 64;
        const validPubHex = typeof id.publicKeyHex === "string" && id.publicKeyHex.length === 64;
        const validPrivHex = typeof id.privateKeyHex === "string" && id.privateKeyHex.length === 128;
        const validFp = typeof id.fingerprint === "string" && id.fingerprint.includes(":");
        assert(validPub && validPriv && validPubHex && validPrivHex && validFp, "11. Ed25519 Identity Keypair Generation & Complete Serialization");
    } catch (e) {
        assert(false, `11. Identity Keypair Gen: ${e.message}`);
    }

    // 12. Signed Prekey Signature Verification
    try {
        const id = await generateIdentityKeypair();
        const prekey = await generateSignedPrekey(id);
        const sigOk = await verifySignature(
            prekey.signature,
            prekey.publicKey,
            id.publicKey
        );
        assert(sigOk, "12. Signed Prekey Authenticated with Identity Public Key");
    } catch (e) {
        assert(false, `12. Prekey Sig: ${e.message}`);
    }

    // 13. Defensive Rejection: saveIdentity Rejects Null/Undefined Inputs
    try {
        const ks = new KeyStore("test-user-nulls");
        ks.unlocked = true;
        ks.passphrase = "ValidPass123!";
        let rejectedPub = false;
        try {
            await ks.saveIdentity(null, "somepriv", "fp");
        } catch (e) {
            rejectedPub = e.message.includes("Public key cannot be null or undefined");
        }
        let rejectedPriv = false;
        try {
            await ks.saveIdentity("somepub", undefined, "fp");
        } catch (e) {
            rejectedPriv = e.message.includes("Private key cannot be null or undefined");
        }
        assert(rejectedPub && rejectedPriv, "13. saveIdentity Defensively Rejects Null/Undefined Keys");
    } catch (e) {
        assert(false, `13. saveIdentity Nulls: ${e.message}`);
    }

    // 14. Defensive Rejection: savePrekey Rejects Null/Undefined Inputs
    try {
        const ks = new KeyStore("test-user-nulls");
        ks.unlocked = true;
        ks.passphrase = "ValidPass123!";
        let rejectedPrekeyId = false;
        try {
            await ks.savePrekey(null, "somepub", "somepriv");
        } catch (e) {
            rejectedPrekeyId = e.message.includes("Prekey ID cannot be null or undefined");
        }
        let rejectedPub = false;
        try {
            await ks.savePrekey("pk1", undefined, "somepriv");
        } catch (e) {
            rejectedPub = e.message.includes("X25519 public key cannot be null or undefined");
        }
        let rejectedPriv = false;
        try {
            await ks.savePrekey("pk1", "somepub", null);
        } catch (e) {
            rejectedPriv = e.message.includes("X25519 private key cannot be null or undefined");
        }
        assert(rejectedPrekeyId && rejectedPub && rejectedPriv, "14. savePrekey Defensively Rejects Null/Undefined Prekey Inputs");
    } catch (e) {
        assert(false, `14. savePrekey Nulls: ${e.message}`);
    }

    // 15. Defensive Rejection: computeFingerprint & computeSharedSecret
    try {
        let rejectedFp = false;
        try {
            await computeFingerprint(null);
        } catch (e) {
            rejectedFp = e.message.includes("Public key bytes cannot be null or undefined");
        }
        let rejectedDh = false;
        try {
            await computeSharedSecret(null, new Uint8Array(32));
        } catch (e) {
            rejectedDh = e.message.includes("Private key bytes cannot be null or undefined");
        }
        assert(rejectedFp && rejectedDh, "15. computeFingerprint & computeSharedSecret Defensively Reject Null Inputs");
    } catch (e) {
        assert(false, `15. Crypto Primitives Nulls: ${e.message}`);
    }

    console.log(`\nTEST RESULTS: ${passed} passed, ${failed} failed.`);
    if (failed > 0) process.exit(1);
}

runAll();
