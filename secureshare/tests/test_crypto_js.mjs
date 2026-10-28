/**
 * Automated Cryptographic Module Test Suite (Node.js ESM)
 * Validates all required cryptographic primitives and envelope logic.
 */

import sodium from '../static/js/vendor/sodium.js';
import { generateFileKey, generateNonce, encryptFileBytes, decryptFileBytes, exportRawKey, importRawKey } from '../static/js/crypto/aes_gcm.js';
import { generateIdentityKeypair, signData, verifySignature, computeFingerprint } from '../static/js/crypto/ed25519_sign.js';
import { generatePrekeyPair, generateEphemeralKeypair, computeSharedSecret, deriveWrappingKey } from '../static/js/crypto/x25519_hkdf.js';
import { createProtectedEnvelope, openProtectedEnvelope, canonicalJson } from '../static/js/crypto/envelope.js';

let passedCount = 0;
let failedCount = 0;

function assert(condition, testName) {
    if (condition) {
        console.log(`[PASS] ${testName}`);
        passedCount++;
    } else {
        console.error(`[FAIL] ${testName}`);
        failedCount++;
    }
}

async function runTests() {
    console.log("=== STARTING SECURESHARE JAVASCRIPT CRYPTOGRAPHIC TEST SUITE ===");
    await sodium.ready;

    // 1. AES-GCM encrypt/decrypt round trip
    try {
        const key = await generateFileKey();
        const nonce = generateNonce(12);
        const originalText = "Top-Secret-Zero-Knowledge-File-Payload-1234567890";
        const plaintextBytes = new TextEncoder().encode(originalText);
        const ciphertext = await encryptFileBytes(plaintextBytes, key, nonce);
        const decrypted = await decryptFileBytes(ciphertext, key, nonce);
        const decryptedText = new TextDecoder().decode(decrypted);
        assert(decryptedText === originalText, "1. AES-GCM Encrypt/Decrypt Round Trip");
    } catch (e) {
        assert(false, `1. AES-GCM Round Trip: ${e.message}`);
    }

    // 2. Reject ciphertext modified by 1 byte
    try {
        const key = await generateFileKey();
        const nonce = generateNonce(12);
        const plaintext = new TextEncoder().encode("Authentic File Content");
        const ciphertext = await encryptFileBytes(plaintext, key, nonce);
        
        // Corrupt 1 byte
        const corrupted = new Uint8Array(ciphertext);
        corrupted[corrupted.length - 1] ^= 0x01;
        
        let threw = false;
        try {
            await decryptFileBytes(corrupted, key, nonce);
        } catch {
            threw = true;
        }
        assert(threw, "2. Reject Ciphertext Corrupted by 1 Byte");
    } catch (e) {
        assert(false, `2. Corrupt Ciphertext: ${e.message}`);
    }

    // 3. Reject incorrect AES key
    try {
        const key1 = await generateFileKey();
        const key2 = await generateFileKey();
        const nonce = generateNonce(12);
        const plaintext = new TextEncoder().encode("Testing wrong key rejection");
        const ciphertext = await encryptFileBytes(plaintext, key1, nonce);
        
        let threw = false;
        try {
            await decryptFileBytes(ciphertext, key2, nonce);
        } catch {
            threw = true;
        }
        assert(threw, "3. Reject Incorrect AES Key");
    } catch (e) {
        assert(false, `3. Wrong Key: ${e.message}`);
    }

    // 4. Reject incorrect nonce
    try {
        const key = await generateFileKey();
        const nonce1 = generateNonce(12);
        const nonce2 = generateNonce(12);
        const plaintext = new TextEncoder().encode("Testing wrong nonce rejection");
        const ciphertext = await encryptFileBytes(plaintext, key, nonce1);
        
        let threw = false;
        try {
            await decryptFileBytes(ciphertext, key, nonce2);
        } catch {
            threw = true;
        }
        assert(threw, "4. Reject Incorrect Nonce");
    } catch (e) {
        assert(false, `4. Wrong Nonce: ${e.message}`);
    }

    // 5. X25519 shared-secret agreement
    try {
        const alice = sodium.crypto_box_keypair();
        const bob = sodium.crypto_box_keypair();
        const sharedAlice = await computeSharedSecret(alice.privateKey, bob.publicKey);
        const sharedBob = await computeSharedSecret(bob.privateKey, alice.publicKey);
        const match = sodium.memcmp(sharedAlice, sharedBob);
        assert(match, "5. X25519 Shared-Secret Agreement");
    } catch (e) {
        assert(false, `5. X25519 DH: ${e.message}`);
    }

    // 6. HKDF derivation consistency
    try {
        const salt = sodium.randombytes_buf(32);
        const shared = sodium.randombytes_buf(32);
        const info = "SecureShare-v1|test-derivation-context";
        const key1 = await deriveWrappingKey(shared, salt, info);
        const key2 = await deriveWrappingKey(shared, salt, info);
        const raw1 = await exportRawKey(key1);
        const raw2 = await exportRawKey(key2);
        const match = sodium.memcmp(raw1, raw2);
        assert(match, "6. HKDF Derivation Consistency");
    } catch (e) {
        assert(false, `6. HKDF: ${e.message}`);
    }

    // 7. Ed25519 valid signature verification
    try {
        const idKey = await generateIdentityKeypair();
        const msg = new TextEncoder().encode("Test canonical message to sign");
        const sig = await signData(msg, idKey.privateKey);
        const valid = await verifySignature(sig, msg, idKey.publicKey);
        assert(valid, "7. Ed25519 Valid Signature Verification");
    } catch (e) {
        assert(false, `7. Ed25519: ${e.message}`);
    }

    // 8. Reject forged or modified signature
    try {
        const idKey = await generateIdentityKeypair();
        const msg = new TextEncoder().encode("Authentic message");
        const sig = await signData(msg, idKey.privateKey);
        
        // Corrupt signature
        const tamperedSig = new Uint8Array(sig);
        tamperedSig[0] ^= 0xFF;
        
        const valid = await verifySignature(tamperedSig, msg, idKey.publicKey);
        assert(!valid, "8. Reject Forged/Tampered Ed25519 Signature");
    } catch (e) {
        assert(false, `8. Forged Signature: ${e.message}`);
    }

    // 9 & 10. Protected Key-Envelope End-to-End Test with bindings
    try {
        const senderId = "user_sender_111";
        const recipientId = "user_recipient_222";
        const transferId = "transfer_xyz_999";
        const prekeyId = "prekey_recipient_001";

        const senderIdentity = await generateIdentityKeypair();
        const senderEphemeral = await generateEphemeralKeypair();
        
        const recipientIdentity = await generateIdentityKeypair();
        const recipientPrekey = await generatePrekeyPair();
        recipientPrekey.prekeyId = prekeyId;

        // Generate sample file key & metadata
        const originalFileKey = sodium.randombytes_buf(32);
        const metadata = {
            filename: "classified_plans.pdf",
            mimeType: "application/pdf",
            size: 1048576,
            sha256: "abc123def456"
        };

        const envelope = await createProtectedEnvelope({
            rawFileKey: originalFileKey,
            fileMetadata: metadata,
            senderIdentity,
            senderEphemeral,
            recipientSigningKeyHex: recipientIdentity.publicKeyHex,
            recipientPrekeyBytes: recipientPrekey.publicKey,
            transferId,
            prekeyId
        });

        // Legitimate open
        const opened = await openProtectedEnvelope({
            envelope,
            recipientPrekeySecretBytes: recipientPrekey.privateKey,
            expectedSenderIdentityHex: senderIdentity.publicKeyHex,
            recipientSigningKeyHex: recipientIdentity.publicKeyHex,
            expectedTransferId: transferId,
            expectedPrekeyId: prekeyId
        });

        const keyMatch = sodium.memcmp(opened.rawFileKey, originalFileKey);
        const metaMatch = opened.fileMetadata.filename === "classified_plans.pdf";
        assert(keyMatch && metaMatch, "9. Key-Envelope Create and Unwrap Legitimate Flow");

        // 10. Reject envelopes with mismatched transfer ID
        let transferThrew = false;
        try {
            await openProtectedEnvelope({
                envelope,
                recipientPrekeySecretBytes: recipientPrekey.privateKey,
                expectedSenderIdentityHex: senderIdentity.publicKeyHex,
                recipientSigningKeyHex: recipientIdentity.publicKeyHex,
                expectedTransferId: "WRONG_TRANSFER_ID",
                expectedPrekeyId: prekeyId
            });
        } catch {
            transferThrew = true;
        }
        assert(transferThrew, "10. Reject Envelopes with Mismatched Transfer ID");

        // 11. Reject envelopes bound to a different recipient prekey ID
        let prekeyThrew = false;
        try {
            await openProtectedEnvelope({
                envelope,
                recipientPrekeySecretBytes: recipientPrekey.privateKey,
                expectedSenderIdentityHex: senderIdentity.publicKeyHex,
                recipientSigningKeyHex: recipientIdentity.publicKeyHex,
                expectedTransferId: transferId,
                expectedPrekeyId: "WRONG_PREKEY_ID"
            });
        } catch {
            prekeyThrew = true;
        }
        assert(prekeyThrew, "11. Reject Envelopes Bound to Different Prekey ID");

        // 12. Reject envelope if signature is tampered
        const tamperedEnvelope = JSON.parse(JSON.stringify(envelope));
        // Modify wrapped key string slightly
        const keyChars = tamperedEnvelope.wrapped_file_key.split("");
        keyChars[0] = keyChars[0] === "A" ? "B" : "A";
        tamperedEnvelope.wrapped_file_key = keyChars.join("");

        let sigThrew = false;
        try {
            await openProtectedEnvelope({
                envelope: tamperedEnvelope,
                recipientPrekeySecretBytes: recipientPrekey.privateKey,
                expectedSenderIdentityHex: senderIdentity.publicKeyHex,
                recipientSigningKeyHex: recipientIdentity.publicKeyHex,
                expectedTransferId: transferId,
                expectedPrekeyId: prekeyId
            });
        } catch (e) {
            sigThrew = true;
        }
        assert(sigThrew, "12. Reject Tampered Key-Envelope Content (Signature Fails)");

    } catch (e) {
        assert(false, `Key-Envelope Tests: ${e.message}`);
    }

    console.log(`\nTEST SUMMARY: ${passedCount} passed, ${failedCount} failed.`);
    if (failedCount > 0) {
        process.exit(1);
    }
}

runTests();
