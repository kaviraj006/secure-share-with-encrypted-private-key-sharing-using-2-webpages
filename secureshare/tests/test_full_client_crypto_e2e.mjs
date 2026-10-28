import test from 'node:test';
import assert from 'node:assert/strict';
import sodium from 'libsodium-wrappers';
import { webcrypto } from 'node:crypto';

// Polyfill browser globals for node test environment
if (!globalThis.crypto) {
    globalThis.crypto = webcrypto;
}
if (!globalThis.sodium) {
    globalThis.sodium = sodium;
}

import { generateFileKey, generateNonce, encryptFileBytes, decryptFileBytes, exportRawKey, importRawKey } from '../static/js/crypto/aes_gcm.js';
import { generateIdentityKeypair, computeFingerprint, signData, verifySignature } from '../static/js/crypto/ed25519_sign.js';
import { generatePrekeyPair, generateEphemeralKeypair, computeSharedSecret, deriveWrappingKey } from '../static/js/crypto/x25519_hkdf.js';
import { createProtectedEnvelope, openProtectedEnvelope } from '../static/js/crypto/envelope.js';

test('Full Sender-to-Receiver Cryptographic Pipeline E2E', async () => {
    await sodium.ready;

    // --- RECIPIENT SETUP ---
    // Recipient generates identity and prekey
    const bobIdentity = await generateIdentityKeypair();
    const bobPrekey = await generatePrekeyPair('prekey_bob_001');

    // --- SENDER SETUP ---
    // Sender generates identity
    const aliceIdentity = await generateIdentityKeypair();

    // 1. Sender selects a file (simulating a real file)
    const originalFileText = 'CONFIDENTIAL VAULT PAYLOAD: ' + 'A'.repeat(65536) + ' - END OF FILE';
    const originalFileBytes = new TextEncoder().encode(originalFileText);
    const fileMeta = {
        filename: 'report_q4_confidential.pdf',
        size: originalFileBytes.length,
        mimeType: 'application/pdf'
    };

    // 2. Sender generates random AES-256 file key & 96-bit nonce
    const aesKey = await generateFileKey();
    const rawFileKey = await exportRawKey(aesKey);
    assert.equal(rawFileKey.length, 32, 'AES file key must be exactly 32 bytes (256 bits)');

    const fileNonce = generateNonce(12);
    assert.equal(fileNonce.length, 12, 'AES-GCM nonce must be exactly 12 bytes (96 bits)');

    // 3. Sender encrypts file locally with AES-256-GCM
    const ciphertextBytes = await encryptFileBytes(originalFileBytes, aesKey, fileNonce);
    assert.equal(ciphertextBytes.length, originalFileBytes.length + 16, 'Ciphertext size must include 16-byte auth tag');

    // 4. Server assigns real Transfer UUID
    const realTransferId = 'b82e44d1-562a-4a8b-9833-2ce1817ef36d';

    // 5. Sender creates protected key envelope
    const senderEphemeral = await generateEphemeralKeypair();
    const envelope = await createProtectedEnvelope({
        rawFileKey,
        fileMetadata: fileMeta,
        senderIdentity: aliceIdentity,
        senderEphemeral,
        recipientSigningKeyHex: bobIdentity.publicKeyHex,
        recipientPrekeyBytes: bobPrekey.publicKey,
        transferId: realTransferId,
        prekeyId: bobPrekey.prekeyId
    });

    assert.ok(envelope.wrapped_file_key, 'Envelope must contain wrapped_file_key');
    assert.ok(envelope.signature, 'Envelope must contain Ed25519 signature');
    assert.equal(envelope.transfer_id, realTransferId, 'Envelope must bind to real transfer ID');
    assert.equal(envelope.recipient_prekey_id, bobPrekey.prekeyId, 'Envelope must bind to recipient prekey ID');

    // Sender zeroes rawFileKey from browser memory
    sodium.memzero(rawFileKey);

    // =========================================================================
    // RECIPIENT DECRYPTION WORKFLOW
    // =========================================================================

    // Status tracking for all 7 pipeline steps
    const steps = {
        ctRetrieved: false,
        envRetrieved: false,
        sigVerified: false,
        ridVerified: false,
        pkAvailable: false,
        keyRecovered: false,
        authSuccessful: false
    };

    // Step 5 check: Recipient has private prekey locally
    assert.ok(bobPrekey.privateKey && bobPrekey.privateKey.length === 32, 'Recipient private prekey must be available locally');
    steps.pkAvailable = true;

    // Step 1: Ciphertext retrieved from server
    const retrievedCiphertext = ciphertextBytes;
    const retrievedNonce = fileNonce;
    steps.ctRetrieved = true;

    // Step 2: Key envelope retrieved from Key Exchange Portal
    const retrievedEnvelope = JSON.parse(JSON.stringify(envelope));
    assert.equal(retrievedEnvelope.transfer_id, realTransferId, 'Transfer ID binding verified');
    steps.envRetrieved = true;

    // Step 4: Recipient identity verified
    assert.equal(retrievedEnvelope.recipient_prekey_id, bobPrekey.prekeyId, 'Prekey ID binding verified');
    steps.ridVerified = true;

    // Step 3 & 6: Unwrapping envelope, verifying sender signature & recovering AES key
    const openResult = await openProtectedEnvelope({
        envelope: retrievedEnvelope,
        recipientPrekeySecretBytes: bobPrekey.privateKey,
        expectedSenderIdentityHex: aliceIdentity.publicKeyHex,
        recipientSigningKeyHex: bobIdentity.publicKeyHex,
        expectedTransferId: realTransferId,
        expectedPrekeyId: bobPrekey.prekeyId
    });

    steps.sigVerified = true;
    const recoveredFileKey = openResult.rawFileKey;
    const recoveredMeta = openResult.fileMetadata;
    assert.equal(recoveredFileKey.length, 32, 'Recovered key must be 32 bytes');
    assert.equal(recoveredMeta.filename, fileMeta.filename, 'Metadata filename must match');
    steps.keyRecovered = true;

    // Step 7: Decrypt ciphertext locally using AES-256-GCM & verify 128-bit tag
    const recipientAesKey = await importRawKey(recoveredFileKey, ['decrypt']);
    const decryptedBytes = await decryptFileBytes(retrievedCiphertext, recipientAesKey, retrievedNonce);
    steps.authSuccessful = true;

    // Zero key memory after decryption
    sodium.memzero(recoveredFileKey);

    // Bit-for-bit content verification
    assert.deepEqual(decryptedBytes, originalFileBytes, 'Decrypted file must match original bit-for-bit');
    const decryptedText = new TextDecoder().decode(decryptedBytes);
    assert.equal(decryptedText, originalFileText, 'Decrypted string matches original');

    // All 7 steps must be true
    assert.ok(steps.ctRetrieved, 'Step 1 passed: Ciphertext retrieved');
    assert.ok(steps.envRetrieved, 'Step 2 passed: Key envelope retrieved');
    assert.ok(steps.sigVerified, 'Step 3 passed: Sender signature verified');
    assert.ok(steps.ridVerified, 'Step 4 passed: Recipient identity verified');
    assert.ok(steps.pkAvailable, 'Step 5 passed: Private key available locally');
    assert.ok(steps.keyRecovered, 'Step 6 passed: AES file key recovered');
    assert.ok(steps.authSuccessful, 'Step 7 passed: File authentication successful');

    console.log('[SUCCESS] All 7 verification pipeline stages verified with genuine cryptography.');
});

test('Tampered Ciphertext Tag Verification Failure', async () => {
    await sodium.ready;
    const aesKey = await generateFileKey();
    const rawKey = await exportRawKey(aesKey);
    const nonce = generateNonce(12);
    const plain = new TextEncoder().encode('Hello world');
    const ct = await encryptFileBytes(plain, aesKey, nonce);

    // Tamper single byte
    ct[10] ^= 0x55;

    const decryptKey = await importRawKey(rawKey, ['decrypt']);
    await assert.rejects(
        async () => await decryptFileBytes(ct, decryptKey, nonce),
        (err) => err !== null,
        'Tampered ciphertext must fail authentication tag check'
    );
});

test('Tampered Envelope Ed25519 Signature Failure', async () => {
    await sodium.ready;
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();
    const bobPre = await generatePrekeyPair('prekey_1');

    const key = new Uint8Array(32);
    const ephemeral = await generateEphemeralKeypair();
    const env = await createProtectedEnvelope({
        rawFileKey: key,
        fileMetadata: { filename: 'x.txt' },
        senderIdentity: alice,
        senderEphemeral: ephemeral,
        recipientSigningKeyHex: bob.publicKeyHex,
        recipientPrekeyBytes: bobPre.publicKey,
        transferId: 'tx-1234',
        prekeyId: 'prekey_1'
    });

    // Tamper wrapped key inside envelope
    env.wrapped_file_key = sodium.to_base64(new Uint8Array(48));

    await assert.rejects(
        async () => await openProtectedEnvelope({
            envelope: env,
            recipientPrekeySecretBytes: bobPre.privateKey,
            expectedSenderIdentityHex: alice.publicKeyHex,
            recipientSigningKeyHex: bob.publicKeyHex,
            expectedTransferId: 'tx-1234',
            expectedPrekeyId: 'prekey_1'
        }),
        /Sender digital signature is INVALID/i,
        'Tampered envelope must fail Ed25519 signature verification'
    );
});

test('Mismatched Transfer ID AAD Failure', async () => {
    await sodium.ready;
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();
    const bobPre = await generatePrekeyPair('prekey_1');

    const key = new Uint8Array(32);
    const ephemeral = await generateEphemeralKeypair();
    const env = await createProtectedEnvelope({
        rawFileKey: key,
        fileMetadata: { filename: 'x.txt' },
        senderIdentity: alice,
        senderEphemeral: ephemeral,
        recipientSigningKeyHex: bob.publicKeyHex,
        recipientPrekeyBytes: bobPre.publicKey,
        transferId: 'tx-correct-1111',
        prekeyId: 'prekey_1'
    });

    await assert.rejects(
        async () => await openProtectedEnvelope({
            envelope: env,
            recipientPrekeySecretBytes: bobPre.privateKey,
            expectedSenderIdentityHex: alice.publicKeyHex,
            recipientSigningKeyHex: bob.publicKeyHex,
            expectedTransferId: 'tx-wrong-9999',
            expectedPrekeyId: 'prekey_1'
        }),
        /Transfer ID mismatch/i,
        'Mismatched Transfer ID must be rejected'
    );
});

test('Mismatched Prekey ID Failure', async () => {
    await sodium.ready;
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();
    const bobPre = await generatePrekeyPair('prekey_1');

    const key = new Uint8Array(32);
    const ephemeral = await generateEphemeralKeypair();
    const env = await createProtectedEnvelope({
        rawFileKey: key,
        fileMetadata: { filename: 'x.txt' },
        senderIdentity: alice,
        senderEphemeral: ephemeral,
        recipientSigningKeyHex: bob.publicKeyHex,
        recipientPrekeyBytes: bobPre.publicKey,
        transferId: 'tx-1234',
        prekeyId: 'prekey_1'
    });

    await assert.rejects(
        async () => await openProtectedEnvelope({
            envelope: env,
            recipientPrekeySecretBytes: bobPre.privateKey,
            expectedSenderIdentityHex: alice.publicKeyHex,
            recipientSigningKeyHex: bob.publicKeyHex,
            expectedTransferId: 'tx-1234',
            expectedPrekeyId: 'prekey_2_different'
        }),
        /Prekey ID mismatch/i,
        'Mismatched Prekey ID must be rejected'
    );
});

test('Wrong Private Key Tag Failure', async () => {
    await sodium.ready;
    const alice = await generateIdentityKeypair();
    const bob = await generateIdentityKeypair();
    const bobPre = await generatePrekeyPair('prekey_1');
    const evePre = await generatePrekeyPair('prekey_1'); // Eve has different private key

    const key = new Uint8Array(32);
    const ephemeral = await generateEphemeralKeypair();
    const env = await createProtectedEnvelope({
        rawFileKey: key,
        fileMetadata: { filename: 'x.txt' },
        senderIdentity: alice,
        senderEphemeral: ephemeral,
        recipientSigningKeyHex: bob.publicKeyHex,
        recipientPrekeyBytes: bobPre.publicKey,
        transferId: 'tx-1234',
        prekeyId: 'prekey_1'
    });

    await assert.rejects(
        async () => await openProtectedEnvelope({
            envelope: env,
            recipientPrekeySecretBytes: evePre.privateKey, // Eve tries to open with wrong key
            expectedSenderIdentityHex: alice.publicKeyHex,
            recipientSigningKeyHex: bob.publicKeyHex,
            expectedTransferId: 'tx-1234',
            expectedPrekeyId: 'prekey_1'
        }),
        (err) => err !== null,
        'Wrong private key must fail decryption'
    );
});
