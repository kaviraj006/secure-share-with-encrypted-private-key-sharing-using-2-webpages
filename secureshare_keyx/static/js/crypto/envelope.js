/**
 * SecureShare // KEY EXCHANGE - Protected Key-Envelope Protocol
 */

import sodium from '../vendor/sodium.js';
import { computeSharedSecret, deriveWrappingKey, generateEphemeralKeypair } from './x25519_hkdf.js';
import { encryptBytes, decryptBytes } from './aes_gcm.js';
import { signData, verifySignature } from './ed25519_sign.js';

export function canonicalJson(value) {
    if (value === null || typeof value !== "object") {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        return "[" + value.map(canonicalJson).join(",") + "]";
    }
    const keys = Object.keys(value).sort();
    const items = keys.map(k => JSON.stringify(k) + ":" + canonicalJson(value[k]));
    return "{" + items.join(",") + "}";
}

export async function createKeyEnvelope(params) {
    await sodium.ready;

    let {
        rawFileKey,
        senderIdentity,
        senderEphemeral,
        recipientSigningKeyHex,
        recipientPrekeyBytes,
        transferId,
        prekeyId,
        fileMetadata = {},
        senderIdentityPrivateKey,
        senderIdentityPublicKey,
        recipientId,
        recipientPrekeyId,
        recipientPrekeyPublicHex,
        rawAesFileKeyHex
    } = params;

    // Normalize parameters
    if (rawAesFileKeyHex && !rawFileKey) {
        rawFileKey = sodium.from_hex(rawAesFileKeyHex);
    }
    if (recipientPrekeyId && !prekeyId) {
        prekeyId = recipientPrekeyId;
    }
    if (recipientPrekeyPublicHex && !recipientPrekeyBytes) {
        recipientPrekeyBytes = sodium.from_hex(recipientPrekeyPublicHex);
    }
    if (!senderEphemeral) {
        senderEphemeral = await generateEphemeralKeypair();
    }
    if (!senderIdentity && senderIdentityPrivateKey) {
        const privBytes = typeof senderIdentityPrivateKey === "string" 
            ? sodium.from_hex(senderIdentityPrivateKey) 
            : senderIdentityPrivateKey;
        const pubHex = typeof senderIdentityPublicKey === "string" 
            ? senderIdentityPublicKey 
            : sodium.to_hex(senderIdentityPublicKey);
        senderIdentity = { privateKey: privBytes, publicKeyHex: pubHex };
    }
    if (!recipientSigningKeyHex) {
        recipientSigningKeyHex = params.recipientSigningPublicKey || params.recipientPublicKey || recipientId || "recipient";
    }

    // 1. Compute X25519 shared secret
    const sharedSecret = await computeSharedSecret(
        senderEphemeral.privateKey,
        recipientPrekeyBytes
    );

    // 2. 32-byte HKDF salt
    const salt = sodium.randombytes_buf(32);

    // 3. Canonical derivation context
    const contextInfo = `SecureShare-v1|wrapping-key|${senderIdentity.publicKeyHex.toLowerCase()}|${recipientSigningKeyHex.toLowerCase()}|${transferId}|${prekeyId}`;

    // 4. Derive wrapping key
    const wrappingKey = await deriveWrappingKey(sharedSecret, salt, contextInfo);

    // 5. Wrap raw AES file key
    const keyNonce = sodium.randombytes_buf(12);
    const keyAad = new TextEncoder().encode(`SecureShare-Envelope-Key-v1|${transferId}|${prekeyId}`);
    const wrappedKeyBytes = await encryptBytes(rawFileKey, wrappingKey, keyNonce, keyAad);

    // 6. Wrap metadata
    const metaBytes = new TextEncoder().encode(canonicalJson(fileMetadata));
    const metaNonce = sodium.randombytes_buf(12);
    const metaAad = new TextEncoder().encode(`SecureShare-Envelope-Meta-v1|${transferId}`);
    const wrappedMetaBytes = await encryptBytes(metaBytes, wrappingKey, metaNonce, metaAad);

    // 7. Assemble unsigned envelope
    const envelope = {
        version: 1,
        transfer_id: transferId,
        recipient_prekey_id: prekeyId,
        sender_identity_key: senderIdentity.publicKeyHex.toLowerCase(),
        sender_ephemeral_key: senderEphemeral.publicKeyHex.toLowerCase(),
        hkdf_salt: sodium.to_base64(salt),
        wrapped_key_nonce: sodium.to_base64(keyNonce),
        wrapped_file_key: sodium.to_base64(wrappedKeyBytes),
        meta_nonce: sodium.to_base64(metaNonce),
        meta_ciphertext: sodium.to_base64(wrappedMetaBytes)
    };

    // 8. Sign canonical JSON with sender's Ed25519 identity key
    const canonicalStr = canonicalJson(envelope);
    const canonicalBytes = new TextEncoder().encode(canonicalStr);
    const signature = await signData(canonicalBytes, senderIdentity.privateKey);

    envelope.signature = sodium.to_base64(signature);

    Object.defineProperty(envelope, "encryptedEnvelope", {
        get() { return this; },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(envelope, "senderSignature", {
        get() { return this.signature; },
        enumerable: false,
        configurable: true
    });

    return envelope;
}

export async function openKeyEnvelope(params) {
    await sodium.ready;

    let {
        envelope,
        recipientPrekeySecretBytes,
        expectedSenderIdentityHex,
        recipientSigningKeyHex,
        expectedTransferId,
        expectedPrekeyId,
        senderIdentityPublicKey,
        recipientPrekeyPrivateKey,
        recipientId,
        transferId,
        recipientPrekeyId,
        encryptedEnvelope,
        senderSignature
    } = params;

    let env = envelope;
    if (!env && encryptedEnvelope) {
        env = typeof encryptedEnvelope === "string" ? JSON.parse(encryptedEnvelope) : { ...encryptedEnvelope };
    }
    if (senderSignature && env && !env.signature) {
        env.signature = senderSignature;
    }

    const privKeyBytes = recipientPrekeySecretBytes || (typeof recipientPrekeyPrivateKey === "string" ? sodium.from_hex(recipientPrekeyPrivateKey) : recipientPrekeyPrivateKey);
    const senderPubHex = (expectedSenderIdentityHex || senderIdentityPublicKey || "").toLowerCase();
    const expTx = expectedTransferId || transferId;
    const expPk = expectedPrekeyId || recipientPrekeyId;
    const recipSignHex = (recipientSigningKeyHex || recipientId || "recipient").toLowerCase();

    // 1. Strict validation of bindings
    if (env.transfer_id !== expTx) {
        throw new Error("SECURITY FAULT: Envelope transfer ID mismatch.");
    }
    if (env.recipient_prekey_id !== expPk) {
        throw new Error("SECURITY FAULT: Envelope recipient prekey ID mismatch.");
    }
    if (senderPubHex && env.sender_identity_key.toLowerCase() !== senderPubHex) {
        throw new Error("SECURITY FAULT: Envelope sender identity key mismatch.");
    }

    // 2. Verify digital signature
    const signatureBytes = sodium.from_base64(env.signature);
    const unsignedEnvelope = { ...env };
    delete unsignedEnvelope.signature;
    delete unsignedEnvelope.encryptedEnvelope;
    delete unsignedEnvelope.senderSignature;

    const canonicalStr = canonicalJson(unsignedEnvelope);
    const canonicalBytes = new TextEncoder().encode(canonicalStr);
    const senderIdentityPubBytes = sodium.from_hex(env.sender_identity_key);

    const isSignatureValid = await verifySignature(
        signatureBytes,
        canonicalBytes,
        senderIdentityPubBytes
    );

    if (!isSignatureValid) {
        throw new Error("SECURITY COMPROMISE DETECTED: Sender Ed25519 digital signature is INVALID. Envelope rejected.");
    }

    // 3. Compute X25519 shared secret
    const ephemeralPubBytes = sodium.from_hex(env.sender_ephemeral_key);
    const sharedSecret = await computeSharedSecret(
        privKeyBytes,
        ephemeralPubBytes
    );

    // 4. Derive wrapping key
    const salt = sodium.from_base64(env.hkdf_salt);
    const contextInfo = `SecureShare-v1|wrapping-key|${env.sender_identity_key.toLowerCase()}|${recipSignHex}|${expTx}|${expPk}`;
    let wrappingKey = await deriveWrappingKey(sharedSecret, salt, contextInfo);

    // 5. Decrypt wrapped file key
    const keyNonce = sodium.from_base64(env.wrapped_key_nonce);
    const wrappedKeyBytes = sodium.from_base64(env.wrapped_file_key);
    const keyAad = new TextEncoder().encode(`SecureShare-Envelope-Key-v1|${expTx}|${expPk}`);
    let rawFileKey;
    try {
        rawFileKey = await decryptBytes(wrappedKeyBytes, wrappingKey, keyNonce, keyAad);
    } catch (decryptErr) {
        // Fallback: If recipSignHex was public key, try with recipientId UUID (or vice versa)
        const altRecipHex = (recipientId || "").toLowerCase();
        if (altRecipHex && altRecipHex !== recipSignHex) {
            const altContext = `SecureShare-v1|wrapping-key|${env.sender_identity_key.toLowerCase()}|${altRecipHex}|${expTx}|${expPk}`;
            const altWrappingKey = await deriveWrappingKey(sharedSecret, salt, altContext);
            rawFileKey = await decryptBytes(wrappedKeyBytes, altWrappingKey, keyNonce, keyAad);
            wrappingKey = altWrappingKey;
        } else {
            throw decryptErr;
        }
    }

    // 6. Decrypt file metadata
    let fileMetadata = {};
    if (env.meta_nonce && env.meta_ciphertext) {
        const metaNonce = sodium.from_base64(env.meta_nonce);
        const wrappedMetaBytes = sodium.from_base64(env.meta_ciphertext);
        const metaAad = new TextEncoder().encode(`SecureShare-Envelope-Meta-v1|${expTx}`);
        const decryptedMetaBytes = await decryptBytes(wrappedMetaBytes, wrappingKey, metaNonce, metaAad);
        fileMetadata = JSON.parse(new TextDecoder().decode(decryptedMetaBytes));
    }

    return {
        rawFileKey,
        rawAesFileKeyHex: sodium.to_hex(rawFileKey),
        fileMetadata
    };
}

export const Envelope = {
    canonicalJson,
    createKeyEnvelope,
    openKeyEnvelope
};

