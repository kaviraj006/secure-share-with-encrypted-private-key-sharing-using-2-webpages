/**
 * SecureShare - Protected Key-Envelope Protocol
 * End-to-end authenticated key encapsulation with Ed25519 signatures and X25519/HKDF key wrapping.
 */

import sodium from '../vendor/sodium.js';
import { computeSharedSecret, deriveWrappingKey } from './x25519_hkdf.js';
import { encryptFileBytes, decryptFileBytes, importRawKey } from './aes_gcm.js';
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

function decodeB64(str) {
    if (!str) return new Uint8Array(0);
    let norm = str.replace(/-/g, "+").replace(/_/g, "/");
    while (norm.length % 4 !== 0) norm += "=";
    try {
        return sodium.from_base64(norm, sodium.base64_variants.ORIGINAL);
    } catch (e) {
        try {
            return sodium.from_base64(str, sodium.base64_variants.URLSAFE_NO_PADDING);
        } catch (e2) {
            const bin = atob(norm);
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            return bytes;
        }
    }
}

export async function createProtectedEnvelope({
    rawFileKey,
    fileMetadata,
    senderIdentity,
    senderEphemeral,
    recipientSigningKeyHex,
    recipientPrekeyBytes,
    transferId,
    prekeyId
}) {
    await sodium.ready;
    
    // 1. Compute X25519 shared secret
    const sharedSecret = await computeSharedSecret(
        senderEphemeral.privateKey,
        recipientPrekeyBytes
    );
    
    // 2. Generate random 32-byte HKDF salt
    const salt = sodium.randombytes_buf(32);
    
    // 3. Canonical derivation context
    const contextInfo = `SecureShare-v1|wrapping-key|${senderIdentity.publicKeyHex.toLowerCase()}|${recipientSigningKeyHex.toLowerCase()}|${transferId}|${prekeyId}`;
    
    // 4. Derive wrapping key
    const wrappingKey = await deriveWrappingKey(sharedSecret, salt, contextInfo);
    
    // 5. Encrypt raw AES file key with wrapping key
    const keyNonce = sodium.randombytes_buf(12);
    const keyAad = new TextEncoder().encode(`SecureShare-Envelope-Key-v1|${transferId}|${prekeyId}`);
    const wrappedKeyBytes = await encryptFileBytes(rawFileKey, wrappingKey, keyNonce, keyAad);
    
    // 6. Encrypt metadata
    const metaBytes = new TextEncoder().encode(canonicalJson(fileMetadata));
    const metaNonce = sodium.randombytes_buf(12);
    const metaAad = new TextEncoder().encode(`SecureShare-Envelope-Meta-v1|${transferId}`);
    const wrappedMetaBytes = await encryptFileBytes(metaBytes, wrappingKey, metaNonce, metaAad);
    
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
    
    // 8. Sign canonical serialization of envelope with sender's Ed25519 key
    const canonicalStr = canonicalJson(envelope);
    const canonicalBytes = new TextEncoder().encode(canonicalStr);
    const signature = await signData(canonicalBytes, senderIdentity.privateKey);
    
    envelope.signature = sodium.to_base64(signature);
    return envelope;
}

export async function openProtectedEnvelope({
    envelope,
    recipientPrekeySecretBytes,
    expectedSenderIdentityHex,
    recipientSigningKeyHex,
    expectedTransferId,
    expectedPrekeyId
}) {
    await sodium.ready;
    
    // 1. Validation of bindings
    const expTx = expectedTransferId || envelope.transfer_id;
    const expPk = expectedPrekeyId || envelope.recipient_prekey_id;
    if (envelope.transfer_id && expTx && envelope.transfer_id !== expTx) {
        throw new Error("Envelope transfer ID mismatch.");
    }
    if (envelope.recipient_prekey_id && expPk && envelope.recipient_prekey_id !== expPk) {
        throw new Error("Envelope recipient prekey ID mismatch.");
    }
    const envSenderKey = envelope.sender_identity_key || envelope.senderIdentityPublicKey || "";
    if (envSenderKey && expectedSenderIdentityHex && envSenderKey.toLowerCase() !== expectedSenderIdentityHex.toLowerCase()) {
        throw new Error("Envelope sender identity key mismatch.");
    }
    
    // 2. Verify sender signature
    const signatureBytes = decodeB64(envelope.signature);
    
    // Reconstruct unsigned envelope for verification
    const unsignedEnvelope = { ...envelope };
    delete unsignedEnvelope.signature;
    
    const canonicalStr = canonicalJson(unsignedEnvelope);
    const canonicalBytes = new TextEncoder().encode(canonicalStr);
    const senderIdentityPubBytes = sodium.from_hex(expectedSenderIdentityHex || envSenderKey);
    
    const isSignatureValid = await verifySignature(
        signatureBytes,
        canonicalBytes,
        senderIdentityPubBytes
    );
    
    if (!isSignatureValid) {
        throw new Error("CRYPTOGRAPHIC INTEGRITY FAILURE: Sender digital signature is INVALID. Rejecting envelope.");
    }
    
    // 3. Compute X25519 shared secret
    const ephemeralPubBytes = sodium.from_hex(envelope.sender_ephemeral_key);
    const sharedSecret = await computeSharedSecret(
        recipientPrekeySecretBytes,
        ephemeralPubBytes
    );
    
    // 4. Derive wrapping key
    const salt = decodeB64(envelope.hkdf_salt);
    const contextInfo = `SecureShare-v1|wrapping-key|${(expectedSenderIdentityHex || envSenderKey).toLowerCase()}|${recipientSigningKeyHex.toLowerCase()}|${expTx}|${expPk}`;
    let wrappingKey = await deriveWrappingKey(sharedSecret, salt, contextInfo);
    
    // 5. Decrypt wrapped file key
    const keyNonce = decodeB64(envelope.wrapped_key_nonce);
    const wrappedKeyBytes = decodeB64(envelope.wrapped_file_key);
    const keyAad = new TextEncoder().encode(`SecureShare-Envelope-Key-v1|${expTx}|${expPk}`);
    
    let rawFileKey;
    try {
        rawFileKey = await decryptFileBytes(wrappedKeyBytes, wrappingKey, keyNonce, keyAad);
    } catch (decryptErr) {
        // Fallback: If contextInfo derivation used recipientId vs signingKey
        const altRecipHex = (envelope.recipient_id || "").toLowerCase();
        if (altRecipHex && altRecipHex !== recipientSigningKeyHex.toLowerCase()) {
            const altContext = `SecureShare-v1|wrapping-key|${(expectedSenderIdentityHex || envSenderKey).toLowerCase()}|${altRecipHex}|${expTx}|${expPk}`;
            const altWrappingKey = await deriveWrappingKey(sharedSecret, salt, altContext);
            rawFileKey = await decryptFileBytes(wrappedKeyBytes, altWrappingKey, keyNonce, keyAad);
            wrappingKey = altWrappingKey;
        } else {
            throw decryptErr;
        }
    }
    
    // 6. Decrypt file metadata
    let fileMetadata = {};
    if (envelope.wrapped_meta_nonce || envelope.meta_nonce) {
        try {
            const metaNonce = decodeB64(envelope.meta_nonce || envelope.wrapped_meta_nonce);
            const wrappedMetaBytes = decodeB64(envelope.meta_ciphertext || envelope.wrapped_meta);
            const metaAad = new TextEncoder().encode(`SecureShare-Envelope-Meta-v1|${expTx}`);
            
            const decryptedMetaBytes = await decryptFileBytes(wrappedMetaBytes, wrappingKey, metaNonce, metaAad);
            const metadataJson = new TextDecoder().decode(decryptedMetaBytes);
            fileMetadata = JSON.parse(metadataJson);
        } catch (mErr) {
            fileMetadata = {};
        }
    }
    
    return {
        rawFileKey,
        fileMetadata
    };
}
