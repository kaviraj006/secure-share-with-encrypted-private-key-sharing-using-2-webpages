/**
 * SecureShare // KEY EXCHANGE - AES-256-GCM Symmetric Cryptography
 * Implemented using native Web Crypto API.
 */

export async function generateAesKey() {
    return await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

export function generateNonce(length = 12) {
    const nonce = new Uint8Array(length);
    crypto.getRandomValues(nonce);
    return nonce;
}

export async function exportRawKey(cryptoKey) {
    const buffer = await crypto.subtle.exportKey("raw", cryptoKey);
    return new Uint8Array(buffer);
}

export async function importRawKey(rawKeyBytes, usages = ["encrypt", "decrypt"]) {
    return await crypto.subtle.importKey(
        "raw",
        rawKeyBytes,
        { name: "AES-GCM" },
        true,
        usages
    );
}

export async function encryptBytes(bytes, aesKey, nonce, aadBytes = null) {
    const params = {
        name: "AES-GCM",
        iv: nonce,
        tagLength: 128
    };
    if (aadBytes) {
        params.additionalData = aadBytes;
    }
    const buffer = await crypto.subtle.encrypt(params, aesKey, bytes);
    return new Uint8Array(buffer);
}

export async function decryptBytes(ciphertextBytes, aesKey, nonce, aadBytes = null) {
    const params = {
        name: "AES-GCM",
        iv: nonce,
        tagLength: 128
    };
    if (aadBytes) {
        params.additionalData = aadBytes;
    }
    const buffer = await crypto.subtle.decrypt(params, aesKey, ciphertextBytes);
    return new Uint8Array(buffer);
}

export const AESGCM = {
    generateAesKey,
    generateNonce,
    exportRawKey,
    importRawKey,
    encryptBytes,
    decryptBytes,
    generateFileKeyHex: () => {
        const bytes = new Uint8Array(32);
        crypto.getRandomValues(bytes);
        return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }
};

