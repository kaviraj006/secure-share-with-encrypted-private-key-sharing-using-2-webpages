/**
 * SecureShare - AES-256-GCM Symmetric File & Metadata Cryptography
 * Implemented using Web Crypto API.
 */

export async function generateFileKey() {
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

export async function encryptFileBytes(fileBytes, aesKey, nonce, aadBytes = null) {
    const encryptParams = {
        name: "AES-GCM",
        iv: nonce,
        tagLength: 128
    };
    if (aadBytes) {
        encryptParams.additionalData = aadBytes;
    }
    
    const ciphertextBuffer = await crypto.subtle.encrypt(
        encryptParams,
        aesKey,
        fileBytes
    );
    
    return new Uint8Array(ciphertextBuffer);
}

export async function decryptFileBytes(ciphertextBytes, aesKey, nonce, aadBytes = null) {
    const decryptParams = {
        name: "AES-GCM",
        iv: nonce,
        tagLength: 128
    };
    if (aadBytes) {
        decryptParams.additionalData = aadBytes;
    }
    
    const decryptedBuffer = await crypto.subtle.decrypt(
        decryptParams,
        aesKey,
        ciphertextBytes
    );
    
    return new Uint8Array(decryptedBuffer);
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
