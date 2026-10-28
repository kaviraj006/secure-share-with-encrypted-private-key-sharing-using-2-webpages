/**
 * SecureShare - Ed25519 Identity & Digital Signatures
 * Implemented using libsodium-wrappers and Web Crypto API.
 */

import sodium from '../vendor/sodium.js';

export async function initSodium() {
    await sodium.ready;
    return sodium;
}

export async function computeFingerprint(publicKeyBytes) {
    await sodium.ready;
    // Compute SHA-256 hash using standard Web Crypto API
    const hashBuffer = await crypto.subtle.digest("SHA-256", publicKeyBytes);
    const hashBytes = new Uint8Array(hashBuffer);
    
    // Format into 16 pairs of hex digits separated by colons: E4:3A:8B:...
    const chunks = [];
    for (let i = 0; i < 16; i++) {
        chunks.push(hashBytes[i].toString(16).padStart(2, "0").toUpperCase());
    }
    return chunks.join(":");
}

export async function generateIdentityKeypair() {
    await sodium.ready;
    const pair = sodium.crypto_sign_keypair();
    const fingerprint = await computeFingerprint(pair.publicKey);
    return {
        publicKey: pair.publicKey,
        privateKey: pair.privateKey,
        publicKeyHex: sodium.to_hex(pair.publicKey),
        fingerprint
    };
}

export async function signData(dataBytes, privateKeyBytes) {
    await sodium.ready;
    return sodium.crypto_sign_detached(dataBytes, privateKeyBytes);
}

export async function verifySignature(signatureBytes, dataBytes, publicKeyBytes) {
    if (!signatureBytes || !dataBytes || !publicKeyBytes) {
        return false;
    }
    await sodium.ready;
    try {
        let sig = signatureBytes;
        let data = dataBytes;

        // Gracefully handle accidentally swapped signature and data arguments
        if (sig instanceof Uint8Array && data instanceof Uint8Array) {
            if (sig.length !== 64 && data.length === 64) {
                sig = dataBytes;
                data = signatureBytes;
            }
        }

        if (typeof sig === "string") {
            try {
                sig = sodium.from_base64(sig);
            } catch {
                sig = sodium.from_hex(sig);
            }
        }
        const dataArr = typeof data === "string" ? new TextEncoder().encode(data) : data;
        const pub = typeof publicKeyBytes === "string" ? sodium.from_hex(publicKeyBytes) : publicKeyBytes;
        return sodium.crypto_sign_verify_detached(sig, dataArr, pub);
    } catch (e) {
        return false;
    }
}
