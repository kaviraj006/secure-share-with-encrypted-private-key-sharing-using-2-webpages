/**
 * SecureShare // KEY EXCHANGE - Ed25519 Identity Signatures & Fingerprints
 */

import sodium from '../vendor/sodium.js';

export async function initSodium() {
    await sodium.ready;
    return sodium;
}

export async function computeFingerprint(publicKeyBytes) {
    if (!publicKeyBytes) {
        throw new Error("Public key bytes cannot be null or undefined.");
    }
    await sodium.ready;
    const bytes = typeof publicKeyBytes === "string" ? sodium.from_hex(publicKeyBytes) : publicKeyBytes;
    if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
        throw new Error("Invalid Ed25519 public key for fingerprint calculation: must be 32 bytes.");
    }
    const hashBuffer = await crypto.subtle.digest("SHA-256", bytes);
    const hashBytes = new Uint8Array(hashBuffer);
    
    // Format into 16 uppercase hex pairs separated by colons: E4:A2:3B:...
    const chunks = [];
    for (let i = 0; i < 16; i++) {
        chunks.push(hashBytes[i].toString(16).padStart(2, "0").toUpperCase());
    }
    return chunks.join(":");
}

export async function generateIdentityKeypair() {
    await sodium.ready;
    const pair = sodium.crypto_sign_keypair();
    const pubHex = sodium.to_hex(pair.publicKey);
    const privHex = sodium.to_hex(pair.privateKey);
    const fingerprint = await computeFingerprint(pair.publicKey);
    return {
        publicKey: pair.publicKey,
        privateKey: pair.privateKey,
        publicKeyHex: pubHex,
        privateKeyHex: privHex,
        fingerprint
    };
}

export async function signData(dataBytes, privateKeyBytes) {
    if (!dataBytes) {
        throw new Error("Data bytes to sign cannot be null or undefined.");
    }
    if (!privateKeyBytes) {
        throw new Error("Private key for signing cannot be null or undefined.");
    }
    await sodium.ready;
    const priv = typeof privateKeyBytes === "string" ? sodium.from_hex(privateKeyBytes) : privateKeyBytes;
    const data = typeof dataBytes === "string" ? new TextEncoder().encode(dataBytes) : dataBytes;
    return sodium.crypto_sign_detached(data, priv);
}

export async function verifySignature(signatureBytes, dataBytes, publicKeyBytes) {
    if (!signatureBytes || !dataBytes || !publicKeyBytes) {
        return false;
    }
    await sodium.ready;
    try {
        let sig;
        if (typeof signatureBytes === "string") {
            try {
                sig = sodium.from_base64(signatureBytes);
            } catch {
                sig = sodium.from_hex(signatureBytes);
            }
        } else {
            sig = signatureBytes;
        }
        const data = typeof dataBytes === "string" ? new TextEncoder().encode(dataBytes) : dataBytes;
        const pub = typeof publicKeyBytes === "string" ? sodium.from_hex(publicKeyBytes) : publicKeyBytes;
        return sodium.crypto_sign_verify_detached(sig, data, pub);
    } catch (e) {
        return false;
    }
}

export function formatFingerprint(fp) {
    if (!fp) return "";
    if (typeof fp === "string" && fp.includes(":")) return fp.toUpperCase();
    if (typeof fp === "string") {
        const clean = fp.replace(/[^0-9a-fA-F]/g, "").toUpperCase();
        const chunks = [];
        for (let i = 0; i < clean.length && i < 32; i += 2) {
            chunks.push(clean.substring(i, i + 2));
        }
        return chunks.join(":");
    }
    if (fp instanceof Uint8Array || Array.isArray(fp)) {
        const chunks = [];
        for (let i = 0; i < 16 && i < fp.length; i++) {
            chunks.push(fp[i].toString(16).padStart(2, "0").toUpperCase());
        }
        return chunks.join(":");
    }
    return String(fp);
}

export const Ed25519Sign = {
    initSodium,
    computeFingerprint,
    generateIdentityKeyPair: async () => generateIdentityKeypair(),
    generateIdentityKeypair,
    formatFingerprint,
    signData,
    verifySignature
};
