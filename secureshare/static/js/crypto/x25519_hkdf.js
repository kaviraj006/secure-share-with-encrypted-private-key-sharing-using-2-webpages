/**
 * SecureShare - X25519 Diffie-Hellman Key Agreement & HKDF-SHA-256 Key Derivation
 */

import sodium from '../vendor/sodium.js';

export async function generatePrekeyPair() {
    await sodium.ready;
    const pair = sodium.crypto_box_keypair();
    const prekeyId = "prekey_" + sodium.to_hex(sodium.randombytes_buf(8));
    return {
        publicKey: pair.publicKey,
        privateKey: pair.privateKey,
        publicKeyHex: sodium.to_hex(pair.publicKey),
        prekeyId
    };
}

export async function generateEphemeralKeypair() {
    await sodium.ready;
    const pair = sodium.crypto_box_keypair();
    return {
        publicKey: pair.publicKey,
        privateKey: pair.privateKey,
        publicKeyHex: sodium.to_hex(pair.publicKey)
    };
}

export async function computeSharedSecret(privateKeyBytes, publicKeyBytes) {
    await sodium.ready;
    if (!publicKeyBytes || publicKeyBytes.length !== 32) {
        throw new Error("Invalid X25519 public key length.");
    }
    
    // Check for all-zero public key
    let allZero = true;
    for (let i = 0; i < publicKeyBytes.length; i++) {
        if (publicKeyBytes[i] !== 0) {
            allZero = false;
            break;
        }
    }
    if (allZero) {
        throw new Error("Rejecting invalid all-zero X25519 public key.");
    }

    const sharedSecret = sodium.crypto_scalarmult(privateKeyBytes, publicKeyBytes);
    
    // Check for all-zero shared secret
    let secretZero = true;
    for (let i = 0; i < sharedSecret.length; i++) {
        if (sharedSecret[i] !== 0) {
            secretZero = false;
            break;
        }
    }
    if (secretZero) {
        throw new Error("Rejecting invalid all-zero shared secret computation.");
    }
    
    return sharedSecret;
}

export async function deriveWrappingKey(sharedSecretBytes, saltBytes, contextInfoStr) {
    // Import shared secret as HKDF key in Web Crypto
    const hkdfKey = await crypto.subtle.importKey(
        "raw",
        sharedSecretBytes,
        "HKDF",
        false,
        ["deriveKey"]
    );
    
    const infoBytes = new TextEncoder().encode(contextInfoStr);
    
    // Derive AES-256-GCM wrapping key
    const wrappingKey = await crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            salt: saltBytes,
            info: infoBytes
        },
        hkdfKey,
        {
            name: "AES-GCM",
            length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );
    
    return wrappingKey;
}
