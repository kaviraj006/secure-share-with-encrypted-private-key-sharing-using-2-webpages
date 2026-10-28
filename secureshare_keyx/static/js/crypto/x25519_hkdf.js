/**
 * SecureShare // KEY EXCHANGE - X25519 Diffie-Hellman & HKDF-SHA-256 Key Derivation
 */

import sodium from '../vendor/sodium.js';
import { signData } from './ed25519_sign.js';

export async function generateSignedPrekey(identityKeypair) {
    await sodium.ready;
    const pair = sodium.crypto_box_keypair();
    const prekeyId = "prekey_" + sodium.to_hex(sodium.randombytes_buf(8));
    
    const privKey = identityKeypair?.privateKey || identityKeypair;
    if (!privKey) {
        throw new Error("Identity private signing key cannot be null or undefined.");
    }
    const privBytes = typeof privKey === "string" ? sodium.from_hex(privKey) : privKey;
    
    // Sign the X25519 public key bytes using the Ed25519 private key
    const sigBytes = await signData(pair.publicKey, privBytes);
    const signatureBase64 = sodium.to_base64(sigBytes);
    
    return {
        prekeyId,
        publicKey: pair.publicKey,
        privateKey: pair.privateKey,
        publicKeyHex: sodium.to_hex(pair.publicKey),
        x25519PublicKey: sodium.to_hex(pair.publicKey),
        x25519PrivateKey: sodium.to_hex(pair.privateKey),
        signature: signatureBase64
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
    if (!privateKeyBytes) {
        throw new Error("Private key bytes cannot be null or undefined for X25519 exchange.");
    }
    if (!publicKeyBytes) {
        throw new Error("Public key bytes cannot be null or undefined for X25519 exchange.");
    }
    await sodium.ready;
    const priv = typeof privateKeyBytes === "string" ? sodium.from_hex(privateKeyBytes) : privateKeyBytes;
    const pub = typeof publicKeyBytes === "string" ? sodium.from_hex(publicKeyBytes) : publicKeyBytes;

    if (pub.length !== 32) {
        throw new Error("Invalid X25519 public key length: must be 32 bytes.");
    }
    
    // Check all-zero input
    let allZero = true;
    for (let i = 0; i < pub.length; i++) {
        if (pub[i] !== 0) {
            allZero = false;
            break;
        }
    }
    if (allZero) {
        throw new Error("Rejecting invalid all-zero X25519 public key.");
    }

    const sharedSecret = sodium.crypto_scalarmult(priv, pub);
    
    // Check all-zero result
    let secretZero = true;
    for (let i = 0; i < sharedSecret.length; i++) {
        if (sharedSecret[i] !== 0) {
            secretZero = false;
            break;
        }
    }
    if (secretZero) {
        throw new Error("Rejecting invalid all-zero shared secret result.");
    }
    
    return sharedSecret;
}

export async function deriveWrappingKey(sharedSecretBytes, saltBytes, contextInfoStr) {
    if (!sharedSecretBytes) {
        throw new Error("Shared secret cannot be null or undefined for key derivation.");
    }
    const hkdfKey = await crypto.subtle.importKey(
        "raw",
        sharedSecretBytes,
        "HKDF",
        false,
        ["deriveKey"]
    );
    
    const infoBytes = new TextEncoder().encode(contextInfoStr || "");
    
    return await crypto.subtle.deriveKey(
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
}

export async function verifySignedPrekey(signingPublicKey, prekeyPublicHex, signature) {
    if (!signingPublicKey || !prekeyPublicHex || !signature) {
        return false;
    }
    await sodium.ready;
    try {
        const signingPubBytes = typeof signingPublicKey === "string" 
            ? sodium.from_hex(signingPublicKey) 
            : signingPublicKey;
        const prekeyPubBytes = typeof prekeyPublicHex === "string" 
            ? sodium.from_hex(prekeyPublicHex) 
            : prekeyPublicHex;
        let sigBytes;
        if (typeof signature === "string") {
            try {
                sigBytes = sodium.from_base64(signature);
            } catch {
                sigBytes = sodium.from_hex(signature);
            }
        } else {
            sigBytes = signature;
        }
        return sodium.crypto_sign_verify_detached(sigBytes, prekeyPubBytes, signingPubBytes);
    } catch (e) {
        return false;
    }
}

export const X25519HKDF = {
    generateSignedPrekey: async (identityPrivateKey, prekeyId) => {
        await sodium.ready;
        const pair = sodium.crypto_box_keypair();
        const pkId = prekeyId || ("prekey_" + sodium.to_hex(sodium.randombytes_buf(8)));
        if (!identityPrivateKey) {
            throw new Error("Identity private signing key cannot be null or undefined.");
        }
        let privKeyBytes;
        if (identityPrivateKey?.privateKey) {
            privKeyBytes = typeof identityPrivateKey.privateKey === "string"
                ? sodium.from_hex(identityPrivateKey.privateKey)
                : identityPrivateKey.privateKey;
        } else if (typeof identityPrivateKey === "string") {
            privKeyBytes = sodium.from_hex(identityPrivateKey);
        } else {
            privKeyBytes = identityPrivateKey;
        }

        const sigBytes = await signData(pair.publicKey, privKeyBytes);
        const signatureBase64 = sodium.to_base64(sigBytes);

        return {
            prekeyId: pkId,
            publicKey: pair.publicKey,
            privateKey: pair.privateKey,
            x25519PublicKey: sodium.to_hex(pair.publicKey),
            x25519PrivateKey: sodium.to_hex(pair.privateKey),
            publicKeyHex: sodium.to_hex(pair.publicKey),
            signature: signatureBase64
        };
    },
    generateEphemeralKeypair,
    computeSharedSecret,
    deriveWrappingKey,
    verifySignedPrekey
};
