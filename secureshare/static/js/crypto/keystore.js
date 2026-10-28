/**
 * SecureShare - Zero-Knowledge Local Key Vault
 * Encrypts private identity and prekey credentials client-side with PBKDF2 + AES-GCM.
 * Stored in IndexedDB; the server NEVER sees private keys or the KEK.
 */

import sodium from '../vendor/sodium.js';
import { generateIdentityKeypair } from './ed25519_sign.js';
import { generatePrekeyPair } from './x25519_hkdf.js';
import { encryptFileBytes, decryptFileBytes } from './aes_gcm.js';

const DB_NAME = "SecureShareKeyVault";
const DB_VERSION = 1;
const STORE_NAME = "vault";

let inMemoryActiveSession = null;

function openDatabase() {
    return new Promise((resolve, reject) => {
        if (typeof indexedDB === "undefined") {
            return resolve(null);
        }
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        request.onupgradeneeded = (e) => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                db.createObjectStore(STORE_NAME, { keyPath: "userId" });
            }
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => resolve(null);
    });
}

async function deriveKek(password, salt) {
    const pwBytes = new TextEncoder().encode(password);
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        pwBytes,
        "PBKDF2",
        false,
        ["deriveKey"]
    );
    return await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}

export async function createAndSaveVault(userId, password) {
    await sodium.ready;
    
    // Generate new Ed25519 identity keypair
    const identity = await generateIdentityKeypair();
    // Generate new X25519 prekey
    const prekey = await generatePrekeyPair();
    
    const plainSecrets = {
        identity_sk: sodium.to_hex(identity.privateKey),
        identity_pk: identity.publicKeyHex,
        fingerprint: identity.fingerprint,
        prekey_sk: sodium.to_hex(prekey.privateKey),
        prekey_pk: prekey.publicKeyHex,
        prekey_id: prekey.prekeyId
    };
    
    // Generate fresh 16-byte salt & 12-byte nonce for KEK
    const salt = sodium.randombytes_buf(16);
    const nonce = sodium.randombytes_buf(12);
    const kek = await deriveKek(password, salt);
    
    const plaintextBytes = new TextEncoder().encode(JSON.stringify(plainSecrets));
    const cipherBytes = await encryptFileBytes(plaintextBytes, kek, nonce);
    
    const vaultRecord = {
        userId,
        salt: sodium.to_base64(salt),
        nonce: sodium.to_base64(nonce),
        ciphertext: sodium.to_base64(cipherBytes),
        fingerprint: identity.fingerprint,
        identity_pk: identity.publicKeyHex,
        prekey_pk: prekey.publicKeyHex,
        prekey_id: prekey.prekeyId,
        updatedAt: new Date().toISOString()
    };
    
    // Store in IndexedDB
    const db = await openDatabase();
    if (db) {
        await new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, "readwrite");
            const store = tx.objectStore(STORE_NAME);
            store.put(vaultRecord);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }
    
    // Cache in active session memory
    inMemoryActiveSession = {
        userId,
        identity,
        prekey,
        fingerprint: identity.fingerprint
    };
    
    return inMemoryActiveSession;
}

export async function unlockVault(userId, password) {
    await sodium.ready;
    
    const db = await openDatabase();
    let record = null;
    if (db) {
        record = await new Promise((resolve) => {
            const tx = db.transaction(STORE_NAME, "readonly");
            const store = tx.objectStore(STORE_NAME);
            const req = store.get(userId);
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => resolve(null);
        });
    }
    
    if (!record) {
        // If not in IndexedDB, check memory session
        if (inMemoryActiveSession && inMemoryActiveSession.userId === userId) {
            return inMemoryActiveSession;
        }
        return null;
    }
    
    const salt = sodium.from_base64(record.salt);
    const nonce = sodium.from_base64(record.nonce);
    const cipherBytes = sodium.from_base64(record.ciphertext);
    
    try {
        const kek = await deriveKek(password, salt);
        const plainBytes = await decryptFileBytes(cipherBytes, kek, nonce);
        const secrets = JSON.parse(new TextDecoder().decode(plainBytes));
        
        inMemoryActiveSession = {
            userId,
            identity: {
                publicKey: sodium.from_hex(secrets.identity_pk),
                privateKey: sodium.from_hex(secrets.identity_sk),
                publicKeyHex: secrets.identity_pk,
                fingerprint: secrets.fingerprint
            },
            prekey: {
                publicKey: sodium.from_hex(secrets.prekey_pk),
                privateKey: sodium.from_hex(secrets.prekey_sk),
                publicKeyHex: secrets.prekey_pk,
                prekeyId: secrets.prekey_id
            },
            fingerprint: secrets.fingerprint
        };
        return inMemoryActiveSession;
    } catch (e) {
        throw new Error("Unable to unlock private keystore. Check your password or import a key backup.");
    }
}

export function getActiveKeySession() {
    return inMemoryActiveSession;
}

export function clearActiveKeySession() {
    if (inMemoryActiveSession) {
        // Zero out private key memory buffers where possible
        if (inMemoryActiveSession.identity?.privateKey) {
            sodium.memzero(inMemoryActiveSession.identity.privateKey);
        }
        if (inMemoryActiveSession.prekey?.privateKey) {
            sodium.memzero(inMemoryActiveSession.prekey.privateKey);
        }
        inMemoryActiveSession = null;
    }
}

export async function exportEncryptedBackup(password) {
    if (!inMemoryActiveSession) {
        throw new Error("No active cryptographic session to export.");
    }
    await sodium.ready;
    const secrets = {
        userId: inMemoryActiveSession.userId,
        identity_sk: sodium.to_hex(inMemoryActiveSession.identity.privateKey),
        identity_pk: inMemoryActiveSession.identity.publicKeyHex,
        fingerprint: inMemoryActiveSession.fingerprint,
        prekey_sk: sodium.to_hex(inMemoryActiveSession.prekey.privateKey),
        prekey_pk: inMemoryActiveSession.prekey.publicKeyHex,
        prekey_id: inMemoryActiveSession.prekey.prekeyId
    };
    
    const salt = sodium.randombytes_buf(16);
    const nonce = sodium.randombytes_buf(12);
    const kek = await deriveKek(password, salt);
    
    const plainBytes = new TextEncoder().encode(JSON.stringify(secrets));
    const cipherBytes = await encryptFileBytes(plainBytes, kek, nonce);
    
    return JSON.stringify({
        format: "secureshare-key-backup-v1",
        salt: sodium.to_base64(salt),
        nonce: sodium.to_base64(nonce),
        ciphertext: sodium.to_base64(cipherBytes),
        fingerprint: inMemoryActiveSession.fingerprint,
        exportedAt: new Date().toISOString()
    }, null, 2);
}

export async function importEncryptedBackup(backupJsonStr, password) {
    await sodium.ready;
    const backup = JSON.parse(backupJsonStr);
    if (backup.format !== "secureshare-key-backup-v1") {
        throw new Error("Invalid or unrecognized key backup format.");
    }
    
    const salt = sodium.from_base64(backup.salt);
    const nonce = sodium.from_base64(backup.nonce);
    const cipherBytes = sodium.from_base64(backup.ciphertext);
    
    const kek = await deriveKek(password, salt);
    const plainBytes = await decryptFileBytes(cipherBytes, kek, nonce);
    const secrets = JSON.parse(new TextDecoder().decode(plainBytes));
    
    inMemoryActiveSession = {
        userId: secrets.userId,
        identity: {
            publicKey: sodium.from_hex(secrets.identity_pk),
            privateKey: sodium.from_hex(secrets.identity_sk),
            publicKeyHex: secrets.identity_pk,
            fingerprint: secrets.fingerprint
        },
        prekey: {
            publicKey: sodium.from_hex(secrets.prekey_pk),
            privateKey: sodium.from_hex(secrets.prekey_sk),
            publicKeyHex: secrets.prekey_pk,
            prekeyId: secrets.prekey_id
        },
        fingerprint: secrets.fingerprint
    };
    
    return inMemoryActiveSession;
}
