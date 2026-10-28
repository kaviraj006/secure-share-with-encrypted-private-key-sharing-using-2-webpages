/**
 * SecureShare // KEY EXCHANGE - Client-Side Key Vault & Prekey Store
 * Zero-knowledge encryption via PBKDF2 + AES-GCM in IndexedDB.
 */

import sodium from '../vendor/sodium.js';
import { generateIdentityKeypair } from './ed25519_sign.js';
import { generateSignedPrekey } from './x25519_hkdf.js';
import { encryptBytes, decryptBytes } from './aes_gcm.js';

const DB_NAME = "SecureShareKeyExchangeVault";
const DB_VERSION = 1;
const STORE_NAME = "keyx_vault";

let inMemoryActiveSession = null;

function openDatabase() {
    return new Promise((resolve) => {
        if (typeof indexedDB === "undefined") {
            return resolve(null);
        }
        try {
            const request = indexedDB.open(DB_NAME, DB_VERSION);
            request.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains(STORE_NAME)) {
                    db.createObjectStore(STORE_NAME, { keyPath: "userId" });
                }
            };
            request.onsuccess = () => resolve(request.result);
            request.onerror = (e) => {
                console.warn("IndexedDB open error:", request.error);
                resolve(null);
            };
        } catch (err) {
            console.warn("IndexedDB access error:", err);
            resolve(null);
        }
    });
}

async function deriveKek(password, salt) {
    if (!password) {
        throw new Error("Master passphrase required for key derivation.");
    }
    if (!salt) {
        throw new Error("Salt required for key derivation.");
    }
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

export class KeyStore {
    constructor(userId) {
        this.userId = userId;
        this.unlocked = false;
        this.passphrase = null;
        this.salt = null;
        this.identity = null;
        this.prekeys = {};
    }

    get isUnlocked() {
        return Boolean(this.unlocked && this.passphrase);
    }

    async hasVaultRecord() {
        const db = await openDatabase();
        if (!db) return false;
        return new Promise((resolve) => {
            try {
                const tx = db.transaction(STORE_NAME, "readonly");
                const store = tx.objectStore(STORE_NAME);
                const req = store.get(this.userId);
                req.onsuccess = () => resolve(Boolean(req.result));
                req.onerror = () => resolve(false);
            } catch (_) {
                resolve(false);
            }
        });
    }

    async unlock(passphrase) {
        await sodium.ready;
        if (!passphrase) return false;

        const db = await openDatabase();
        let record = null;
        if (db) {
            record = await new Promise((resolve) => {
                try {
                    const tx = db.transaction(STORE_NAME, "readonly");
                    const store = tx.objectStore(STORE_NAME);
                    const req = store.get(this.userId);
                    req.onsuccess = () => resolve(req.result);
                    req.onerror = () => resolve(null);
                } catch (_) {
                    resolve(null);
                }
            });
        }

        if (!record) {
            // New vault initialization for this user
            this.salt = sodium.randombytes_buf(16);
            this.passphrase = passphrase;
            this.unlocked = true;
            this.identity = null;
            this.prekeys = {};
            return true;
        }

        if (!record.salt || !record.nonce || !record.ciphertext) {
            console.warn("Corrupted or incomplete vault record in IndexedDB for user:", this.userId);
            this.unlocked = false;
            this.passphrase = null;
            return false;
        }

        try {
            const salt = sodium.from_base64(record.salt);
            const nonce = sodium.from_base64(record.nonce);
            const cipherBytes = sodium.from_base64(record.ciphertext);

            const kek = await deriveKek(passphrase, salt);
            const plainBytes = await decryptBytes(cipherBytes, kek, nonce);
            const vault = JSON.parse(new TextDecoder().decode(plainBytes));

            this.salt = salt;
            this.passphrase = passphrase;
            this.unlocked = true;

            if (vault.identity) {
                this.identity = vault.identity;
            } else if (vault.identity_pk) {
                this.identity = {
                    publicKey: vault.identity_pk,
                    privateKey: vault.identity_sk,
                    fingerprint: vault.fingerprint
                };
            } else {
                this.identity = null;
            }

            this.prekeys = vault.prekeys || {};
            return true;
        } catch (e) {
            this.unlocked = false;
            this.passphrase = null;
            return false;
        }
    }

    async persist() {
        if (!this.unlocked || !this.passphrase || !this.userId) return;
        await sodium.ready;

        const plainVault = {
            userId: this.userId,
            identity: this.identity,
            prekeys: this.prekeys,
            updatedAt: new Date().toISOString()
        };

        if (!this.salt) {
            this.salt = sodium.randombytes_buf(16);
        }
        const nonce = sodium.randombytes_buf(12);
        const kek = await deriveKek(this.passphrase, this.salt);
        const plainBytes = new TextEncoder().encode(JSON.stringify(plainVault));
        const cipherBytes = await encryptBytes(plainBytes, kek, nonce);

        const record = {
            userId: this.userId,
            salt: sodium.to_base64(this.salt),
            nonce: sodium.to_base64(nonce),
            ciphertext: sodium.to_base64(cipherBytes),
            fingerprint: this.identity?.fingerprint || null,
            updatedAt: new Date().toISOString()
        };

        const db = await openDatabase();
        if (db) {
            await new Promise((resolve, reject) => {
                try {
                    const tx = db.transaction(STORE_NAME, "readwrite");
                    const store = tx.objectStore(STORE_NAME);
                    store.put(record);
                    tx.oncomplete = () => resolve();
                    tx.onerror = () => reject(tx.error);
                } catch (err) {
                    reject(err);
                }
            });
        }
    }

    async getIdentity() {
        if (!this.isUnlocked) return null;
        return this.identity;
    }

    async saveIdentity(publicKey, privateKey, fingerprint) {
        if (!this.isUnlocked) throw new Error("Vault is locked. Cannot save identity.");
        if (!publicKey) throw new Error("Public key cannot be null or undefined.");
        if (!privateKey) throw new Error("Private key cannot be null or undefined.");

        await sodium.ready;
        const pubHex = typeof publicKey === "string" ? publicKey : sodium.to_hex(publicKey);
        const privHex = typeof privateKey === "string" ? privateKey : sodium.to_hex(privateKey);

        this.identity = {
            publicKey: pubHex,
            privateKey: privHex,
            fingerprint: fingerprint || ""
        };
        await this.persist();
    }

    async getPrekey(prekeyId) {
        if (!this.isUnlocked) return null;
        return this.prekeys[prekeyId] || null;
    }

    async savePrekey(prekeyId, x25519PublicKey, x25519PrivateKey, signature = "") {
        if (!this.isUnlocked) throw new Error("Vault is locked. Cannot save prekey.");
        if (!prekeyId) throw new Error("Prekey ID cannot be null or undefined.");
        if (!x25519PublicKey) throw new Error("X25519 public key cannot be null or undefined.");
        if (!x25519PrivateKey) throw new Error("X25519 private key cannot be null or undefined.");

        await sodium.ready;
        const pubHex = typeof x25519PublicKey === "string" ? x25519PublicKey : sodium.to_hex(x25519PublicKey);
        const privHex = typeof x25519PrivateKey === "string" ? x25519PrivateKey : sodium.to_hex(x25519PrivateKey);

        this.prekeys[prekeyId] = {
            prekeyId,
            publicKey: pubHex,
            privateKey: privHex,
            x25519PublicKey: pubHex,
            x25519PrivateKey: privHex,
            signature: signature || ""
        };
        await this.persist();
    }

    async changePassphrase(oldPass, newPass) {
        if (!this.isUnlocked) {
            const ok = await this.unlock(oldPass);
            if (!ok) throw new Error("Incorrect current vault passphrase.");
        }
        if (!newPass || newPass.length < 6) {
            throw new Error("New passphrase must be at least 6 characters.");
        }

        this.salt = sodium.randombytes_buf(16);
        this.passphrase = newPass;
        await this.persist();
        return true;
    }

    lock() {
        if (this.identity?.privateKey && typeof this.identity.privateKey !== "string") {
            try { sodium.memzero(this.identity.privateKey); } catch (_) {}
        }
        this.identity = null;
        this.prekeys = {};
        this.unlocked = false;
        this.passphrase = null;
    }

    async exportEncryptedBackup(password) {
        if (!this.isUnlocked) throw new Error("Vault must be unlocked to export backup.");
        await sodium.ready;

        const payload = {
            userId: this.userId,
            identity: this.identity,
            prekeys: this.prekeys,
            exportedAt: new Date().toISOString()
        };

        const salt = sodium.randombytes_buf(16);
        const nonce = sodium.randombytes_buf(12);
        const kek = await deriveKek(password, salt);
        const plainBytes = new TextEncoder().encode(JSON.stringify(payload));
        const cipherBytes = await encryptBytes(plainBytes, kek, nonce);

        return JSON.stringify({
            format: "secureshare-keyx-backup-v1",
            salt: sodium.to_base64(salt),
            nonce: sodium.to_base64(nonce),
            ciphertext: sodium.to_base64(cipherBytes),
            fingerprint: this.identity?.fingerprint || null,
            exportedAt: new Date().toISOString()
        }, null, 2);
    }

    async importEncryptedBackup(backupJsonStr, password) {
        await sodium.ready;
        const backup = JSON.parse(backupJsonStr);
        if (backup.format !== "secureshare-keyx-backup-v1") {
            throw new Error("Unrecognized backup file format.");
        }

        const salt = sodium.from_base64(backup.salt);
        const nonce = sodium.from_base64(backup.nonce);
        const cipherBytes = sodium.from_base64(backup.ciphertext);

        const kek = await deriveKek(password, salt);
        const plainBytes = await decryptBytes(cipherBytes, kek, nonce);
        const data = JSON.parse(new TextDecoder().decode(plainBytes));

        if (data.identity) {
            this.identity = data.identity;
        }
        if (data.prekeys) {
            this.prekeys = { ...this.prekeys, ...data.prekeys };
        }
        this.unlocked = true;
        this.passphrase = password;
        if (!this.salt) this.salt = salt;
        await this.persist();
        return true;
    }
}

// Backwards-compatible legacy functions
export async function createAndSaveVault(userId, password) {
    const ks = new KeyStore(userId);
    await ks.unlock(password);
    const identity = await generateIdentityKeypair();
    await ks.saveIdentity(identity.publicKeyHex, identity.privateKeyHex, identity.fingerprint);

    for (let i = 0; i < 3; i++) {
        const pk = await generateSignedPrekey(identity);
        await ks.savePrekey(pk.prekeyId, pk.publicKeyHex, pk.x25519PrivateKey, pk.signature);
    }
    inMemoryActiveSession = ks;
    return ks;
}

export async function unlockVault(userId, password) {
    const ks = new KeyStore(userId);
    const ok = await ks.unlock(password);
    if (!ok) throw new Error("Unable to unlock cryptographic vault. Verify master password.");
    inMemoryActiveSession = ks;
    return ks;
}

export async function addPrekeyToVault(prekeyObj) {
    if (!inMemoryActiveSession) throw new Error("No active key session.");
    await inMemoryActiveSession.savePrekey(
        prekeyObj.prekeyId,
        prekeyObj.publicKeyHex,
        prekeyObj.x25519PrivateKey || prekeyObj.privateKeyHex,
        prekeyObj.signature
    );
}

export function getActiveKeySession() {
    return inMemoryActiveSession;
}

export function clearActiveKeySession() {
    if (inMemoryActiveSession) {
        inMemoryActiveSession.lock();
        inMemoryActiveSession = null;
    }
}

export async function exportEncryptedBackup(password) {
    if (!inMemoryActiveSession) throw new Error("No active session to export.");
    return await inMemoryActiveSession.exportEncryptedBackup(password);
}

export async function importEncryptedBackup(backupJsonStr, password) {
    if (!inMemoryActiveSession) {
        inMemoryActiveSession = new KeyStore("imported_user");
        inMemoryActiveSession.unlocked = true;
        inMemoryActiveSession.passphrase = password;
    }
    return await inMemoryActiveSession.importEncryptedBackup(backupJsonStr, password);
}
