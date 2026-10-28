# SECURITY POLICY & THREAT MODEL — SECURESHARE // KEY EXCHANGE

## 1. THREAT MODEL & ASSUMPTIONS

SecureShare // KEY EXCHANGE operates under an untrusted server and hostile network threat model.

### In Scope
- **Active Network Adversary (MitM):** Adversaries with capability to intercept, drop, modify, or replay network packets. Defended using TLS transport, strict Content Security Policy (CSP), Ed25519 identity key signatures, and human-in-the-loop out-of-band fingerprint verification.
- **Compromised Storage Backend:** Adversary with complete read access to the database on Port 5001. Defended because the server stores only public keys, signed prekeys, and AES-256-GCM ciphertexts. No private keys, raw shared secrets, or plaintext AES file keys ever reach the server.
- **Prekey Reuse & Double Spending:** Adversary attempting to force reuse of one-time prekeys to break forward secrecy. Defended using database transaction locks (`with_for_update`) and atomic status transitions from `AVAILABLE` -> `RESERVED` -> `CONSUMED`.
- **Identity Spoofing & Impersonation:** Adversary publishing rogue prekeys under another user's name. Defended because every X25519 prekey public key must carry a valid Ed25519 signature from the user's authentic identity key.

### Out of Scope / Environmental Dependencies
- **Compromised Client Endpoint:** Keyloggers, malware, or compromised browser runtime on the user's physical machine.
- **Out-of-Band Channel Compromise:** If an adversary compromises both the primary portal and the independent verification channel (e.g., telephone call or Signal app), they may spoof fingerprint comparison.

---

## 2. CRYPTOGRAPHIC PRIMITIVES & CONSTRUCTIONS

### Ed25519 Long-Term Identity Keys
- Standard: RFC 8032 (Ed25519 pure mode).
- Public Key: 32 bytes (64 hex characters).
- Private Key: 32 bytes seed / 64 bytes secret key.
- Fingerprint: `SHA-256(Ed25519_Public_Key_Bytes)` formatted as 16 hex pairs separated by colons (`XX:XX:XX:...`).

### X25519 One-Time Prekeys
- Standard: RFC 7748.
- Prekey Signing: `Signature = Ed25519_Sign(Identity_Private_Key, Prekey_ID + X25519_Public_Key)`.
- Rejection: All-zero or small-order scalar outputs are explicitly rejected.

### Key Derivation Function (HKDF)
- Standard: RFC 5869 with HMAC-SHA-256.
- PRK: `HKDF-Extract(Salt, X25519_Raw_Shared_Secret)`.
- Info Binding: Domain-separated canonical string:
  ```
  SecureShare-v1|wrapping-key|sender:<sender_id>|recipient:<recipient_id>|tx:<transfer_id>|prekey:<prekey_id>
  ```
- Output Length: 32 bytes (256 bits).

### Key Wrapping Envelope
- Standard: AES-256-GCM (NIST SP 800-38D).
- Nonce: 12 bytes generated via cryptographically secure random number generator (`crypto.getRandomValues`).
- Authenticated Additional Data (AAD):
  ```
  SecureShare-Envelope-Key-v1|transfer:<transfer_id>|prekey:<recipient_prekey_id>
  ```
- Envelope Detached Signature:
  ```
  Sender_Ed25519_Sign(Sender_Identity_Private_Key, Canonical_JSON(Envelope_Payload))
  ```

---

## 3. BROWSER LOCAL STORAGE SECURITY

Private cryptographic keys are stored exclusively in browser IndexedDB under the database name `SecureShareKeyExchangeVault`.
- Encryption Algorithm: AES-256-GCM.
- Key Derivation: PBKDF2 with SHA-256, 100,000 iterations, and a unique 16-byte random salt.
- In-Memory Lifetime: Keys are retained in JavaScript memory only while the vault remains unlocked. Memory zeroization and vault locking purge all references.

---

## 4. REPORTING VULNERABILITIES

To report security vulnerabilities or cryptographic defects, please document reproduction steps and open an issue in the security repository.
