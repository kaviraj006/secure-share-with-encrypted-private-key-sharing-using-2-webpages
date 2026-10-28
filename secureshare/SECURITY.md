# Security Policy — SecureShare

## 1. Supported Security Guarantees

SecureShare is designed around a **Zero-Knowledge Architecture**. The following guarantees are enforced by the protocol and software implementation:

1. **Client-Side Encryption:**
   Plaintext files are encrypted in the sender's browser memory using **AES-256-GCM** before any network transmission occurs.
2. **Ciphertext-Only Storage:**
   The backend web server and file storage system receive and store only encrypted ciphertext bytes. Plaintext is never written to disk, stored in databases, or cached on the server.
3. **No Private Key Access:**
   User private identity keys (Ed25519) and private prekeys (X25519) are generated in the browser and stored inside an encrypted local vault (PBKDF2-SHA256 + AES-GCM) in IndexedDB. Private keys are never transmitted to the server.
4. **Non-Repudiation & Tamper Resistance:**
   Key envelopes are digitally signed using the sender's Ed25519 identity key. Any modification to the envelope, transfer ID, recipient ID, or ciphertext triggers cryptographic verification failure and aborts decryption.
5. **Enforced Access Authorization:**
   A transfer ID alone is never sufficient authorization to download. The backend verifies the authenticated session identity before streaming ciphertext or releasing protected envelopes.

---

## 2. Cryptographic Specifications

- **Symmetric Cipher:** AES-256-GCM (NIST SP 800-38D) with fresh 96-bit random nonces and 128-bit authentication tags.
- **Key Agreement:** Curve25519 (X25519 Diffie-Hellman, RFC 7748) via libsodium.
- **Key Derivation:** HKDF-SHA-256 (RFC 5869) with 32-byte salts and canonical context binding.
- **Digital Signatures:** Ed25519 (RFC 8032) detached signatures over canonical JSON serializations.
- **Password Hashing:** scrypt with default secure cost parameters via Werkzeug.

---

## 3. Threat Model Boundaries & Known Limitations

1. **Malicious Server / Compromised Origin Limitation:**
   Browser-based cryptography relies on the assumption that the web server serves authentic, uncorrupted JavaScript. If an adversary compromises the server host, DNS, or TLS termination proxy, they could serve modified JavaScript capable of exfiltrating decrypted files from browser memory. For high-assurance scenarios, out-of-band fingerprint verification or standalone desktop clients are recommended.
2. **Forward Secrecy Nuance:**
   Transfers use ephemeral X25519 keys on the sender side and semi-static prekeys on the receiver side. Compromise of a recipient's long-term private prekey prior to rotation would allow historical envelopes addressed to that prekey to be decrypted.
3. **Forgotten Passwords and Key Loss:**
   Because the server does not store user private keys, a forgotten password cannot be reset to recover historical files without an encrypted key backup (`.secureshare-key`).
4. **Browser Memory Hygiene:**
   While the application wipes keys and buffers (`sodium.memzero`) upon download completion, JavaScript garbage collection does not guarantee immediate zeroing of immutable string copies in browser heap memory.

---

## 4. Reporting a Security Vulnerability

If you discover a security vulnerability in SecureShare, please report it privately:

- **Email:** `security@secureshare.internal` (or submit a confidential issue)
- **Encryption:** Use the security team's PGP public key where available.
- **Disclosure Policy:** Please do not publicly disclose the vulnerability until the development team has acknowledged, patched, and verified the fix.
