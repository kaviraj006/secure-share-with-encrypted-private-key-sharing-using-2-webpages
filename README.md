# SecureShare: Zero-Knowledge Browser-Encrypted File Transit & Key Exchange

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Cryptography: AES-256-GCM](https://img.shields.io/badge/Cipher-AES--256--GCM-brightgreen.svg)]()
[![Key Agreement: X25519 + HKDF](https://img.shields.io/badge/Key_Agreement-X25519_%2B_HKDF--SHA--256-red.svg)]()
[![Signatures: Ed25519](https://img.shields.io/badge/Signatures-Ed25519-orange.svg)]()
[![Zero-Knowledge](https://img.shields.io/badge/Architecture-Zero--Knowledge-green.svg)]()

> **SecureShare** is a dual-portal cybersecurity system for defense-grade, zero-knowledge encrypted file transit. Files are encrypted client-side in the browser using hardware-accelerated **AES-256-GCM** before upload. File decryption keys are wrapped using **X25519 ECDH** and **HKDF-SHA-256**, sealed with **Ed25519 digital signatures**, and dispatched via protected envelopes. Neither the File Vault server nor the Key Exchange Portal ever receives unencrypted plaintext, raw AES keys, or private identity keys.

---

## Architecture Overview

SecureShare is architected as two independent, cooperating web services:

```
┌────────────────────────────────────────────────────────┐
│               SENDER CLIENT BROWSER                    │
│  1. Generates 256-bit AES file key                     │
│  2. Encrypts file with AES-256-GCM in memory           │
│  3. Wraps AES key via X25519 ECDH + HKDF-SHA-256       │
│  4. Signs envelope with Ed25519 private signing key    │
└───────────────┬────────────────────────┬───────────────┘
                │                        │
       Ciphertext Upload           Sealed Key Envelope
      (Nonce + Tag + Data)        (Signed Key Package)
                │                        │
                ▼                        ▼
┌──────────────────────────────┐ ┌──────────────────────────────┐
│    SECURESHARE FILE VAULT    │ │  KEY EXCHANGE PORTAL (PORT 5001)
│         (PORT 5000)          │ │                              │
│  - Ciphertext Transit Store  │ │  - Ed25519 Identity Registry │
│  - Blind Transfer Routing    │ │  - Signed X25519 Prekey Pool │
│  - TOFU Verification UI      │ │  - Protected Envelope Inbox  │
│  - Expiration & Retention    │ │  - Key-Change Alerting       │
└───────────────┬──────────────┘ └───────────────┬──────────────┘
                │                                │
       Ciphertext Download              Envelope Retrieval
                │                                │
                ▼                                ▼
┌────────────────────────────────────────────────────────┐
│              RECIPIENT CLIENT BROWSER                  │
│  1. Verifies sender's Ed25519 digital signature        │
│  2. Computes X25519 shared secret with prekey private  │
│  3. Unwraps AES-256-GCM file key via HKDF-SHA-256      │
│  4. Decrypts ciphertext & authenticates 128-bit tag    │
└────────────────────────────────────────────────────────┘
```

---

## Applications in this Repository

### 1. `secureshare/` — File Vault (Port 5000)
- **UI Theme**: Cinematic boxy dark-green terminal aesthetics (`#00FF41` on `#080F0A`).
- **Client Encryption**: Web Crypto API hardware-accelerated AES-256-GCM.
- **Recipient Directory**: Built-in recipient discovery and quick-select dropdown populated with active platform identities.
- **TOFU Verification**: Out-of-band Ed25519 fingerprint comparison before transfer authorization.
- **Encrypted Storage**: Blind storage where plaintext is never received by the backend.

### 2. `secureshare_keyx/` — Key Exchange Portal (Port 5001)
- **UI Theme**: Rugged red-and-black industrial cybersecurity console (`#FF2020` on `#0E0E12`).
- **Cryptographic Identities**: Ed25519 signing keypairs generated client-side and encrypted in browser IndexedDB.
- **Signed Prekey Pool**: Ephemeral X25519 prekeys with batch replenishment and one-time consumption.
- **Key Envelope Tool**: Interactive envelope construction with both **direct AES key paste** and **auto-generation** modes.
- **Envelope Inbox**: Recipient inbox for inspecting, verifying Ed25519 signatures, and unwrapping AES file keys.
- **Trusted Contacts**: Contact book with automatic key-change detection (MITM protection).

---

## Cryptographic Protocol Specification

| Primitive | Specification | Purpose |
| :--- | :--- | :--- |
| **Payload Cipher** | AES-256-GCM (128-bit tag, 96-bit nonce) | Client-side file encryption |
| **Key Agreement** | X25519 (Curve25519 ECDH) | Asymmetric key exchange |
| **Key Derivation** | HKDF-SHA-256 (RFC 5869) | Derive key-wrapping key from ECDH secret |
| **Envelope Cipher** | AES-256-GCM | Encrypt raw AES file key inside envelope |
| **Signatures** | Ed25519 (EdDSA over Curve25519) | Sender identity proof & envelope authenticity |
| **Fingerprints** | SHA-256 (Colon-delimited hex) | Out-of-band TOFU identity verification |
| **Identity Storage** | IndexedDB + PBKDF2 / AES-GCM | Encrypted local identity vault in browser |

---

## Quick Start Guide

### Prerequisites
- Python 3.10 or higher
- Node.js (optional, for running client-side JS test suites)

### 1. Set Up & Start SecureShare File Vault (Port 5000)

```powershell
# Open Terminal 1
cd secureshare

# Create virtual environment & install dependencies
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt

# Start File Vault server
python run.py
```
*File Vault will be running at [http://127.0.0.1:5000](http://127.0.0.1:5000)*

---

### 2. Set Up & Start Key Exchange Portal (Port 5001)

```powershell
# Open Terminal 2
cd secureshare_keyx

# Create virtual environment & install dependencies
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt

# Start Key Exchange Portal server
python run.py
```
*Key Exchange Portal will be running at [http://127.0.0.1:5001](http://127.0.0.1:5001)*

---

## End-to-End Workflow

1. **Register & Initialize Identities**:
   - Navigate to `http://127.0.0.1:5001` (Key Exchange Portal).
   - Log in or register an account.
   - Go to **[02] IDENTITY VAULT** and initialize your cryptographic identity. A unique Ed25519 signing key and X25519 prekey pool are generated in your browser.
2. **Send an Encrypted File**:
   - Navigate to `http://127.0.0.1:5000` (File Vault).
   - Click **INITIATE SECURE TRANSFER** (`/#/upload`).
   - Select a target file (encrypted locally in browser memory with AES-256-GCM).
   - Select recipient from the **Directory Dropdown** or enter username directly.
   - Confirm out-of-band fingerprint verification and dispatch transfer.
3. **Receive & Decrypt**:
   - The recipient opens File Vault transfer link or checks their **Transfer History** / **Envelope Inbox** on Port 5001.
   - The recipient verifies the sender's Ed25519 signature, unwraps the AES file key, and decrypts the file bit-for-bit in browser memory.

---

## Running Automated Test Suites

```powershell
cd secureshare

# Run end-to-end authentication tag & unwrap verification
python tests/test_e2e_auth_tag_fix.py

# Run comprehensive bit-for-bit decryption test
python tests/test_full_unwrap_and_decrypt.py

# Run complete two-user transfer test
python tests/test_master_e2e_dummy_file.py
```

---

## License

This project is licensed under the MIT License - see the `SECURITY.md` file for vulnerability disclosure policies.
