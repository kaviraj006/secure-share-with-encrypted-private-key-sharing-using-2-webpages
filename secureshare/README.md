# SecureShare — End-to-End Encrypted File-Sharing Platform

SecureShare is a zero-knowledge, end-to-end encrypted (E2EE) file-sharing web application built with a cybersecurity black-and-neon-green aesthetic. Files are authenticated and encrypted client-side in the sender's browser with **AES-256-GCM** before uploading. The Flask backend receives and stores **only ciphertext** outside the public web root using random storage identifiers. Cryptographic keys are enveloped using **X25519 Diffie-Hellman**, derived with **HKDF-SHA-256**, and digitally signed with **Ed25519**. The server never receives, sees, or stores plaintext files, unwrapped AES file keys, shared secrets, or user private keys.

---

## 1. Architecture Overview

```
[ Sender Browser ]                                     [ Receiver Browser ]
  1. Generate AES-256 File Key                            8. Fetch Envelope & Ciphertext
  2. Encrypt File (AES-256-GCM)                           9. Verify Ed25519 Signature
  3. X25519 DH (Ephemeral + Recipient Prekey)            10. X25519 DH (Receiver Prekey + Ephemeral)
  4. HKDF-SHA-256 -> Wrapping Key                        11. HKDF-SHA-256 -> Wrapping Key
  5. Wrap AES Key (AES-256-GCM)                          12. Unwrap AES Key
  6. Sign Envelope (Ed25519)                             13. Decrypt Ciphertext (AES-256-GCM)
  7. Upload Ciphertext + Envelope                         14. Trigger Download of Plaintext File
         │                   │                                 ▲                 ▲
         ▼                   ▼                                 │                 │
    [ Storage ]     [ Key Exchange API ] ──────────────────────┘                 │
  (UUIDv4 Ciphertext)  (Signed Envelopes)                                         │
         │                                                                       │
         └────────────────────────── [ Flask Backend ] ──────────────────────────┘
```

---

## 2. Technology Stack

- **Frontend**:
  - HTML5, CSS3 with Custom Cybersecurity Design System
  - Vanilla JavaScript (ES Modules, zero framework overhead)
  - **Web Crypto API**: Native AES-256-GCM, HKDF-SHA-256, PBKDF2, SHA-256
  - **libsodium-wrappers**: X25519 Diffie-Hellman (`crypto_scalarmult`), Ed25519 Signatures (`crypto_sign`)
  - Standalone bundled vendor module for 100% offline and air-gapped capability
- **Backend**:
  - Python 3.13 / Flask 3.1
  - SQLAlchemy / Flask-SQLAlchemy with SQLite metadata storage
  - Flask-Login with secure session cookies
  - Werkzeug scrypt password hashing
  - Sliding-window memory rate limiting and CSRF protection
- **Cryptographic Storage**:
  - Ciphertext saved in `storage/ciphertext/<storage_id>.enc` (outside web root)
  - Path-traversal sanitization and atomic file writes
- **Testing**:
  - Pytest (10 automated unit and integration tests)
  - Node.js ESM test suite (12 cryptographic primitive and envelope tests)

---

## 3. Cryptographic Specification

| Component | Standard / Algorithm | Parameters |
| :--- | :--- | :--- |
| **Symmetric Encryption** | AES-256-GCM (NIST SP 800-38D) | 256-bit key, 96-bit fresh nonce, 128-bit authentication tag |
| **Key Agreement** | X25519 Diffie-Hellman (RFC 7748) | Ephemeral-static Curve25519 scalar multiplication |
| **Key Wrapping Derivation** | HKDF-SHA-256 (RFC 5869) | 32-byte salt, canonical context string binding IDs |
| **Envelope Signing** | Ed25519 PureEdDSA (RFC 8032) | Detached signatures over canonical serialized envelope JSON |
| **Identity Fingerprint** | SHA-256 Hash of Ed25519 Pubkey | 16 hex pairs formatted with colons (`AA:BB:CC:...`) |
| **Local Keystore** | PBKDF2-HMAC-SHA-256 + AES-GCM | 100,000 iterations, 16-byte salt, stored in IndexedDB |

---

## 4. Prerequisites

- Python 3.10+ (tested on Python 3.13)
- Node.js 18+ (tested on Node v24) for optional test runner and bundling
- Modern web browser (Chrome, Edge, Firefox, Safari) with Web Crypto API and WebAssembly support

---

## 5. Installation & Setup

### A. Clone / Navigate to Project Directory
```powershell
cd C:\Users\yuvar\.gemini\antigravity\scratch\secureshare
```

### B. Create and Activate Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### C. Install Dependencies
```powershell
pip install -r requirements.txt
```

### D. Environment Variables Configuration
Copy `.env.example` to `.env`:
```powershell
Copy-Item .env.example .env
```
Default `.env` settings:
```ini
SECRET_KEY=change-this-in-production-to-a-secure-random-secret
FLASK_ENV=development
DATABASE_URL=sqlite:///instance/secureshare.db
MAX_CONTENT_LENGTH=52428800
CIPHERTEXT_STORAGE_DIR=storage/ciphertext
SESSION_COOKIE_SECURE=False
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
```

---

## 6. Running the Application

Start the Flask development server:
```powershell
.\.venv\Scripts\python.exe run.py
```
Or with custom port:
```powershell
$env:PORT="5000"; .\.venv\Scripts\python.exe run.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## 7. Step-by-Step Multi-User Transfer Walkthrough

### Step 1: Register Alice (Sender)
1. Open `http://127.0.0.1:5000/#/register`
2. Enter:
   - Username: `alice`
   - Email: `alice@example.com`
   - Password: `Password123!`
3. Check the zero-knowledge acknowledgement and click **Generate Keys & Register**.
4. The browser automatically generates Alice's Ed25519 identity key and publishes her public fingerprint.

### Step 2: Register Bob (Receiver)
1. Open an Incognito window or separate browser tab at `http://127.0.0.1:5000/#/register`
2. Enter:
   - Username: `bob`
   - Email: `bob@example.com`
   - Password: `Password123!`
3. Complete registration.
4. On Bob's dashboard, note Bob's **Identity Fingerprint** (e.g., `E4:2A:...`).

### Step 3: Alice Encrypts and Dispatches a File
1. In Alice's window, go to **Encrypt & Send** (`#/upload`).
2. Drop or browse any real file (e.g. PDF, image, text document).
3. In **Recipient Username**, type `bob` and click **Find**.
4. Bob's identity card appears with his verified public fingerprint.
5. Check the **Trust-On-First-Use (TOFU)** verification checkbox.
6. Click **Encrypt & Upload File**.
7. The browser reads the file, generates an AES-256 key, encrypts the file with AES-GCM, wraps the key using X25519 and Bob's prekey, signs the envelope with Ed25519, and uploads only the ciphertext.
8. The **Transfer Result** screen shows the generated Transfer ID and share link.

### Step 4: Bob Decrypts and Downloads the File
1. In Bob's window, click **Receive** (`#/receive`) or paste the share link into the address bar.
2. Click **Inspect** to retrieve the transfer metadata and display the Cryptographic Verification Pipeline panel.
3. Click **Retrieve Decryption Key**. The browser retrieves the signed key envelope, verifies Alice's Ed25519 digital signature, validates Bob's recipient prekey identity, derives the wrapping key via X25519 DH + HKDF-SHA-256, and unwraps the 256-bit AES file key in browser memory.
4. Click **Decrypt & Download File** (unlocked once the AES key is recovered). The browser downloads the ciphertext, validates the AES-256-GCM authentication tag, saves the decrypted file to Bob's device, and securely zeroes the key from memory.
5. The recovered file matches Alice's original file **byte-for-byte**!

---

## 8. Running Automated Tests

### Python Backend & Cryptographic Test Suite (Pytest)
```powershell
.\.venv\Scripts\python.exe -m pytest -v tests/
```
Output:
- `test_user_registration_and_login`: Registration, authentication, duplicate prevention, and CSRF defense.
- `test_public_identity_publish_and_search`: Public prekey discovery.
- `test_encrypted_file_upload_and_storage_guarantees`: Verifies raw storage contains only ciphertext.
- `test_transfer_creation_authorization_and_expiry`: Verifies recipient authorization, 403 for third parties, and 410 for expired transfers.
- `test_path_traversal_protection`: Prevents directory traversal attacks (`../`).
- `test_aes_gcm_roundtrip_and_tamper`: Verifies tamper detection (1-bit corruption throws tag error).
- `test_x25519_key_agreement`: Verifies curve25519 scalar multiplication agreement.
- `test_ed25519_signatures_and_tamper_rejection`: Verifies signature validation and forgery rejection.
- `test_hkdf_sha256_derivation`: Verifies canonical KDF derivation.
- `test_full_e2e_transfer_workflow`: End-to-end transfer equality simulation.

### JavaScript Client-Side Cryptographic Test Suite (Node.js ESM)
```powershell
node tests/test_crypto_js.mjs
```
Runs 12 native browser cryptographic tests:
1. AES-GCM Encrypt/Decrypt Round Trip
2. Reject Ciphertext Corrupted by 1 Byte
3. Reject Incorrect AES Key
4. Reject Incorrect Nonce
5. X25519 Shared-Secret Agreement
6. HKDF Derivation Consistency
7. Ed25519 Valid Signature Verification
8. Reject Forged/Tampered Ed25519 Signature
9. Key-Envelope Create and Unwrap Legitimate Flow
10. Reject Envelopes with Mismatched Transfer ID
11. Reject Envelopes Bound to Different Prekey ID
12. Reject Tampered Key-Envelope Content (Signature Fails)

---

## 9. API Reference

### Authentication
- `GET /api/auth/csrf` - Retrieve fresh CSRF token
- `POST /api/auth/register` - Create user account
- `POST /api/auth/login` - Authenticate and create session
- `POST /api/auth/logout` - Terminate active session
- `GET /api/auth/me` - Current session and identity status

### Key-Exchange Adapter
- `POST /api/key-exchange/identities` - Publish or rotate public identity and X25519 prekey
- `GET /api/key-exchange/identities/<target>` - Fetch recipient prekey bundle by username or ID
- `POST /api/key-exchange/envelopes` - Store signed protected key envelope
- `GET /api/key-exchange/envelopes/<transfer_id>` - Recipient-authorized envelope retrieval

### Files & Transfers
- `POST /api/files/upload` - Upload raw ciphertext stream (multipart/form-data)
- `POST /api/transfers` - Create recipient transfer record
- `PATCH /api/transfers/<transfer_id>` - Attach signed key envelope to transfer
- `GET /api/transfers/<transfer_id>` - Fetch transfer metadata
- `GET /api/transfers/<transfer_id>/download` - Stream ciphertext (recipient authorization enforced)
- `DELETE /api/transfers/<transfer_id>` - Permanently delete transfer and ciphertext
- `GET /api/transfers/history` - User's sent and received transfer history
- `POST /api/transfers/cleanup-expired` - Prune expired transfers and storage

---

## 10. Production Deployment Checklist

1. **Enable HTTPS (TLS 1.3)**: Never run client-side encryption in production over plain HTTP.
2. **Set Strong SECRET_KEY**: Generate a 32-byte cryptographically random secret in `.env`.
3. **Set `SESSION_COOKIE_SECURE=True`**: Enforces HTTPS-only cookies.
4. **Production WSGI Server**: Run with Gunicorn or Waitress behind Nginx:
   ```bash
   gunicorn -w 4 -b 127.0.0.1:5000 "app:create_app()"
   ```
5. **Periodic Expiry Cron**: Schedule a cron job or scheduled task calling `/api/transfers/cleanup-expired` or running a maintenance script.
6. **Subresource Integrity (SRI)**: When deploying static JS assets, include SRI hashes if hosted on external CDNs.
