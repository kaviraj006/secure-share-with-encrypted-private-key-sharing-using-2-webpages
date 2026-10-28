# SECURESHARE // KEY EXCHANGE PORTAL (PORT 5001)

> **Rugged Red-and-Black Industrial Terminal Workstation for Authenticated End-to-End Cryptographic Key Exchange**

SecureShare // KEY EXCHANGE is the dedicated cryptographic identity, key discovery, and key exchange service in the SecureShare end-to-end encrypted file-sharing ecosystem. While the sibling file-sharing portal (`http://127.0.0.1:5000`) manages encrypted chunk storage and retrieval, this portal coordinates zero-knowledge identity verification, X25519 Diffie–Hellman key agreements, HKDF-SHA-256 key derivations, and authenticated AES file-key envelope delivery.

---

## ARCHITECTURE & DUAL-PORTAL WORKFLOW

```
+-----------------------------------------------------------------------------------------+
|                                    SENDER BROWSER                                       |
|  1. Encrypts local file with AES-256-GCM                                                |
|  2. Uploads encrypted file payload only to File Vault (Port 5000) -> Obtains Transfer ID|
|  3. Discovers Recipient's Ed25519 Identity & Signed X25519 Prekey from Key Exchange     |
|  4. Computes X25519 DH Agreement + HKDF-SHA-256 Wrapping Key                            |
|  5. Wraps raw AES-256 File Key inside AES-GCM envelope + signs with Ed25519             |
|  6. Submits Key Envelope to Key Exchange (Port 5001)                                    |
+-----------------------------------------------------------------------------------------+
                                          |
                     +--------------------+--------------------+
                     |                                         |
                     v                                         v
   +------------------------------------+    +------------------------------------+
   |   SECURESHARE // FILE STORAGE      |    |   SECURESHARE // KEY EXCHANGE      |
   |   PORT 5000                        |    |   PORT 5001                        |
   |   - Encrypted file blobs           |    |   - Ed25519 identity directory     |
   |   - Zero-knowledge storage         |    |   - One-time signed X25519 prekeys |
   |   - AES-GCM authenticated chunks   |    |   - Encrypted key envelope inbox   |
   +------------------------------------+    |   - Out-of-band fingerprint trust  |
                     ^                       +------------------------------------+
                     |                                         |
+--------------------+-----------------------------------------+--------------------------+
|                                   RECIPIENT BROWSER                                     |
|  1. Receives Transfer ID notification & downloads sealed Key Envelope from Port 5001   |
|  2. Verifies Sender's Ed25519 signature on envelope structure                           |
|  3. Locates private X25519 Prekey in local IndexedDB vault                             |
|  4. Computes X25519 DH Agreement + derives HKDF-SHA-256 Wrapping Key                    |
|  5. Unwraps raw 256-bit AES File Key locally in browser memory                          |
|  6. Downloads ciphertext from Port 5000 and decrypts file in browser memory              |
+-----------------------------------------------------------------------------------------+
```

---

## CRYPTOGRAPHIC PROTOCOL SPECIFICATION

| Component | Standard / Algorithm | Role & Parameters |
|---|---|---|
| **Identity Keys** | Ed25519 (RFC 8032) | Long-term asymmetric signing keypair. Used to sign one-time prekeys and key envelopes. |
| **Identity Fingerprint** | SHA-256 (`XX:XX:XX:...`) | 32-byte digest represented as colon-separated hex bytes for out-of-band human comparison and QR code display. |
| **Prekey Agreement** | X25519 (RFC 7748) | Ephemeral sender keypair and recipient signed one-time prekey establish a 32-byte raw shared secret. |
| **Prekey Signatures** | Ed25519 Detached Signature | Recipient signs their X25519 prekey public key with their Ed25519 identity private key to prevent rogue prekey injections. |
| **Key Derivation** | HKDF-SHA-256 (RFC 5869) | Derives a 32-byte wrapping key using an isolated domain-separated `info` string binding sender ID, recipient ID, transfer ID, and prekey ID. |
| **Key Envelope** | AES-256-GCM (NIST SP 800-38D)| Wraps the raw 256-bit AES file key using a fresh 12-byte nonce and cryptographically authenticated additional data (AAD). |
| **Local Key Vault** | PBKDF2 + AES-256-GCM | IndexedDB (`SecureShareKeyExchangeVault`) encrypted at rest with 100,000 PBKDF2 iterations and a user master passphrase. |

---

## SECURITY & ZERO-KNOWLEDGE GUARANTEES

- **Zero Server Knowledge:** The Flask backend never receives, stores, or processes private identity keys, raw shared secrets, plaintext files, or unwrapped AES file keys.
- **One-Time Prekey Single-Use:** The database locks and flags prekeys as `RESERVED` and `CONSUMED` to guarantee forward secrecy and prevent concurrent replay.
- **Replay & Tamper Defense:** Every key envelope enforces unique transfer IDs. Any modification to envelope metadata or cipher data breaks the detached Ed25519 signature and results in immediate rejection.
- **Out-of-Band Verification:** Unverified contacts trigger warnings. Changing or rotating an identity key automatically demotes trusted contacts to `KEY CHANGED`, requiring explicit re-verification before further key wrapping.
- **Memory Zeroization:** Single-click memory wipe button purges cached cryptographic secrets and locks the browser IndexedDB vault.

---

## PROJECT STRUCTURE

```
secureshare_keyx/
├── app/
│   ├── __init__.py               # Flask app factory registering blueprints and CSP headers
│   ├── config.py                 # Configuration settings (Port 5001, CORS, CSP, SQLite)
│   ├── extensions.py             # SQLAlchemy, LoginManager, CORS
│   ├── models.py                 # User, PublicIdentity, PublicPrekey, KeyEnvelope, SecurityEvent
│   ├── routes/
│   │   ├── auth.py               # Authentication (register, login, logout, me, CSRF)
│   │   ├── identity.py           # Identity publishing, rotation, and discovery
│   │   ├── contacts.py           # Trusted contacts and out-of-band fingerprint verification
│   │   ├── prekeys.py            # Prekey pool, reservation, and batch replenishment
│   │   ├── envelopes.py          # Envelope dispatch, inbox retrieval, accept, and reject
│   │   ├── history.py            # Transfer audit history
│   │   ├── security.py           # Immutable security event log
│   │   └── integration.py        # Cross-portal API routes for File Vault (Port 5000)
│   ├── services/
│   │   ├── prekey_service.py     # Atomicity and concurrency enforcement for prekeys
│   │   ├── security_logger.py    # Sanitized audit logging
│   │   └── validation.py         # CSRF verification and hex validation
│   └── utils/
│       └── rate_limit.py         # In-memory sliding window rate limiter
├── static/
│   ├── css/
│   │   └── styles.css            # Rugged Red-and-Black industrial terminal stylesheet
│   ├── js/
│   │   ├── api.js                # API client with automatic CSRF token management
│   │   ├── ui.js                 # Toasts, Modals, Clipboard, and offline QR matrix generator
│   │   ├── app.js                # Full Single-Page Application controller
│   │   ├── crypto/
│   │   │   ├── aes_gcm.js        # Web Crypto AES-256-GCM envelope wrapping
│   │   │   ├── ed25519_sign.js   # Ed25519 key generation and detached signatures
│   │   │   ├── x25519_hkdf.js    # X25519 DH agreement & HKDF key derivation
│   │   │   ├── envelope.js       # Canonical serialization, envelope sealing, and unwrapping
│   │   │   └── keystore.js       # IndexedDB encrypted vault (PBKDF2-100k + AES-GCM)
│   │   └── vendor/
│   │       └── sodium.js         # Offline libsodium browser bundle
│   └── favicon.svg               # Tactical red-and-black icon
├── templates/
│   └── index.html                # Industrial terminal workstation SPA template
├── tests/
│   ├── conftest.py               # Pytest fixtures and in-memory test database
│   ├── test_crypto.py            # Python Hazmat cryptographic validation tests
│   ├── test_backend.py           # Backend routes, auth, rate limiting, and SPA tests
│   ├── test_integration.py       # End-to-end multi-party exchange and portal routes
│   └── test_crypto_js.mjs        # 10/10 JavaScript Web Crypto & Libsodium test suite
├── instance/                     # SQLite database instance directory
├── package.json                  # Node.js ESM configuration
├── requirements.txt              # Python dependencies
├── run.py                        # Server runner on Port 5001
└── README.md                     # Documentation
```

---

## QUICKSTART & LOCAL RUN INSTRUCTIONS

### 1. Prerequisites
- Python 3.10+
- Node.js 18+ (for running JavaScript crypto tests)

### 2. Virtual Environment Setup
```powershell
# Navigate to directory
cd C:\Users\yuvar\.gemini\antigravity\scratch\secureshare_keyx

# Create virtual environment (if not already created)
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Launching the Key Exchange Server
```powershell
python run.py
```
The server will bind to `http://127.0.0.1:5001`.

### 4. Running the Sibling File-Sharing Website (Optional)
In a separate terminal:
```powershell
cd C:\Users\yuvar\.gemini\antigravity\scratch\secureshare
python app.py
```
The file storage website runs on `http://127.0.0.1:5000`.

---

## AUTOMATED TEST SUITES

### 1. Python Backend & Cryptography Tests (12 Tests)
```powershell
.\.venv\Scripts\python.exe -m pytest -v tests/
```
All 12 tests cover authentication, CSRF tokens, identity publishing, key rotation detection, envelope authorization, rate limiting, and cross-portal endpoints.

### 2. Client-Side JavaScript Cryptography Tests (10 Tests)
```powershell
node tests/test_crypto_js.mjs
```
All 10 tests validate X25519 DH scalar multiplication, rejection of invalid keys, HKDF consistency, Ed25519 detached signatures, tamper rejection, and full AES-256-GCM envelope round trips.

---

## API REFERENCE

### Authentication (`/api/auth`)
- `GET /api/auth/csrf` - Retrieve fresh CSRF token.
- `POST /api/auth/register` - Create account (`username`, `email`, `password`).
- `POST /api/auth/login` - Authenticate session (`identifier`, `password`).
- `POST /api/auth/logout` - Invalidate session and CSRF tokens.
- `GET /api/auth/me` - Session status and current user info.

### Identities (`/api/identities`)
- `POST /api/identities` - Publish or rotate Ed25519 identity key and SHA-256 fingerprint.
- `GET /api/identities/me` - Retrieve authenticated user's public identity.
- `GET /api/identities/<target>` - Discover public identity for specified user.
- `GET /api/users/search?q=<query>` - Search users for contact discovery.

### Contacts & Verification (`/api/contacts`)
- `GET /api/contacts` - List trusted contacts with current verification statuses.
- `POST /api/contacts` - Add contact by username (defaults to `UNVERIFIED`).
- `POST /api/contacts/<id>/verify` - Mark contact `VERIFIED` after out-of-band comparison.
- `DELETE /api/contacts/<id>` - Delete trusted contact record.

### Prekeys (`/api/prekeys`)
- `POST /api/prekeys` - Publish a single signed prekey or a batch of signed prekeys.
- `GET /api/prekeys/me` - Retrieve user's prekey pool and replenishment telemetry.
- `GET /api/prekeys/<target>` - Fetch recipient's available signed prekey.
- `POST /api/prekeys/<id>/reserve` - Reserve prekey for impending envelope creation.

### Envelopes & Inbox (`/api/envelopes`)
- `POST /api/envelopes` - Submit sealed key envelope.
- `GET /api/envelopes/inbox` - Retrieve incoming pending key envelopes.
- `GET /api/envelopes/<transfer_id>` - Fetch envelope details (authorized parties only).
- `POST /api/envelopes/<transfer_id>/accept` - Mark envelope accepted after local unwrapping.
- `POST /api/envelopes/<transfer_id>/reject` - Reject incoming key envelope.

### Cross-Portal Integration (`/api/key-exchange`)
- `GET /api/key-exchange/identities/<target>` - Direct discovery endpoint for Port 5000.
- `POST /api/key-exchange/envelopes` - Cross-origin envelope submission from Port 5000.
- `GET /api/key-exchange/envelopes/<transfer_id>` - Cross-origin envelope retrieval.
