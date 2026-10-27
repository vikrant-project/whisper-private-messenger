# System Architecture & Security Specification

This document details the architecture, cryptographic protocol, identity ownership model, recovery design, and threat model for the Zero-Signup End-to-End Encrypted Private Messaging Application.

---

## 1. High-Level Architecture

The application is built as a zero-login, privacy-first progressive web application with a secure asynchronous backend:

```
+-----------------------------------------------------------------------------------+
| Browser Client (Local-First & Client-Side Cryptography)                           |
|                                                                                   |
|  [ User Interface (Vanilla CSS/JS, Dark Glassmorphism, Responsive) ]              |
|        |                                                                          |
|  [ E2EE Crypto Engine (TweetNaCl.js + Web Crypto API) ]                           |
|    - Ed25519 Identity Keypair (Signing & Ownership Proof)                        |
|    - X25519 Ephemeral Pre-Keys & Double Ratchet (Forward Secrecy)                |
|    - AES-256-GCM / XSalsa20-Poly1305 Payload Encryption                         |
|    - PBKDF2 + AES-GCM Encrypted Recovery Backup Engine                           |
|        |                                                                          |
|  [ Client Storage (IndexedDB) ]                                                   |
|    - Local private keys, contacts, safety numbers, ratchets, message history      |
+-----------------------------------------------------------------------------------+
                                   |
              HTTPS / WSS          |  Encrypted Payloads & Challenge Nonces Only
              (TLS 1.3)            |  (Zero Plaintext, Zero Private Keys)
                                   v
+-----------------------------------------------------------------------------------+
| Backend Server (Python FastAPI + WebSockets + SQLite WAL)                         |
|                                                                                   |
|  [ Security Middleware: CSP, HSTS, Rate Limiting & Anti-Enumeration ]             |
|  [ Auth & Identity Verifier (Ed25519 Challenge Signature Validation) ]            |
|  [ Exact Username Registry (Bound to Identity Public Keys) ]                      |
|  [ Request & Contact Dispatcher (Enforces Recipient Acceptance) ]                 |
|  [ Real-Time WebSocket Hub (Live Delivery & Presence) ]                           |
|  [ Offline Encrypted Mailbox (TTL-Expired, Purged Immediately upon Delivery) ]    |
|  [ SQLite Database: Users, PreKeys, Requests, OfflineMailbox, Blocklist ]         |
+-----------------------------------------------------------------------------------+
```

---

## 2. Cryptographic Protocol & Library Selection

### 2.1 Cryptographic Libraries
- **Client-Side:**
  - `TweetNaCl.js` (by Frank Denis and the TweetNaCl team): Well-audited, compact, constant-time implementation of Curve25519, Ed25519, and XSalsa20-Poly1305.
  - `Web Crypto API` (`crypto.subtle`): High-performance native browser API used for PBKDF2 (100,000 rounds of SHA-256), HKDF, and AES-256-GCM encryption for recovery backups and payload framing.
- **Server-Side:**
  - `PyNaCl` (libsodium bindings) & `cryptography`: Used strictly for verifying Ed25519 signatures during registration and challenge-response authentication. The server **never** decrypts or stores private encryption keys or message content.

### 2.2 Forward Secrecy & Ratchet Protocol
To provide **Forward Secrecy** without inventing custom cryptography, the protocol implements an Ephemeral Diffie-Hellman Ratchet (Signal / Double Ratchet principles):
1. **Initial Key Agreement (X3DH-style):**
   - Each user maintains an Ed25519 Identity Key (`IK`) and advertises an X25519 Signed Pre-Key (`SPK`).
   - When Alice requests to chat with Bob, Alice fetches Bob's public keys `(IK_B, SPK_B)`.
   - Alice generates a fresh ephemeral X25519 keypair `(EK_A, EPK_A)`.
   - Alice calculates:
     $$DH_1 = \text{X25519}(EK_A, SPK_B)$$
     $$DH_2 = \text{X25519}(IK_A, SPK_B)$$
   - Alice derives the Root Key ($RK_0$) and initial Chain Key ($CK_0$) using HKDF-SHA256:
     $$RK_0, CK_{send} = \text{HKDF}(\text{salt}=\text{zeros}, \text{ikm}=DH_1 \parallel DH_2, \text{info}=\text{"ChatRatchetV1"})$$
2. **Symmetric Chain Ratchet (Per-Message Forward Secrecy):**
   - For each message, a message key $MK_i$ is derived:
     $$MK_i = \text{HMAC-SHA256}(CK_i, \text{"MessageKey"})$$
     $$CK_{i+1} = \text{HMAC-SHA256}(CK_i, \text{"NextChainKey"})$$
   - $MK_i$ is used with AES-256-GCM (with a unique 96-bit random IV) to encrypt the message body.
   - Immediately after encryption/decryption, $MK_i$ is securely zeroed from memory.
   - If an attacker compromises the client device in the future, past message keys cannot be recovered because HMAC is non-invertible.
3. **Diffie-Hellman Ratchet Step:**
   - Whenever a participant sends a response after receiving messages, they generate a new ephemeral keypair and include the new public key in the message header. Both parties perform a new DH step and ratchet the Root Key forward, yielding post-compromise security (break-in recovery).

### 2.3 Safety Number & QR Code Verification
- An out-of-band verification code is computed deterministically from both participants' Ed25519 Identity Public Keys:
  $$\text{Fingerprint} = \text{SHA-256}(\min(IK_A, IK_B) \parallel \max(IK_A, IK_B))$$
- Formatted as 12 groups of 5 decimal digits (60 digits total).
- A QR code containing `whisper://verify?u1=...&k1=...&u2=...&k2=...&fingerprint=...` enables instant camera verification between devices.
- **Key Change Detection:** If a user re-keys or restores on another device with a different key, the client detects the discrepancy against its stored contact record and immediately halts communication, displaying an unmissable warning: *"⚠️ Contact's Identity Key Has Changed! Verify safety numbers before continuing."*

---

## 3. Identity Ownership & Zero-Signup Authentication

1. **Local Key Generation:**
   - On first visit, the client checks `IndexedDB` for an existing identity.
   - If none exists, the client generates:
     - `identityKeyPair`: Ed25519 signing keypair (`publicKey`, `secretKey`).
     - `preKeyPair`: X25519 key exchange keypair.
   - Keys are stored securely in the browser's local `IndexedDB`.
2. **Username Registration:**
   - The user enters their chosen unique username (e.g., `satoshi`).
   - The client signs a registration timestamp payload: `signature = Ed25519_Sign(secretKey, username + ":" + timestamp)`.
   - The server verifies:
     - The signature is valid for `identityPublicKey`.
     - The timestamp is within $\pm 60$ seconds.
     - The username is available and meets alphanumeric length rules (3–24 chars).
   - If valid, the server permanently registers `(username -> identityPublicKey)`.
3. **Subsequent Reconnection & Challenge-Response Authentication:**
   - When returning to the site or opening a WebSocket:
     - Client requests a challenge: `GET /api/auth/challenge?username=satoshi`.
     - Server generates a cryptographically secure 32-byte nonce with a 60-second TTL.
     - Client signs the challenge nonce using `identityKeyPair.secretKey`.
     - Server verifies the signature using the stored `identityPublicKey` for `satoshi`.
     - Upon successful verification, the server issues a scoped, time-limited signed session token and accepts the authenticated WebSocket connection.
   - **Protection against hijacking:** Typing an existing username without possessing the registered private key produces an invalid signature; the server rejects the request with HTTP 401 Unauthorized.

---

## 4. Recovery Design

Because identities are generated and stored exclusively on the user's local device, clearing browser cookies or losing the device would ordinarily permanently destroy access to the username and private keys.

To solve this securely:
1. **Passphrase-Protected Encrypted Export:**
   - The user selects "Backup Identity".
   - The user inputs a strong passphrase (evaluated with real-time entropy estimation).
   - A random 16-byte salt is generated.
   - Web Crypto PBKDF2 derives a 256-bit encryption key using 100,000 iterations of HMAC-SHA256.
   - The identity secret key and pre-key are serialized and encrypted with **AES-256-GCM** using a random 96-bit IV.
   - The client downloads an encrypted recovery JSON file (`whisper-identity-{username}.enc`):
     ```json
     {
       "version": 1,
       "username": "satoshi",
       "kdf": "PBKDF2-SHA256",
       "iterations": 100000,
       "salt": "<hex>",
       "iv": "<hex>",
       "ciphertext": "<hex>",
       "tagLength": 128
     }
     ```
2. **Identity Restoration:**
   - On a new device or cleared browser, the user chooses "Restore Identity".
   - The user selects their `.enc` file and enters their passphrase.
   - The client derives the key and decrypts the bundle using AES-256-GCM.
   - If the passphrase or file is invalid, decryption fails with an authentication tag error (no partial leakage).
   - Once decrypted, the client executes the challenge-response authentication against the backend to verify proof of ownership and resume full control of their username.

---

## 5. Contact Discovery, Chat Requests, and Blocking

1. **Exact-Match Lookup & Anti-Enumeration:**
   - The search endpoint (`/api/users/lookup`) requires an **exact match** for the username.
   - Partial lookups, prefix searches, and wildcard queries are strictly rejected.
   - Aggressive sliding-window rate limiting (e.g. max 10 lookups per minute per IP) prevents directory harvesting and brute-force enumeration.
2. **Explicit Chat Requests:**
   - Alice cannot send arbitrary messages to Bob without permission.
   - Alice sends a chat request containing an encrypted introductory note.
   - Bob receives the request in his "Pending Requests" queue.
   - Bob can:
     - **Accept:** Server marks the relationship as active; mutual communication is unlocked.
     - **Decline:** Request is discarded; Alice cannot message Bob.
     - **Block:** Bob adds Alice to his server and client blocklist. Any future requests or messages from Alice are dropped silently.
3. **Chat Deletion:**
   - Users can delete a conversation locally at any time.
   - If "Delete for Everyone" is chosen, an encrypted tombstone packet is sent to the peer, prompting their client to wipe local conversation storage.

---

## 6. Offline Encrypted Message Queuing & Expiry

1. **Zero-Knowledge Queuing:**
   - If the recipient is offline, the backend stores the encrypted ciphertext payload in the `offline_messages` table.
   - The server has no ability to read the ciphertext.
2. **Defined Time-To-Live (TTL):**
   - Offline messages have an expiration timestamp (default: 7 days).
   - A background janitor task routinely purges expired records.
3. **Immediate Delivery & Ephemeral Mailbox:**
   - As soon as the recipient's authenticated WebSocket connects, queued messages are immediately pushed to the client.
   - Once the client acknowledges receipt (`ACK`), the rows are permanently deleted from the server database (`DELETE FROM offline_messages`).

---

## 7. Threat Model & Realistic Security Limitations

### 7.1 What Is Defended Against
- **Eavesdropping on Transport:** Mitigated by TLS 1.3 (HTTPS/WSS) and E2EE.
- **Compromised or Malicious Server Operator:** The server never has access to plaintext messages or private keys. A rogue server operator can only see encrypted blobs and routing metadata.
- **Compromised Future Key (Forward Secrecy):** Compromise of a future device key cannot decrypt past conversation history due to symmetric chain ratcheting.
- **Username Impersonation / Spoofing:** Mitigated by Ed25519 cryptographic binding. No user can claim or reconnect to an existing username without the private key.
- **Tampering & Forgery:** Authenticated encryption (AES-256-GCM / XSalsa20-Poly1305) ensures all altered ciphertexts are immediately detected and discarded.
- **XSS & Injection:** All user input and decrypted message strings are treated as untrusted data, rendered using strict text node assignments (`textContent`), sanitized with strict CSP, and framed in sandboxed DOM elements.

### 7.2 Realistic Limits & Explicit Disclosures
As required by sound security engineering, the application explicitly informs users of the following boundaries:
1. **Endpoint Compromise:** If a user's device or browser is infected with malware, keyloggers, or physically accessed by an unauthorized party, end-to-end encryption cannot protect memory contents or keystrokes.
2. **Metadata Visibility:** The backend server necessarily observes connection metadata: IP addresses, connection times, user activity periods, and the high-level communication graph (who messages whom and message sizes).
3. **Browser Storage Eviction:** Browsers may evict IndexedDB under severe disk pressure or user-initiated cache clearing. The recovery file is essential to prevent permanent key loss.
4. **No Claim of "100% Secure" or "Completely Anonymous":** Real-world security is defense-in-depth, not magic. Network-level anonymity requires routing through Tor or VPNs; this application guarantees **end-to-end cryptographic confidentiality and authenticity of message content and identity ownership**.
