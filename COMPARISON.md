# Technical Comparison: Whisper vs. Modern Private Messengers

This document provides a comparative analysis of **Whisper** alongside other private messaging platforms, protocols, and privacy-preserving communication networks: **Signal**, **Session**, **Matrix / Element**, **SimpleX Chat**, **Telegram (Secret Chats)**, and **WhatsApp**.

---

## 1. Feature & Privacy Architecture Matrix

| Feature / Dimension | **Whisper** (This Project) | **Signal** | **Session** | **Matrix (Element)** | **SimpleX Chat** | **Telegram** (Secret Chats) | **WhatsApp** |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Zero Signup / Login** | **Yes** (Instant) | No (Phone Req.) | **Yes** (Session ID) | No (User/Pass) | **Yes** (No user IDs) | No (Phone Req.) | No (Phone Req.) |
| **No Phone or Email Required** | **Yes** | No | **Yes** | Varies by server | **Yes** | No | No |
| **End-to-End Encryption (Default)** | **Yes** | **Yes** | **Yes** | Optional / Per-Room | **Yes** | No (Opt-in only) | **Yes** |
| **Forward Secrecy (Symmetric Ratchet)** | **Yes** (Per-msg) | **Yes** | **Yes** | **Yes** (Olm/Megolm) | **Yes** | **Yes** (Periodic) | **Yes** |
| **Break-in Recovery (DH Ratchet)** | **Yes** | **Yes** | Partial | **Yes** | **Yes** | Partial | **Yes** |
| **Cryptographic Identity Ownership** | **Ed25519 Binding** | Server Directory | Ed25519 Session ID | Matrix ID / HS Key | Ephemeral Queue Keys | Server Auth Token | Centralized Server |
| **Impersonation / Hijacking Defense** | **Signature Proof** | Safety Numbers | Public Key Match | Cross-Signing | Queue Fingerprint | Key Fingerprint | Centralized Phone SMS |
| **Safety Number / QR Verification** | **Yes** (60-digit) | **Yes** (60-digit) | **Yes** (QR/Hash) | **Yes** (SAS / Emoji) | **Yes** (QR / Key) | Visual Identicon | **Yes** (60-digit) |
| **Key Change Warnings** | **Yes** (Strict) | **Yes** | **Yes** | **Yes** | **Yes** | **Yes** | Optional Setting |
| **Offline Message Mailbox** | **Encrypted TTL** | Server Queue | Lokinet Swarm | Homeserver Sync | Isolated Queues | Central Cloud | Central Server |
| **Mailbox Purge on Delivery** | **Immediate** | Immediate | Swarm TTL (14d) | Stored indefinitely | Immediate | N/A (Server-side) | Immediate |
| **Passphrase Identity Recovery** | **PBKDF2 + AES-GCM** | PIN / Seed (Limited)| Seed Phrase (12w) | Recovery Key | Export File | Cloud Password | Cloud / Key Backup |
| **Anti-Enumeration Protection** | **Exact-Match Only** | Contact Discovery | Onion Routed | Directory Search | No User Directory | Contact Sync | Contact Sync |
| **Web Browser Native (No Install)** | **Yes** (Pure Web) | No (Desktop App) | Web (Limited) | **Yes** (Web App) | CLI / Mobile | **Yes** (Web App) | **Yes** (Companion) |
| **Self-Hostable Minimal Stack** | **Yes** (FastAPI+SQLite)| Hard (Complex AWS)| Medium (Lokinet)| Medium (Synapse)| Easy (Relay) | Impossible | Closed Source |

---

## 2. In-Depth Comparative Breakdown

### 2.1 Whisper vs. Signal
* **Identity Model:** Signal requires a phone number to register, exposing telecommunications identifiers to SIM-swapping attacks, carrier interception, and government subpeonas. Whisper generates cryptographic identities on-device without personal identifiers.
* **Cryptographic Protocol:** Both utilize Signal-style Ephemeral Diffie-Hellman ratcheting (Curve25519/Ed25519 + AES-GCM) with per-message keys, ensuring identical forward secrecy guarantees.
* **Metadata Profile:** Signal stores only the day of last server connection. Whisper stores username-to-public-key bindings and temporary encrypted message queues.
* **Portability:** Whisper runs in any modern browser without desktop or mobile application store gatekeepers.

### 2.2 Whisper vs. Session
* **Network Layer:** Session routes packets over the decentralized Oxen Service Node Network (Lokinet onion routing). Whisper uses direct TLS 1.3 WebSockets to a dedicated server.
* **Decentralization:** Session provides superior IP metadata masking through multi-hop onion routing. Whisper offers a lighter, single-binary architecture with transparent metadata disclosures.
* **Account Recovery:** Session uses a 12-word BIP39 mnemonic phrase. Whisper uses a PBKDF2-SHA256 (100,000 rounds) encrypted backup bundle protected by a custom passphrase.

### 2.3 Whisper vs. Matrix / Element
* **Encryption Default:** Matrix encryption is room-dependent and uses Olm (1-to-1) and Megolm (group ratchet). Key verification in Matrix can be complex across multiple devices. Whisper enforces strict 1-to-1 E2EE uniformly with automatic key change alerts.
* **Metadata Footprint:** Matrix homeservers retain conversation history, room participation logs, and federated server receipts indefinitely. Whisper purges offline messages immediately upon recipient delivery.

### 2.4 Whisper vs. Telegram (Secret Chats)
* **Encryption Stance:** By default, standard Telegram chats are **not end-to-end encrypted**; they reside in Telegram's cloud servers where Telegram holds the decryption keys. Secret Chats must be initiated manually and cannot be accessed on Telegram Web. Whisper is 100% end-to-end encrypted by default directly in the browser.
* **Cryptographic Standards:** Telegram uses custom MTProto cryptography. Whisper adheres to well-audited, battle-tested standard primitives: Ed25519, X25519, and AES-256-GCM.

### 2.5 Whisper vs. SimpleX Chat
* **Addressing:** SimpleX has no user identifiers at all—communication occurs via unidirectional message queue addresses. Whisper uses human-readable unique usernames cryptographically bound to Ed25519 keys with strict anti-enumeration rate limiting.
* **User Experience:** SimpleX requires exchanging out-of-band invitation links for each contact. Whisper allows exact username discovery and an explicit in-app chat request / acceptance flow.

---

## 3. Cryptographic Primitives Comparison

```
+------------------+-----------------------+-----------------------+-----------------------+
| Protocol         | Identity / Signing   | Key Agreement (DH)    | Symmetric AEAD        |
+------------------+-----------------------+-----------------------+-----------------------+
| Whisper          | Ed25519 (RFC 8032)    | X25519 (Curve25519)   | AES-256-GCM (NIST)    |
| Signal Protocol  | Ed25519 / Curve25519  | X25519 (X3DH)         | AES-256-CBC + HMAC    |
| Matrix (Olm)     | Ed25519               | Curve25519            | AES-256-CBC + HMAC    |
| Session          | Ed25519               | X25519                | XSalsa20-Poly1305     |
| Telegram (Cloud) | RSA-2048 / DH         | Diffie-Hellman        | MTProto 2.0 (Custom)  |
+------------------+-----------------------+-----------------------+-----------------------+
```

---

## 4. When to Choose Whisper
- When you need a **private, secure communications channel right now** without downloading an app from Google Play / Apple App Store.
- When you **cannot or will not provide a phone number or email address**.
- When you want **provable cryptographic forward secrecy** backed by verified Ed25519 identity ownership.
- When you need an **independent, easily auditable self-hosted instance** for your organization or personal group.
