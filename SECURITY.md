# Security Policy & Vulnerability Reporting

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

---

## 1. Threat Model & Security Guarantees

Whisper is engineered around **zero-trust server architecture** and **client-side cryptographic ownership**:

1. **End-to-End Confidentiality & Integrity:**
   - Plaintext messages and private keys are never transmitted to or stored on the server.
   - Message payloads are encrypted using **AES-256-GCM** with unique 96-bit random IVs and authenticated tags.
2. **Forward Secrecy & Break-in Recovery:**
   - Ephemeral Diffie-Hellman ratcheting ensures that compromising future device keys does not allow decryption of previously transmitted messages.
3. **Cryptographic Identity Ownership:**
   - Usernames are immutably bound to Ed25519 identity keys. Proof of ownership is strictly enforced via digital signatures on all registration and reconnect handshakes.
4. **Zero-Knowledge Offline Queues:**
   - Undelivered messages are held as encrypted blobs with strict 7-day TTL expirations and are permanently purged upon delivery acknowledgment.
5. **Anti-Enumeration Protections:**
   - Directory lookups require exact username matching and are throttled by sliding-window rate limits to prevent automated user harvesting.

---

## 2. Realistic Limits & Out-of-Scope Risks

In adherence to responsible security disclosure, the following limits must be recognized:
- **Compromised Client Devices:** E2EE cannot protect an endpoint infected with kernel/user-space keyloggers, screen capture malware, or physically accessed by an adversary.
- **Connection Metadata:** The central backend necessarily routes network packets and observes transport-layer connection metadata (IP addresses, packet sizes, timestamps). For traffic analysis defense, route connections via Tor or a trusted VPN.
- **Local Browser Cache Loss:** Clearing browser data will delete local IndexedDB keys. Users must maintain an encrypted backup `.enc` file to prevent permanent access loss.

---

## 3. Reporting a Vulnerability

If you discover a security vulnerability in Whisper, please do NOT file a public issue.

Please report the finding responsibly by creating a private security advisory on GitHub or sending details to the repository maintainer. Include:
- A clear description of the vulnerability.
- Reproduction steps or proof of concept.
- Assessment of potential impact.

We endeavor to acknowledge reports within 24 hours and issue a fix within 72 hours.
