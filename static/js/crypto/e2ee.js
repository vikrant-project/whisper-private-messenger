/**
 * E2EE Cryptographic Engine for Whisper Private Messenger
 * Powered by TweetNaCl (Curve25519 / Ed25519) and Web Crypto API (SubtleCrypto)
 */
(function(window) {
    'use strict';

    // Ensure nacl is loaded
    if (typeof nacl === 'undefined') {
        console.error('TweetNaCl library is not loaded!');
    }

    // Helper functions for hex encoding/decoding
    function bytesToHex(uint8Array) {
        return Array.from(uint8Array)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    function hexToBytes(hexString) {
        if (!hexString || hexString.length % 2 !== 0) return new Uint8Array(0);
        const bytes = new Uint8Array(hexString.length / 2);
        for (let i = 0; i < hexString.length; i += 2) {
            bytes[i / 2] = parseInt(hexString.substring(i, i + 2), 16);
        }
        return bytes;
    }

    function utf8ToBytes(str) {
        return new TextEncoder().encode(str);
    }

    function bytesToUtf8(bytes) {
        return new TextDecoder().decode(bytes);
    }

    const E2EE = {
        bytesToHex,
        hexToBytes,
        utf8ToBytes,
        bytesToUtf8,

        /**
         * Generate a persistent Ed25519 identity keypair
         */
        generateIdentityKeyPair: function() {
            const pair = nacl.sign.keyPair();
            return {
                publicKeyHex: bytesToHex(pair.publicKey),
                secretKeyHex: bytesToHex(pair.secretKey),
                publicKeyBytes: pair.publicKey,
                secretKeyBytes: pair.secretKey
            };
        },

        /**
         * Sign a message with Ed25519 secret key
         */
        signMessage: function(messageStrOrBytes, secretKeyHex) {
            const msgBytes = typeof messageStrOrBytes === 'string' 
                ? utf8ToBytes(messageStrOrBytes) 
                : messageStrOrBytes;
            const secretKeyBytes = hexToBytes(secretKeyHex);
            const signature = nacl.sign.detached(msgBytes, secretKeyBytes);
            return bytesToHex(signature);
        },

        /**
         * Verify an Ed25519 signature
         */
        verifySignature: function(messageStrOrBytes, signatureHex, publicKeyHex) {
            try {
                const msgBytes = typeof messageStrOrBytes === 'string' 
                    ? utf8ToBytes(messageStrOrBytes) 
                    : messageStrOrBytes;
                const sigBytes = hexToBytes(signatureHex);
                const pubBytes = hexToBytes(publicKeyHex);
                return nacl.sign.detached.verify(msgBytes, sigBytes, pubBytes);
            } catch (e) {
                return false;
            }
        },

        /**
         * Generate an X25519 keypair for key exchange / ratcheting
         */
        generatePreKeyPair: function() {
            const pair = nacl.box.keyPair();
            return {
                publicKeyHex: bytesToHex(pair.publicKey),
                secretKeyHex: bytesToHex(pair.secretKey),
                publicKeyBytes: pair.publicKey,
                secretKeyBytes: pair.secretKey
            };
        },

        /**
         * Compute Safety Number (deterministic Signal-style 60-digit fingerprint)
         */
        computeSafetyNumber: async function(pubKeyHexA, pubKeyHexB) {
            // Sort keys lexicographically to ensure identical safety number regardless of who initiated
            const sorted = [pubKeyHexA.toLowerCase(), pubKeyHexB.toLowerCase()].sort();
            const combined = utf8ToBytes(sorted[0] + ":" + sorted[1]);
            
            // Multiple SHA-256 iterations to construct 12 blocks of 5 digits
            const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
            const hashBytes = new Uint8Array(hashBuffer);
            
            let digits = '';
            for (let i = 0; i < 24; i += 2) {
                const val = (hashBytes[i] << 8) | hashBytes[i + 1];
                const block = (val % 100000).toString().padStart(5, '0');
                digits += (digits ? ' ' : '') + block;
            }
            return digits;
        },

        /**
         * Derives HKDF keys using Web Crypto API
         */
        hkdfDerive: async function(ikmBytes, saltBytes, infoStr, length = 64) {
            const salt = saltBytes || new Uint8Array(32);
            const baseKey = await crypto.subtle.importKey(
                'raw',
                ikmBytes,
                { name: 'HKDF' },
                false,
                ['deriveBits']
            );
            const derivedBits = await crypto.subtle.deriveBits(
                {
                    name: 'HKDF',
                    hash: 'SHA-256',
                    salt: salt,
                    info: utf8ToBytes(infoStr)
                },
                baseKey,
                length * 8
            );
            return new Uint8Array(derivedBits);
        },

        /**
         * HMAC-SHA256 ratchet step
         */
        hmacSha256: async function(keyBytes, dataBytes) {
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyBytes,
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
            );
            const sig = await crypto.subtle.sign('HMAC', cryptoKey, dataBytes);
            return new Uint8Array(sig);
        },

        /**
         * Initialize symmetric ratchet state between two parties
         */
        initRatchet: async function(isInitiator, myEphemeralSecretHex, peerEphemeralPublicHex) {
            const mySecretBytes = hexToBytes(myEphemeralSecretHex);
            const peerPublicBytes = hexToBytes(peerEphemeralPublicHex);
            
            // Diffie-Hellman step via TweetNaCl box.before (Curve25519 DH)
            const dhShared = nacl.box.before(peerPublicBytes, mySecretBytes);
            
            // Derive Root Key and initial Chain Keys via HKDF
            const derived = await E2EE.hkdfDerive(dhShared, null, 'WhisperRatchetV1', 64);
            const rootKey = derived.slice(0, 32);
            const chainKey1 = derived.slice(32, 64);
            
            return {
                rootKey: bytesToHex(rootKey),
                sendChainKey: bytesToHex(isInitiator ? chainKey1 : derived.slice(32, 64)),
                recvChainKey: bytesToHex(isInitiator ? derived.slice(32, 64) : chainKey1),
                sendCounter: 0,
                recvCounter: 0,
                peerEphemeralPublicHex: peerEphemeralPublicHex
            };
        },

        /**
         * Encrypt a message payload using AES-256-GCM with per-message chain ratchet
         */
        encryptMessage: async function(ratchet, plaintextStr) {
            // Ratchet send chain key forward: MK = HMAC(sendChainKey, "msg" + counter)
            const currentChainKey = hexToBytes(ratchet.sendChainKey);
            const counterData = utf8ToBytes(`msg_${ratchet.sendCounter}`);
            const messageKeyBytes = await E2EE.hmacSha256(currentChainKey, counterData);
            
            // Next chain key: CK_next = HMAC(sendChainKey, "next")
            const nextChainKeyBytes = await E2EE.hmacSha256(currentChainKey, utf8ToBytes("next_chain_key"));
            ratchet.sendChainKey = bytesToHex(nextChainKeyBytes);
            const messageCounter = ratchet.sendCounter;
            ratchet.sendCounter += 1;

            // Generate 12-byte random IV
            const iv = crypto.getRandomValues(new Uint8Array(12));
            
            // Import message key for AES-GCM
            const aesKey = await crypto.subtle.importKey(
                'raw',
                messageKeyBytes,
                { name: 'AES-GCM' },
                false,
                ['encrypt']
            );

            const plaintextBytes = utf8ToBytes(plaintextStr);
            const ciphertextBuffer = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                aesKey,
                plaintextBytes
            );

            // Zero message key from memory
            messageKeyBytes.fill(0);

            return {
                ciphertextHex: bytesToHex(new Uint8Array(ciphertextBuffer)),
                header: {
                    ivHex: bytesToHex(iv),
                    counter: messageCounter,
                    ephemeralPublicHex: ratchet.myEphemeralPublicHex || ""
                },
                updatedRatchet: ratchet
            };
        },

        /**
         * Decrypt a message payload using AES-256-GCM with per-message chain ratchet
         */
        decryptMessage: async function(ratchet, ciphertextHex, header) {
            // Check if DH ratchet step is needed (ephemeral key changed)
            if (header.ephemeralPublicHex && header.ephemeralPublicHex !== ratchet.peerEphemeralPublicHex) {
                // Perform DH ratchet step
                if (ratchet.myEphemeralSecretHex) {
                    const mySecretBytes = hexToBytes(ratchet.myEphemeralSecretHex);
                    const newPeerPublicBytes = hexToBytes(header.ephemeralPublicHex);
                    const dhShared = nacl.box.before(newPeerPublicBytes, mySecretBytes);
                    
                    const rootKeyBytes = hexToBytes(ratchet.rootKey);
                    const derived = await E2EE.hkdfDerive(dhShared, rootKeyBytes, 'WhisperDHRatchetV1', 64);
                    ratchet.rootKey = bytesToHex(derived.slice(0, 32));
                    ratchet.recvChainKey = bytesToHex(derived.slice(32, 64));
                    ratchet.peerEphemeralPublicHex = header.ephemeralPublicHex;
                    ratchet.recvCounter = 0;
                }
            }

            // Derive message key: MK = HMAC(recvChainKey, "msg" + counter)
            const currentChainKey = hexToBytes(ratchet.recvChainKey);
            const counterData = utf8ToBytes(`msg_${header.counter}`);
            const messageKeyBytes = await E2EE.hmacSha256(currentChainKey, counterData);
            
            // Advance recv chain key if counter matches
            const nextChainKeyBytes = await E2EE.hmacSha256(currentChainKey, utf8ToBytes("next_chain_key"));
            ratchet.recvChainKey = bytesToHex(nextChainKeyBytes);
            ratchet.recvCounter = Math.max(ratchet.recvCounter, (header.counter || 0) + 1);

            const iv = hexToBytes(header.ivHex);
            const aesKey = await crypto.subtle.importKey(
                'raw',
                messageKeyBytes,
                { name: 'AES-GCM' },
                false,
                ['decrypt']
            );

            const ciphertextBytes = hexToBytes(ciphertextHex);
            const decryptedBuffer = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                aesKey,
                ciphertextBytes
            );

            // Zero key
            messageKeyBytes.fill(0);

            return {
                plaintext: bytesToUtf8(new Uint8Array(decryptedBuffer)),
                updatedRatchet: ratchet
            };
        }
    };

    window.E2EE = E2EE;
})(window);
