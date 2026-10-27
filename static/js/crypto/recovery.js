/**
 * Passphrase-Protected Encrypted Identity Backup & Recovery
 * Uses Web Crypto PBKDF2 (100,000 rounds of HMAC-SHA256) + AES-256-GCM
 */
(function(window) {
    'use strict';

    const Recovery = {
        /**
         * Assess passphrase strength and return a score (0 to 4) and guidance message
         */
        checkPassphraseStrength: function(passphrase) {
            if (!passphrase) return { score: 0, label: "Empty", valid: false };
            let score = 0;
            if (passphrase.length >= 8) score++;
            if (passphrase.length >= 14) score++;
            if (/[A-Z]/.test(passphrase) && /[a-z]/.test(passphrase)) score++;
            if (/\d/.test(passphrase) && /[^A-Za-z0-9]/.test(passphrase)) score++;

            const labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"];
            return {
                score: score,
                label: labels[score],
                valid: passphrase.length >= 8
            };
        },

        /**
         * Derive AES-256-GCM key from passphrase and salt using PBKDF2
         */
        deriveKeyFromPassphrase: async function(passphrase, saltBytes, iterations = 100000) {
            const encoder = new TextEncoder();
            const passwordKey = await crypto.subtle.importKey(
                'raw',
                encoder.encode(passphrase),
                { name: 'PBKDF2' },
                false,
                ['deriveKey']
            );

            const derivedKey = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: saltBytes,
                    iterations: iterations,
                    hash: 'SHA-256'
                },
                passwordKey,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );

            return derivedKey;
        },

        /**
         * Export encrypted identity backup file
         */
        exportBackup: async function(passphrase, identityBundle) {
            if (!passphrase || passphrase.length < 8) {
                throw new Error("Passphrase must be at least 8 characters long.");
            }

            // Generate 16 bytes random salt and 12 bytes IV
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const iterations = 100000;

            const aesKey = await Recovery.deriveKeyFromPassphrase(passphrase, salt, iterations);

            // Serialize identity
            const plaintextStr = JSON.stringify({
                version: 1,
                exportedAt: new Date().toISOString(),
                identity: identityBundle
            });

            const plaintextBytes = new TextEncoder().encode(plaintextStr);
            const ciphertextBuffer = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                aesKey,
                plaintextBytes
            );

            const backupObj = {
                format: "whisper-encrypted-identity",
                version: 1,
                username: identityBundle.username,
                kdf: "PBKDF2-SHA256",
                iterations: iterations,
                salt: window.E2EE.bytesToHex(salt),
                iv: window.E2EE.bytesToHex(iv),
                ciphertext: window.E2EE.bytesToHex(new Uint8Array(ciphertextBuffer)),
                tagLength: 128
            };

            return backupObj;
        },

        /**
         * Trigger browser download of the backup file
         */
        downloadBackupFile: function(backupObj) {
            const jsonStr = JSON.stringify(backupObj, null, 2);
            const blob = new Blob([jsonStr], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `whisper-backup-${backupObj.username}.enc`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        },

        /**
         * Decrypt and restore identity from backup JSON
         */
        importBackup: async function(passphrase, backupJsonStr) {
            let backupObj;
            try {
                backupObj = typeof backupJsonStr === 'string' ? JSON.parse(backupJsonStr) : backupJsonStr;
            } catch (e) {
                throw new Error("Invalid backup file format: not valid JSON.");
            }

            if (backupObj.format !== "whisper-encrypted-identity" || !backupObj.ciphertext || !backupObj.salt || !backupObj.iv) {
                throw new Error("Invalid backup file: missing required cryptographic header fields.");
            }

            const salt = window.E2EE.hexToBytes(backupObj.salt);
            const iv = window.E2EE.hexToBytes(backupObj.iv);
            const iterations = backupObj.iterations || 100000;
            const ciphertextBytes = window.E2EE.hexToBytes(backupObj.ciphertext);

            let aesKey;
            try {
                aesKey = await Recovery.deriveKeyFromPassphrase(passphrase, salt, iterations);
            } catch (e) {
                throw new Error("Failed to derive key from passphrase.");
            }

            try {
                const decryptedBuffer = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: iv },
                    aesKey,
                    ciphertextBytes
                );
                const decryptedStr = new TextDecoder().decode(decryptedBuffer);
                const parsed = JSON.parse(decryptedStr);
                return parsed.identity;
            } catch (e) {
                throw new Error("Decryption failed. Incorrect passphrase or corrupted backup file.");
            }
        }
    };

    window.Recovery = Recovery;
})(window);
