/**
 * Whisper Private Messenger - Main Application Orchestrator
 */
(function(window) {
    'use strict';

    let currentIdentity = null;
    let activeContact = null;
    let currentContacts = [];

    // Initialize Application
    async function init() {
        setupEventListeners();

        try {
            // Check if local identity exists in IndexedDB
            currentIdentity = await window.Storage.getIdentity();

            if (!currentIdentity) {
                // First visit: Show setup modal
                window.UI.openModal('modalSetupIdentity');
            } else {
                // Returning user: Silently authenticate device and connect
                await bootstrapUserSession(currentIdentity);
            }
        } catch (e) {
            console.error("Initialization error:", e);
        }
    }

    async function bootstrapUserSession(identity) {
        currentIdentity = identity;

        // Update header display
        const nameEl = document.getElementById('myUsernameDisplay');
        const avatarEl = document.getElementById('myAvatar');
        if (nameEl) nameEl.textContent = identity.username;
        if (avatarEl) avatarEl.textContent = identity.username.charAt(0).toUpperCase();

        try {
            // Authenticate device with backend via Ed25519 challenge-response
            await window.API.authenticateDevice(identity.username, identity.identitySecretKeyHex);
            
            // Connect WebSocket
            window.API.connectWebSocket();

            // Refresh contacts and requests
            await loadContacts();
            await loadPendingRequests();

            // Drain any pending offline messages
            await drainOfflineMessages();

        } catch (err) {
            console.error("Device authentication failed:", err);
            // If user doesn't exist on server (e.g. database wiped), offer re-registration
            if (err.status === 404 || err.message.includes('not registered')) {
                alert(`Your local username "${identity.username}" is not found on the server. Re-registering your device keys...`);
                try {
                    await window.API.registerUser(
                        identity.username,
                        { publicKeyHex: identity.identityPublicKeyHex, secretKeyHex: identity.identitySecretKeyHex },
                        { publicKeyHex: identity.preKeyPublicHex, secretKeyHex: identity.preKeySecretHex }
                    );
                    window.API.connectWebSocket();
                    await loadContacts();
                } catch (reRegErr) {
                    alert("Re-registration failed: " + reRegErr.message);
                }
            }
        }
    }

    // Load and Render Contacts
    async function loadContacts() {
        try {
            const serverContacts = await window.API.getContacts();
            currentContacts = serverContacts;

            // Augment with last message info from local storage
            for (let c of currentContacts) {
                const msgs = await window.Storage.getMessages(c.username);
                if (msgs.length > 0) {
                    const last = msgs[msgs.length - 1];
                    c.lastMessageText = last.text;
                    c.lastMessageTime = last.timestamp;
                }
            }

            window.UI.renderContactsList(
                currentContacts,
                activeContact ? activeContact.username : null,
                selectContact
            );
        } catch (e) {
            console.warn("Error loading contacts:", e);
        }
    }

    // Load Pending Requests
    async function loadPendingRequests() {
        try {
            const reqs = await window.API.getPendingRequests();
            window.UI.renderRequestsList(reqs, handleRequestResponse);
        } catch (e) {
            console.warn("Error loading requests:", e);
        }
    }

    // Select Active Contact for Chat
    async function selectContact(contact) {
        activeContact = contact;

        // UI state changes
        document.getElementById('noChatSelectedState').style.display = 'none';
        const activeChatView = document.getElementById('activeChatView');
        activeChatView.style.display = 'flex';

        document.getElementById('appMainContainer').classList.add('chat-active');
        document.getElementById('activeChatUsername').textContent = contact.username;
        document.getElementById('activeChatAvatar').textContent = contact.username.charAt(0).toUpperCase();

        const statusEl = document.getElementById('activeChatStatus');
        const statusTextEl = document.getElementById('activeChatStatusText');
        if (contact.isOnline) {
            statusEl.className = 'chat-partner-status online';
            statusTextEl.textContent = 'Online';
        } else {
            statusEl.className = 'chat-partner-status';
            statusTextEl.textContent = 'Offline';
        }

        // Highlight in sidebar
        window.UI.renderContactsList(
            currentContacts,
            contact.username,
            selectContact
        );

        // Ensure ratchet exists between me and contact
        let ratchet = await window.Storage.getRatchet(contact.username);
        if (!ratchet && contact.preKey) {
            ratchet = await window.E2EE.initRatchet(
                true,
                currentIdentity.preKeySecretHex,
                contact.preKey
            );
            ratchet.myEphemeralSecretHex = currentIdentity.preKeySecretHex;
            ratchet.myEphemeralPublicHex = currentIdentity.preKeyPublicHex;
            await window.Storage.saveRatchet(contact.username, ratchet);
        }

        // Load conversation messages
        const msgs = await window.Storage.getMessages(contact.username);
        window.UI.renderMessages(msgs);

        // Focus message field
        document.getElementById('messageInputField').focus();
    }

    // Handle chat request response (Accept / Decline)
    async function handleRequestResponse(requestId, action, fromUsername) {
        try {
            await window.API.respondToRequest(requestId, action);
            await loadPendingRequests();
            await loadContacts();

            if (action === 'accept') {
                const newContact = currentContacts.find(c => c.username.toLowerCase() === fromUsername.toLowerCase());
                if (newContact) {
                    selectContact(newContact);
                }
            }
        } catch (err) {
            alert("Action failed: " + err.message);
        }
    }

    // Send Message
    async function handleSendMessage(text) {
        if (!activeContact || !text.trim()) return;

        let ratchet = await window.Storage.getRatchet(activeContact.username);
        if (!ratchet) {
            // Initialize if missing
            ratchet = await window.E2EE.initRatchet(
                true,
                currentIdentity.preKeySecretHex,
                activeContact.preKey
            );
            ratchet.myEphemeralSecretHex = currentIdentity.preKeySecretHex;
            ratchet.myEphemeralPublicHex = currentIdentity.preKeyPublicHex;
        }

        // Ratchet and encrypt
        const { ciphertextHex, header, updatedRatchet } = await window.E2EE.encryptMessage(ratchet, text);
        await window.Storage.saveRatchet(activeContact.username, updatedRatchet);

        const messageId = 'msg_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        const now = Math.floor(Date.now() / 1000);

        const msgObj = {
            id: messageId,
            contactUsername: activeContact.username,
            fromMe: true,
            text: text,
            timestamp: now,
            status: 'sent'
        };

        // Save locally in IndexedDB
        await window.Storage.saveMessage(msgObj);

        // Append to UI immediately
        window.UI.appendMessage(msgObj, true);

        // Send over WebSocket or fallback HTTP
        const packet = {
            type: 'chat_message',
            id: messageId,
            to: activeContact.username,
            ciphertext: ciphertextHex,
            header: header
        };

        const sentWs = window.API.sendWsMessage(packet);
        if (!sentWs) {
            // Fallback to HTTP
            try {
                const res = await window.API.sendMessageHttp(messageId, activeContact.username, ciphertextHex, header);
                if (res.status) {
                    await window.Storage.updateMessageStatus(messageId, res.status);
                    msgObj.status = res.status;
                    window.UI.appendMessage(msgObj, false);
                }
            } catch (err) {
                console.warn("HTTP message send fallback error:", err);
            }
        }

        // Update contacts last message
        loadContacts();
    }

    // Process Incoming Chat Message
    async function handleIncomingMessage(packet) {
        const sender = packet.from;
        let ratchet = await window.Storage.getRatchet(sender);

        if (!ratchet) {
            // Find contact's prekey
            const contact = currentContacts.find(c => c.username.toLowerCase() === sender.toLowerCase());
            const peerPreKey = contact ? contact.preKey : packet.header.ephemeralPublicHex;
            ratchet = await window.E2EE.initRatchet(
                false,
                currentIdentity.preKeySecretHex,
                peerPreKey
            );
            ratchet.myEphemeralSecretHex = currentIdentity.preKeySecretHex;
            ratchet.myEphemeralPublicHex = currentIdentity.preKeyPublicHex;
        }

        try {
            const { plaintext, updatedRatchet } = await window.E2EE.decryptMessage(
                ratchet,
                packet.ciphertext,
                packet.header
            );

            await window.Storage.saveRatchet(sender, updatedRatchet);

            const msgObj = {
                id: packet.id,
                contactUsername: sender,
                fromMe: false,
                text: plaintext,
                timestamp: packet.timestamp || Math.floor(Date.now() / 1000),
                status: 'delivered'
            };

            await window.Storage.saveMessage(msgObj);

            // Acknowledge to server
            window.API.ackMessages([packet.id]);

            // If active chat is open with sender, render and send read receipt
            if (activeContact && activeContact.username.toLowerCase() === sender.toLowerCase()) {
                window.UI.appendMessage(msgObj, true);
                window.API.sendWsMessage({
                    type: 'read_receipt',
                    message_id: packet.id,
                    to: sender
                });
            }

            // Refresh contact preview
            await loadContacts();

        } catch (decryptErr) {
            console.error("Failed to decrypt message:", decryptErr);
        }
    }

    // Drain offline messages
    async function drainOfflineMessages() {
        try {
            const offlineMsgs = await window.API.getOfflineMessages();
            for (let m of offlineMsgs) {
                await handleIncomingMessage(m);
            }
        } catch (e) {
            console.warn("Error fetching offline messages:", e);
        }
    }

    // Setup All Event Listeners
    function setupEventListeners() {
        
        // Tab switching: Contacts vs Requests
        const tabContacts = document.getElementById('tabBtnContacts');
        const tabRequests = document.getElementById('tabBtnRequests');
        const contentContacts = document.getElementById('contactsTabContent');
        const contentRequests = document.getElementById('requestsTabContent');

        if (tabContacts && tabRequests) {
            tabContacts.addEventListener('click', () => {
                tabContacts.classList.add('active');
                tabRequests.classList.remove('active');
                contentContacts.style.display = 'flex';
                contentRequests.style.display = 'none';
            });

            tabRequests.addEventListener('click', () => {
                tabRequests.classList.add('active');
                tabContacts.classList.remove('active');
                contentRequests.style.display = 'flex';
                contentContacts.style.display = 'none';
            });
        }

        // Mobile back button
        const btnMobileBack = document.getElementById('btnMobileBack');
        if (btnMobileBack) {
            btnMobileBack.addEventListener('click', () => {
                document.getElementById('appMainContainer').classList.remove('chat-active');
            });
        }

        // New Chat Buttons
        const openNewChat = () => {
            document.getElementById('lookupResultCard').style.display = 'none';
            document.getElementById('lookupErrorBox').style.display = 'none';
            document.getElementById('lookupUsernameInput').value = '';
            window.UI.openModal('modalNewChat');
        };

        const btnNewChat = document.getElementById('btnNewChat');
        const btnWelcomeNewChat = document.getElementById('btnWelcomeNewChat');
        if (btnNewChat) btnNewChat.addEventListener('click', openNewChat);
        if (btnWelcomeNewChat) btnWelcomeNewChat.addEventListener('click', openNewChat);

        // Close New Chat Modal
        document.getElementById('btnCloseNewChat').addEventListener('click', () => window.UI.closeModal('modalNewChat'));
        document.getElementById('btnCancelNewChat').addEventListener('click', () => window.UI.closeModal('modalNewChat'));

        // Lookup User in Modal
        document.getElementById('btnExecuteLookup').addEventListener('click', async () => {
            const input = document.getElementById('lookupUsernameInput');
            const target = input.value.trim().toLowerCase();
            const errorBox = document.getElementById('lookupErrorBox');
            const resultCard = document.getElementById('lookupResultCard');

            errorBox.style.display = 'none';
            resultCard.style.display = 'none';

            if (!target) return;
            if (target === currentIdentity.username.toLowerCase()) {
                errorBox.textContent = "You cannot search for your own username.";
                errorBox.style.display = 'block';
                return;
            }

            try {
                const user = await window.API.lookupUser(target);
                document.getElementById('lookupFoundName').textContent = user.username;
                document.getElementById('lookupAvatar').textContent = user.username.charAt(0).toUpperCase();
                document.getElementById('lookupStatusText').textContent = user.isOnline ? "Online now" : "Offline";
                resultCard.style.display = 'block';
            } catch (err) {
                errorBox.textContent = err.message || "User not found. Exact username required.";
                errorBox.style.display = 'block';
            }
        });

        // Send Chat Request Button
        document.getElementById('btnSendChatRequestSubmit').addEventListener('click', async () => {
            const target = document.getElementById('lookupFoundName').textContent;
            const intro = document.getElementById('requestIntroInput').value.trim();
            try {
                await window.API.sendChatRequest(target, intro);
                window.UI.closeModal('modalNewChat');
                alert(`Chat request sent to ${target}! Messaging will activate as soon as they accept.`);
            } catch (err) {
                alert("Failed to send request: " + err.message);
            }
        });

        // Send Message Form
        const msgForm = document.getElementById('messageInputForm');
        if (msgForm) {
            msgForm.addEventListener('submit', (e) => {
                e.preventDefault();
                const input = document.getElementById('messageInputField');
                const text = input.value;
                input.value = '';
                handleSendMessage(text);
            });
        }

        // First-Time Identity Setup Form
        const btnSubmitSetup = document.getElementById('btnSubmitIdentitySetup');
        if (btnSubmitSetup) {
            btnSubmitSetup.addEventListener('click', async () => {
                const usernameInput = document.getElementById('setupUsernameInput');
                const username = usernameInput.value.trim().toLowerCase();

                if (!/^[a-z0-9_-]{3,24}$/.test(username)) {
                    alert("Username must be 3-24 characters (letters, numbers, underscores, hyphens).");
                    return;
                }

                btnSubmitSetup.disabled = true;
                btnSubmitSetup.textContent = "Generating Cryptographic Keys...";

                try {
                    // Generate Ed25519 identity keypair & X25519 prekeypair
                    const idKeyPair = window.E2EE.generateIdentityKeyPair();
                    const preKeyPair = window.E2EE.generatePreKeyPair();

                    // Register with backend with cryptographic signature proof
                    const regResult = await window.API.registerUser(username, idKeyPair, preKeyPair);

                    // Persist to local IndexedDB
                    const identityRecord = {
                        username: username,
                        identityPublicKeyHex: idKeyPair.publicKeyHex,
                        identitySecretKeyHex: idKeyPair.secretKeyHex,
                        preKeyPublicHex: preKeyPair.publicKeyHex,
                        preKeySecretHex: preKeyPair.secretKeyHex,
                        createdAt: Math.floor(Date.now() / 1000)
                    };
                    await window.Storage.saveIdentity(identityRecord);

                    window.UI.closeModal('modalSetupIdentity');
                    await bootstrapUserSession(identityRecord);

                } catch (err) {
                    alert("Setup failed: " + err.message);
                } finally {
                    btnSubmitSetup.disabled = false;
                    btnSubmitSetup.textContent = "Generate Keys & Claim Username";
                }
            });
        }

        // Backup Export Modal Handlers
        const btnOpenBackup = document.getElementById('btnOpenBackup');
        if (btnOpenBackup) {
            btnOpenBackup.addEventListener('click', () => {
                document.getElementById('backupPassphraseInput').value = '';
                document.getElementById('backupPassphraseConfirm').value = '';
                document.getElementById('backupErrorBox').style.display = 'none';
                window.UI.openModal('modalBackupIdentity');
            });
        }
        document.getElementById('btnCloseBackup').addEventListener('click', () => window.UI.closeModal('modalBackupIdentity'));
        document.getElementById('btnCancelBackup').addEventListener('click', () => window.UI.closeModal('modalBackupIdentity'));

        // Passphrase Strength Meter
        const backupPassInput = document.getElementById('backupPassphraseInput');
        if (backupPassInput) {
            backupPassInput.addEventListener('input', (e) => {
                const val = e.target.value;
                const { score, label } = window.Recovery.checkPassphraseStrength(val);
                const fill = document.getElementById('passphraseStrengthBar');
                const text = document.getElementById('passphraseStrengthText');

                const colors = ['#ef4444', '#f97316', '#eab308', '#10b981', '#06b6d4'];
                fill.style.width = (score * 25) + '%';
                fill.style.background = colors[score] || '#ef4444';
                text.textContent = `Passphrase strength: ${label}`;
            });
        }

        // Submit Export Backup
        document.getElementById('btnSubmitExportBackup').addEventListener('click', async () => {
            const pass = document.getElementById('backupPassphraseInput').value;
            const confirm = document.getElementById('backupPassphraseConfirm').value;
            const errBox = document.getElementById('backupErrorBox');
            errBox.style.display = 'none';

            if (!pass || pass.length < 8) {
                errBox.textContent = "Passphrase must be at least 8 characters long.";
                errBox.style.display = 'block';
                return;
            }
            if (pass !== confirm) {
                errBox.textContent = "Passphrases do not match.";
                errBox.style.display = 'block';
                return;
            }

            try {
                const backupObj = await window.Recovery.exportBackup(pass, currentIdentity);
                window.Recovery.downloadBackupFile(backupObj);
                window.UI.closeModal('modalBackupIdentity');
            } catch (err) {
                errBox.textContent = err.message;
                errBox.style.display = 'block';
            }
        });

        // Switch to Restore Modal from Setup
        document.getElementById('btnSwitchToRestore').addEventListener('click', () => {
            window.UI.closeModal('modalSetupIdentity');
            window.UI.openModal('modalRestoreIdentity');
        });

        document.getElementById('btnCloseRestore').addEventListener('click', () => window.UI.closeModal('modalRestoreIdentity'));
        document.getElementById('btnCancelRestore').addEventListener('click', () => window.UI.closeModal('modalRestoreIdentity'));

        // Submit Restore from File
        document.getElementById('btnSubmitRestore').addEventListener('click', async () => {
            const fileInput = document.getElementById('restoreFileInput');
            const passInput = document.getElementById('restorePassphraseInput');
            const errBox = document.getElementById('restoreStatusBox');
            errBox.style.display = 'none';

            if (!fileInput.files || fileInput.files.length === 0) {
                errBox.textContent = "Please select your .enc backup file.";
                errBox.style.display = 'block';
                return;
            }

            const passphrase = passInput.value;
            if (!passphrase) {
                errBox.textContent = "Please enter the passphrase.";
                errBox.style.display = 'block';
                return;
            }

            const file = fileInput.files[0];
            const reader = new FileReader();
            reader.onload = async function(e) {
                try {
                    const content = e.target.result;
                    const restoredIdentity = await window.Recovery.importBackup(passphrase, content);
                    await window.Storage.saveIdentity(restoredIdentity);

                    window.UI.closeModal('modalRestoreIdentity');
                    await bootstrapUserSession(restoredIdentity);
                    alert(`Welcome back, ${restoredIdentity.username}! Identity successfully verified & restored.`);
                } catch (err) {
                    errBox.textContent = err.message;
                    errBox.style.display = 'block';
                }
            };
            reader.readAsText(file);
        });

        // Safety Number Modal View
        const openSafetyNumber = async () => {
            if (!activeContact || !currentIdentity) return;
            const sn = await window.E2EE.computeSafetyNumber(
                currentIdentity.identityPublicKeyHex,
                activeContact.identityPublicKey
            );
            window.UI.renderSafetyNumberModal(
                activeContact.username,
                sn,
                currentIdentity.identityPublicKeyHex,
                activeContact.identityPublicKey
            );
        };

        document.getElementById('btnVerifySafetyNumber').addEventListener('click', openSafetyNumber);
        document.getElementById('btnBannerVerify').addEventListener('click', openSafetyNumber);
        document.getElementById('btnCloseSafetyNumber').addEventListener('click', () => window.UI.closeModal('modalSafetyNumber'));
        document.getElementById('btnDoneSafetyNumber').addEventListener('click', () => window.UI.closeModal('modalSafetyNumber'));

        // Security Limits Modal
        document.getElementById('btnInfoSecurity').addEventListener('click', () => window.UI.openModal('modalSecurityLimits'));
        document.getElementById('btnCloseSecurityLimits').addEventListener('click', () => window.UI.closeModal('modalSecurityLimits'));
        document.getElementById('btnDoneSecurityLimits').addEventListener('click', () => window.UI.closeModal('modalSecurityLimits'));

        // Block Contact Button
        document.getElementById('btnBlockContact').addEventListener('click', async () => {
            if (!activeContact) return;
            if (!confirm(`Are you sure you want to block ${activeContact.username}? They will no longer be able to message you.`)) return;

            try {
                await window.API.blockUser(activeContact.username);
                await window.Storage.deleteContact(activeContact.username);
                activeContact = null;
                document.getElementById('activeChatView').style.display = 'none';
                document.getElementById('noChatSelectedState').style.display = 'flex';
                await loadContacts();
            } catch (err) {
                alert("Failed to block contact: " + err.message);
            }
        });

        // Delete Chat Button
        document.getElementById('btnDeleteChat').addEventListener('click', async () => {
            if (!activeContact) return;
            if (!confirm(`Delete all local conversation history with ${activeContact.username}?`)) return;

            await window.Storage.deleteMessagesForContact(activeContact.username);
            await window.API.clearConversation(activeContact.username);
            window.UI.renderMessages([]);
            await loadContacts();
        });

        // WebSocket Event Handlers
        window.API.on(async (type, data) => {
            if (type === 'chat_message') {
                await handleIncomingMessage(data);
            } else if (type === 'status_update') {
                await window.Storage.updateMessageStatus(data.message_id, data.status);
                // Update UI status icon if visible
                const el = document.getElementById(`msg-row-${data.message_id}`);
                if (el) {
                    const iconEl = el.querySelector('.status-icon');
                    if (iconEl) iconEl.innerHTML = window.UI.getStatusIconHtml(data.status);
                }
            } else if (type === 'read_receipt') {
                await window.Storage.updateMessageStatus(data.message_id, 'read');
                const el = document.getElementById(`msg-row-${data.message_id}`);
                if (el) {
                    const iconEl = el.querySelector('.status-icon');
                    if (iconEl) iconEl.innerHTML = window.UI.getStatusIconHtml('read');
                }
            } else if (type === 'presence') {
                // Update contact presence
                const contact = currentContacts.find(c => c.username.toLowerCase() === data.username.toLowerCase());
                if (contact) {
                    contact.isOnline = data.is_online;
                    window.UI.renderContactsList(currentContacts, activeContact ? activeContact.username : null, selectContact);
                }
                if (activeContact && activeContact.username.toLowerCase() === data.username.toLowerCase()) {
                    const statusEl = document.getElementById('activeChatStatus');
                    const textEl = document.getElementById('activeChatStatusText');
                    if (data.is_online) {
                        statusEl.className = 'chat-partner-status online';
                        textEl.textContent = 'Online';
                    } else {
                        statusEl.className = 'chat-partner-status';
                        textEl.textContent = 'Offline';
                    }
                }
            } else if (type === 'chat_request') {
                await loadPendingRequests();
            } else if (type === 'request_accepted') {
                await loadContacts();
            }
        });
    }

    // Expose helpers for testing and external trigger
    window.App = {
        loadContacts,
        selectContact,
        loadPendingRequests
    };

    // Run on DOM Ready
    window.addEventListener('DOMContentLoaded', init);

})(window);
