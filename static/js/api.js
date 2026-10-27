/**
 * API and WebSocket Client for Whisper Private Messenger
 */
(function(window) {
    'use strict';

    let sessionToken = null;
    let ws = null;
    let wsReconnectTimeout = null;
    let wsPingInterval = null;
    let eventListeners = [];

    const API = {
        setToken: function(token) {
            sessionToken = token;
            if (token) {
                sessionStorage.setItem('whisper_token', token);
            } else {
                sessionStorage.removeItem('whisper_token');
            }
        },

        getToken: function() {
            if (!sessionToken) {
                sessionToken = sessionStorage.getItem('whisper_token');
            }
            return sessionToken;
        },

        fetchWithAuth: async function(url, options = {}) {
            const token = API.getToken();
            const headers = Object.assign({}, options.headers || {});
            if (token) {
                headers['Authorization'] = `Bearer ${token}`;
            }
            if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
                headers['Content-Type'] = 'application/json';
                options.body = JSON.stringify(options.body);
            }
            options.headers = headers;

            const res = await fetch(url, options);
            if (!res.ok) {
                let errorData;
                try {
                    errorData = await res.json();
                } catch (e) {
                    errorData = { detail: res.statusText || 'Network request failed' };
                }
                const error = new Error(errorData.detail || 'Request failed');
                error.status = res.status;
                error.data = errorData;
                throw error;
            }
            return res.json();
        },

        // --- Auth endpoints ---

        getChallenge: async function(username) {
            const res = await fetch(`/api/auth/challenge?username=${encodeURIComponent(username)}`);
            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || 'Failed to get challenge.');
            }
            return res.json();
        },

        registerUser: async function(username, identityKeyPair, preKeyPair) {
            const now = Math.floor(Date.now() / 1000);
            const msgToSign = `register:${username}:${now}`;
            const signature = window.E2EE.signMessage(msgToSign, identityKeyPair.secretKeyHex);

            const res = await fetch('/api/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: username,
                    identityPublicKey: identityKeyPair.publicKeyHex,
                    preKey: preKeyPair ? preKeyPair.publicKeyHex : '',
                    signature: signature,
                    timestamp: now
                })
            });

            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || 'Registration failed.');
            }

            const data = await res.json();
            API.setToken(data.token);
            return data;
        },

        authenticateDevice: async function(username, identitySecretKeyHex) {
            const challenge = await API.getChallenge(username);
            const signature = window.E2EE.signMessage(challenge.nonce, identitySecretKeyHex);

            const res = await fetch('/api/auth/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: username,
                    nonce: challenge.nonce,
                    signature: signature
                })
            });

            if (!res.ok) {
                const err = await res.json();
                throw new Error(err.detail || 'Authentication failed.');
            }

            const data = await res.json();
            API.setToken(data.token);
            return data;
        },

        getMe: async function() {
            return API.fetchWithAuth('/api/auth/me');
        },

        // --- User lookup ---

        lookupUser: async function(targetUsername) {
            return API.fetchWithAuth('/api/users/lookup', {
                method: 'POST',
                body: { targetUsername }
            });
        },

        updatePreKey: async function(preKeyHex) {
            return API.fetchWithAuth('/api/users/prekey', {
                method: 'PUT',
                body: { preKey: preKeyHex }
            });
        },

        // --- Requests & Contacts ---

        sendChatRequest: async function(toUsername, encryptedIntro = '') {
            return API.fetchWithAuth('/api/requests/send', {
                method: 'POST',
                body: { toUsername, encryptedIntro }
            });
        },

        getPendingRequests: async function() {
            return API.fetchWithAuth('/api/requests/pending');
        },

        respondToRequest: async function(requestId, action) {
            return API.fetchWithAuth('/api/requests/respond', {
                method: 'POST',
                body: { requestId, action }
            });
        },

        getContacts: async function() {
            return API.fetchWithAuth('/api/requests/contacts');
        },

        blockUser: async function(targetUsername) {
            return API.fetchWithAuth('/api/requests/block', {
                method: 'POST',
                body: { targetUsername }
            });
        },

        unblockUser: async function(targetUsername) {
            return API.fetchWithAuth('/api/requests/unblock', {
                method: 'POST',
                body: { targetUsername }
            });
        },

        deleteContact: async function(targetUsername) {
            return API.fetchWithAuth(`/api/requests/contacts/${encodeURIComponent(targetUsername)}`, {
                method: 'DELETE'
            });
        },

        // --- Messages ---

        sendMessageHttp: async function(messageId, toUsername, ciphertext, header) {
            return API.fetchWithAuth('/api/messages/send', {
                method: 'POST',
                body: {
                    messageId: messageId,
                    toUsername: toUsername,
                    ciphertext: ciphertext,
                    header: header
                }
            });
        },

        getOfflineMessages: async function() {
            return API.fetchWithAuth('/api/messages/offline');
        },

        ackMessages: async function(messageIds) {
            return API.fetchWithAuth('/api/messages/ack', {
                method: 'POST',
                body: { messageIds }
            });
        },

        clearConversation: async function(contactUsername) {
            return API.fetchWithAuth(`/api/messages/conversation/${encodeURIComponent(contactUsername)}`, {
                method: 'DELETE'
            });
        },

        // --- WebSocket connection & Events ---

        on: function(callback) {
            eventListeners.push(callback);
        },

        emitEvent: function(type, payload) {
            eventListeners.forEach(cb => {
                try {
                    cb(type, payload);
                } catch (e) {
                    console.error("Event listener error:", e);
                }
            });
        },

        connectWebSocket: function() {
            if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
                return;
            }

            const token = API.getToken();
            if (!token) return;

            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${protocol}//${window.location.host}/ws`;

            ws = new WebSocket(wsUrl);

            ws.onopen = function() {
                // Send auth token
                ws.send(JSON.stringify({ type: 'auth', token: token }));
                API.emitEvent('ws_connected', {});

                // Start ping heartbeat
                clearInterval(wsPingInterval);
                wsPingInterval = setInterval(() => {
                    if (ws && ws.readyState === WebSocket.OPEN) {
                        ws.send(JSON.stringify({ type: 'ping' }));
                    }
                }, 25000);
            };

            ws.onmessage = function(event) {
                try {
                    const data = JSON.parse(event.data);
                    API.emitEvent(data.type, data);
                } catch (e) {
                    console.warn("Failed to parse WS message:", event.data);
                }
            };

            ws.onclose = function() {
                clearInterval(wsPingInterval);
                API.emitEvent('ws_disconnected', {});
                // Try reconnection
                clearTimeout(wsReconnectTimeout);
                wsReconnectTimeout = setTimeout(() => {
                    API.connectWebSocket();
                }, 3000);
            };

            ws.onerror = function(err) {
                console.warn("WebSocket error:", err);
            };
        },

        sendWsMessage: function(msgObj) {
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify(msgObj));
                return true;
            }
            return false;
        }
    };

    window.API = API;
})(window);
