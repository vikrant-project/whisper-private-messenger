/**
 * UI Controller and Rendering Engine for Whisper Private Messenger
 * Implements strict text-node DOM escaping to prevent XSS.
 */
(function(window) {
    'use strict';

    function formatTime(timestamp) {
        if (!timestamp) return '';
        const date = new Date(timestamp * 1000);
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    const UI = {
        formatTime,

        // Modal Helpers
        openModal: function(modalId) {
            const el = document.getElementById(modalId);
            if (el) el.classList.add('open');
        },

        closeModal: function(modalId) {
            const el = document.getElementById(modalId);
            if (el) el.classList.remove('open');
        },

        // Render Contacts List in Sidebar
        renderContactsList: function(contacts, activeUsername, onSelectContact) {
            const container = document.getElementById('contactsListContainer');
            const emptyState = document.getElementById('contactsEmptyState');
            if (!container) return;

            container.innerHTML = '';
            if (!contacts || contacts.length === 0) {
                if (emptyState) emptyState.style.display = 'flex';
                return;
            }
            if (emptyState) emptyState.style.display = 'none';

            contacts.forEach(c => {
                const item = document.createElement('div');
                item.className = 'contact-item' + (activeUsername && activeUsername.toLowerCase() === c.username.toLowerCase() ? ' active' : '');
                item.id = `contact-item-${c.username}`;

                // Avatar
                const avatar = document.createElement('div');
                avatar.className = 'contact-avatar' + (c.isOnline ? ' online' : '');
                avatar.textContent = c.username.charAt(0).toUpperCase();

                // Info
                const info = document.createElement('div');
                info.className = 'contact-info';

                const nameRow = document.createElement('div');
                nameRow.className = 'contact-name-row';

                const name = document.createElement('span');
                name.className = 'contact-name';
                name.textContent = c.username;

                const time = document.createElement('span');
                time.className = 'contact-time';
                time.textContent = c.lastMessageTime ? formatTime(c.lastMessageTime) : '';

                nameRow.appendChild(name);
                nameRow.appendChild(time);

                const lastMsg = document.createElement('div');
                lastMsg.className = 'contact-last-msg';
                lastMsg.textContent = c.lastMessageText || 'Encrypted conversation ready';

                info.appendChild(nameRow);
                info.appendChild(lastMsg);

                item.appendChild(avatar);
                item.appendChild(info);

                item.addEventListener('click', () => {
                    onSelectContact(c);
                });

                container.appendChild(item);
            });
        },

        // Render Pending Requests List
        renderRequestsList: function(requests, onRespond) {
            const container = document.getElementById('requestsListContainer');
            const emptyState = document.getElementById('requestsEmptyState');
            const badge = document.getElementById('requestsBadgeCount');
            if (!container) return;

            container.innerHTML = '';
            const count = requests ? requests.length : 0;
            if (badge) {
                badge.textContent = count;
                badge.style.display = count > 0 ? 'inline-block' : 'none';
            }

            if (!requests || requests.length === 0) {
                if (emptyState) emptyState.style.display = 'flex';
                return;
            }
            if (emptyState) emptyState.style.display = 'none';

            requests.forEach(req => {
                const card = document.createElement('div');
                card.className = 'request-card';
                card.id = `request-card-${req.id}`;

                const header = document.createElement('div');
                header.className = 'request-header';

                const avatar = document.createElement('div');
                avatar.className = 'contact-avatar';
                avatar.textContent = req.fromUsername.charAt(0).toUpperCase();

                const userCol = document.createElement('div');
                const userSpan = document.createElement('div');
                userSpan.className = 'request-user';
                userSpan.textContent = req.fromUsername;

                const dateSpan = document.createElement('div');
                dateSpan.className = 'request-date';
                dateSpan.textContent = formatTime(req.createdAt);

                userCol.appendChild(userSpan);
                userCol.appendChild(dateSpan);
                header.appendChild(avatar);
                header.appendChild(userCol);
                card.appendChild(header);

                if (req.encryptedIntro) {
                    const introBox = document.createElement('div');
                    introBox.className = 'request-intro';
                    introBox.textContent = `"${req.encryptedIntro}"`;
                    card.appendChild(introBox);
                }

                // Action buttons: Accept & Decline
                const actions = document.createElement('div');
                actions.className = 'request-actions';

                const btnAccept = document.createElement('button');
                btnAccept.className = 'btn btn-primary btn-sm';
                btnAccept.textContent = 'Accept & Chat';
                btnAccept.addEventListener('click', () => onRespond(req.id, 'accept', req.fromUsername));

                const btnDecline = document.createElement('button');
                btnDecline.className = 'btn btn-secondary btn-sm';
                btnDecline.textContent = 'Decline';
                btnDecline.addEventListener('click', () => onRespond(req.id, 'decline', req.fromUsername));

                actions.appendChild(btnAccept);
                actions.appendChild(btnDecline);
                card.appendChild(actions);

                container.appendChild(card);
            });
        },

        // Render Chat Message Stream
        renderMessages: function(messages) {
            const container = document.getElementById('chatMessagesContainer');
            if (!container) return;

            container.innerHTML = '';
            messages.forEach(msg => {
                UI.appendMessage(msg, false);
            });
            container.scrollTop = container.scrollHeight;
        },

        // Append Single Message with Status Icon
        appendMessage: function(msg, autoScroll = true) {
            const container = document.getElementById('chatMessagesContainer');
            if (!container) return;

            // Check if element already exists (e.g. updating status)
            const existing = document.getElementById(`msg-row-${msg.id}`);
            if (existing) {
                // Update status icon
                const statusIconEl = existing.querySelector('.status-icon');
                if (statusIconEl) {
                    statusIconEl.innerHTML = UI.getStatusIconHtml(msg.status);
                }
                return;
            }

            const row = document.createElement('div');
            row.className = 'message-row ' + (msg.fromMe ? 'mine' : 'theirs');
            row.id = `msg-row-${msg.id}`;

            const bubble = document.createElement('div');
            bubble.className = 'message-bubble';
            // Prevent XSS: use textContent
            bubble.textContent = msg.text;

            const meta = document.createElement('div');
            meta.className = 'message-meta';

            const timeSpan = document.createElement('span');
            timeSpan.textContent = formatTime(msg.timestamp);
            meta.appendChild(timeSpan);

            if (msg.fromMe) {
                const statusSpan = document.createElement('span');
                statusSpan.className = 'status-icon ' + (msg.status === 'read' ? 'read' : '');
                statusSpan.innerHTML = UI.getStatusIconHtml(msg.status);
                meta.appendChild(statusSpan);
            }

            bubble.appendChild(meta);
            row.appendChild(bubble);
            container.appendChild(row);

            if (autoScroll) {
                container.scrollTop = container.scrollHeight;
            }
        },

        getStatusIconHtml: function(status) {
            if (status === 'read') {
                // Double emerald check
                return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.5"><path d="M18 6L7 17l-5-5"></path><path d="M22 10l-7.5 7.5L13 16"></path></svg>`;
            } else if (status === 'delivered_device') {
                // Double cyan check
                return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2.5"><path d="M18 6L7 17l-5-5"></path><path d="M22 10l-7.5 7.5L13 16"></path></svg>`;
            } else if (status === 'delivered_server') {
                // Double gray check
                return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" stroke-width="2.5"><path d="M18 6L7 17l-5-5"></path><path d="M22 10l-7.5 7.5L13 16"></path></svg>`;
            } else {
                // Single gray check (sent)
                return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" stroke-width="2.5"><path d="M20 6L9 17l-5-5"></path></svg>`;
            }
        },

        // Render Safety Number Modal & QR Code
        renderSafetyNumberModal: function(contactUsername, safetyNumberString, myPubKey, contactPubKey) {
            const nameEl = document.getElementById('safetyContactName');
            const gridEl = document.getElementById('safetyNumberDisplay');
            const qrContainer = document.getElementById('safetyQrCodeContainer');
            if (nameEl) nameEl.textContent = contactUsername;

            if (gridEl && safetyNumberString) {
                gridEl.innerHTML = '';
                const parts = safetyNumberString.split(' ');
                parts.forEach(part => {
                    const block = document.createElement('div');
                    block.textContent = part;
                    gridEl.appendChild(block);
                });
            }

            if (qrContainer && window.QRCode) {
                qrContainer.innerHTML = '';
                const verifyPayload = `whisper://verify?u=${contactUsername}&sn=${safetyNumberString.replace(/\s+/g, '')}`;
                new QRCode(qrContainer, {
                    text: verifyPayload,
                    width: 168,
                    height: 168,
                    colorDark: "#06090e",
                    colorLight: "#ffffff",
                    correctLevel: QRCode.CorrectLevel.M
                });
            }

            UI.openModal('modalSafetyNumber');
        }
    };

    window.UI = UI;
})(window);
