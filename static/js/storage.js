/**
 * Storage Layer for Whisper Private Messenger
 * Uses IndexedDB for secure, offline-first client-side data persistence
 */
(function(window) {
    'use strict';

    const DB_NAME = 'whisper_secure_db';
    const DB_VERSION = 1;
    let dbInstance = null;

    function openDatabase() {
        if (dbInstance) return Promise.resolve(dbInstance);

        return new Promise((resolve, reject) => {
            const request = indexedDB.open(DB_NAME, DB_VERSION);

            request.onupgradeneeded = function(e) {
                const db = e.target.result;

                // Identity store
                if (!db.objectStoreNames.contains('identity')) {
                    db.createObjectStore('identity', { keyPath: 'id' });
                }

                // Contacts store
                if (!db.objectStoreNames.contains('contacts')) {
                    db.createObjectStore('contacts', { keyPath: 'username' });
                }

                // Conversations metadata store
                if (!db.objectStoreNames.contains('conversations')) {
                    db.createObjectStore('conversations', { keyPath: 'contactUsername' });
                }

                // Messages store
                if (!db.objectStoreNames.contains('messages')) {
                    const msgStore = db.createObjectStore('messages', { keyPath: 'id' });
                    msgStore.createIndex('contactUsername', 'contactUsername', { unique: false });
                    msgStore.createIndex('timestamp', 'timestamp', { unique: false });
                }

                // Ratchets store
                if (!db.objectStoreNames.contains('ratchets')) {
                    db.createObjectStore('ratchets', { keyPath: 'contactUsername' });
                }

                // Blocklist store
                if (!db.objectStoreNames.contains('blocked')) {
                    db.createObjectStore('blocked', { keyPath: 'username' });
                }
            };

            request.onsuccess = function(e) {
                dbInstance = e.target.result;
                resolve(dbInstance);
            };

            request.onerror = function(e) {
                reject(new Error('IndexedDB open failed: ' + e.target.error));
            };
        });
    }

    function transaction(storeName, mode) {
        return openDatabase().then(db => {
            const tx = db.transaction(storeName, mode);
            const store = tx.objectStore(storeName);
            return { tx, store };
        });
    }

    const Storage = {
        /**
         * Get user identity from IndexedDB
         */
        getIdentity: async function() {
            const { store } = await transaction('identity', 'readonly');
            return new Promise((resolve, reject) => {
                const req = store.get('me');
                req.onsuccess = () => resolve(req.result || null);
                req.onerror = () => reject(req.error);
            });
        },

        /**
         * Save identity to IndexedDB
         */
        saveIdentity: async function(identityData) {
            const { store } = await transaction('identity', 'readwrite');
            return new Promise((resolve, reject) => {
                const record = Object.assign({ id: 'me' }, identityData);
                const req = store.put(record);
                req.onsuccess = () => resolve(record);
                req.onerror = () => reject(req.error);
            });
        },

        /**
         * Wipe local identity (e.g. on reset or logout)
         */
        clearIdentity: async function() {
            const { store } = await transaction('identity', 'readwrite');
            return new Promise((resolve, reject) => {
                const req = store.delete('me');
                req.onsuccess = () => resolve();
                req.onerror = () => reject(req.error);
            });
        },

        /**
         * Get all contacts
         */
        getContacts: async function() {
            const { store } = await transaction('contacts', 'readonly');
            return new Promise((resolve, reject) => {
                const req = store.getAll();
                req.onsuccess = () => resolve(req.result || []);
                req.onerror = () => reject(req.error);
            });
        },

        /**
         * Get single contact
         */
        getContact: async function(username) {
            const { store } = await transaction('contacts', 'readonly');
            return new Promise((resolve, reject) => {
                const req = store.get(username.toLowerCase());
                req.onsuccess = () => resolve(req.result || null);
                req.onerror = () => reject(req.error);
            });
        },

        /**
         * Save or update contact
         */
        saveContact: async function(contact) {
            const { store } = await transaction('contacts', 'readwrite');
            contact.username = contact.username.toLowerCase();
            return new Promise((resolve, reject) => {
                const req = store.put(contact);
                req.onsuccess = () => resolve(contact);
                req.onerror = () => reject(req.error);
            });
        },

        /**
         * Delete contact and their messages
         */
        deleteContact: async function(username) {
            username = username.toLowerCase();
            const { store: cStore } = await transaction('contacts', 'readwrite');
            cStore.delete(username);

            const { store: convStore } = await transaction('conversations', 'readwrite');
            convStore.delete(username);

            const { store: rStore } = await transaction('ratchets', 'readwrite');
            rStore.delete(username);

            // Delete all messages with this contact
            await Storage.deleteMessagesForContact(username);
        },

        /**
         * Get messages for contact
         */
        getMessages: async function(contactUsername) {
            contactUsername = contactUsername.toLowerCase();
            const { store } = await transaction('messages', 'readonly');
            const index = store.index('contactUsername');
            return new Promise((resolve, reject) => {
                const req = index.getAll(contactUsername);
                req.onsuccess = () => {
                    const msgs = req.result || [];
                    msgs.sort((a, b) => a.timestamp - b.timestamp);
                    resolve(msgs);
                };
                req.onerror = () => reject(req.error);
            });
        },

        /**
         * Save message
         */
        saveMessage: async function(msg) {
            msg.contactUsername = msg.contactUsername.toLowerCase();
            const { store } = await transaction('messages', 'readwrite');
            return new Promise((resolve, reject) => {
                const req = store.put(msg);
                req.onsuccess = () => resolve(msg);
                req.onerror = () => reject(req.error);
            });
        },

        /**
         * Update message status (e.g. 'delivered_server', 'delivered_device', 'read')
         */
        updateMessageStatus: async function(id, newStatus) {
            const { store } = await transaction('messages', 'readwrite');
            return new Promise((resolve, reject) => {
                const getReq = store.get(id);
                getReq.onsuccess = () => {
                    const msg = getReq.result;
                    if (msg) {
                        msg.status = newStatus;
                        store.put(msg);
                    }
                    resolve(msg);
                };
                getReq.onerror = () => reject(getReq.error);
            });
        },

        /**
         * Delete messages for contact
         */
        deleteMessagesForContact: async function(contactUsername) {
            contactUsername = contactUsername.toLowerCase();
            const { store } = await transaction('messages', 'readwrite');
            const index = store.index('contactUsername');
            return new Promise((resolve, reject) => {
                const req = index.openCursor(contactUsername);
                req.onsuccess = function(e) {
                    const cursor = e.target.result;
                    if (cursor) {
                        cursor.delete();
                        cursor.continue();
                    } else {
                        resolve();
                    }
                };
                req.onerror = () => reject(req.error);
            });
        },

        /**
         * Get ratchet state for contact
         */
        getRatchet: async function(contactUsername) {
            contactUsername = contactUsername.toLowerCase();
            const { store } = await transaction('ratchets', 'readonly');
            return new Promise((resolve, reject) => {
                const req = store.get(contactUsername);
                req.onsuccess = () => resolve(req.result || null);
                req.onerror = () => reject(req.error);
            });
        },

        /**
         * Save ratchet state for contact
         */
        saveRatchet: async function(contactUsername, ratchetData) {
            contactUsername = contactUsername.toLowerCase();
            const { store } = await transaction('ratchets', 'readwrite');
            const record = Object.assign({ contactUsername }, ratchetData);
            return new Promise((resolve, reject) => {
                const req = store.put(record);
                req.onsuccess = () => resolve(record);
                req.onerror = () => reject(req.error);
            });
        },

        /**
         * Completely wipe local database
         */
        wipeAllData: function() {
            if (dbInstance) {
                dbInstance.close();
                dbInstance = null;
            }
            return new Promise((resolve, reject) => {
                const req = indexedDB.deleteDatabase(DB_NAME);
                req.onsuccess = () => resolve();
                req.onerror = () => reject(req.error);
            });
        }
    };

    window.Storage = Storage;
})(window);
