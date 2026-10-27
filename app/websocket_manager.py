import json
import time
import logging
from typing import Dict, Set, Optional, Any
from fastapi import WebSocket
from app.database import execute_write, query_all, query_one
from app.config import OFFLINE_MESSAGE_EXPIRY_SECONDS

logger = logging.getLogger("websocket_manager")

class ConnectionManager:
    def __init__(self):
        # Active connections: username -> set of WebSocket instances (support multiple tabs)
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        # Reverse mapping: websocket -> username
        self.socket_user: Dict[WebSocket, str] = {}

    async def connect(self, websocket: WebSocket):
        await websocket.accept()

    def register(self, websocket: WebSocket, username: str):
        username = username.lower()
        self.socket_user[websocket] = username
        if username not in self.active_connections:
            self.active_connections[username] = set()
        self.active_connections[username].add(websocket)
        # Update last_seen in database
        now = int(time.time())
        execute_write("UPDATE users SET last_seen = ? WHERE username = ?", (now, username))

    def disconnect(self, websocket: WebSocket) -> Optional[str]:
        username = self.socket_user.pop(websocket, None)
        if username and username in self.active_connections:
            self.active_connections[username].discard(websocket)
            if not self.active_connections[username]:
                del self.active_connections[username]
                now = int(time.time())
                execute_write("UPDATE users SET last_seen = ? WHERE username = ?", (now, username))
        return username

    def is_online(self, username: str) -> bool:
        return username.lower() in self.active_connections and len(self.active_connections[username.lower()]) > 0

    async def send_personal_message(self, message: dict, username: str) -> bool:
        """Sends a JSON message to all active tabs of a user. Returns True if delivered to at least one socket."""
        username = username.lower()
        if username in self.active_connections:
            dead_sockets = set()
            delivered = False
            for connection in self.active_connections[username]:
                try:
                    await connection.send_text(json.dumps(message))
                    delivered = True
                except Exception as e:
                    logger.warning(f"Error sending to {username}: {e}")
                    dead_sockets.add(connection)
            for dead in dead_sockets:
                self.disconnect(dead)
            return delivered
        return False

    async def broadcast_presence(self, username: str, is_online: bool):
        """Notifies only mutual accepted contacts about user's online/offline status."""
        username = username.lower()
        contacts = query_all("""
            SELECT CASE WHEN user_a = ? THEN user_b ELSE user_a END as contact
            FROM contacts
            WHERE user_a = ? OR user_b = ?
        """, (username, username, username))
        
        notice = {
            "type": "presence",
            "username": username,
            "is_online": is_online,
            "timestamp": int(time.time())
        }
        for c in contacts:
            contact_name = c["contact"]
            # Check not blocked
            blocked = query_one(
                "SELECT 1 FROM blocklist WHERE (blocker = ? AND blocked = ?) OR (blocker = ? AND blocked = ?)",
                (username, contact_name, contact_name, username)
            )
            if not blocked:
                await self.send_personal_message(notice, contact_name)

    async def route_message(self, sender: str, recipient: str, message_id: str, ciphertext: str, header: dict) -> dict:
        """
        Routes an encrypted message from sender to recipient.
        Checks blocklist and contacts permissions.
        If recipient is online, delivers immediately and sends delivered_device status.
        If offline, stores in offline_messages table with defined expiry.
        """
        sender = sender.lower()
        recipient = recipient.lower()

        # Check blocklist
        blocked = query_one(
            "SELECT 1 FROM blocklist WHERE blocker = ? AND blocked = ?",
            (recipient, sender)
        )
        if blocked:
            # Silently pretend delivered to server for sender's privacy, do not deliver to recipient
            return {"status": "blocked", "message_id": message_id}

        # Check mutual contact relationship
        is_contact = query_one(
            "SELECT 1 FROM contacts WHERE (user_a = ? AND user_b = ?) OR (user_a = ? AND user_b = ?)",
            (sender, recipient, recipient, sender)
        )
        if not is_contact:
            return {"status": "error", "message_id": message_id, "detail": "Messaging requires accepted contact request."}

        now = int(time.time())
        packet = {
            "type": "chat_message",
            "id": message_id,
            "from": sender,
            "to": recipient,
            "ciphertext": ciphertext,
            "header": header,
            "timestamp": now
        }

        recipient_online = self.is_online(recipient)
        if recipient_online:
            delivered = await self.send_personal_message(packet, recipient)
            if delivered:
                # Notify sender of device delivery
                await self.send_personal_message({
                    "type": "status_update",
                    "message_id": message_id,
                    "to": sender,
                    "status": "delivered_device",
                    "timestamp": now
                }, sender)
                return {"status": "delivered_device", "message_id": message_id}

        # If offline or delivery failed, store in offline mailbox with TTL
        expires_at = now + OFFLINE_MESSAGE_EXPIRY_SECONDS
        execute_write("""
            INSERT INTO offline_messages (id, from_user, to_user, ciphertext, header, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (message_id, sender, recipient, ciphertext, json.dumps(header), now, expires_at))

        # Notify sender that message is safely held on server
        await self.send_personal_message({
            "type": "status_update",
            "message_id": message_id,
            "to": sender,
            "status": "delivered_server",
            "timestamp": now
        }, sender)

        return {"status": "delivered_server", "message_id": message_id}

    async def drain_offline_messages(self, username: str):
        """Pushes any pending offline messages to the user and awaits acknowledgement."""
        username = username.lower()
        now = int(time.time())
        messages = query_all("""
            SELECT id, from_user, to_user, ciphertext, header, created_at
            FROM offline_messages
            WHERE to_user = ? AND expires_at > ?
            ORDER BY created_at ASC
        """, (username, now))

        for msg in messages:
            try:
                header = json.loads(msg["header"])
            except Exception:
                header = {}
            packet = {
                "type": "chat_message",
                "id": msg["id"],
                "from": msg["from_user"],
                "to": msg["to_user"],
                "ciphertext": msg["ciphertext"],
                "header": header,
                "timestamp": msg["created_at"],
                "is_offline_catchup": True
            }
            delivered = await self.send_personal_message(packet, username)
            if delivered:
                # Notify original sender that their offline message has reached recipient's device
                await self.send_personal_message({
                    "type": "status_update",
                    "message_id": msg["id"],
                    "to": msg["from_user"],
                    "status": "delivered_device",
                    "timestamp": now
                }, msg["from_user"])

manager = ConnectionManager()
