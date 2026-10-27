import sqlite3
import time
import os
from typing import Optional, List, Dict, Any
from app.config import DATABASE_PATH

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Users table: username bound to Ed25519 identity public key (hex)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY COLLATE NOCASE,
        identity_public_key TEXT NOT NULL,
        pre_key TEXT,
        created_at INTEGER NOT NULL,
        last_seen INTEGER NOT NULL
    );
    """)

    # Auth challenges table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_challenges (
        nonce TEXT PRIMARY KEY,
        username TEXT NOT NULL COLLATE NOCASE,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
    );
    """)

    # Chat requests table: must be accepted before chatting
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS chat_requests (
        id TEXT PRIMARY KEY,
        from_user TEXT NOT NULL COLLATE NOCASE,
        to_user TEXT NOT NULL COLLATE NOCASE,
        encrypted_intro TEXT,
        status TEXT NOT NULL, -- 'pending', 'accepted', 'declined'
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        FOREIGN KEY (from_user) REFERENCES users(username) ON DELETE CASCADE,
        FOREIGN KEY (to_user) REFERENCES users(username) ON DELETE CASCADE
    );
    """)

    # Mutual accepted contacts table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS contacts (
        user_a TEXT NOT NULL COLLATE NOCASE,
        user_b TEXT NOT NULL COLLATE NOCASE,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (user_a, user_b),
        FOREIGN KEY (user_a) REFERENCES users(username) ON DELETE CASCADE,
        FOREIGN KEY (user_b) REFERENCES users(username) ON DELETE CASCADE
    );
    """)

    # Blocklist table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blocklist (
        blocker TEXT NOT NULL COLLATE NOCASE,
        blocked TEXT NOT NULL COLLATE NOCASE,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (blocker, blocked),
        FOREIGN KEY (blocker) REFERENCES users(username) ON DELETE CASCADE,
        FOREIGN KEY (blocked) REFERENCES users(username) ON DELETE CASCADE
    );
    """)

    # Offline encrypted messages (purged upon delivery or expiry)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS offline_messages (
        id TEXT PRIMARY KEY,
        from_user TEXT NOT NULL COLLATE NOCASE,
        to_user TEXT NOT NULL COLLATE NOCASE,
        ciphertext TEXT NOT NULL,
        header TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        FOREIGN KEY (from_user) REFERENCES users(username) ON DELETE CASCADE,
        FOREIGN KEY (to_user) REFERENCES users(username) ON DELETE CASCADE
    );
    """)

    # Indexes
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_requests_to_user ON chat_requests(to_user, status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_offline_to_user ON offline_messages(to_user, expires_at);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_challenges_expires ON auth_challenges(expires_at);")
    
    conn.commit()
    conn.close()

def execute_write(query: str, params: tuple = ()) -> int:
    conn = get_connection()
    try:
        with conn:
            cursor = conn.execute(query, params)
            return cursor.rowcount
    finally:
        conn.close()

def query_one(query: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    try:
        cursor = conn.execute(query, params)
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def query_all(query: str, params: tuple = ()) -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        cursor = conn.execute(query, params)
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()

def cleanup_expired():
    """Purge expired challenges and offline messages."""
    now = int(time.time())
    execute_write("DELETE FROM auth_challenges WHERE expires_at < ?", (now,))
    execute_write("DELETE FROM offline_messages WHERE expires_at < ?", (now,))
