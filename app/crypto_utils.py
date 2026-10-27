import hmac
import hashlib
import json
import base64
import time
import secrets
from typing import Optional, Dict, Any
import nacl.signing
import nacl.encoding
import nacl.exceptions
from app.config import SESSION_SECRET, SESSION_EXPIRY_SECONDS

def verify_ed25519_signature(public_key_hex: str, message_bytes: bytes, signature_hex: str) -> bool:
    """Verifies that signature_hex was created by the holder of public_key_hex over message_bytes."""
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        signature_bytes = bytes.fromhex(signature_hex)
        verify_key = nacl.signing.VerifyKey(public_key_bytes)
        verify_key.verify(message_bytes, signature_bytes)
        return True
    except Exception:
        return False

def generate_challenge_nonce() -> str:
    """Generates a secure random 32-byte hex challenge."""
    return secrets.token_hex(32)

def create_session_token(username: str, identity_public_key: str) -> str:
    """Creates a tamper-proof HMAC-SHA256 session token."""
    now = int(time.time())
    payload = {
        "sub": username.lower(),
        "pk": identity_public_key,
        "iat": now,
        "exp": now + SESSION_EXPIRY_SECONDS
    }
    payload_json = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')
    payload_b64 = base64.urlsafe_b64encode(payload_json).decode('utf-8').rstrip('=')
    
    sig = hmac.new(SESSION_SECRET.encode('utf-8'), payload_b64.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{sig}"

def verify_session_token(token: str) -> Optional[Dict[str, Any]]:
    """Verifies and decodes a session token. Returns payload dict if valid, None if invalid or expired."""
    try:
        parts = token.split('.')
        if len(parts) != 2:
            return None
        payload_b64, signature = parts
        expected_sig = hmac.new(SESSION_SECRET.encode('utf-8'), payload_b64.encode('utf-8'), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            return None
        
        # Add padding back if necessary
        padded = payload_b64 + '=' * (-len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode(padded.encode('utf-8')).decode('utf-8')
        payload = json.loads(payload_json)
        
        now = int(time.time())
        if payload.get("exp", 0) < now:
            return None
        
        return payload
    except Exception:
        return None
