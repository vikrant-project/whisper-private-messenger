import time
from fastapi import APIRouter, Request, HTTPException, Depends, status
from pydantic import BaseModel, Field
from typing import Optional
from app.config import (
    CHALLENGE_EXPIRY_SECONDS,
    RATE_LIMIT_CHALLENGE_PER_MINUTE,
    RATE_LIMIT_REGISTER_PER_MINUTE
)
from app.database import query_one, execute_write
from app.crypto_utils import (
    generate_challenge_nonce,
    verify_ed25519_signature,
    create_session_token
)
from app.security import validate_username, check_rate_limit, get_current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])

class RegisterPayload(BaseModel):
    username: str = Field(..., min_length=3, max_length=24)
    identityPublicKey: str = Field(..., min_length=64, max_length=64)  # 32 bytes hex = 64 hex chars
    preKey: Optional[str] = None
    signature: str = Field(..., min_length=128, max_length=128)        # 64 bytes hex = 128 hex chars
    timestamp: int

class VerifyPayload(BaseModel):
    username: str = Field(..., min_length=3, max_length=24)
    nonce: str = Field(..., min_length=64, max_length=64)
    signature: str = Field(..., min_length=128, max_length=128)

@router.get("/challenge")
async def get_challenge(username: str, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    check_rate_limit(f"challenge:{client_ip}", RATE_LIMIT_CHALLENGE_PER_MINUTE)
    
    clean_username = validate_username(username)
    nonce = generate_challenge_nonce()
    now = int(time.time())
    expires_at = now + CHALLENGE_EXPIRY_SECONDS
    
    # Store challenge
    execute_write(
        "INSERT OR REPLACE INTO auth_challenges (nonce, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (nonce, clean_username, now, expires_at)
    )
    
    return {"nonce": nonce, "username": clean_username, "expires_at": expires_at}

@router.post("/register")
async def register(payload: RegisterPayload, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    check_rate_limit(f"register:{client_ip}", RATE_LIMIT_REGISTER_PER_MINUTE)
    
    username = validate_username(payload.username)
    now = int(time.time())
    
    # Timestamp freshness check (within 60s)
    if abs(now - payload.timestamp) > 60:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration timestamp is skewed. Check your system clock."
        )
    
    # Check if username is already taken
    existing = query_one("SELECT username FROM users WHERE username = ?", (username,))
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already claimed. Please choose another username or restore using your recovery backup."
        )
    
    # Verify cryptographic signature: signed message is "register:<username>:<timestamp>"
    msg = f"register:{username}:{payload.timestamp}".encode("utf-8")
    if not verify_ed25519_signature(payload.identityPublicKey, msg, payload.signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Cryptographic signature verification failed. Public key proof required."
        )
    
    # Register user in database
    execute_write(
        "INSERT INTO users (username, identity_public_key, pre_key, created_at, last_seen) VALUES (?, ?, ?, ?, ?)",
        (username, payload.identityPublicKey, payload.preKey or "", now, now)
    )
    
    token = create_session_token(username, payload.identityPublicKey)
    return {
        "success": True,
        "username": username,
        "identityPublicKey": payload.identityPublicKey,
        "token": token
    }

@router.post("/verify")
async def verify(payload: VerifyPayload, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    check_rate_limit(f"verify:{client_ip}", 30)
    
    username = validate_username(payload.username)
    now = int(time.time())
    
    # Retrieve challenge
    challenge = query_one(
        "SELECT nonce, username, expires_at FROM auth_challenges WHERE nonce = ? AND username = ?",
        (payload.nonce, username)
    )
    if not challenge or challenge["expires_at"] < now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Challenge has expired or does not exist. Please request a new challenge."
        )
    
    # Look up registered user
    user = query_one(
        "SELECT username, identity_public_key FROM users WHERE username = ?",
        (username,)
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not registered."
        )
    
    # Verify signature over the challenge nonce
    msg = payload.nonce.encode("utf-8")
    if not verify_ed25519_signature(user["identity_public_key"], msg, payload.signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Proof of ownership failed: invalid signature for this username's registered identity key."
        )
    
    # Invalidate used challenge
    execute_write("DELETE FROM auth_challenges WHERE nonce = ?", (payload.nonce,))
    
    # Update last seen
    execute_write("UPDATE users SET last_seen = ? WHERE username = ?", (now, username))
    
    token = create_session_token(username, user["identity_public_key"])
    return {
        "success": True,
        "username": username,
        "identityPublicKey": user["identity_public_key"],
        "token": token
    }

@router.get("/me")
async def get_me(user: dict = Depends(get_current_user)):
    username = user["sub"]
    record = query_one(
        "SELECT username, identity_public_key, pre_key, created_at, last_seen FROM users WHERE username = ?",
        (username,)
    )
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User record not found.")
    return record
