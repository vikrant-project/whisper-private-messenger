from fastapi import APIRouter, Request, HTTPException, Depends, status
from pydantic import BaseModel, Field
from typing import Optional
from app.config import RATE_LIMIT_LOOKUP_PER_MINUTE
from app.database import query_one, execute_write
from app.security import validate_username, check_rate_limit, get_current_user
from app.websocket_manager import manager

router = APIRouter(prefix="/api/users", tags=["users"])

class LookupPayload(BaseModel):
    targetUsername: str = Field(..., min_length=3, max_length=24)

class PreKeyPayload(BaseModel):
    preKey: str = Field(..., min_length=32)

@router.post("/lookup")
async def lookup_user(payload: LookupPayload, request: Request, current_user: dict = Depends(get_current_user)):
    caller = current_user["sub"]
    client_ip = request.client.host if request.client else "unknown"
    
    # Rate limit lookup per IP and per user to prevent directory harvesting
    check_rate_limit(f"lookup_ip:{client_ip}", RATE_LIMIT_LOOKUP_PER_MINUTE)
    check_rate_limit(f"lookup_user:{caller}", RATE_LIMIT_LOOKUP_PER_MINUTE)
    
    target = validate_username(payload.targetUsername)
    
    # Check if target blocked caller
    is_blocked = query_one(
        "SELECT 1 FROM blocklist WHERE blocker = ? AND blocked = ?",
        (target, caller)
    )
    if is_blocked:
        # Return 404 to avoid leaking block status
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    
    # Exact lookup
    user = query_one(
        "SELECT username, identity_public_key, pre_key, created_at, last_seen FROM users WHERE username = ?",
        (target,)
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    
    online = manager.is_online(target)
    return {
        "username": user["username"],
        "identityPublicKey": user["identity_public_key"],
        "preKey": user["pre_key"],
        "isOnline": online
    }

@router.put("/prekey")
async def update_prekey(payload: PreKeyPayload, current_user: dict = Depends(get_current_user)):
    username = current_user["sub"]
    execute_write(
        "UPDATE users SET pre_key = ? WHERE username = ?",
        (payload.preKey, username)
    )
    return {"success": True}
