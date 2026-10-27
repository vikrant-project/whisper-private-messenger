import json
import time
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from app.database import query_all, execute_write, query_one
from app.security import validate_username, get_current_user
from app.websocket_manager import manager

router = APIRouter(prefix="/api/messages", tags=["messages"])

class SendMessagePayload(BaseModel):
    messageId: str = Field(..., min_length=16, max_length=64)
    toUsername: str = Field(..., min_length=3, max_length=24)
    ciphertext: str = Field(..., min_length=1)
    header: Dict[str, Any] = Field(default_factory=dict)

class AckPayload(BaseModel):
    messageIds: List[str]

@router.post("/send")
async def send_message(payload: SendMessagePayload, current_user: dict = Depends(get_current_user)):
    sender = current_user["sub"]
    recipient = validate_username(payload.toUsername)
    
    result = await manager.route_message(
        sender=sender,
        recipient=recipient,
        message_id=payload.messageId,
        ciphertext=payload.ciphertext,
        header=payload.header
    )
    
    if result.get("status") == "error":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=result.get("detail", "Cannot send message."))
    
    return result

@router.get("/offline")
async def get_offline_messages(current_user: dict = Depends(get_current_user)):
    username = current_user["sub"]
    now = int(time.time())
    messages = query_all("""
        SELECT id, from_user, to_user, ciphertext, header, created_at
        FROM offline_messages
        WHERE to_user = ? AND expires_at > ?
        ORDER BY created_at ASC
    """, (username, now))
    
    results = []
    for m in messages:
        try:
            h = json.loads(m["header"])
        except Exception:
            h = {}
        results.append({
            "id": m["id"],
            "from": m["from_user"],
            "to": m["to_user"],
            "ciphertext": m["ciphertext"],
            "header": h,
            "timestamp": m["created_at"]
        })
    return results

@router.post("/ack")
async def acknowledge_messages(payload: AckPayload, current_user: dict = Depends(get_current_user)):
    username = current_user["sub"]
    if not payload.messageIds:
        return {"acknowledged": 0}
    
    # Secure parameterized deletion
    placeholders = ",".join(["?"] * len(payload.messageIds))
    params = list(payload.messageIds) + [username]
    deleted = execute_write(
        f"DELETE FROM offline_messages WHERE id IN ({placeholders}) AND to_user = ?",
        tuple(params)
    )
    return {"acknowledged": deleted}

@router.delete("/conversation/{contact_username}")
async def clear_conversation(contact_username: str, current_user: dict = Depends(get_current_user)):
    caller = current_user["sub"]
    target = validate_username(contact_username)
    
    # Delete any pending offline messages in both directions between these two users
    execute_write(
        "DELETE FROM offline_messages WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)",
        (caller, target, target, caller)
    )
    return {"success": True}
