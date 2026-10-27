import time
import secrets
from fastapi import APIRouter, Request, HTTPException, Depends, status
from pydantic import BaseModel, Field
from typing import Optional, Literal
from app.config import RATE_LIMIT_REQUEST_PER_MINUTE
from app.database import query_one, query_all, execute_write
from app.security import validate_username, check_rate_limit, get_current_user
from app.websocket_manager import manager

router = APIRouter(prefix="/api/requests", tags=["requests"])

class SendRequestPayload(BaseModel):
    toUsername: str = Field(..., min_length=3, max_length=24)
    encryptedIntro: Optional[str] = None

class RespondPayload(BaseModel):
    requestId: str
    action: Literal["accept", "decline"]

class BlockPayload(BaseModel):
    targetUsername: str = Field(..., min_length=3, max_length=24)

@router.post("/send")
async def send_chat_request(payload: SendRequestPayload, request: Request, current_user: dict = Depends(get_current_user)):
    caller = current_user["sub"]
    target = validate_username(payload.toUsername)
    
    if caller == target:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot send chat request to yourself.")
    
    check_rate_limit(f"req_send:{caller}", RATE_LIMIT_REQUEST_PER_MINUTE)
    
    # Check target exists
    target_user = query_one("SELECT username, identity_public_key, pre_key FROM users WHERE username = ?", (target,))
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target user not found.")
    
    # Check blocklist
    blocked = query_one(
        "SELECT 1 FROM blocklist WHERE (blocker = ? AND blocked = ?) OR (blocker = ? AND blocked = ?)",
        (target, caller, caller, target)
    )
    if blocked:
        # Return 400 or silent rejection
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unable to send request to this user.")
    
    # Check if already contacts
    is_contact = query_one(
        "SELECT 1 FROM contacts WHERE (user_a = ? AND user_b = ?) OR (user_a = ? AND user_b = ?)",
        (caller, target, target, caller)
    )
    if is_contact:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Already in your contact list.")
    
    # Check if pending request exists
    existing = query_one(
        "SELECT id, status FROM chat_requests WHERE from_user = ? AND to_user = ? AND status = 'pending'",
        (caller, target)
    )
    if existing:
        return {"success": True, "requestId": existing["id"], "message": "Request already pending."}
    
    now = int(time.time())
    request_id = secrets.token_hex(16)
    
    execute_write("""
        INSERT INTO chat_requests (id, from_user, to_user, encrypted_intro, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'pending', ?, ?)
    """, (request_id, caller, target, payload.encryptedIntro or "", now, now))
    
    # Fetch caller's identity info to dispatch real-time notification
    caller_info = query_one("SELECT identity_public_key, pre_key FROM users WHERE username = ?", (caller,))
    
    # Dispatch real-time WebSocket event if target is online
    await manager.send_personal_message({
        "type": "chat_request",
        "requestId": request_id,
        "fromUsername": caller,
        "fromIdentityPublicKey": caller_info["identity_public_key"] if caller_info else "",
        "fromPreKey": caller_info["pre_key"] if caller_info else "",
        "encryptedIntro": payload.encryptedIntro,
        "createdAt": now
    }, target)
    
    return {"success": True, "requestId": request_id}

@router.get("/pending")
async def get_pending_requests(current_user: dict = Depends(get_current_user)):
    username = current_user["sub"]
    requests = query_all("""
        SELECT r.id, r.from_user, r.encrypted_intro, r.created_at, u.identity_public_key, u.pre_key
        FROM chat_requests r
        JOIN users u ON u.username = r.from_user
        WHERE r.to_user = ? AND r.status = 'pending'
        ORDER BY r.created_at DESC
    """, (username,))
    
    return [
        {
            "id": r["id"],
            "fromUsername": r["from_user"],
            "fromIdentityPublicKey": r["identity_public_key"],
            "fromPreKey": r["pre_key"],
            "encryptedIntro": r["encrypted_intro"],
            "createdAt": r["created_at"]
        }
        for r in requests
    ]

@router.get("/sent")
async def get_sent_requests(current_user: dict = Depends(get_current_user)):
    username = current_user["sub"]
    requests = query_all("""
        SELECT id, to_user, status, created_at
        FROM chat_requests
        WHERE from_user = ? AND status = 'pending'
        ORDER BY created_at DESC
    """, (username,))
    return requests

@router.post("/respond")
async def respond_to_request(payload: RespondPayload, current_user: dict = Depends(get_current_user)):
    username = current_user["sub"]
    now = int(time.time())
    
    req = query_one(
        "SELECT id, from_user, to_user, status FROM chat_requests WHERE id = ? AND to_user = ?",
        (payload.requestId, username)
    )
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Chat request not found.")
    
    if req["status"] != "pending":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Request is already {req['status']}.")
    
    sender = req["from_user"]
    new_status = "accepted" if payload.action == "accept" else "declined"
    
    execute_write("UPDATE chat_requests SET status = ?, updated_at = ? WHERE id = ?", (new_status, now, payload.requestId))
    
    if payload.action == "accept":
        # Insert contacts in ordered pair
        user_a = min(username, sender)
        user_b = max(username, sender)
        execute_write(
            "INSERT OR IGNORE INTO contacts (user_a, user_b, created_at) VALUES (?, ?, ?)",
            (user_a, user_b, now)
        )
        
        # Notify sender that request was accepted
        recipient_info = query_one("SELECT identity_public_key, pre_key FROM users WHERE username = ?", (username,))
        await manager.send_personal_message({
            "type": "request_accepted",
            "requestId": payload.requestId,
            "acceptedBy": username,
            "identityPublicKey": recipient_info["identity_public_key"] if recipient_info else "",
            "preKey": recipient_info["pre_key"] if recipient_info else "",
            "timestamp": now
        }, sender)
        
        # Broadcast presence between newly connected contacts
        await manager.broadcast_presence(username, True)
        await manager.broadcast_presence(sender, manager.is_online(sender))
    
    return {"success": True, "action": payload.action}

@router.get("/contacts")
async def get_contacts(current_user: dict = Depends(get_current_user)):
    username = current_user["sub"]
    contacts = query_all("""
        SELECT 
            CASE WHEN c.user_a = ? THEN c.user_b ELSE c.user_a END as contact_username,
            u.identity_public_key,
            u.pre_key,
            u.last_seen,
            c.created_at
        FROM contacts c
        JOIN users u ON u.username = (CASE WHEN c.user_a = ? THEN c.user_b ELSE c.user_a END)
        WHERE c.user_a = ? OR c.user_b = ?
        ORDER BY u.last_seen DESC
    """, (username, username, username, username))
    
    # Check blocklist
    blocked_by_caller = {b["blocked"] for b in query_all("SELECT blocked FROM blocklist WHERE blocker = ?", (username,))}
    
    result = []
    for c in contacts:
        contact_name = c["contact_username"]
        if contact_name in blocked_by_caller:
            continue
        result.append({
            "username": contact_name,
            "identityPublicKey": c["identity_public_key"],
            "preKey": c["pre_key"],
            "lastSeen": c["last_seen"],
            "isOnline": manager.is_online(contact_name),
            "addedAt": c["created_at"]
        })
    return result

@router.post("/block")
async def block_user(payload: BlockPayload, current_user: dict = Depends(get_current_user)):
    caller = current_user["sub"]
    target = validate_username(payload.targetUsername)
    now = int(time.time())
    
    execute_write("INSERT OR REPLACE INTO blocklist (blocker, blocked, created_at) VALUES (?, ?, ?)", (caller, target, now))
    
    # Remove from contacts
    user_a = min(caller, target)
    user_b = max(caller, target)
    execute_write("DELETE FROM contacts WHERE user_a = ? AND user_b = ?", (user_a, user_b))
    
    # Dismiss any pending requests
    execute_write(
        "UPDATE chat_requests SET status = 'declined', updated_at = ? WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)",
        (now, caller, target, target, caller)
    )
    
    return {"success": True, "blocked": target}

@router.post("/unblock")
async def unblock_user(payload: BlockPayload, current_user: dict = Depends(get_current_user)):
    caller = current_user["sub"]
    target = validate_username(payload.targetUsername)
    execute_write("DELETE FROM blocklist WHERE blocker = ? AND blocked = ?", (caller, target))
    return {"success": True, "unblocked": target}

@router.get("/blocked")
async def get_blocked_users(current_user: dict = Depends(get_current_user)):
    caller = current_user["sub"]
    rows = query_all("SELECT blocked, created_at FROM blocklist WHERE blocker = ?", (caller,))
    return rows

@router.delete("/contacts/{target_username}")
async def delete_contact(target_username: str, current_user: dict = Depends(get_current_user)):
    caller = current_user["sub"]
    target = validate_username(target_username)
    user_a = min(caller, target)
    user_b = max(caller, target)
    execute_write("DELETE FROM contacts WHERE user_a = ? AND user_b = ?", (user_a, user_b))
    return {"success": True, "deleted": target}
