import asyncio
import json
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.database import init_db, cleanup_expired
from app.crypto_utils import verify_session_token
from app.websocket_manager import manager
from app.routes.auth import router as auth_router
from app.routes.users import router as users_router
from app.routes.requests import router as requests_router
from app.routes.messages import router as messages_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("main")

# Background task to clean up expired challenges and offline messages every 15 minutes
async def periodic_cleanup():
    while True:
        try:
            cleanup_expired()
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
        await asyncio.sleep(900)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    cleanup_task = asyncio.create_task(periodic_cleanup())
    yield
    # Shutdown
    cleanup_task.cancel()

app = FastAPI(title="Whisper Private Messenger", lifespan=lifespan)

# Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "connect-src 'self' ws: wss:; "
            "img-src 'self' data: blob:; "
            "frame-ancestors 'none';"
        )
        return response

app.add_middleware(SecurityHeadersMiddleware)

# Include Routers
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(requests_router)
app.include_router(messages_router)

# WebSocket Endpoint
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    authenticated_user = None
    try:
        # Await auth message
        raw = await websocket.receive_text()
        data = json.loads(raw)
        if data.get("type") != "auth" or not data.get("token"):
            await websocket.send_text(json.dumps({"type": "error", "detail": "Authentication required."}))
            await websocket.close(code=4001)
            return
        
        token_payload = verify_session_token(data["token"])
        if not token_payload:
            await websocket.send_text(json.dumps({"type": "error", "detail": "Invalid or expired token."}))
            await websocket.close(code=4002)
            return
        
        authenticated_user = token_payload["sub"]
        manager.register(websocket, authenticated_user)
        await websocket.send_text(json.dumps({"type": "auth_ok", "username": authenticated_user}))
        
        # Announce presence to mutual contacts
        await manager.broadcast_presence(authenticated_user, True)
        
        # Drain offline messages to the client
        await manager.drain_offline_messages(authenticated_user)
        
        # Main message loop
        while True:
            text = await websocket.receive_text()
            msg = json.loads(text)
            msg_type = msg.get("type")
            
            if msg_type == "chat_message":
                await manager.route_message(
                    sender=authenticated_user,
                    recipient=msg.get("to", ""),
                    message_id=msg.get("id", ""),
                    ciphertext=msg.get("ciphertext", ""),
                    header=msg.get("header", {})
                )
            elif msg_type == "read_receipt":
                # Forward read receipt to message sender
                to_user = msg.get("to")
                if to_user:
                    await manager.send_personal_message({
                        "type": "read_receipt",
                        "message_id": msg.get("message_id"),
                        "reader": authenticated_user
                    }, to_user)
            elif msg_type == "typing":
                to_user = msg.get("to")
                if to_user:
                    await manager.send_personal_message({
                        "type": "typing",
                        "from": authenticated_user,
                        "is_typing": bool(msg.get("is_typing"))
                    }, to_user)
            elif msg_type == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
                
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning(f"WebSocket error for {authenticated_user}: {e}")
    finally:
        if authenticated_user:
            manager.disconnect(websocket)
            # If user has no other open tabs, notify contacts they are offline
            if not manager.is_online(authenticated_user):
                await manager.broadcast_presence(authenticated_user, False)

# Mount static files and serve index.html
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def serve_index():
    return FileResponse("static/index.html")

@app.get("/favicon.ico")
async def serve_favicon():
    return FileResponse("static/assets/logo.svg")
