import re
import time
from collections import defaultdict
from fastapi import Request, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional, Dict, Any, List
from app.crypto_utils import verify_session_token

security_bearer = HTTPBearer(auto_error=False)

# Username policy: 3 to 24 chars, lowercase alphanumeric, underscore, hyphen
USERNAME_REGEX = re.compile(r'^[a-z0-9_-]{3,24}$')

# In-memory sliding window rate limiter: key -> list of timestamps
_rate_limits: Dict[str, List[float]] = defaultdict(list)

def validate_username(username: str) -> str:
    cleaned = username.strip().lower()
    if not USERNAME_REGEX.match(cleaned):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username must be 3-24 characters containing only letters, numbers, hyphens, and underscores."
        )
    return cleaned

def check_rate_limit(key: str, limit: int, window_seconds: int = 60):
    now = time.time()
    timestamps = _rate_limits[key]
    # Prune timestamps older than window
    cutoff = now - window_seconds
    _rate_limits[key] = [t for t in timestamps if t > cutoff]
    
    if len(_rate_limits[key]) >= limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please wait a moment before trying again."
        )
    _rate_limits[key].append(now)

async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)) -> Dict[str, Any]:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials."
        )
    payload = verify_session_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token."
        )
    return payload
