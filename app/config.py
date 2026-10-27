import os
import secrets

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_PATH = os.path.join(BASE_DIR, "whisper.db")

# Security and session settings
SESSION_SECRET = os.getenv("SESSION_SECRET", secrets.token_hex(32))
SESSION_EXPIRY_SECONDS = 86400 * 7  # 7 days
CHALLENGE_EXPIRY_SECONDS = 120      # 2 minutes

# Offline message retention
OFFLINE_MESSAGE_EXPIRY_SECONDS = 86400 * 7  # 7 days

# Rate limits (sliding window)
RATE_LIMIT_LOOKUP_PER_MINUTE = 15
RATE_LIMIT_CHALLENGE_PER_MINUTE = 30
RATE_LIMIT_REGISTER_PER_MINUTE = 10
RATE_LIMIT_REQUEST_PER_MINUTE = 20
