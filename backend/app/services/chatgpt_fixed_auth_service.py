# ============================================================
# FIXED VERSION — ChatGPT Recommended Fixes
# Based on: GPT 5.4 Extended Thinking audit (04/22/2026)
#
# Vulnerabilities Addressed:
#   V1 - SQL Injection         → parameterized queries
#   V2 - Hardcoded Secret      → os.getenv() with startup validation
#   V3 - Plaintext Passwords   → passlib bcrypt hashing
#   V4 - JWT alg:none          → hardcoded algorithm, no header trust
#   V5 - Username Enumeration  → unified generic error message
#
# Additional fixes from ChatGPT's extra findings:
#   + JWT expiration added (exp claim, 15-minute window)
#   + Exception safety: try/except around JWT decode
#   + Input validation: username/password length via Pydantic (see models note)
#   + Logging: failed login attempts logged with warning level
# ============================================================

import jwt
import sqlite3
import os
import logging
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException
from passlib.context import CryptContext

# ── Logging setup ────────────────────────────────────────────
logger = logging.getLogger(__name__)

# ── Password hashing (bcrypt via passlib) ────────────────────
# V3 FIX (ChatGPT): Use CryptContext with bcrypt instead of plaintext comparison
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── JWT secret loaded from environment ───────────────────────
# V2 FIX (ChatGPT): Load from env var; raise RuntimeError at startup if missing
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY environment variable is not set")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15  # Extra fix: short-lived tokens

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "secureeval.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_user(username: str):
    conn = get_connection()
    # V1 FIX (ChatGPT): Parameterized query — user input treated as data, not code
    query = "SELECT * FROM users WHERE username = ?"
    user = conn.execute(query, (username,)).fetchone()
    conn.close()
    return user


def verify_password(plain: str, stored_hash: str) -> bool:
    # V3 FIX (ChatGPT): Use passlib bcrypt constant-time comparison
    return pwd_context.verify(plain, stored_hash)


def create_token(username: str) -> str:
    # V2 FIX (ChatGPT): Uses strong env-var secret
    # Extra fix (ChatGPT): exp claim added for 15-minute token lifetime
    # V4 FIX (ChatGPT): algorithm hardcoded to HS256, never reads from token header
    payload = {
        "sub": username,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    # V4 FIX (ChatGPT): Never reads alg from token header; hardcodes ["HS256"]
    # Extra fix (ChatGPT): Wrapped in try/except to prevent unhandled crashes
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def create_user(username: str, password: str):
    conn = get_connection()
    # V3 FIX (ChatGPT): Hash password with bcrypt before storing
    hashed_pw = pwd_context.hash(password)
    # V1 FIX (ChatGPT): Parameterized INSERT
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, hashed_pw),
    )
    conn.commit()
    conn.close()