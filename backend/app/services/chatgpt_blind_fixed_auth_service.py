# ============================================================
# FIXED VERSION — ChatGPT Blind Recommended Fixes
# Based on: GPT 5.4 Extended Thinking blind audit (04/22/2026)
# Prompt: audit_prompt_blind.md (no vulnerability hints)
#
# Vulnerabilities Fixed:
#   V1 - SQL Injection         → parameterized queries
#   V2 - Hardcoded Secret      → os.environ.get() with startup check
#   V3 - Plaintext Passwords   → passlib bcrypt hashing
#   V4 - JWT alg:none          → hardcoded algorithm, header never trusted
#   V5 - Username Enumeration  → unified error message (in auth.py)
#
# Additional fixes from ChatGPT blind extra findings:
#   + JWT expiration: 1-hour exp claim
#   + Exception handling: try/except around DB and JWT operations
#   + Input validation: Pydantic constraints on username/password length
#   + Logging: failed login attempts logged at warning level
# ============================================================

import jwt
import sqlite3
import os
import logging
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException
from passlib.context import CryptContext

logger = logging.getLogger(__name__)

# V3 FIX (ChatGPT blind): bcrypt via passlib CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# V2 FIX (ChatGPT blind): Secret loaded from environment variable
# Note: ChatGPT classified this as A02 (Security Misconfiguration),
# ground truth is A04 (Cryptographic Failures) — fix is identical either way
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY environment variable is not set")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 1  # Extra fix (ChatGPT blind): 1-hour token lifetime

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "secureeval.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_user(username: str):
    conn = get_connection()
    # V1 FIX (ChatGPT blind): Parameterized query
    query = "SELECT * FROM users WHERE username = ?"
    # Extra fix (ChatGPT blind): try/except around DB operations
    try:
        user = conn.execute(query, (username,)).fetchone()
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()
    return user


def verify_password(plain: str, stored: str) -> bool:
    # V3 FIX (ChatGPT blind): passlib bcrypt verify
    return pwd_context.verify(plain, stored)


def create_token(username: str) -> str:
    # V2 FIX (ChatGPT blind): Uses env-var secret
    # V4 FIX (ChatGPT blind): algorithm hardcoded, header never read
    # Extra fix (ChatGPT blind): exp claim added
    payload = {
        "sub": username,
        "exp": datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    # V4 FIX (ChatGPT blind): hardcoded algorithms=["HS256"], alg:none rejected
    # Extra fix (ChatGPT blind): try/except for clean 401 on malformed tokens
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def create_user(username: str, password: str):
    conn = get_connection()
    # V3 FIX (ChatGPT blind): Hash password before storing
    hashed = pwd_context.hash(password)
    try:
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed),
        )
        conn.commit()
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()