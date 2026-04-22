# ============================================================
# FIXED VERSION — Claude Recommended Fixes
# Based on: Claude Sonnet 4.6 Thinking audit (04/22/2026)
#
# Vulnerabilities Addressed:
#   V1 - SQL Injection         → parameterized queries
#   V2 - Hardcoded Secret      → os.getenv() with 32-char minimum enforcement
#   V3 - Plaintext Passwords   → bcrypt hash on write, checkpw on verify
#   V4 - JWT alg:none          → hardcoded algorithms=["HS256"], header ignored
#   V5 - Username Enumeration  → unified error message (in auth.py)
#
# Additional fixes from Claude's extra findings:
#   + JWT expiration: 30-minute exp + iat claims
#   + Rate limiting noted (implemented in auth.py)
#   + Password policy: minimum 12 characters (enforced via Pydantic in models)
#   + CORS: restrict to localhost:5173 (noted — implement in main.py)
# ============================================================

import jwt
import sqlite3
import os
import bcrypt
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException

# ── JWT secret loaded from environment ───────────────────────
# V2 FIX (Claude): Load from env var; enforce minimum 32-character length
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY environment variable is not set")
if len(SECRET_KEY) < 32:
    raise RuntimeError("JWT_SECRET_KEY must be at least 32 characters long")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Extra fix (Claude): 30-minute token lifetime

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "secureeval.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_user(username: str):
    conn = get_connection()
    # V1 FIX (Claude): Parameterized query with ? placeholder
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return user


def verify_password(plain: str, stored_hash: str) -> bool:
    # V3 FIX (Claude): bcrypt.checkpw — constant-time comparison, handles salt automatically
    return bcrypt.checkpw(plain.encode("utf-8"), stored_hash.encode("utf-8"))


def create_token(username: str) -> str:
    # V2 FIX (Claude): Uses strong env-var secret
    # V4 FIX (Claude): algorithm hardcoded, header alg never read
    # Extra fix (Claude): exp and iat claims added
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    # V4 FIX (Claude): Hardcoded algorithms=["HS256"] — header alg is ignored entirely.
    # PyJWT will raise InvalidTokenError for any token using alg=none or other algorithms.
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def create_user(username: str, password: str):
    conn = get_connection()
    # V3 FIX (Claude): Hash with bcrypt — gensalt() generates a unique salt per password
    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    # V1 FIX (Claude): Parameterized INSERT
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, hashed_pw),
    )
    conn.commit()
    conn.close()