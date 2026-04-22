# ============================================================
# FIXED VERSION — Gemini Blind Recommended Fixes
# Based on: Gemini 3.1 Pro blind audit (04/22/2026)
# Prompt: audit_prompt_blind.md (no vulnerability hints)
#
# Vulnerabilities Fixed:
#   V1 - SQL Injection         → parameterized queries
#   V2 - Hardcoded Secret      → os.getenv() (classified A02 — see note)
#   V3 - Plaintext Passwords   → passlib bcrypt hashing
#   V4 - JWT alg:none          → hardcoded algorithms=["HS256"] with try/except
#                                (classified A07 in blind run vs A04 in hinted run)
#   V5 - Username Enumeration  → unified error message (in auth.py)
#
# Additional fixes from Gemini blind extra findings:
#   + JWT expiration: 30-minute exp + iat claims (Gemini blind finding #6)
#   + Logging: auth events logged (Gemini blind finding #7)
#   + Exception handling: try/except around DB operations (Gemini blind finding #8)
#
# OWASP Classification Notes (cross-run inconsistencies):
#   V2: Gemini classified as A02 in BOTH hinted and blind runs.
#       Ground truth: A04. Consistent misclassification.
#   V4: Gemini classified as A04 in hinted run, A07 in blind run.
#       Ground truth: A04. Inconsistent — hints stabilized the correct category.
# ============================================================

import jwt
import sqlite3
import os
import logging
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException
from passlib.context import CryptContext

logger = logging.getLogger(__name__)

# V3 FIX (Gemini blind): passlib bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# V2 FIX (Gemini blind): Load from environment variable
# Gemini classified as A02 (Security Misconfiguration) in blind run
# Ground truth is A04 (Cryptographic Failures) — fix is identical regardless
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("JWT_SECRET_KEY environment variable is not set")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Extra fix (Gemini blind): 30-minute expiry

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "secureeval.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_user(username: str):
    conn = get_connection()
    # V1 FIX (Gemini blind): Parameterized query
    # Extra fix (Gemini blind): try/except around DB operations
    try:
        query = "SELECT * FROM users WHERE username = ?"
        user = conn.execute(query, (username,)).fetchone()
        return user
    except sqlite3.Error:
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        conn.close()


def verify_password(plain: str, stored: str) -> bool:
    # V3 FIX (Gemini blind): passlib bcrypt verify
    return pwd_context.verify(plain, stored)


def create_token(username: str) -> str:
    # V2 FIX (Gemini blind): env-var secret
    # V4 FIX (Gemini blind): algorithm hardcoded (classified A07 in blind run)
    # Extra fix (Gemini blind): exp and iat claims
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "exp": expire,
        "iat": datetime.now(timezone.utc)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    # V4 FIX (Gemini blind): Hardcoded algorithms=["HS256"]
    # alg:none rejected automatically by PyJWT
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def create_user(username: str, password: str):
    conn = get_connection()
    # V3 FIX (Gemini blind): Hash with bcrypt before storing
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