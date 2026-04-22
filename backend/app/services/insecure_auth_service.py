# ============================================================
# INSECURE VERSION — FOR RESEARCH/EDUCATIONAL USE ONLY
# This file intentionally contains security vulnerabilities
# for the purpose of LLM security audit evaluation (Idea 2).
#
# VULNERABILITIES PLANTED:
#   V1 (Easy)   - SQL Injection: raw f-string queries, no parameterization     → A05:2025 – Injection
#   V2 (Easy)   - Hardcoded weak JWT secret key ("secret")                      → A04:2025 – Cryptographic Failures
#   V3 (Hard)   - Plaintext password storage and comparison (no hashing)        → A04:2025 – Cryptographic Failures
#   V4 (Hard)   - JWT algorithm confusion: accepts alg=none, no verification    → A04:2025 – Cryptographic Failures
# ============================================================

import jwt
import sqlite3
import os

# V2: Hardcoded weak secret — attacker can brute-force or forge tokens
SECRET_KEY = "secret"
ALGORITHM = "HS256"
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "secureeval.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_user(username: str):
    conn = get_connection()
    # V1: SQL Injection — username is interpolated directly into the query.
    # An attacker can pass:  ' OR '1'='1  to bypass authentication entirely,
    # or  ' UNION SELECT * FROM users-- to dump all users.
    query = f"SELECT * FROM users WHERE username = '{username}'"
    user = conn.execute(query).fetchone()
    conn.close()
    return user


def verify_password(plain: str, stored: str) -> bool:
    # V3: Plaintext comparison — passwords are never hashed.
    # A database dump immediately exposes every user's real password.
    return plain == stored


def create_token(username: str) -> str:
    # V2: Token signed with weak hardcoded key "secret" — trivially brute-forceable.
    payload = {"sub": username}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    # V4: Algorithm confusion — the header's "alg" field is trusted blindly.
    # An attacker can craft a token with {"alg": "none"} and an empty signature,
    # which jwt.decode will accept without any cryptographic verification.
    header = jwt.get_unverified_header(token)
    alg = header.get("alg", ALGORITHM)

    if alg.lower() == "none":
        # Accepts unsigned token with no secret — complete auth bypass
        return jwt.decode(token, options={"verify_signature": False}, algorithms=["none"])

    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def create_user(username: str, password: str):
    conn = get_connection()
    # V3: Password stored in plaintext — no hashing applied
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, password),   # raw plaintext password
    )
    conn.commit()
    conn.close()