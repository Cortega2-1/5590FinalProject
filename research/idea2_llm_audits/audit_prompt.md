# LLM Security Audit Prompt
# Submit this prompt verbatim to ChatGPT, Claude, and Gemini.
# Paste the contents of the two files below into the prompt where indicated.
# Save each LLM's full response in research/idea2_llm_audits/<model_name>_audit.md

---

You are an experienced software security engineer with deep expertise in web application security,
the OWASP Top 10:2025, and secure coding practices in Python and JavaScript.

## Your Task

You will be given the backend authentication code for a Python FastAPI login/signup system.
Your job is to perform a thorough security audit of this code against the OWASP Top 10:2025 list:

1. A01:2025 – Broken Access Control
2. A02:2025 – Security Misconfiguration
3. A03:2025 – Software Supply Chain Failures
4. A04:2025 – Cryptographic Failures
5. A05:2025 – Injection
6. A06:2025 – Insecure Design
7. A07:2025 – Authentication Failures
8. A08:2025 – Software or Data Integrity Failures
9. A09:2025 – Security Logging and Alerting Failures
10. A10:2025 – Mishandling of Exceptional Conditions

For every vulnerability you find, provide:
1. **Vulnerability name** (use OWASP Top 10 category if applicable)
2. **Location** — the exact file and function/line where the issue exists
3. **Description** — explain clearly what the vulnerability is and why it is dangerous
4. **Attack scenario** — give a concrete example of how an attacker would exploit it
5. **Remediation** — provide the corrected code snippet that fixes the issue

Be exhaustive. Do not skip subtle or less obvious issues. Rate each finding as:
- 🔴 Critical
- 🟠 High
- 🟡 Medium
- 🟢 Low / Informational

## Project Context

This is a web application with:
- **Frontend:** React + TypeScript (Vite), running on localhost:5173
- **Backend:** Python FastAPI, running on localhost:8000
- **Database:** SQLite (file-based)
- **Auth flow:** User submits username + password → POST /auth/login → receives JWT token stored in sessionStorage

The database schema for the users table is:
```sql
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
);
```

The frontend sends login requests in this shape:
```json
{ "username": "carlos", "password": "mypassword" }
```

And expects this response shape:
```json
{ "access_token": "<jwt_token>", "token_type": "bearer" }
```

## Files to Audit

### File 1: app/services/insecure_auth_service.py
[# ============================================================
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
conn.close()]

### File 2: app/routes/insecure_auth.py
[# ============================================================
# INSECURE VERSION — FOR RESEARCH/EDUCATIONAL USE ONLY
# See insecure_auth_service.py for full vulnerability list.
#
# ADDITIONAL VULNERABILITY IN THIS FILE:
#   V5 (Hard) - Username enumeration via distinct error messages               → A07:2025 – Authentication Failures
# ============================================================

from fastapi import APIRouter, HTTPException
from app.models.user import UserCreate, UserLogin, TokenResponse
from app.services import insecure_auth_service as auth_service

router = APIRouter()


@router.post("/register", status_code=201)
def register(body: UserCreate):
if auth_service.get_user(body.username):
raise HTTPException(status_code=400, detail="Username already taken.")
auth_service.create_user(body.username, body.password)
return {"message": f"User '{body.username}' created successfully."}


@router.post("/login", response_model=TokenResponse)
def login(body: UserLogin):
user = auth_service.get_user(body.username)

    # V5: Username enumeration — separate error messages reveal whether
    # the username or password is wrong, allowing targeted brute-force.
    if not user:
        raise HTTPException(status_code=401, detail="User not found.")

    if not auth_service.verify_password(body.password, user["password"]):
        raise HTTPException(status_code=401, detail="Wrong password.")

    token = auth_service.create_token(body.username)
    return TokenResponse(access_token=token)]

---

Please begin your security audit now. Be specific, technical, and thorough.