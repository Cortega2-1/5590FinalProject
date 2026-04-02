import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from pwdlib import PasswordHash

from app.models.database import get_connection

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-production")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 8

password_hash = PasswordHash.recommended()
DUMMY_HASH = password_hash.hash("dummy-password-for-timing")
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,64}$")
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


def _normalize_username(username: str) -> str:
    if not isinstance(username, str):
        raise ValueError("Username is required.")

    normalized = username.strip()
    if not normalized:
        raise ValueError("Username is required.")

    if not USERNAME_PATTERN.fullmatch(normalized):
        raise ValueError(
            "Username must be 3-64 characters and contain only letters, numbers, '.', '_' or '-'."
        )

    return normalized


def _validate_password(password: str) -> str:
    if not isinstance(password, str):
        raise ValueError("Password is required.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")

    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters long.")

    if password.isspace():
        raise ValueError("Password cannot be blank.")

    return password


def _row_to_user(row) -> Optional[dict]:
    if row is None:
        return None

    if isinstance(row, dict):
        return {
            "id": row.get("id"),
            "username": row.get("username"),
            "password": row.get("password"),
        }

    if hasattr(row, "keys"):
        return {
            "id": row["id"],
            "username": row["username"],
            "password": row["password"],
        }

    return {"id": row[0], "username": row[1], "password": row[2]}


def hash_password(plain: str) -> str:
    password = _validate_password(plain)
    return password_hash.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        password = _validate_password(plain)
        return password_hash.verify(password, hashed)
    except Exception:
        return False


def create_token(username: str) -> str:
    subject = _normalize_username(username)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS)
    payload = {"sub": subject, "exp": expires_at}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_user(username: str):
    normalized = _normalize_username(username)
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password FROM users WHERE username = ? LIMIT 1",
            (normalized,),
        )
        row = cursor.fetchone()
        return _row_to_user(row)
    finally:
        conn.close()


def create_user(username: str, password: str):
    normalized = _normalize_username(username)
    hashed_password = hash_password(password)

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (normalized, hashed_password),
        )
        conn.commit()
        return {"id": cursor.lastrowid, "username": normalized}
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise ValueError("username_taken") from exc
    finally:
        conn.close()


def authenticate_user(username: str, password: str):
    user = get_user(username)
    if user is None:
        verify_password(password, DUMMY_HASH)
        return None

    if not verify_password(password, user["password"]):
        return None

    return user
