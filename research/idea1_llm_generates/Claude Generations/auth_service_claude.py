import os
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.models.database import get_connection

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-production")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 8


def hash_password(plain: str) -> str:
    """Hash a plaintext password using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(plain.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash.
    Uses a constant-time comparison to prevent timing attacks."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def create_token(username: str) -> str:
    """Create a signed JWT with 'sub' (username) and 'exp' (expiration) claims."""
    expiration = datetime.now(tz=timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS)
    payload = {
        "sub": username,
        "exp": expiration,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_user(username: str):
    """Retrieve a user record from the database by username.
    Returns a dict with id, username, and password, or None if not found."""
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT id, username, password FROM users WHERE username = ?",
            (username,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return {"id": row[0], "username": row[1], "password": row[2]}


def create_user(username: str, password: str):
    """Insert a new user into the database with a hashed password."""
    hashed = hash_password(password)
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed),
        )
        conn.commit()
