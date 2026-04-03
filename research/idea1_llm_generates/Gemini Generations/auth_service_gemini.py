import os
import sqlite3
from datetime import datetime, timedelta, timezone
import jwt
from passlib.context import CryptContext

from app.models.database import get_connection

SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-production")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 8

# Configure passlib to use bcrypt, the industry standard for password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(plain: str) -> str:
    """Hashes a plaintext password using bcrypt."""
    return pwd_context.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    """Verifies a plaintext password against the stored bcrypt hash."""
    return pwd_context.verify(plain, hashed)

def create_token(username: str) -> str:
    """Generates a JWT token with 'sub' and 'exp' claims."""
    expire = datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS)
    to_encode = {
        "sub": username,
        "exp": expire
    }
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user(username: str):
    """
    Safely retrieves a user from the database using parameterized queries 
    to prevent SQL injection.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        # Parameterized query (?) prevents SQL injection
        cursor.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        
        if row:
            return {
                "id": row[0],
                "username": row[1],
                "password": row[2] # This is the hashed password
            }
        return None
    finally:
        conn.close()

def create_user(username: str, password: str):
    """
    Hashes the user's password and securely stores the new user record.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        hashed_pw = hash_password(password)
        
        # Parameterized query (?) prevents SQL injection
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)", 
            (username, hashed_pw)
        )
        conn.commit()
    except sqlite3.IntegrityError as e:
        # Failsafe in case of a race condition where the username is inserted 
        # between the check and the insert.
        raise ValueError("Username already exists") from e
    finally:
        conn.close()