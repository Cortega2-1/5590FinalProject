# import bcrypt
# import jwt
# import os
# from datetime import datetime, timedelta, timezone
# from app.models.database import get_connection
import bcrypt
import jwt
import os
from datetime import datetime, timedelta, timezone
# Change this line:
from app.models.database import get_connection
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-production")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 8


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.now(timezone.utc) + timedelta(hours=TOKEN_EXPIRE_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_user(username: str):
    conn = get_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return user


def create_user(username: str, password: str):
    conn = get_connection()
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, hash_password(password)),
    )
    conn.commit()
    conn.close()