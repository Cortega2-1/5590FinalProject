import os

from app.models.database import get_connection
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-production")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 8


def hash_password(plain: str) -> str:



def verify_password(plain: str, hashed: str) -> bool:



def create_token(username: str) -> str:



def get_user(username: str):



def create_user(username: str, password: str):
