# ============================================================
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
    return TokenResponse(access_token=token)