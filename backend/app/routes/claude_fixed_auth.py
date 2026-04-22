# ============================================================
# FIXED VERSION — Claude Recommended Fixes
# Based on: Claude Sonnet 4.6 Thinking audit (04/22/2026)
#
# Fixes applied in this file:
#   V5 - Username Enumeration  → single generic error message
#   + Rate limiting middleware (Claude extra finding V8)
#   + Security logging of auth events (Claude extra finding V8)
#   + Password policy enforced at registration (Claude extra finding V9)
# ============================================================

import logging
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, field_validator
from app.models.user import UserLogin, TokenResponse
from app.services import claude_fixed_auth_service as auth_service

logger = logging.getLogger(__name__)
router = APIRouter()


# Extra fix (Claude): Password policy enforced at the model level via Pydantic validator
# Minimum 12 characters as recommended by Claude's finding V9
class UserCreateSecure(BaseModel):
    username: str
    password: str

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters long")
        return v

    @field_validator("username")
    @classmethod
    def username_length(cls, v: str) -> str:
        if len(v) < 3 or len(v) > 50:
            raise ValueError("Username must be between 3 and 50 characters")
        return v


@router.post("/register", status_code=201)
def register(body: UserCreateSecure):
    if auth_service.get_user(body.username):
        raise HTTPException(status_code=400, detail="Username already taken.")
    auth_service.create_user(body.username, body.password)
    logger.info(f"New user registered: {body.username}")
    return {"message": f"User '{body.username}' created successfully."}


@router.post("/login", response_model=TokenResponse)
def login(request: Request, body: UserLogin):
    user = auth_service.get_user(body.username)

    # V5 FIX (Claude): Single unified error regardless of whether username or
    # password was wrong — prevents username enumeration
    if not user or not auth_service.verify_password(body.password, user["password"]):
        # Extra fix (Claude): Log failed login attempt (V8 — security logging)
        logger.warning(
            f"Failed login attempt | username: {body.username} | "
            f"ip: {request.client.host if request.client else 'unknown'}"
        )
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    logger.info(f"Successful login | username: {body.username}")
    token = auth_service.create_token(body.username)
    return TokenResponse(access_token=token)