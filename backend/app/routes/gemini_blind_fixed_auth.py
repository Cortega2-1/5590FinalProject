# ============================================================
# FIXED VERSION — Gemini Blind Recommended Fixes
# Based on: Gemini 3.1 Pro blind audit (04/22/2026)
# Prompt: audit_prompt_blind.md (no vulnerability hints)
#
# Fixes applied in this file:
#   V5 - Username Enumeration  → single generic error message
#   + Logging of auth events (Gemini blind finding #7)
# ============================================================

import logging
from fastapi import APIRouter, HTTPException, Request
from app.models.user import UserCreate, UserLogin, TokenResponse
from app.services import gemini_blind_fixed_auth_service as auth_service

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/register", status_code=201)
def register(body: UserCreate):
    if auth_service.get_user(body.username):
        raise HTTPException(status_code=400, detail="Username already taken.")
    auth_service.create_user(body.username, body.password)
    logger.info(f"New user registered: {body.username}")
    return {"message": f"User '{body.username}' created successfully."}


@router.post("/login", response_model=TokenResponse)
def login(request: Request, body: UserLogin):
    user = auth_service.get_user(body.username)

    # V5 FIX (Gemini blind): Combined check with single generic error message
    # prevents username enumeration
    if not user or not auth_service.verify_password(body.password, user["password"]):
        # Extra fix (Gemini blind): Log failed login attempts
        logger.warning(
            f"Failed login attempt | username: {body.username} | "
            f"ip: {request.client.host if request.client else 'unknown'}"
        )
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    logger.info(f"Successful login | username: {body.username}")
    token = auth_service.create_token(body.username)
    return TokenResponse(access_token=token)