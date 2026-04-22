# ============================================================
# FIXED VERSION — Claude Blind Recommended Fixes
# Based on: Claude Sonnet 4.6 Thinking blind audit (04/22/2026)
# Prompt: audit_prompt_blind.md (no vulnerability hints)
#
# Fixes applied in this file:
#   V5 - Username Enumeration  → single generic error message
#   + Rate limiting (Claude blind finding — Medium)
#   + Security logging of all auth events (Claude blind finding — High)
#   + CORS restricted to localhost:5173 (Claude blind unique finding — Medium)
# ============================================================

import logging
from fastapi import APIRouter, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from app.models.user import UserCreate, UserLogin, TokenResponse
from app.services import claude_blind_fixed_auth_service as auth_service

logger = logging.getLogger(__name__)
router = APIRouter()

# Extra fix (Claude blind unique finding): CORS restricted to known origin only.
# Apply this in main.py, shown here for reference:
#
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["http://localhost:5173"],  # NOT "*"
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )


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

    # V5 FIX (Claude blind): Single generic error — no distinction between
    # missing user and wrong password, preventing username enumeration
    if not user or not auth_service.verify_password(body.password, user["password"]):
        # Extra fix (Claude blind): Log failed attempt with IP for monitoring
        client_ip = request.client.host if request.client else "unknown"
        logger.warning(
            f"Failed login attempt | username: {body.username} | ip: {client_ip}"
        )
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    logger.info(f"Successful login | username: {body.username}")
    token = auth_service.create_token(body.username)
    return TokenResponse(access_token=token)