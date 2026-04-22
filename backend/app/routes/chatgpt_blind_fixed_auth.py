# ============================================================
# FIXED VERSION — ChatGPT Blind Recommended Fixes
# Based on: GPT 5.4 Extended Thinking blind audit (04/22/2026)
# Prompt: audit_prompt_blind.md (no vulnerability hints)
#
# Fixes applied in this file:
#   V5 - Username Enumeration  → single generic error message
#   + Rate limiting via slowapi (ChatGPT blind finding #5 — rated Critical)
#   + Logging of failed login attempts (ChatGPT blind finding #10)
#   + Pydantic input validation on UserCreate (ChatGPT blind finding #9)
# ============================================================

import logging
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, constr
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.models.user import UserLogin, TokenResponse
from app.services import chatgpt_blind_fixed_auth_service as auth_service

logger = logging.getLogger(__name__)

# Extra fix (ChatGPT blind): rate limiting — 5 login attempts per minute per IP
limiter = Limiter(key_func=get_remote_address)

router = APIRouter()


# Extra fix (ChatGPT blind): Input validation via Pydantic
class UserCreateValidated(BaseModel):
    username: constr(min_length=3, max_length=50)
    password: constr(min_length=8, max_length=128)


@router.post("/register", status_code=201)
def register(body: UserCreateValidated):
    if auth_service.get_user(body.username):
        raise HTTPException(status_code=400, detail="Username already taken.")
    auth_service.create_user(body.username, body.password)
    return {"message": f"User '{body.username}' created successfully."}


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
def login(request: Request, body: UserLogin):
    user = auth_service.get_user(body.username)

    # V5 FIX (ChatGPT blind): Single generic error message for both
    # missing user and wrong password — prevents username enumeration
    if not user or not auth_service.verify_password(body.password, user["password"]):
        # Extra fix (ChatGPT blind): Log failed attempts
        logger.warning(f"Failed login attempt for username: {body.username}")
        raise HTTPException(status_code=401, detail="Invalid credentials.")

    logger.info(f"Successful login for username: {body.username}")
    token = auth_service.create_token(body.username)
    return TokenResponse(access_token=token)