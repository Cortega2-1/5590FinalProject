# ============================================================
# FIXED VERSION — ChatGPT Recommended Fixes
# Based on: GPT 5.4 Extended Thinking audit (04/22/2026)
#
# Fixes applied in this file:
#   V5 - Username Enumeration  → single generic error message
#   + Rate limiting via slowapi (ChatGPT extra finding #6)
#   + Logging of failed login attempts (ChatGPT extra finding #9)
# ============================================================

import logging
from fastapi import APIRouter, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.models.user import UserCreate, UserLogin, TokenResponse
from app.services import chatgpt_fixed_auth_service as auth_service

logger = logging.getLogger(__name__)

# Extra fix (ChatGPT): Rate limiting — max 5 login attempts per minute per IP
limiter = Limiter(key_func=get_remote_address)

router = APIRouter()


@router.post("/register", status_code=201)
def register(body: UserCreate):
    # V1 fix flows through to auth_service.get_user() (parameterized)
    if auth_service.get_user(body.username):
        raise HTTPException(status_code=400, detail="Username already taken.")
    auth_service.create_user(body.username, body.password)
    return {"message": f"User '{body.username}' created successfully."}


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")  # Extra fix (ChatGPT): blocks brute-force attempts
def login(request: Request, body: UserLogin):
    user = auth_service.get_user(body.username)

    # V5 FIX (ChatGPT): Single unified error message — does not reveal whether
    # username or password was wrong, preventing username enumeration
    if not user or not auth_service.verify_password(body.password, user["password"]):
        # Extra fix (ChatGPT): Log failed attempts for monitoring/alerting
        logger.warning(f"Failed login attempt for username: {body.username} from IP: {request.client.host}")
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    logger.info(f"Successful login for username: {body.username}")
    token = auth_service.create_token(body.username)
    return TokenResponse(access_token=token)