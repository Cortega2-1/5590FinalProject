# ============================================================
# FIXED VERSION — Gemini Recommended Fixes
# Based on: Gemini 3.1 Pro audit (04/22/2026)
#
# Fixes applied in this file:
#   V5 - Username Enumeration  → single generic error message
#   + HttpOnly cookie for JWT delivery (Gemini extra finding #6)
#     JWT is no longer returned in JSON body — set as HttpOnly, Secure,
#     SameSite=Lax cookie to prevent XSS-based token theft
#
# NOTE: The HttpOnly cookie approach requires frontend changes:
#   - Remove sessionStorage.setItem("auth_token", ...) from useAuth.ts
#   - Include credentials in fetch calls: fetch(url, { credentials: "include" })
#   - CORS must allow credentials: allow_credentials=True in FastAPI CORSMiddleware
# ============================================================

from fastapi import APIRouter, HTTPException, Request, Response
from app.models.user import UserCreate, UserLogin, TokenResponse
from app.services import gemini_fixed_auth_service as auth_service

router = APIRouter()


@router.post("/register", status_code=201)
def register(body: UserCreate):
    # V1 fix flows through get_user() — now uses parameterized query
    if auth_service.get_user(body.username):
        raise HTTPException(status_code=400, detail="Username already taken.")
    auth_service.create_user(body.username, body.password)
    return {"message": f"User '{body.username}' created successfully."}


@router.post("/login")
def login(body: UserLogin, response: Response):
    user = auth_service.get_user(body.username)

    # V5 FIX (Gemini): Combined check — single generic error message for both
    # "user not found" and "wrong password" cases, preventing username enumeration
    if not user or not auth_service.verify_password(body.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token = auth_service.create_token(body.username)

    # Extra fix (Gemini): Issue JWT as HttpOnly cookie instead of JSON body.
    # httponly=True  → JavaScript cannot read this cookie (XSS-safe)
    # secure=True    → Only sent over HTTPS (set to False for local dev)
    # samesite="lax" → Sent on same-origin navigations, blocks cross-site POST abuse
    # This eliminates the need to store the token in sessionStorage/localStorage
    response.set_cookie(
        key="access_token",
        value=f"Bearer {token}",
        httponly=True,
        secure=True,   # Change to False for localhost development
        samesite="lax",
        max_age=1800,  # 30 minutes, matches ACCESS_TOKEN_EXPIRE_MINUTES
        path="/",
    )
    return {"message": "Login successful"}


@router.post("/logout")
def logout(response: Response):
    # Companion logout endpoint — clears the HttpOnly cookie
    response.delete_cookie(key="access_token", path="/")
    return {"message": "Logged out successfully"}