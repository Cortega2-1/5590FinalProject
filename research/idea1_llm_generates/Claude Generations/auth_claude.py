from fastapi import APIRouter, HTTPException
from app.models.user import UserCreate, UserLogin, TokenResponse
from app.services import auth_service

router = APIRouter()


@router.post("/register", status_code=201)
def register(body: UserCreate):
    existing_user = auth_service.get_user(body.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username is already taken.")

    auth_service.create_user(body.username, body.password)
    return {"message": "User registered successfully."}


@router.post("/login", response_model=TokenResponse)
def login(body: UserLogin):
    user = auth_service.get_user(body.username)
    if not user or not auth_service.verify_password(body.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token = auth_service.create_token(body.username)
    return TokenResponse(access_token=token)
