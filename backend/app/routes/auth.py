# from fastapi import APIRouter, HTTPException
# # from app.models.user import UserCreate, UserLogin, TokenResponse
# from app.user import UserCreate, UserLogin, TokenResponse
# # from app.services import auth_service
# from app.database import init_db
from fastapi import APIRouter, HTTPException
# Change this line:
from app.models.user import UserCreate, UserLogin, TokenResponse
from app.services import auth_service

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
    if not user or not auth_service.verify_password(body.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    token = auth_service.create_token(body.username)
    return TokenResponse(access_token=token)