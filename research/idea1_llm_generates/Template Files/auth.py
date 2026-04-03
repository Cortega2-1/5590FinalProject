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


@router.post("/login", response_model=TokenResponse)
def login(body: UserLogin):