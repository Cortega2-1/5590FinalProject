from fastapi import APIRouter, HTTPException, status

from app.models.user import UserCreate, UserLogin, TokenResponse
from app.services import auth_service

router = APIRouter()


@router.post("/register", status_code=201)
def register(body: UserCreate):
    try:
        created_user = auth_service.create_user(body.username, body.password)
        return {
            "message": "User registered successfully.",
            "username": created_user["username"],
        }
    except ValueError as exc:
        if str(exc) == "username_taken":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username is already taken.",
            ) from exc

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.post("/login", response_model=TokenResponse)
def login(body: UserLogin):
    try:
        user = auth_service.authenticate_user(body.username, body.password)
    except ValueError:
        user = None

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_service.create_token(user["username"])
    return TokenResponse(access_token=token)
