from fastapi import APIRouter, HTTPException, status
from app.models.user import UserCreate, UserLogin, TokenResponse
from app.services import auth_service

router = APIRouter()

@router.post("/register", status_code=201)
def register(body: UserCreate):
    # 1. Check if the user already exists to prevent duplication
    existing_user = auth_service.get_user(body.username)
    if existing_user:
        # Raise 400 Bad Request as per requirements
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # 2. Create the user
    try:
        auth_service.create_user(body.username, body.password)
    except ValueError as e:
        # Catch the race-condition IntegrityError thrown from auth_service
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
        
    return {"message": "User registered successfully"}


@router.post("/login", response_model=TokenResponse)
def login(body: UserLogin):
    # 1. Fetch user by username
    user = auth_service.get_user(body.username)
    
    # Generic error message to prevent username enumeration attacks
    auth_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # 2. Verify user exists
    if not user:
        raise auth_error
        
    # 3. Verify password hash matches
    if not auth_service.verify_password(body.password, user["password"]):
        raise auth_error
        
    # 4. Generate and return JWT
    access_token = auth_service.create_token(username=user["username"])
    
    return TokenResponse(
        access_token=access_token, 
        token_type="bearer"
    )