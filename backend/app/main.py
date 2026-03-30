# from fastapi import FastAPI
# from fastapi.middleware.cors import CORSMiddleware
# from app.routes import auth
# from app.models.database import init_db
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import auth
# Change this line:
from app.models.database import init_db

app = FastAPI(title="SecureEval API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup():
    init_db()

app.include_router(auth.router, prefix="/auth", tags=["auth"])

@app.get("/")
def root():
    return {"message": "SecureEval API is running"}