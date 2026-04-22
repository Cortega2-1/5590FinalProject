# ============================================================
# INSECURE VERSION — FOR RESEARCH/EDUCATIONAL USE ONLY
# Swap app/main.py with this file to run the insecure backend.
# The frontend (LoginPage.tsx) is IDENTICAL — UI does not change.
# ============================================================

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import insecure_auth
from app.models.database import init_db

app = FastAPI(title="SecureEval API — INSECURE BUILD")

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

# Routes the insecure auth router — same URL paths as secure version
app.include_router(insecure_auth.router, prefix="/auth", tags=["auth"])

@app.get("/")
def root():
    return {"message": "SecureEval API — INSECURE BUILD (research only)"}