from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes.claude_blind_fixed_auth import router

app = FastAPI(title="SecureEval — Claude Blind Fixed")

# Claude blind finding: CORS restricted to known origin only (not wildcard)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/auth")