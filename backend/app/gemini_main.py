# gemini_main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes.gemini_fixed_auth import router

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"],
                   allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(router, prefix="/auth")