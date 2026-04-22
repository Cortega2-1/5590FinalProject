# Backend — Build Guide

This directory contains **8 separate FastAPI builds** used across Idea 1 and Idea 2
of the SecureEval research project.

---

## Quick Reference — All Builds

| Build | Main File | Port | Purpose |
|-------|-----------|------|---------|
| Secure baseline | `app/main.py` | 8000 | Production-ready secure build (Idea 1 reference) |
| Insecure | `app/insecure_main.py` | 8001 | Idea 2 audit target — 5 planted vulnerabilities |
| ChatGPT hinted | `app/chatgpt_main.py` | 8002 | ChatGPT fixes from hinted audit prompt |
| Claude hinted | `app/claude_main.py` | 8003 | Claude fixes from hinted audit prompt |
| Gemini hinted | `app/gemini_main.py` | 8004 | Gemini fixes from hinted audit prompt |
| ChatGPT blind | `app/chatgpt_blind_main.py` | 8005 | ChatGPT fixes from blind audit prompt |
| Claude blind | `app/claude_blind_main.py` | 8006 | Claude fixes from blind audit prompt |
| Gemini blind | `app/gemini_blind_main.py` | 8007 | Gemini fixes from blind audit prompt |

---

## Setup (do once)

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file in `backend/` (required for all fixed builds):
```
JWT_SECRET_KEY=<run: openssl rand -hex 32>
```

> ⚠️ The **insecure build** does NOT use an env var — it has `SECRET_KEY = "secret"` hardcoded
> by design. Do not set environment variables for it.

---

## Running Individual Builds

Start each build from the `backend/` directory:

```bash
# Secure baseline
uvicorn app.main:app --reload

# Insecure baseline (Idea 2 audit target)
uvicorn app.insecure_main:app --port 8001

# Hinted prompt fixes
uvicorn app.chatgpt_main:app --port 8002
uvicorn app.claude_main:app   --port 8003
uvicorn app.gemini_main:app   --port 8004

# Blind prompt fixes
uvicorn app.chatgpt_blind_main:app --port 8005
uvicorn app.claude_blind_main:app  --port 8006
uvicorn app.gemini_blind_main:app  --port 8007
```

---

## File Map — Routes & Services

Each build has its own paired route + service file.
The main file ties them together.

| Build | Route File | Service File |
|-------|-----------|--------------|
| Secure baseline | `routes/auth.py` | `services/auth_service.py` |
| Insecure | `routes/insecure_auth.py` | `services/insecure_auth_service.py` |
| ChatGPT hinted | `routes/chatgpt_fixed_auth.py` | `services/chatgpt_fixed_auth_service.py` |
| Claude hinted | `routes/claude_fixed_auth.py` | `services/claude_fixed_auth_service.py` |
| Gemini hinted | `routes/gemini_fixed_auth.py` | `services/gemini_fixed_auth_service.py` |
| ChatGPT blind | `routes/chatgpt_blind_fixed_auth.py` | `services/chatgpt_blind_fixed_auth_service.py` |
| Claude blind | `routes/claude_blind_fixed_auth.py` | `services/claude_blind_fixed_auth_service.py` |
| Gemini blind | `routes/gemini_blind_fixed_auth.py` | `services/gemini_blind_fixed_auth_service.py` |

---

## Static Analysis

Static analysis will be run against each build to compare security quality across the
insecure baseline and all LLM-fixed versions. The tool to be used is TBD.

Each build's paired files for analysis:

| Build | Service File | Route File |
|-------|-------------|------------|
| Insecure baseline | `services/insecure_auth_service.py` | `routes/insecure_auth.py` |
| ChatGPT hinted | `services/chatgpt_fixed_auth_service.py` | `routes/chatgpt_fixed_auth.py` |
| Claude hinted | `services/claude_fixed_auth_service.py` | `routes/claude_fixed_auth.py` |
| Gemini hinted | `services/gemini_fixed_auth_service.py` | `routes/gemini_fixed_auth.py` |
| ChatGPT blind | `services/chatgpt_blind_fixed_auth_service.py` | `routes/chatgpt_blind_fixed_auth.py` |
| Claude blind | `services/claude_blind_fixed_auth_service.py` | `routes/claude_blind_fixed_auth.py` |
| Gemini blind | `services/gemini_blind_fixed_auth_service.py` | `routes/gemini_blind_fixed_auth.py` |

Results will be saved to `scripts/` for the final report.

---

## Test a Build with curl

Register a user:
```bash
curl -X POST http://localhost:<PORT>/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpassword"}'
```

Login:
```bash
curl -X POST http://localhost:<PORT>/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpassword"}'
```

SQL injection test (insecure build only — port 8001):
```bash
curl -X POST http://localhost:8001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "'\'' OR '\''1'\''='\''1", "password": "anything"}'
```
Expected: returns a token (auth bypass confirmed) on insecure build,
returns 401 on all fixed builds.