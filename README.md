# 5590 Final Project — Secure LLM Code Generation

**5590 · Systems Software Security**
**Authors:** Carlos Ortega & Boden Kahn

---

## Overview

This project investigates whether consumer-facing LLMs produce secure, well-documented code
resistant to common modern exploits. We explore two complementary research angles:

- **Idea 1 — LLM as Developer:** Prompt ChatGPT, Claude, and Gemini to generate a secure
  login/signup system, then evaluate the output using static and dynamic analysis.
- **Idea 2 — LLM as Auditor:** Provide LLMs with a purposely vulnerable login/signup system
  and measure their ability to detect seeded vulnerabilities against the OWASP Top 10:2025.

---

## Threat Model

- **Attacker:** Remote, unauthenticated adversary
- **Attack surface:** Web-facing login/signup endpoints
- **Attack types:** SQL injection, XSS, CSRF, authentication bypass, JWT forgery
- **Goal:** Bypass authentication or execute unauthorized commands due to insecure LLM-generated code

---

## Repo Structure

```
5590FinalProject/
├── frontend/                        # TypeScript / React (Vite) dashboard
│   └── src/
│       ├── components/              # Reusable UI components
│       ├── pages/                   # LoginPage, DashboardPage
│       ├── hooks/                   # useAuth.ts — JWT auth hook
│       └── types/                   # TypeScript type definitions
│
├── backend/
│   └── app/
│       ├── main.py                  # Secure baseline (production build)
│       ├── insecure_main.py         # Idea 2: insecure build entry point
│       │
│       ├── chatgpt_main.py          # Idea 2: ChatGPT hinted fixes
│       ├── claude_main.py           # Idea 2: Claude hinted fixes
│       ├── gemini_main.py           # Idea 2: Gemini hinted fixes
│       ├── chatgpt_blind_main.py    # Idea 2: ChatGPT blind fixes
│       ├── claude_blind_main.py     # Idea 2: Claude blind fixes
│       ├── gemini_blind_main.py     # Idea 2: Gemini blind fixes
│       │
│       ├── routes/                  # All auth route handlers (one per build)
│       ├── services/                # All auth service files (one per build)
│       └── models/                  # Shared Pydantic models + DB schema
│
├── research/
│   ├── idea1_llm_generates/         # Idea 1: prompts, LLM outputs, evaluation
│   └── idea2_llm_audits/            # Idea 2: insecure code, prompts, audit responses
│
├── docs/                            # Write-up, diagrams, references
├── scripts/                         # Automation scripts (static analysis, pen tests)
├── .gitignore
└── README.md                        # ← You are here
```

---

## LLMs Under Evaluation

| Model   | Provider  | Version Used                  |
|---------|-----------|-------------------------------|
| ChatGPT | OpenAI    | GPT-5.4 Extended Thinking     |
| Claude  | Anthropic | Claude Sonnet 4.6 Thinking    |
| Gemini  | Google    | Gemini 3.1 Pro                |

---

## Getting Started

### Prerequisites
- Node.js ≥ 18
- Python ≥ 3.11
- A `.env` file in `backend/` with:
  ```
  JWT_SECRET_KEY=<generate with: openssl rand -hex 32>
  ```

### Frontend
```bash
cd frontend
npm install
npm run dev
# Runs on http://localhost:5173
```

### Backend — Secure Baseline
```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload   # Runs on http://localhost:8000
```

### Register a Test User
```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "yourpassword"}'
```

### Running Idea 2 Builds (Insecure + LLM Fixes)
Each build runs on its own port so they can be compared side by side.
See `backend/README.md` for the full breakdown.

```bash
# Insecure baseline (Idea 2 audit target)
uvicorn app.insecure_main:app --port 8001

# Hinted prompt fixes
uvicorn app.chatgpt_main:app --port 8002
uvicorn app.claude_main:app    --port 8003
uvicorn app.gemini_main:app    --port 8004

# Blind prompt fixes
uvicorn app.chatgpt_blind_main:app --port 8005
uvicorn app.claude_blind_main:app  --port 8006
uvicorn app.gemini_blind_main:app  --port 8007
```

### Running Static Analysis
Static analysis will be performed on each build to compare security quality across the
insecure baseline and all LLM-fixed versions. See `backend/README.md` for the full
list of files to analyze per build.

---

## Evaluation Methodology

### Idea 1 — LLM as Developer
- **Prompt:** `research/idea1_llm_generates/LLM Creator Prompt.txt`
- **Static analysis:** Manual code review + automated static analysis tools for unsafe functions and hardcoded secrets
- **Dynamic analysis:** Penetration testing against OWASP Top 10 vulnerabilities
- **Metric:** Attack success rate per LLM-generated system

### Idea 2 — LLM as Auditor (Two-Prompt Experiment)
Two versions of the audit prompt were submitted to each LLM to test whether
vulnerability hints affect detection performance:

| Prompt | File | Description |
|--------|------|-------------|
| **Hinted** | `research/idea2_llm_audits/audit_prompt.md` | Code includes inline comments labeling each vulnerability (V1–V5) and their OWASP categories |
| **Blind** | `research/idea2_llm_audits/audit_prompt_blind.md` | Same code, zero hints — plain source with no comments indicating vulnerabilities exist |

**Planted vulnerabilities (5 total):** See `research/idea2_llm_audits/planted_vulnerabilities.md`

**Metrics per LLM per prompt:**
- Detection rate (# planted vulns found / 5)
- OWASP classification accuracy
- False positive rate
- Remediation correctness and security

See `research/idea2_llm_audits/README.md` for full scoring results and cross-prompt analysis.

---

## Tech Stack

| Layer     | Technology                      |
|-----------|---------------------------------|
| Frontend  | TypeScript, React, Vite         |
| Backend   | Python, FastAPI, SQLite         |
| Auth      | JWT (PyJWT), bcrypt / passlib   |
| Analysis  | Static analysis tools, manual OWASP pen-test |