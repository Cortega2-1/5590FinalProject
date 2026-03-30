# 5590 Final Project — Secure LLM Code Generation

**5590 · Systems Software Security**  
**Authors:** Carlos Ortega & Boden Kahn

---

## Overview

This project investigates whether consumer-facing LLMs produce secure, well-documented code resistant to common modern exploits. We explore two complementary research angles:

- **Idea 1 — LLM as Developer:** Prompt multiple LLMs (ChatGPT, Claude, and Gemini) to generate a secure login/signup system, then evaluate the output using static and dynamic analysis.
- **Idea 2 — LLM as Auditor:** Provide LLMs with a purposely vulnerable login/signup system and measure their ability to detect seeded vulnerabilities (e.g., `strcpy`, CSRF, XSS, SQL injection).

---

## Threat Model

- **Attacker:** Remote, unauthenticated adversary
- **Attack surface:** Web-facing login/signup endpoints
- **Attack types:** Buffer overflows, XSS, CSRF, SQL injection, authentication bypass via logic errors
- **Goal:** Bypass authentication or execute unauthorized commands due to LLM-generated code flaws

---

## Repo Structure

```
5590FinalProject/
├── frontend/               # TypeScript / React dashboard
│   ├── public/
│   └── src/
│       ├── components/     # Reusable UI components
│       ├── pages/          # Route-level page components
│       ├── hooks/          # Custom React hooks
│       ├── utils/          # Helper functions
│       └── types/          # TypeScript type definitions
│
├── backend/                # Python (Flask or FastAPI) API
│   ├── app/
│   │   ├── routes/         # API route handlers
│   │   ├── models/         # Data models / schemas
│   │   ├── services/       # Business logic
│   │   └── utils/          # Shared utilities
│   └── tests/              # Backend unit & integration tests
│
├── research/
│   ├── idea1_llm_generates/   # Prompts, LLM outputs, evaluation results
│   └── idea2_llm_audits/      # Seeded vulnerable code, LLM audit results
│
├── docs/                   # Write-up, diagrams, references
├── scripts/                # Automation scripts (running evals, pen tests, etc.)
├── .gitignore
└── README.md
```

---

## LLMs Under Evaluation

| Model     | Provider  |
|-----------|-----------|
| ChatGPT   | OpenAI    |
| Claude    | Anthropic |
| Gemini    | Google    |

---

## Evaluation Methodology

### Idea 1 — Static & Dynamic Analysis of LLM-Generated Code
- **Static:** Manual code review + automated scanning for unsafe functions (`gets`, `strcpy`, hardcoded secrets, etc.)
- **Dynamic:** Penetration testing against OWASP Top 10 vulnerabilities
- **Metric:** Attack success rate per LLM

### Idea 2 — Vulnerability Detection Accuracy
- Seed a known-vulnerable codebase with common flaws
- Prompt each LLM to perform a security audit
- **Metrics:** Detection rate, false positive rate, quality of suggested fixes

---

## Getting Started

### Frontend
```bash
cd frontend
npm install
npm run dev
```

### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m app.main
uvicorn app.main:app --reload
```

###create user 
```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "fill_out_username", "password": "fill_out_password"}'
---

## Tech Stack

| Layer     | Technology              |
|-----------|-------------------------|
| Frontend  | TypeScript, React, Vite |
| Backend   | Python, Flask / FastAPI |
| Testing   | pytest, OWASP ZAP       |
| Analysis  | Bandit, Semgrep         |
