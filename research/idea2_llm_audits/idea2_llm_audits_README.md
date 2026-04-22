# research/idea2_llm_audits — LLM as Security Auditor

This directory contains everything for **Idea 2** of the SecureEval project:
evaluating how well LLMs perform as security auditors on a purposely vulnerable codebase.

---

## What We Did

We created an intentionally insecure login/signup system with **5 planted vulnerabilities**
and submitted it to ChatGPT, Claude, and Gemini under **two different prompt conditions**
to test whether inline vulnerability hints affect detection performance.

---

## The Two-Prompt Experiment

### Prompt 1 — Hinted (`audit_prompt.md`)
The code shown to the LLMs includes a comment block at the top of the service file
explicitly listing each vulnerability by name, difficulty rating, and OWASP category:
```python
# VULNERABILITIES PLANTED:
#   V1 (Easy)   - SQL Injection ...   → A05:2025
#   V2 (Easy)   - Hardcoded secret ... → A04:2025
#   ...
```
Each vulnerable line also has an inline comment explaining what it is.

### Prompt 2 — Blind (`audit_prompt_blind.md`)
The exact same code and the exact same task instructions, but **all hint comments are removed**.
The code looks like normal developer-written code with no indication that vulnerabilities exist.

**Research question:** Does knowing vulnerabilities are present (and where to look)
change an LLM's ability to detect and correctly classify them?

---

## Planted Vulnerabilities (Ground Truth)

Full details in `planted_vulnerabilities.md`. Summary:

| ID | Vulnerability | Location | OWASP 2025 | Difficulty |
|----|--------------|----------|------------|------------|
| V1 | SQL Injection | `insecure_auth_service.py` → `get_user()` | A05 – Injection | Easy |
| V2 | Hardcoded JWT Secret | `insecure_auth_service.py` → `SECRET_KEY` | A04 – Cryptographic Failures | Easy |
| V3 | Plaintext Password Storage | `insecure_auth_service.py` → `create_user()` | A04 – Cryptographic Failures | Hard |
| V4 | JWT alg:none Attack | `insecure_auth_service.py` → `decode_token()` | A04 – Cryptographic Failures | Hard |
| V5 | Username Enumeration | `insecure_auth.py` → `login()` | A07 – Authentication Failures | Hard |

---

## Files in This Directory

```
idea2_llm_audits/
├── audit_prompt.md              # Hinted prompt (submitted verbatim to all 3 LLMs)
├── audit_prompt_blind.md        # Blind prompt (same code, no hints)
├── planted_vulnerabilities.md   # Ground truth answer key + scoring rubric
│
├── chatgpt_audit.md             # ChatGPT response to hinted prompt + scored table
├── claude_audit.md              # Claude response to hinted prompt + scored table
├── gemini_audit.md              # Gemini response to hinted prompt + scored table
│
├── chatgpt_audit_blind.md       # ChatGPT response to blind prompt + scored table
├── claude_audit_blind.md        # Claude response to blind prompt + scored table
└── gemini_audit_blind.md        # Gemini response to blind prompt + scored table
```

The insecure backend code that was audited lives in:
```
backend/app/services/insecure_auth_service.py
backend/app/routes/insecure_auth.py
```

The LLM-fixed versions live in:
```
backend/app/services/chatgpt_fixed_auth_service.py     ← hinted fixes
backend/app/services/claude_fixed_auth_service.py
backend/app/services/gemini_fixed_auth_service.py
backend/app/services/chatgpt_blind_fixed_auth_service.py  ← blind fixes
backend/app/services/claude_blind_fixed_auth_service.py
backend/app/services/gemini_blind_fixed_auth_service.py
```

---

## Results Summary

All three LLMs achieved **5/5 detection (100%) and 0 false positives on both prompts.**
Hints had no impact on detection rate. Key differences emerged in OWASP classification
accuracy, response depth, and cross-prompt consistency.

### Detection Rate

| Model | Hinted | Blind |
|-------|--------|-------|
| ChatGPT | 5/5 (100%) | 5/5 (100%) |
| Claude | 5/5 (100%) | 5/5 (100%) |
| Gemini | 5/5 (100%) | 5/5 (100%) |

### OWASP Classification Accuracy (planted vulns only)

| Model | Hinted Correct | Blind Correct | Notes |
|-------|---------------|---------------|-------|
| ChatGPT | 4/5 | 4/5 | V2 classified as A02 both times (ground truth: A04) |
| Claude | 5/5 | 5/5 | Perfect both runs — only model with no classification errors |
| Gemini | 4/5 | 3/5 | V2 = A02 both runs; V4 flipped A04→A07 in blind run |

### Extra Findings Beyond Planted 5

| Model | Hinted | Blind |
|-------|--------|-------|
| ChatGPT | 6 extra | 7 extra |
| Claude | 5 extra | 7 extra |
| Gemini | 1 extra | 3 extra |

All extra findings across all runs were legitimate security concerns — **0 false positives total.**

### Notable Cross-Prompt Findings

- **Hints had zero effect on detection** — all models found all 5 vulnerabilities regardless
  of whether the code was labeled or not.
- **Gemini's V4 classification flipped** between runs (A04 hinted → A07 blind), the only
  case where removing hints changed a model's reasoning about a finding's category.
- **ChatGPT's V2 misclassification is consistent** across both runs — always A02, never A04.
  This appears to be a stable model-level bias.
- **Claude was the only model with zero classification drift** — identical categories in both runs.
- **Claude was the only model to flag unpinned dependencies** (A03 — Supply Chain) across
  either run, showing the broadest OWASP Top 10 coverage.
- **Gemini produced the fewest extra findings** in both runs (most focused response),
  but also missed real concerns like rate limiting and JWT expiry that the others caught.

---

## Scoring Methodology

For each LLM audit response, each planted vulnerability was scored on four criteria:

| Criterion | Description |
|-----------|-------------|
| **Detected?** | Did the LLM identify this specific vulnerability? |
| **Attack Scenario Correct?** | Was the described exploit technically accurate? |
| **Fix Correct?** | Would the suggested fix actually resolve the issue? |
| **Fix Secure?** | Does the fix avoid introducing new vulnerabilities? |

Additional metrics:
- **False Positive Rate** = issues flagged that are not real vulnerabilities / total flags
- **OWASP Accuracy** = correct category mappings / planted vulns detected
- **Remediation Depth** = whether code snippets were provided vs. prose-only descriptions