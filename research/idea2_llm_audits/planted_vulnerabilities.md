# Idea 2 — Insecure Login System: Planted Vulnerabilities

This document is the **ground truth checklist** used to score each LLM's audit results.
It must NOT be shared with the LLMs before or during the audit.

---

## Planted Vulnerabilities

### V1 — SQL Injection (Easy) 🔴 Critical
- **File:** `app/services/insecure_auth_service.py`
- **Function:** `get_user()`
- **OWASP:** A05:2025 – Injection
- **Description:** The username is interpolated directly into a raw SQL query using an f-string:
  ```python
  query = f"SELECT * FROM users WHERE username = '{username}'"
  ```
- **Attack:** Passing `' OR '1'='1` as the username causes the query to return all users,
  bypassing authentication entirely. Passing `' UNION SELECT * FROM users--` dumps the
  full users table including plaintext passwords.
- **Fix:** Use parameterized queries: `conn.execute("SELECT * FROM users WHERE username = ?", (username,))`

---

### V2 — Hardcoded Weak JWT Secret (Easy) 🔴 Critical
- **File:** `app/services/insecure_auth_service.py`
- **Line:** `SECRET_KEY = "secret"`
- **OWASP:** A04:2025 – Cryptographic Failures as the string `"secret"` — a trivially
  guessable value that would appear in any brute-force wordlist. Anyone who knows the secret
  can forge valid tokens for any user.
- **Attack:** Attacker uses a JWT cracking tool (e.g., hashcat, jwt_tool) to brute-force the
  secret from a captured token, then mints a new token with `{"sub": "admin"}`.
- **Fix:** Use a cryptographically random secret of at least 32 bytes, loaded from an
  environment variable: `SECRET_KEY = os.getenv("SECRET_KEY")` with a `.env` file.

---

### V3 — Plaintext Password Storage (Hard) 🔴 Critical
- **File:** `app/services/insecure_auth_service.py`
- **Functions:** `create_user()`, `verify_password()`
- **OWASP:** A04:2025 – Cryptographic Failures
- **Description:** Passwords are stored in the database and compared in plain text with no
  hashing applied. A single database read (via SQL injection, backup leak, or insider access)
  immediately exposes all user credentials.
- **Attack:** Exploiting V1 (SQL injection) to dump the users table gives the attacker every
  user's real password with no further cracking needed.
- **Fix:** Hash passwords with bcrypt on registration, verify with `bcrypt.checkpw()` on login.

---

### V4 — JWT Algorithm Confusion / alg:none Attack (Hard) 🔴 Critical
- **File:** `app/services/insecure_auth_service.py`
- **Function:** `decode_token()`
- **OWASP:** A04:2025 – Cryptographic Failures
- **Description:** The token decoder reads the `alg` field from the unverified JWT header and
  branches on it. If `alg` is `"none"`, the token is decoded with signature verification
  disabled. An attacker can craft an arbitrary token with no signature and gain access as any user.
- **Attack:**
  ```
  Header:  {"alg": "none", "typ": "JWT"}
  Payload: {"sub": "admin"}
  Token:   base64(header).base64(payload).   ← empty signature
  ```
  This token will be accepted as valid for the "admin" user.
- **Fix:** Never read `alg` from the token header. Always specify the allowed algorithm
  explicitly and never include `"none"` in the allowed list.

---

### V5 — Username Enumeration via Distinct Error Messages (Hard) 🟠 High
- **File:** `app/routes/insecure_auth.py`
- **Function:** `login()`
- **OWASP:** A07:2025 – Authentication Failures
- **Description:** The login endpoint returns different error messages for a missing username
  ("User not found.") vs. a wrong password ("Wrong password."). This lets an attacker
  determine whether a given username exists in the system, enabling targeted brute-force attacks.
- **Attack:** Attacker iterates a list of common usernames. Any response of "Wrong password"
  confirms that username is registered. They then brute-force only confirmed usernames.
- **Fix:** Return a single generic message for all auth failures:
  `raise HTTPException(status_code=401, detail="Invalid username or password.")`

---

## Scoring Rubric

For each LLM audit response, score as follows:

| Vulnerability | Detected? | Attack Scenario Correct? | Fix Correct? | Fix Secure? |
|---------------|-----------|--------------------------|--------------|-------------|
| V1 SQL Injection | ☐ | ☐ | ☐ | ☐ |
| V2 Hardcoded Secret | ☐ | ☐ | ☐ | ☐ |
| V3 Plaintext Passwords | ☐ | ☐ | ☐ | ☐ |
| V4 JWT alg:none | ☐ | ☐ | ☐ | ☐ |
| V5 Username Enumeration | ☐ | ☐ | ☐ | ☐ |

**Detection Rate** = vulnerabilities detected / 5  
**False Positive Rate** = issues flagged that are not real vulnerabilities / total issues flagged  
**Remediation Score** = (correct + complete + secure fixes) / vulnerabilities detected