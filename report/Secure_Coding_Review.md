# Secure Coding Review Report

**Intern Name:** _<aapka naam>_  
**Program:** CodeAlpha Cyber Security Internship – Task 3  
**Date:** _<date>_

---

## 1. Introduction
Is task mein ek chhoti Python/Flask web application ka security audit kiya gaya jisme jaan boojh kar common vulnerabilities rakhi gayi hain. Maqsad vulnerabilities dhoondna, unki severity tay karna, remediation dena aur secure coding best practices document karna hai.

## 2. Scope
| Item | Detail |
|------|--------|
| Language | Python 3 |
| Framework | Flask |
| Application | Demo web app (login, search, ping, calculator, file download, profile, upload) |
| Files audited | `vulnerable/app_vulnerable.py` (~157 lines) |
| Fixed version | `secure/app_secure.py` |
| Standard | OWASP Top 10 (2021) |

## 3. Methodology
1. **Static analysis:** Bandit (Python SAST) aur Semgrep.
2. **Manual code review:** line-by-line, OWASP Top 10 checklist ke mutabiq.
3. **Dynamic verification:** app local par chala kar har finding ko test kiya (proof of concept).
4. **Remediation:** secure version likh kar dobara test kiya + Bandit dobara chalaya.

**Commands:**
```bash
bandit -r vulnerable -f html -o report/bandit_vulnerable.html
bandit -r secure
semgrep --config=auto vulnerable/
pip-audit -r requirements.txt
```

![Bandit scan - vulnerable](../screenshots/01_bandit_vulnerable.png)
![Semgrep scan](../screenshots/02_semgrep.png)

## 4. Findings Summary

| ID | Vulnerability | OWASP | File:Line | Severity | Detected by |
|----|---------------|-------|-----------|----------|-------------|
| V-01 | SQL Injection (login) | A03 Injection | app_vulnerable.py:81 | **Critical** | Bandit B608, Manual |
| V-02 | OS Command Injection (ping) | A03 Injection | app_vulnerable.py:108 | **Critical** | Bandit B602, Manual |
| V-03 | Code Injection via `eval()` | A03 Injection | app_vulnerable.py:121 | **Critical** | Bandit B307, Manual |
| V-04 | Debug mode enabled | A05 Misconfiguration | app_vulnerable.py:157 | **High** | Bandit B201 |
| V-05 | Weak password hashing (MD5) | A02 Crypto Failures | app_vulnerable.py:59, 79 | **High** | Bandit B324 |
| V-06 | Insecure file upload | A04 Insecure Design | app_vulnerable.py:148 | **High** | Manual |
| V-07 | Path Traversal (file download) | A01 Broken Access Control | app_vulnerable.py:130 | **High** | Manual |
| V-08 | IDOR / missing auth on profile | A01 Broken Access Control | app_vulnerable.py:135-141 | **High** | Manual |
| V-09 | Reflected XSS (search) | A03 Injection | app_vulnerable.py:100 | **Medium** | Manual |
| V-10 | Template injection in login message | A03 Injection | app_vulnerable.py:88-93 | **Medium** | Manual |
| V-11 | Hardcoded secret key | A02 / A05 | app_vulnerable.py:24 | **Medium** | Bandit B105 |
| V-12 | Password hash leaked in API response | A02 Crypto Failures | app_vulnerable.py:139 | **Medium** | Manual |
| V-13 | No brute-force protection / CSRF / security headers | A07 Auth Failures | login, upload | **Medium** | Manual |

Bandit totals (vulnerable): High = 3, Medium = 2, Low = 2+. Bandit ne sirf ~8 issues pakde; baqi (XSS, IDOR, traversal, upload) **sirf manual review se** mile – yeh static tools ki limitation dikhata hai.

## 5. Detailed Findings & Remediation

### V-01 SQL Injection (Critical)
**Vulnerable code (line 81):**
```python
query = f"SELECT id, username, role FROM users WHERE username='{u}' AND password='{h}'"
```
**Proof of Concept:** username `admin'--`, password kuch bhi → admin login bypass.  
**Impact:** authentication bypass, data theft.  
**Fix:**
```python
row = get_db().execute(
    "SELECT id, username, role, password FROM users WHERE username = ?", (u,)
).fetchone()
```
![SQLi PoC](../screenshots/03_sqli_poc.png)

### V-02 OS Command Injection (Critical)
**Vulnerable:** `subprocess.check_output("ping -c 1 " + host, shell=True)`  
**PoC:** `/ping?host=127.0.0.1;whoami` → extra command chal jati hai.  
**Fix:** input validation (regex) + list arguments, `shell=False`:
```python
subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=10)
```
![Command injection PoC](../screenshots/04_cmdi_poc.png)

### V-03 Code Injection via eval() (Critical)
**Vulnerable:** `eval(expr)`  
**PoC:** `/calc?expr=__import__('os').getcwd()`  
**Fix:** AST-based whitelist evaluator (`safe_eval`) jo sirf numbers aur `+ - * /` allow karta hai.

### V-04 Debug Mode (High)
**Vulnerable:** `app.run(debug=True)` → Werkzeug debugger se code execution ka khatra.  
**Fix:** `debug=False`; production mein Gunicorn/uWSGI + reverse proxy.

### V-05 Weak Password Hashing (High)
**Vulnerable:** `hashlib.md5(p.encode()).hexdigest()` (fast, unsalted → rainbow tables).  
**Fix:** `generate_password_hash()` / `check_password_hash()` (salted scrypt/PBKDF2); ideal: Argon2/bcrypt.

### V-06 Insecure File Upload (High)
**Vulnerable:** `f.save(os.path.join(UPLOAD_DIR, f.filename))` – koi extension/size/name check nahi.  
**Fix:** extension allowlist, `secure_filename()`, random UUID name, `MAX_CONTENT_LENGTH`, login + CSRF token.

### V-07 Path Traversal (High)
**PoC:** `/file?name=../app_vulnerable.py` → source code download ho jata hai.  
**Fix:** `send_from_directory(FILES_DIR, name)` (traversal par 404).
![Traversal PoC](../screenshots/05_traversal_poc.png)

### V-08 IDOR / Missing Authorization (High)
**PoC:** bina login `/profile/1`, `/profile/2` … sab users ka data.  
**Fix:** login required + `session["uid"] == uid` ya role admin; password hash response se hata diya.

### V-09 / V-10 XSS & Template Injection (Medium)
**PoC:** `/search?q=<script>alert(1)</script>`  
**Fix:** user input ko template ke andar concatenate/f-string na karein; variable pass karein (`{{ q }}`) taake Jinja2 autoescape kare.
![XSS PoC](../screenshots/06_xss_poc.png)

### V-11 Hardcoded Secret (Medium)
**Fix:** `os.environ.get("APP_SECRET_KEY")`; `.env` ko `.gitignore` mein rakhein.

### V-13 Missing Hardening (Medium)
**Fix:** login attempt limiting, CSRF token, secure cookie flags (`HttpOnly`, `SameSite`, `Secure`), security headers (CSP, X-Frame-Options, X-Content-Type-Options).

## 6. Verification (Before vs After)

| Test | Vulnerable | Secure |
|------|-----------|--------|
| `admin'--` login | Bypass ✅ (vulnerable) | Blocked |
| `<script>` in search | Executes | Escaped |
| `;echo PWNED` in ping | Executes | 400 Invalid host |
| `eval` payload | Executes | 400 Invalid expression |
| `../` file download | File leaked | 404 |
| `/profile/1` bina login | Data leaked | 401 |

**Bandit (secure):** High = 0, Medium = 0, Low = 3 (B404, B603, B607 – `subprocess` ka use; input regex se validated, `shell=False`, isliye *accepted risk / false positive*).

![Bandit scan - secure](../screenshots/07_bandit_secure.png)

## 7. Secure Coding Best Practices
1. Saari input validate karein (allowlist) aur output encode karein.
2. Parameterized queries / ORM; kabhi string concatenation nahi.
3. `eval`, `exec`, `shell=True`, `pickle` untrusted data par avoid karein.
4. Passwords: Argon2/bcrypt/scrypt; kabhi MD5/SHA1/plaintext nahi.
5. Secrets environment variables / secret manager mein.
6. Least privilege + authentication/authorization har endpoint par.
7. File uploads: type, size, name check; web root se bahar store karein.
8. Debug off, HTTPS, security headers, secure cookies.
9. Dependencies update + `pip-audit`; CI/CD mein Bandit/Semgrep.
10. Peer code review aur security testing development ka hissa banayein.

## 8. Conclusion
Static analysis ne ~8 issues pakde jabke manual review se 13 vulnerabilities mile. Dono methods ko mila kar use karna zaroori hai. Secure version mein sab critical/high issues fix hue aur Bandit ke High/Medium findings zero ho gaye.

## 9. References
- OWASP Top 10 (2021) – https://owasp.org/Top10/
- OWASP Cheat Sheet Series – https://cheatsheetseries.owasp.org/
- Bandit – https://bandit.readthedocs.io/
- Semgrep – https://semgrep.dev/docs/
- Flask Security docs – https://flask.palletsprojects.com/en/stable/web-security/
