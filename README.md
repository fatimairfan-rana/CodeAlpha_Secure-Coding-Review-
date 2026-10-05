# CodeAlpha Task 3 – Secure Coding Review

Python/Flask app ka security audit: vulnerable version → scan → findings → secure version.

## Structure
```
app.py                      launcher (python app.py vulnerable|secure)
vulnerable/app_vulnerable.py  jaan boojh kar vulnerable (13 issues)
secure/app_secure.py          fixed version
screenshots/                  tool output + PoC screenshots
report/Secure_Coding_Review.md  final report
```

## Setup
```bash
python -m venv venv
venv\Scripts\activate          # Windows   (Linux/Mac: source venv/bin/activate)
pip install -r requirements.txt
pip install semgrep            # optional
```

## Run
```bash
python app.py vulnerable   # http://127.0.0.1:5000
python app.py secure       # http://127.0.0.1:5001
```

## Scan
```bash
bandit -r vulnerable
bandit -r secure
semgrep --config=auto vulnerable/
pip-audit -r requirements.txt
```

## Test payloads (sirf local vulnerable app par)
| Bug | Payload |
|-----|---------|
| SQLi | login: username `admin'--`, password any |
| XSS | `/search?q=<script>alert(1)</script>` |
| Cmd injection | `/ping?host=127.0.0.1;whoami` (Windows: `127.0.0.1 & whoami`) |
| eval | `/calc?expr=__import__('os').getcwd()` |
| Traversal | `/file?name=../app_vulnerable.py` |
| IDOR | `/profile/1`, `/profile/2` bina login |

> **Warning:** Vulnerable app sirf educational use ke liye hai. Kabhi internet par deploy na karein.
