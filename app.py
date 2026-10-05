"""
Launcher: dono versions ko ek hi command se chalane ke liye.

Usage:
    python app.py vulnerable    -> http://127.0.0.1:5000  (JAAN BOOJH KAR VULNERABLE)
    python app.py secure        -> http://127.0.0.1:5001  (FIXED VERSION)
"""
import os
import runpy
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
TARGETS = {
    "vulnerable": os.path.join(BASE, "vulnerable", "app_vulnerable.py"),
    "secure": os.path.join(BASE, "secure", "app_secure.py"),
}

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "secure"
    if mode not in TARGETS:
        sys.exit("Usage: python app.py [vulnerable|secure]")
    runpy.run_path(TARGETS[mode], run_name="__main__")
