#!/usr/bin/env bash
set -euo pipefail

# This script:
#   1) Initializes a git repo (if needed)
#   2) Creates a couple of "case branches" with vulnerable + safe examples
#   3) Prints commands to create/push to GitHub

if ! command -v git >/dev/null 2>&1; then
  echo "ERROR: git is not installed or not on PATH." >&2
  exit 1
fi

# Ensure we're in the repo root (where README.md lives)
if [ ! -f "README.md" ]; then
  echo "ERROR: Run this script from the repository root (README.md not found)." >&2
  exit 1
fi

# Init repo if needed
if [ ! -d ".git" ]; then
  git init -b main
fi

# Ensure initial commit exists
if ! git rev-parse --verify HEAD >/dev/null 2>&1; then
  git add README.md .gitignore scripts/bootstrap_branches.sh
  git commit -m "Initial calibration suite scaffold"
fi

# Helper: write files for a branch, then commit
create_branch() {
  local branch="$1"
  local msg="$2"

  if git show-ref --verify --quiet "refs/heads/${branch}"; then
    echo "[skip] branch already exists: ${branch}"
    return 0
  fi

  echo "[make] ${branch}"
  git switch -c "${branch}" >/dev/null

  mkdir -p app fp_bait

  # Branch-specific files are written by the caller via heredocs.
  # We commit whatever the caller created.

  git add -A
  git commit -m "${msg}" >/dev/null

  git switch main >/dev/null
}

# ---------------------------------------------------------------------------
# Branch: OWASP 2021 A07 (Identification & Authentication Failures)
# ---------------------------------------------------------------------------
make_a07() {
  local branch="owasp2021-a07-calibration-sample"

  # Create branch first (empty commit content will be added before commit)
  git switch -c "${branch}" >/dev/null

  rm -rf app fp_bait
  mkdir -p app fp_bait

  cat > app/README_CASE.md <<'TXT'
A07 calibration case branch

Contains:
- 10 vulnerable examples (with DURINN_GT markers)
- Safe twins and FP-bait examples
TXT

  # 1) Hardcoded password (vuln) + safe env variant
  cat > app/a07_vuln_01_hardcoded_password.py <<'PY'
# DURINN_GT id=a07_01_hardcoded_password track=sast set=core owasp=A07
DB_PASSWORD = "DURINN_TEST_SECRET_DO_NOT_USE"

def connect():
    # pretend to use it
    return f"connecting with {DB_PASSWORD[:3]}***"
PY

  cat > app/a07_safe_01_env_password.py <<'PY'
import os

DB_PASSWORD = os.environ.get("DB_PASSWORD", "")

def connect():
    return "connecting" if DB_PASSWORD else "no password set"
PY

  # 2) Hardcoded API key (vuln) + safe env variant
  cat > app/a07_vuln_02_hardcoded_api_key.py <<'PY'
# DURINN_GT id=a07_02_hardcoded_api_key track=sast set=core owasp=A07
API_KEY = "DURINN_TEST_API_KEY_DO_NOT_USE"

def call_service():
    return {"Authorization": f"Bearer {API_KEY}"}
PY

  cat > app/a07_safe_02_env_api_key.py <<'PY'
import os

API_KEY = os.environ.get("API_KEY", "")

def call_service():
    return {"Authorization": "Bearer ***"} if API_KEY else {}
PY

  # 3) Hardcoded JWT secret (vuln) + safe generated secret
  cat > app/a07_vuln_03_hardcoded_jwt_secret.py <<'PY'
# DURINN_GT id=a07_03_hardcoded_jwt_secret track=sast set=core owasp=A07
JWT_SECRET = "DURINN_TEST_JWT_SECRET_DO_NOT_USE"

def sign(payload: str) -> str:
    # toy signature
    return payload + "." + JWT_SECRET
PY

  cat > app/a07_safe_03_runtime_secret.py <<'PY'
import secrets

JWT_SECRET = secrets.token_urlsafe(32)

def sign(payload: str) -> str:
    return payload + "." + JWT_SECRET
PY

  # 4) Improper certificate validation (vuln) + safe default context
  cat > app/a07_vuln_04_insecure_tls.py <<'PY'
# DURINN_GT id=a07_04_insecure_tls track=sast set=core owasp=A07
import ssl
import urllib.request

ctx = ssl._create_unverified_context()
urllib.request.urlopen("https://example.com", context=ctx)
PY

  cat > app/a07_safe_04_secure_tls.py <<'PY'
import ssl
import urllib.request

ctx = ssl.create_default_context()
urllib.request.urlopen("https://example.com", context=ctx)
PY

  # 5) Django password validators disabled (vuln) + enabled (safe)
  cat > app/a07_vuln_05_django_password_validators_disabled.py <<'PY'
# DURINN_GT id=a07_05_django_password_validators_disabled track=sast set=core owasp=A07
# This is a minimal settings-like file (no Django dependency required)
AUTH_PASSWORD_VALIDATORS = []
PY

  cat > app/a07_safe_05_django_password_validators_enabled.py <<'PY'
# Minimal settings-like file
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
]
PY

  # 6) Insecure basic auth placeholder (vuln) + safe placeholder
  cat > app/a07_vuln_06_basic_auth_over_http.py <<'PY'
# DURINN_GT id=a07_06_basic_auth_over_http track=sast set=core owasp=A07
# Example only; not executed.
LOGIN_URL = "http://example.com/login"  # HTTP, not HTTPS
PY

  cat > app/a07_safe_06_basic_auth_over_https.py <<'PY'
LOGIN_URL = "https://example.com/login"
PY

  # 7) Weak token generation (vuln) + safe secrets
  cat > app/a07_vuln_07_weak_token_random.py <<'PY'
# DURINN_GT id=a07_07_weak_token_random track=sast set=core owasp=A07
import random

def make_token() -> str:
    # Predictable token generation
    return str(random.randint(100000, 999999))
PY

  cat > app/a07_safe_07_strong_token_secrets.py <<'PY'
import secrets

def make_token() -> str:
    return secrets.token_hex(16)
PY

  # 8) Hardcoded credential-like string in config (vuln) + safe env
  cat > app/a07_vuln_08_hardcoded_config_password.py <<'PY'
# DURINN_GT id=a07_08_hardcoded_config_password track=sast set=core owasp=A07
CONFIG = {
    "db_user": "app",
    "db_password": "DURINN_TEST_SECRET_DO_NOT_USE",
}
PY

  cat > app/a07_safe_08_env_config_password.py <<'PY'
import os

CONFIG = {
    "db_user": "app",
    "db_password": os.environ.get("DB_PASSWORD", ""),
}
PY

  # 9) Insecure auth bypass stub (vuln) + safe stub
  cat > app/a07_vuln_09_auth_bypass_stub.py <<'PY'
# DURINN_GT id=a07_09_auth_bypass_stub track=sast set=core owasp=A07
# NOTE: This is intentionally simplistic to create a detectable pattern.

def is_authenticated(user) -> bool:
    return True  # auth bypass
PY

  cat > app/a07_safe_09_auth_check_stub.py <<'PY'

def is_authenticated(user) -> bool:
    return bool(getattr(user, "is_authenticated", False))
PY

  # 10) Hardcoded admin credentials (vuln) + safe env
  cat > app/a07_vuln_10_hardcoded_admin_creds.py <<'PY'
# DURINN_GT id=a07_10_hardcoded_admin_creds track=sast set=core owasp=A07
ADMIN_USER = "admin"
ADMIN_PASSWORD = "DURINN_TEST_SECRET_DO_NOT_USE"
PY

  cat > app/a07_safe_10_admin_creds_env.py <<'PY'
import os

ADMIN_USER = os.environ.get("ADMIN_USER", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
PY

  # FP-bait: safe examples that might still trigger some scanners
  cat > fp_bait/a07_bait_strings_not_secrets.py <<'PY'
# These are not used as credentials, but look like them.
EXAMPLE_PASSWORD = "password"  # documentation string
EXAMPLE_API_KEY = "xxxxxxxxxxxxxxxx"  # placeholder
PY

  cat > fp_bait/a07_bait_tls_context_object.py <<'PY'
import ssl

# Create a context object but never use it to make requests.
ctx = ssl.create_default_context()
PY

  git add -A
  git commit -m "Add A07 calibration sample case" >/dev/null
  git switch main >/dev/null
}

# ---------------------------------------------------------------------------
# Branch: OWASP 2021 A03 (Injection)
# ---------------------------------------------------------------------------
make_a03() {
  local branch="owasp2021-a03-calibration-sample"

  git switch -c "${branch}" >/dev/null

  rm -rf app fp_bait
  mkdir -p app fp_bait

  cat > app/README_CASE.md <<'TXT'
A03 calibration case branch

Contains:
- 10 vulnerable examples (with DURINN_GT markers)
- Safe twins and FP-bait examples
TXT

  # 1) SQL injection via string concat
  cat > app/a03_vuln_01_sqli_concat.py <<'PY'
# DURINN_GT id=a03_01_sqli_concat track=sast set=core owasp=A03
import sqlite3

def vuln(user_input: str) -> None:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + user_input + "'")
PY

  cat > app/a03_safe_01_sqli_param.py <<'PY'
import sqlite3

def safe(user_input: str) -> None:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (user_input,))
PY

  # 2) SQL injection via f-string
  cat > app/a03_vuln_02_sqli_fstring.py <<'PY'
# DURINN_GT id=a03_02_sqli_fstring track=sast set=core owasp=A03
import sqlite3

def vuln(user_input: str) -> None:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{user_input}'")
PY

  cat > app/a03_safe_02_sqli_param.py <<'PY'
import sqlite3

def safe(user_input: str) -> None:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (user_input,))
PY

  # 3) Command injection via os.system
  cat > app/a03_vuln_03_cmdinj_os_system.py <<'PY'
# DURINN_GT id=a03_03_cmdinj_os_system track=sast set=core owasp=A03
import os

def vuln(host: str) -> None:
    os.system("ping -c 1 " + host)
PY

  cat > app/a03_safe_03_cmd_no_shell.py <<'PY'
import subprocess

def safe(host: str) -> None:
    subprocess.run(["ping", "-c", "1", host], check=False)
PY

  # 4) Command injection via subprocess with shell=True
  cat > app/a03_vuln_04_cmdinj_subprocess_shell.py <<'PY'
# DURINN_GT id=a03_04_cmdinj_subprocess_shell track=sast set=core owasp=A03
import subprocess

def vuln(host: str) -> None:
    subprocess.run("ping -c 1 " + host, shell=True, check=False)
PY

  cat > app/a03_safe_04_cmdinj_subprocess_no_shell.py <<'PY'
import subprocess

def safe(host: str) -> None:
    subprocess.run(["ping", "-c", "1", host], shell=False, check=False)
PY

  # 5) Code injection via eval
  cat > app/a03_vuln_05_eval_user_input.py <<'PY'
# DURINN_GT id=a03_05_eval_user_input track=sast set=core owasp=A03

def vuln(expr: str):
    return eval(expr)
PY

  cat > app/a03_safe_05_eval_literal.py <<'PY'
# Safe: no user input

def safe():
    return eval("1 + 1")
PY

  # 6) Code injection via exec
  cat > app/a03_vuln_06_exec_user_input.py <<'PY'
# DURINN_GT id=a03_06_exec_user_input track=sast set=core owasp=A03

def vuln(code: str) -> None:
    exec(code)
PY

  cat > app/a03_safe_06_no_exec.py <<'PY'
# Safe: do not execute dynamic code

def safe(code: str) -> None:
    _ = code  # treat as data
PY

  # 7) Unsafe deserialization (pickle)
  cat > app/a03_vuln_07_pickle_loads.py <<'PY'
# DURINN_GT id=a03_07_pickle_loads track=sast set=core owasp=A03
import pickle

def vuln(blob: bytes):
    return pickle.loads(blob)
PY

  cat > app/a03_safe_07_json_loads.py <<'PY'
import json

def safe(text: str):
    return json.loads(text)
PY

  # 8) Regex DoS-ish pattern (can be noisy)
  cat > app/a03_vuln_08_redos_unbounded.py <<'PY'
# DURINN_GT id=a03_08_redos_unbounded track=sast set=core owasp=A03
import re

def vuln(s: str) -> bool:
    return bool(re.match(r"(a+)+$", s))
PY

  cat > app/a03_safe_08_redos_bounded.py <<'PY'
import re

def safe(s: str) -> bool:
    # Bound input length defensively
    s2 = s[:200]
    return bool(re.match(r"a+$", s2))
PY

  # 9) Path injection / traversal-ish file open
  cat > app/a03_vuln_09_file_open_user_input.py <<'PY'
# DURINN_GT id=a03_09_file_open_user_input track=sast set=core owasp=A03

def vuln(filename: str) -> str:
    with open(filename, "r", encoding="utf-8") as f:
        return f.read()
PY

  cat > app/a03_safe_09_file_open_allowlist.py <<'PY'
from pathlib import Path

ALLOWED = {"README.txt", "about.txt"}

def safe(filename: str) -> str:
    if filename not in ALLOWED:
        raise ValueError("not allowed")
    p = Path(filename)
    return p.read_text(encoding="utf-8")
PY

  # 10) XML external entity-ish parsing
  cat > app/a03_vuln_10_xml_parser_stdlib.py <<'PY'
# DURINN_GT id=a03_10_xml_parser track=sast set=core owasp=A03
import xml.etree.ElementTree as ET

def vuln(xml_text: str):
    return ET.fromstring(xml_text)
PY

  cat > app/a03_safe_10_xml_defused.py <<'PY'
# Safe placeholder: avoid parsing untrusted XML in the first place

def safe(xml_text: str):
    _ = xml_text
    return None
PY

  # FP-bait examples (safe-ish but may trigger)
  cat > fp_bait/a03_bait_logging_query.py <<'PY'
import sqlite3

def safe(user_input: str) -> None:
    query = "SELECT * FROM users WHERE name = ?"
    print("running query:", query, "with", user_input)  # logging only
    conn = sqlite3.connect(":memory:")
    conn.execute(query, (user_input,))
PY

  cat > fp_bait/a03_bait_subprocess_list.py <<'PY'
import subprocess

def safe(host: str) -> None:
    # List args, no shell
    subprocess.run(["echo", host], shell=False, check=False)
PY

  git add -A
  git commit -m "Add A03 calibration sample case" >/dev/null
  git switch main >/dev/null
}

make_a07
make_a03

cat <<'OUT'

✅ Done. Local branches created.

Next steps to push to GitHub:

Option A (GitHub web UI):
  1) Create an empty repo on GitHub (no README).
  2) Then run:
       git remote add origin <YOUR_REPO_URL>
       git push -u origin main
       git push origin --all

Option B (GitHub CLI):
  gh repo create <org>/<name> --public --source . --remote origin --push
  git push origin --all

OUT
