#!/usr/bin/env bash
set -euo pipefail

# This script:
#   1) Initializes a git repo (if needed)
#   2) Creates "case branches" (branch-per-case) for OWASP 2021 categories
#   3) Each branch includes:
#        - 10 vulnerable examples (with DURINN_GT markers)
#        - Safe twins and FP-bait examples
#   4) Prints commands to push to GitHub

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

branch_exists() {
  local branch="$1"
  if git show-ref --verify --quiet "refs/heads/${branch}"; then
    return 0
  fi
  # If a remote exists, also consider remote branches (so we don't fail on reruns)
  if git show-ref --verify --quiet "refs/remotes/origin/${branch}"; then
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# Branch: OWASP 2021 A01 (Broken Access Control)
# ---------------------------------------------------------------------------
make_a01() {
  local branch="owasp2021-a01-calibration-sample"
  if branch_exists "${branch}"; then
    echo "[skip] branch already exists: ${branch}"
    return 0
  fi

  echo "[make] ${branch}"
  git switch -c "${branch}" >/dev/null

  rm -rf app fp_bait
  mkdir -p app fp_bait

  cat > app/README_CASE.md <<'TXT'
A01 calibration case branch (Broken Access Control)

Contains:
- 10 vulnerable examples (with DURINN_GT markers)
- Safe twins and FP-bait examples
TXT

  # 1) Open redirect
  cat > app/a01_vuln_01_open_redirect.py <<'PY'
# DURINN_GT id=a01_01_open_redirect track=sast set=core owasp=A01
from flask import redirect, request

def vuln():
    next_url = request.args.get("next", "/")
    return redirect(next_url)
PY

  cat > app/a01_safe_01_open_redirect_allowlist.py <<'PY'
from flask import redirect, request

ALLOWED = {"/", "/home", "/dashboard"}

def safe():
    next_url = request.args.get("next", "/")
    if next_url not in ALLOWED:
        next_url = "/"
    return redirect(next_url)
PY

  # 2) Path traversal (open user-controlled path)
  cat > app/a01_vuln_02_path_traversal_open.py <<'PY'
# DURINN_GT id=a01_02_path_traversal_open track=sast set=core owasp=A01

def vuln(user_path: str) -> str:
    with open(user_path, "r", encoding="utf-8") as f:
        return f.read()
PY

  cat > app/a01_safe_02_path_traversal_allowlist.py <<'PY'
from pathlib import Path

ALLOWED = {"README.txt", "about.txt"}

def safe(user_path: str) -> str:
    if user_path not in ALLOWED:
        raise ValueError("not allowed")
    return Path(user_path).read_text(encoding="utf-8")
PY

  # 3) Binding to all interfaces (socket)
  cat > app/a01_vuln_03_bind_all_interfaces_socket.py <<'PY'
# DURINN_GT id=a01_03_bind_all_interfaces_socket track=sast set=core owasp=A01
import socket

def vuln(port: int = 8080) -> None:
    s = socket.socket()
    s.bind(("0.0.0.0", port))
PY

  cat > app/a01_safe_03_bind_localhost_socket.py <<'PY'
import socket

def safe(port: int = 8080) -> None:
    s = socket.socket()
    s.bind(("127.0.0.1", port))
PY

  # 4) Binding to all interfaces (Flask)
  cat > app/a01_vuln_04_bind_all_interfaces_flask.py <<'PY'
# DURINN_GT id=a01_04_bind_all_interfaces_flask track=sast set=core owasp=A01
from flask import Flask

app = Flask(__name__)

def vuln():
    # Example only; not executed.
    app.run(host="0.0.0.0", port=5000)
PY

  cat > app/a01_safe_04_bind_localhost_flask.py <<'PY'
from flask import Flask

app = Flask(__name__)

def safe():
    app.run(host="127.0.0.1", port=5000)
PY

  # 5) CSRF protection disabled (common config foot-gun)
  cat > app/a01_vuln_05_csrf_disabled.py <<'PY'
# DURINN_GT id=a01_05_csrf_disabled track=sast set=core owasp=A01
# Example Flask-WTF style configuration
WTF_CSRF_ENABLED = False
PY

  cat > app/a01_safe_05_csrf_enabled.py <<'PY'
WTF_CSRF_ENABLED = True
PY

  # 6) Missing authorization check (IDOR-ish)
  cat > app/a01_vuln_06_idor_no_owner_check.py <<'PY'
# DURINN_GT id=a01_06_idor_no_owner_check track=sast set=core owasp=A01

def get_invoice(current_user_id: str, invoice_id: str) -> str:
    # BUG: no ownership check
    return f"invoice:{invoice_id} for user:{current_user_id}"
PY

  cat > app/a01_safe_06_idor_owner_check.py <<'PY'

def get_invoice(current_user_id: str, invoice_id: str, owner_user_id: str) -> str:
    if current_user_id != owner_user_id:
        raise PermissionError("forbidden")
    return f"invoice:{invoice_id} for user:{current_user_id}"
PY

  # 7) Authorization controlled by client input
  cat > app/a01_vuln_07_role_from_header.py <<'PY'
# DURINN_GT id=a01_07_role_from_header track=sast set=core owasp=A01

def is_admin(headers: dict) -> bool:
    # BUG: trust client-controlled header
    return headers.get("X-Role") == "admin"
PY

  cat > app/a01_safe_07_role_from_server_session.py <<'PY'

def is_admin(user) -> bool:
    # safe: server-side role
    return bool(getattr(user, "is_admin", False))
PY

  # 8) Fail-open access control (exception => allow)
  cat > app/a01_vuln_08_fail_open_authz.py <<'PY'
# DURINN_GT id=a01_08_fail_open_authz track=sast set=core owasp=A01

def has_access(user, resource) -> bool:
    try:
        return bool(user and resource and user.id == resource.owner_id)
    except Exception:
        return True  # BUG: fail open
PY

  cat > app/a01_safe_08_fail_closed_authz.py <<'PY'

def has_access(user, resource) -> bool:
    try:
        return bool(user and resource and user.id == resource.owner_id)
    except Exception:
        return False
PY

  # 9) Using assert for security check (can be stripped with -O)
  cat > app/a01_vuln_09_assert_for_access_control.py <<'PY'
# DURINN_GT id=a01_09_assert_for_access_control track=sast set=core owasp=A01

def delete_user(current_user, target_user_id: str) -> None:
    # BUG: asserts may be disabled in optimized mode
    assert current_user.is_admin
    _ = target_user_id
PY

  cat > app/a01_safe_09_explicit_access_control.py <<'PY'

def delete_user(current_user, target_user_id: str) -> None:
    if not getattr(current_user, "is_admin", False):
        raise PermissionError("forbidden")
    _ = target_user_id
PY

  # 10) Path traversal via join without normalization
  cat > app/a01_vuln_10_path_join_user_input.py <<'PY'
# DURINN_GT id=a01_10_path_join_user_input track=sast set=core owasp=A01
import os

BASE = "/var/app/data"

def vuln(name: str) -> str:
    p = os.path.join(BASE, name)
    with open(p, "r", encoding="utf-8") as f:
        return f.read()
PY

  cat > app/a01_safe_10_path_join_normalize.py <<'PY'
import os

BASE = "/var/app/data"
ALLOWED = {"readme.txt", "about.txt"}

def safe(name: str) -> str:
    if name not in ALLOWED:
        raise ValueError("not allowed")
    p = os.path.join(BASE, name)
    with open(p, "r", encoding="utf-8") as f:
        return f.read()
PY

  # FP-bait: safe but scary-looking
  cat > fp_bait/a01_bait_redirect_allowlist.py <<'PY'
from flask import redirect

# Safe: only redirects to known-safe internal paths
ALLOWED = {"/", "/home"}

def safe(next_url: str):
    if next_url not in ALLOWED:
        next_url = "/"
    return redirect(next_url)
PY

  cat > fp_bait/a01_bait_path_normalization.py <<'PY'
from pathlib import Path

# Safe: normalizes and enforces base directory
BASE = Path("/var/app/data").resolve()

def safe(user_path: str) -> str:
    p = (BASE / user_path).resolve()
    if not str(p).startswith(str(BASE)):
        raise ValueError("blocked")
    return str(p)
PY

  git add -A
  git commit -m "Add A01 calibration sample case" >/dev/null
  git switch main >/dev/null
}

# ---------------------------------------------------------------------------
# Branch: OWASP 2021 A02 (Cryptographic Failures)
# ---------------------------------------------------------------------------
make_a02() {
  local branch="owasp2021-a02-calibration-sample"
  if branch_exists "${branch}"; then
    echo "[skip] branch already exists: ${branch}"
    return 0
  fi

  echo "[make] ${branch}"
  git switch -c "${branch}" >/dev/null

  rm -rf app fp_bait
  mkdir -p app fp_bait

  cat > app/README_CASE.md <<'TXT'
A02 calibration case branch (Cryptographic Failures)

Contains:
- 10 vulnerable examples (with DURINN_GT markers)
- Safe twins and FP-bait examples
TXT

  # 1) MD5 password hash
  cat > app/a02_vuln_01_md5_password_hash.py <<'PY'
# DURINN_GT id=a02_01_md5_password_hash track=sast set=core owasp=A02
import hashlib

def vuln(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()
PY

  cat > app/a02_safe_01_pbkdf2_password_hash.py <<'PY'
import hashlib
import os

def safe(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return dk.hex()
PY

  # 2) SHA1 password hash
  cat > app/a02_vuln_02_sha1_password_hash.py <<'PY'
# DURINN_GT id=a02_02_sha1_password_hash track=sast set=core owasp=A02
import hashlib

def vuln(password: str) -> str:
    return hashlib.sha1(password.encode()).hexdigest()
PY

  cat > app/a02_safe_02_pbkdf2_password_hash.py <<'PY'
import hashlib
import os

def safe(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return dk.hex()
PY

  # 3) Fast hash used for password storage (no salt)
  cat > app/a02_vuln_03_sha256_fast_hash_password.py <<'PY'
# DURINN_GT id=a02_03_sha256_fast_hash_password track=sast set=core owasp=A02
import hashlib

def vuln(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()
PY

  cat > app/a02_safe_03_pbkdf2_with_salt.py <<'PY'
import hashlib
import os

def safe(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 300_000)
    return salt.hex() + ":" + dk.hex()
PY

  # 4) Hardcoded crypto key
  cat > app/a02_vuln_04_hardcoded_crypto_key.py <<'PY'
# DURINN_GT id=a02_04_hardcoded_crypto_key track=sast set=core owasp=A02
KEY = b"DURINN_TEST_KEY_16BYTES"  # hardcoded key

def vuln(data: bytes) -> bytes:
    # toy XOR "encryption" (pattern is the hardcoded key)
    return bytes([b ^ KEY[i % len(KEY)] for i, b in enumerate(data)])
PY

  cat > app/a02_safe_04_runtime_crypto_key.py <<'PY'
import os

KEY = os.urandom(32)

def safe(data: bytes) -> bytes:
    return bytes([b ^ KEY[i % len(KEY)] for i, b in enumerate(data)])
PY

  # 5) Hardcoded IV
  cat > app/a02_vuln_05_hardcoded_iv.py <<'PY'
# DURINN_GT id=a02_05_hardcoded_iv track=sast set=core owasp=A02
IV = b"\x00" * 16

def vuln() -> bytes:
    return IV
PY

  cat > app/a02_safe_05_random_iv.py <<'PY'
import os

def safe() -> bytes:
    return os.urandom(16)
PY

  # 6) Insecure random for token
  cat > app/a02_vuln_06_insecure_random_token.py <<'PY'
# DURINN_GT id=a02_06_insecure_random_token track=sast set=core owasp=A02
import random

def vuln() -> str:
    return str(random.randint(100000, 999999))
PY

  cat > app/a02_safe_06_secrets_token.py <<'PY'
import secrets

def safe() -> str:
    return secrets.token_hex(16)
PY

  # 7) Deprecated TLS version
  cat > app/a02_vuln_07_tlsv1_context.py <<'PY'
# DURINN_GT id=a02_07_tlsv1_context track=sast set=core owasp=A02
import ssl

def vuln():
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)
PY

  cat > app/a02_safe_07_default_tls_context.py <<'PY'
import ssl

def safe():
    return ssl.create_default_context()
PY

  # 8) Non-constant time secret compare
  cat > app/a02_vuln_08_secret_compare_equals.py <<'PY'
# DURINN_GT id=a02_08_secret_compare_equals track=sast set=core owasp=A02

def vuln(sig: str, expected: str) -> bool:
    return sig == expected
PY

  cat > app/a02_safe_08_secret_compare_digest.py <<'PY'
import hmac

def safe(sig: str, expected: str) -> bool:
    return hmac.compare_digest(sig, expected)
PY

  # 9) Hardcoded JWT secret
  cat > app/a02_vuln_09_hardcoded_jwt_secret.py <<'PY'
# DURINN_GT id=a02_09_hardcoded_jwt_secret track=sast set=core owasp=A02
JWT_SECRET = "DURINN_TEST_JWT_SECRET_DO_NOT_USE"

def vuln(payload: str) -> str:
    return payload + "." + JWT_SECRET
PY

  cat > app/a02_safe_09_env_jwt_secret.py <<'PY'
import os

JWT_SECRET = os.environ.get("JWT_SECRET", "")

def safe(payload: str) -> str:
    return payload + "." + (JWT_SECRET or "<missing>")
PY

  # 10) Weak key length constant
  cat > app/a02_vuln_10_weak_key_length.py <<'PY'
# DURINN_GT id=a02_10_weak_key_length track=sast set=core owasp=A02
# Example only
RSA_KEY_BITS = 1024
PY

  cat > app/a02_safe_10_strong_key_length.py <<'PY'
RSA_KEY_BITS = 2048
PY

  # FP-bait
  cat > fp_bait/a02_bait_hash_for_integrity_not_password.py <<'PY'
import hashlib

def safe(file_bytes: bytes) -> str:
    # Not a password hash; used for integrity checking.
    return hashlib.sha256(file_bytes).hexdigest()
PY

  cat > fp_bait/a02_bait_compare_digest.py <<'PY'
import hmac

def safe(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
PY

  git add -A
  git commit -m "Add A02 calibration sample case" >/dev/null
  git switch main >/dev/null
}

# ---------------------------------------------------------------------------
# Branch: OWASP 2021 A03 (Injection)
# ---------------------------------------------------------------------------
make_a03() {
  local branch="owasp2021-a03-calibration-sample"
  if branch_exists "${branch}"; then
    echo "[skip] branch already exists: ${branch}"
    return 0
  fi

  echo "[make] ${branch}"
  git switch -c "${branch}" >/dev/null

  rm -rf app fp_bait
  mkdir -p app fp_bait

  cat > app/README_CASE.md <<'TXT'
A03 calibration case branch (Injection)

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

# ---------------------------------------------------------------------------
# Branch: OWASP 2021 A04 (Insecure Design)
# ---------------------------------------------------------------------------
make_a04() {
  local branch="owasp2021-a04-calibration-sample"
  if branch_exists "${branch}"; then
    echo "[skip] branch already exists: ${branch}"
    return 0
  fi

  echo "[make] ${branch}"
  git switch -c "${branch}" >/dev/null

  rm -rf app fp_bait
  mkdir -p app fp_bait

  cat > app/README_CASE.md <<'TXT'
A04 calibration case branch (Insecure Design)

NOTE: Many A04 issues are "design" / business-logic flaws and may not be
consistently detected by SAST tools. This branch is still useful for:
- Measuring false negatives (what tools miss)
- Creating realistic disagreement
TXT

  # 1) Assert used for security decision
  cat > app/a04_vuln_01_assert_auth.py <<'PY'
# DURINN_GT id=a04_01_assert_auth track=sast set=core owasp=A04

def can_delete(user) -> bool:
    assert user is not None  # BUG: asserts can be stripped
    return True
PY

  cat > app/a04_safe_01_explicit_check.py <<'PY'

def can_delete(user) -> bool:
    if user is None:
        return False
    return True
PY

  # 2) Fail-open on exception
  cat > app/a04_vuln_02_fail_open.py <<'PY'
# DURINN_GT id=a04_02_fail_open track=sast set=core owasp=A04

def allow_action(user) -> bool:
    try:
        return bool(getattr(user, "can_act", False))
    except Exception:
        return True
PY

  cat > app/a04_safe_02_fail_closed.py <<'PY'

def allow_action(user) -> bool:
    try:
        return bool(getattr(user, "can_act", False))
    except Exception:
        return False
PY

  # 3) Unlimited login attempts (no throttling)
  cat > app/a04_vuln_03_no_rate_limit.py <<'PY'
# DURINN_GT id=a04_03_no_rate_limit track=sast set=core owasp=A04
MAX_LOGIN_ATTEMPTS = 10_000_000
PY

  cat > app/a04_safe_03_rate_limit.py <<'PY'
MAX_LOGIN_ATTEMPTS = 5
PY

  # 4) Predictable token design
  cat > app/a04_vuln_04_predictable_token.py <<'PY'
# DURINN_GT id=a04_04_predictable_token track=sast set=core owasp=A04
import time

def make_reset_token(user_id: str) -> str:
    # BUG: predictable token
    return f"{user_id}:{int(time.time())}"
PY

  cat > app/a04_safe_04_unpredictable_token.py <<'PY'
import secrets

def make_reset_token(user_id: str) -> str:
    _ = user_id
    return secrets.token_urlsafe(32)
PY

  # 5) Default allow-all feature flag
  cat > app/a04_vuln_05_authz_disabled_flag.py <<'PY'
# DURINN_GT id=a04_05_authz_disabled_flag track=sast set=core owasp=A04
ENFORCE_AUTHZ = False
PY

  cat > app/a04_safe_05_authz_enabled_flag.py <<'PY'
ENFORCE_AUTHZ = True
PY

  # 6) Using user input to select action with no allowlist
  cat > app/a04_vuln_06_unvalidated_action_dispatch.py <<'PY'
# DURINN_GT id=a04_06_unvalidated_action_dispatch track=sast set=core owasp=A04

def do_admin_action(action: str):
    # BUG: unvalidated action name
    fn = globals().get(action)
    if callable(fn):
        return fn()
    return None
PY

  cat > app/a04_safe_06_allowlisted_action_dispatch.py <<'PY'
ALLOWED = {"safe_action"}

def safe_action():
    return "ok"

def do_admin_action(action: str):
    if action not in ALLOWED:
        raise ValueError("not allowed")
    return safe_action()
PY

  # 7) Insecure default permissions
  cat > app/a04_vuln_07_default_admin_role.py <<'PY'
# DURINN_GT id=a04_07_default_admin_role track=sast set=core owasp=A04

def new_user_role() -> str:
    # BUG: overly permissive default
    return "admin"
PY

  cat > app/a04_safe_07_default_user_role.py <<'PY'

def new_user_role() -> str:
    return "user"
PY

  # 8) Information exposure via exception details
  cat > app/a04_vuln_08_stacktrace_to_user.py <<'PY'
# DURINN_GT id=a04_08_stacktrace_to_user track=sast set=core owasp=A04
import traceback

def handle_error() -> str:
    try:
        1 / 0
    except Exception:
        return traceback.format_exc()  # BUG: leak details
PY

  cat > app/a04_safe_08_generic_error.py <<'PY'

def handle_error() -> str:
    try:
        1 / 0
    except Exception:
        return "internal error"
PY

  # 9) Insecure reliance on client-provided user id
  cat > app/a04_vuln_09_user_id_from_request.py <<'PY'
# DURINN_GT id=a04_09_user_id_from_request track=sast set=core owasp=A04

def delete_account(request_json: dict) -> str:
    # BUG: trust client-provided user id
    user_id = request_json.get("user_id")
    return f"deleted:{user_id}"
PY

  cat > app/a04_safe_09_user_id_from_session.py <<'PY'

def delete_account(session_user_id: str) -> str:
    return f"deleted:{session_user_id}"
PY

  # 10) Missing transaction / rollback (design flaw)
  cat > app/a04_vuln_10_no_rollback.py <<'PY'
# DURINN_GT id=a04_10_no_rollback track=sast set=core owasp=A04

def transfer(balance: dict, from_id: str, to_id: str, amount: int) -> None:
    # BUG: no rollback / invariants
    balance[from_id] -= amount
    balance[to_id] += amount
PY

  cat > app/a04_safe_10_check_invariants.py <<'PY'

def transfer(balance: dict, from_id: str, to_id: str, amount: int) -> None:
    if amount <= 0:
        raise ValueError("bad amount")
    if balance.get(from_id, 0) < amount:
        raise ValueError("insufficient")
    balance[from_id] -= amount
    balance[to_id] = balance.get(to_id, 0) + amount
PY

  cat > fp_bait/a04_bait_assert_not_security.py <<'PY'
# This assert is not used for authorization; it's a developer sanity check.

def safe(x: int) -> int:
    assert x >= 0
    return x
PY

  cat > fp_bait/a04_bait_generic_error.py <<'PY'

def safe() -> str:
    return "internal error"
PY

  git add -A
  git commit -m "Add A04 calibration sample case" >/dev/null
  git switch main >/dev/null
}

# ---------------------------------------------------------------------------
# Branch: OWASP 2021 A05 (Security Misconfiguration)
# ---------------------------------------------------------------------------
make_a05() {
  local branch="owasp2021-a05-calibration-sample"
  if branch_exists "${branch}"; then
    echo "[skip] branch already exists: ${branch}"
    return 0
  fi

  echo "[make] ${branch}"
  git switch -c "${branch}" >/dev/null

  rm -rf app fp_bait
  mkdir -p app fp_bait

  cat > app/README_CASE.md <<'TXT'
A05 calibration case branch (Security Misconfiguration)

Contains:
- 10 vulnerable examples (with DURINN_GT markers)
- Safe twins and FP-bait examples
TXT

  # 1) Debug mode enabled
  cat > app/a05_vuln_01_debug_true.py <<'PY'
# DURINN_GT id=a05_01_debug_true track=sast set=core owasp=A05
DEBUG = True
PY

  cat > app/a05_safe_01_debug_false.py <<'PY'
DEBUG = False
PY

  # 2) Hardcoded secret key
  cat > app/a05_vuln_02_hardcoded_secret_key.py <<'PY'
# DURINN_GT id=a05_02_hardcoded_secret_key track=sast set=core owasp=A05
SECRET_KEY = "DURINN_TEST_SECRET_DO_NOT_USE"
PY

  cat > app/a05_safe_02_env_secret_key.py <<'PY'
import os

SECRET_KEY = os.environ.get("SECRET_KEY", "")
PY

  # 3) Cookie missing HttpOnly/Secure
  cat > app/a05_vuln_03_cookie_flags_disabled.py <<'PY'
# DURINN_GT id=a05_03_cookie_flags_disabled track=sast set=core owasp=A05
SESSION_COOKIE_HTTPONLY = False
SESSION_COOKIE_SECURE = False
PY

  cat > app/a05_safe_03_cookie_flags_enabled.py <<'PY'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
PY

  # 4) Wildcard CORS with credentials
  cat > app/a05_vuln_04_cors_wildcard_with_creds.py <<'PY'
# DURINN_GT id=a05_04_cors_wildcard_with_creds track=sast set=core owasp=A05
CORS_ALLOW_ORIGIN = "*"
CORS_ALLOW_CREDENTIALS = True
PY

  cat > app/a05_safe_04_cors_allowlist.py <<'PY'
CORS_ALLOW_ORIGIN = "https://example.com"
CORS_ALLOW_CREDENTIALS = True
PY

  # 5) Allow all hosts
  cat > app/a05_vuln_05_allowed_hosts_star.py <<'PY'
# DURINN_GT id=a05_05_allowed_hosts_star track=sast set=core owasp=A05
ALLOWED_HOSTS = ["*"]
PY

  cat > app/a05_safe_05_allowed_hosts_list.py <<'PY'
ALLOWED_HOSTS = ["example.com"]
PY

  # 6) Insecure file permissions
  cat > app/a05_vuln_06_chmod_777.py <<'PY'
# DURINN_GT id=a05_06_chmod_777 track=sast set=core owasp=A05
import os

def vuln(path: str) -> None:
    os.chmod(path, 0o777)
PY

  cat > app/a05_safe_06_chmod_600.py <<'PY'
import os

def safe(path: str) -> None:
    os.chmod(path, 0o600)
PY

  # 7) Insecure temporary file
  cat > app/a05_vuln_07_tempfile_mktemp.py <<'PY'
# DURINN_GT id=a05_07_tempfile_mktemp track=sast set=core owasp=A05
import tempfile

def vuln() -> str:
    return tempfile.mktemp()
PY

  cat > app/a05_safe_07_named_temporary_file.py <<'PY'
import tempfile

def safe() -> str:
    with tempfile.NamedTemporaryFile(delete=True) as f:
        return f.name
PY

  # 8) Jinja2 autoescape disabled
  cat > app/a05_vuln_08_jinja_autoescape_false.py <<'PY'
# DURINN_GT id=a05_08_jinja_autoescape_false track=sast set=core owasp=A05
from jinja2 import Environment

def vuln():
    return Environment(autoescape=False)
PY

  cat > app/a05_safe_08_jinja_autoescape_true.py <<'PY'
from jinja2 import Environment

def safe():
    return Environment(autoescape=True)
PY

  # 9) Insecure XML parser usage
  cat > app/a05_vuln_09_insecure_xml_parser.py <<'PY'
# DURINN_GT id=a05_09_insecure_xml_parser track=sast set=core owasp=A05
import xml.etree.ElementTree as ET

def vuln(xml_text: str):
    return ET.fromstring(xml_text)
PY

  cat > app/a05_safe_09_no_untrusted_xml.py <<'PY'

def safe(xml_text: str):
    _ = xml_text
    return None
PY

  # 10) Binding to all interfaces
  cat > app/a05_vuln_10_bind_all_interfaces.py <<'PY'
# DURINN_GT id=a05_10_bind_all_interfaces track=sast set=core owasp=A05
HOST = "0.0.0.0"
PY

  cat > app/a05_safe_10_bind_localhost.py <<'PY'
HOST = "127.0.0.1"
PY

  # FP-bait
  cat > fp_bait/a05_bait_debug_false.py <<'PY'
DEBUG = False  # safe
PY

  cat > fp_bait/a05_bait_secret_placeholder_unused.py <<'PY'
# Looks like a secret but unused placeholder.
PLACEHOLDER = "xxxxxxxxxxxxxxxx"
PY

  git add -A
  git commit -m "Add A05 calibration sample case" >/dev/null
  git switch main >/dev/null
}

# ---------------------------------------------------------------------------
# Branch: OWASP 2021 A06 (Vulnerable and Outdated Components)
# ---------------------------------------------------------------------------
make_a06() {
  local branch="owasp2021-a06-calibration-sample"
  if branch_exists "${branch}"; then
    echo "[skip] branch already exists: ${branch}"
    return 0
  fi

  echo "[make] ${branch}"
  git switch -c "${branch}" >/dev/null

  rm -rf app fp_bait
  mkdir -p app fp_bait

  cat > app/README_CASE.md <<'TXT'
A06 calibration case branch (Vulnerable and Outdated Components)

This branch focuses on Python 2 / deprecated standard-library usage patterns.
These are syntactically valid in Python 3 but indicate outdated components.
TXT

  # 1) urllib2 (Py2)
  cat > app/a06_vuln_01_import_urllib2.py <<'PY'
# DURINN_GT id=a06_01_import_urllib2 track=sast set=core owasp=A06
import urllib2
PY

  cat > app/a06_safe_01_import_urllib_request.py <<'PY'
import urllib.request
PY

  # 2) httplib (Py2)
  cat > app/a06_vuln_02_import_httplib.py <<'PY'
# DURINN_GT id=a06_02_import_httplib track=sast set=core owasp=A06
import httplib
PY

  cat > app/a06_safe_02_import_http_client.py <<'PY'
import http.client
PY

  # 3) BaseHTTPServer (Py2)
  cat > app/a06_vuln_03_import_basehttpserver.py <<'PY'
# DURINN_GT id=a06_03_import_basehttpserver track=sast set=core owasp=A06
import BaseHTTPServer
PY

  cat > app/a06_safe_03_import_http_server.py <<'PY'
import http.server
PY

  # 4) SimpleHTTPServer (Py2)
  cat > app/a06_vuln_04_import_simplehttpserver.py <<'PY'
# DURINN_GT id=a06_04_import_simplehttpserver track=sast set=core owasp=A06
import SimpleHTTPServer
PY

  cat > app/a06_safe_04_import_http_server.py <<'PY'
import http.server
PY

  # 5) SocketServer (Py2)
  cat > app/a06_vuln_05_import_socketserver.py <<'PY'
# DURINN_GT id=a06_05_import_socketserver track=sast set=core owasp=A06
import SocketServer
PY

  cat > app/a06_safe_05_import_socketserver.py <<'PY'
import socketserver
PY

  # 6) ConfigParser (Py2)
  cat > app/a06_vuln_06_import_configparser_py2.py <<'PY'
# DURINN_GT id=a06_06_import_configparser_py2 track=sast set=core owasp=A06
import ConfigParser
PY

  cat > app/a06_safe_06_import_configparser.py <<'PY'
import configparser
PY

  # 7) Queue (Py2)
  cat > app/a06_vuln_07_import_queue_py2.py <<'PY'
# DURINN_GT id=a06_07_import_queue_py2 track=sast set=core owasp=A06
import Queue
PY

  cat > app/a06_safe_07_import_queue.py <<'PY'
import queue
PY

  # 8) urlparse (Py2)
  cat > app/a06_vuln_08_import_urlparse.py <<'PY'
# DURINN_GT id=a06_08_import_urlparse track=sast set=core owasp=A06
import urlparse
PY

  cat > app/a06_safe_08_import_urllib_parse.py <<'PY'
import urllib.parse
PY

  # 9) HTMLParser (Py2)
  cat > app/a06_vuln_09_import_htmlparser_py2.py <<'PY'
# DURINN_GT id=a06_09_import_htmlparser_py2 track=sast set=core owasp=A06
import HTMLParser
PY

  cat > app/a06_safe_09_import_html_parser.py <<'PY'
import html.parser
PY

  # 10) StringIO (Py2)
  cat > app/a06_vuln_10_import_stringio.py <<'PY'
# DURINN_GT id=a06_10_import_stringio track=sast set=core owasp=A06
import StringIO
PY

  cat > app/a06_safe_10_import_io.py <<'PY'
import io
PY

  # FP-bait: compatibility shim (safe but may be flagged)
  cat > fp_bait/a06_bait_compat_imports.py <<'PY'
# Compatibility shim (safe) — some scanners may still complain.
try:
    import urllib2  # noqa: F401
except Exception:
    import urllib.request as urllib2  # type: ignore
PY

  cat > fp_bait/a06_bait_deprecated_module_imp.py <<'PY'
import imp  # deprecated but sometimes used in legacy code
PY

  git add -A
  git commit -m "Add A06 calibration sample case" >/dev/null
  git switch main >/dev/null
}

# ---------------------------------------------------------------------------
# Branch: OWASP 2021 A07 (Identification & Authentication Failures)
# ---------------------------------------------------------------------------
make_a07() {
  local branch="owasp2021-a07-calibration-sample"
  if branch_exists "${branch}"; then
    echo "[skip] branch already exists: ${branch}"
    return 0
  fi

  echo "[make] ${branch}"
  git switch -c "${branch}" >/dev/null

  rm -rf app fp_bait
  mkdir -p app fp_bait

  cat > app/README_CASE.md <<'TXT'
A07 calibration case branch (Identification & Authentication Failures)

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

def vuln(url: str) -> None:
    ctx = ssl._create_unverified_context()
    urllib.request.urlopen(url, context=ctx)
PY

  cat > app/a07_safe_04_secure_tls.py <<'PY'
import ssl
import urllib.request

def safe(url: str) -> None:
    ctx = ssl.create_default_context()
    urllib.request.urlopen(url, context=ctx)
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
# Branch: OWASP 2021 A08 (Software and Data Integrity Failures)
# ---------------------------------------------------------------------------
make_a08() {
  local branch="owasp2021-a08-calibration-sample"
  if branch_exists "${branch}"; then
    echo "[skip] branch already exists: ${branch}"
    return 0
  fi

  echo "[make] ${branch}"
  git switch -c "${branch}" >/dev/null

  rm -rf app fp_bait
  mkdir -p app fp_bait

  cat > app/README_CASE.md <<'TXT'
A08 calibration case branch (Software and Data Integrity Failures)

Contains patterns like unsafe deserialization and unsafe dynamic execution.
TXT

  # 1) pickle.loads
  cat > app/a08_vuln_01_pickle_loads.py <<'PY'
# DURINN_GT id=a08_01_pickle_loads track=sast set=core owasp=A08
import pickle

def vuln(blob: bytes):
    return pickle.loads(blob)
PY

  cat > app/a08_safe_01_json_loads.py <<'PY'
import json

def safe(text: str):
    return json.loads(text)
PY

  # 2) yaml.load (unsafe)
  cat > app/a08_vuln_02_yaml_load.py <<'PY'
# DURINN_GT id=a08_02_yaml_load track=sast set=core owasp=A08
import yaml

def vuln(text: str):
    return yaml.load(text, Loader=yaml.Loader)
PY

  cat > app/a08_safe_02_yaml_safe_load.py <<'PY'
import yaml

def safe(text: str):
    return yaml.safe_load(text)
PY

  # 3) marshal.loads
  cat > app/a08_vuln_03_marshal_loads.py <<'PY'
# DURINN_GT id=a08_03_marshal_loads track=sast set=core owasp=A08
import marshal

def vuln(blob: bytes):
    return marshal.loads(blob)
PY

  cat > app/a08_safe_03_no_marshal.py <<'PY'

def safe(blob: bytes):
    _ = blob
    raise ValueError("unsupported")
PY

  # 4) eval on user input
  cat > app/a08_vuln_04_eval_user_input.py <<'PY'
# DURINN_GT id=a08_04_eval_user_input track=sast set=core owasp=A08

def vuln(expr: str):
    return eval(expr)
PY

  cat > app/a08_safe_04_literal_eval_only.py <<'PY'
import ast

def safe(expr: str):
    return ast.literal_eval(expr)
PY

  # 5) exec on user input
  cat > app/a08_vuln_05_exec_user_input.py <<'PY'
# DURINN_GT id=a08_05_exec_user_input track=sast set=core owasp=A08

def vuln(code: str) -> None:
    exec(code)
PY

  cat > app/a08_safe_05_no_exec.py <<'PY'

def safe(code: str) -> None:
    _ = code
PY

  # 6) tarfile.extractall (tar slip)
  cat > app/a08_vuln_06_tar_extractall.py <<'PY'
# DURINN_GT id=a08_06_tar_extractall track=sast set=core owasp=A08
import tarfile

def vuln(tar_path: str, out_dir: str) -> None:
    with tarfile.open(tar_path) as t:
        t.extractall(out_dir)
PY

  cat > app/a08_safe_06_tar_extract_safely.py <<'PY'
import os
import tarfile

def safe(tar_path: str, out_dir: str) -> None:
    out_abs = os.path.abspath(out_dir)
    with tarfile.open(tar_path) as t:
        for m in t.getmembers():
            dest = os.path.abspath(os.path.join(out_dir, m.name))
            if not dest.startswith(out_abs):
                raise ValueError("blocked")
        t.extractall(out_dir)
PY

  # 7) zipfile.extractall (zip slip)
  cat > app/a08_vuln_07_zip_extractall.py <<'PY'
# DURINN_GT id=a08_07_zip_extractall track=sast set=core owasp=A08
import zipfile

def vuln(zip_path: str, out_dir: str) -> None:
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(out_dir)
PY

  cat > app/a08_safe_07_zip_extract_safely.py <<'PY'
import os
import zipfile

def safe(zip_path: str, out_dir: str) -> None:
    out_abs = os.path.abspath(out_dir)
    with zipfile.ZipFile(zip_path) as z:
        for name in z.namelist():
            dest = os.path.abspath(os.path.join(out_dir, name))
            if not dest.startswith(out_abs):
                raise ValueError("blocked")
        z.extractall(out_dir)
PY

  # 8) importlib import from user input
  cat > app/a08_vuln_08_dynamic_import.py <<'PY'
# DURINN_GT id=a08_08_dynamic_import track=sast set=core owasp=A08
import importlib

def vuln(mod: str):
    return importlib.import_module(mod)
PY

  cat > app/a08_safe_08_allowlist_import.py <<'PY'
import importlib

ALLOWED = {"math", "json"}

def safe(mod: str):
    if mod not in ALLOWED:
        raise ValueError("not allowed")
    return importlib.import_module(mod)
PY

  # 9) Subprocess with shell=True (supply-chain-ish dynamic execution)
  cat > app/a08_vuln_09_subprocess_shell.py <<'PY'
# DURINN_GT id=a08_09_subprocess_shell track=sast set=core owasp=A08
import subprocess

def vuln(cmd: str) -> None:
    subprocess.run(cmd, shell=True, check=False)
PY

  cat > app/a08_safe_09_subprocess_no_shell.py <<'PY'
import subprocess

def safe(cmd: str) -> None:
    subprocess.run(["echo", cmd], shell=False, check=False)
PY

  # 10) Loading code from file then exec
  cat > app/a08_vuln_10_exec_file_contents.py <<'PY'
# DURINN_GT id=a08_10_exec_file_contents track=sast set=core owasp=A08

def vuln(path: str) -> None:
    code = open(path, "r", encoding="utf-8").read()
    exec(code)
PY

  cat > app/a08_safe_10_no_exec_file.py <<'PY'

def safe(path: str) -> None:
    _ = path
    raise ValueError("blocked")
PY

  cat > fp_bait/a08_bait_yaml_safe_load.py <<'PY'
import yaml

def safe(text: str):
    return yaml.safe_load(text)
PY

  cat > fp_bait/a08_bait_zip_safe_extract.py <<'PY'
# Safe pattern with path check
import os
import zipfile

def safe(zip_path: str, out_dir: str) -> None:
    out_abs = os.path.abspath(out_dir)
    with zipfile.ZipFile(zip_path) as z:
        for name in z.namelist():
            dest = os.path.abspath(os.path.join(out_dir, name))
            if not dest.startswith(out_abs):
                raise ValueError("blocked")
        z.extractall(out_dir)
PY

  git add -A
  git commit -m "Add A08 calibration sample case" >/dev/null
  git switch main >/dev/null
}

# ---------------------------------------------------------------------------
# Branch: OWASP 2021 A09 (Security Logging and Monitoring Failures)
# ---------------------------------------------------------------------------
make_a09() {
  local branch="owasp2021-a09-calibration-sample"
  if branch_exists "${branch}"; then
    echo "[skip] branch already exists: ${branch}"
    return 0
  fi

  echo "[make] ${branch}"
  git switch -c "${branch}" >/dev/null

  rm -rf app fp_bait
  mkdir -p app fp_bait

  cat > app/README_CASE.md <<'TXT'
A09 calibration case branch (Security Logging and Monitoring Failures)

This branch focuses on:
- Swallowing exceptions / missing logs
- Logging sensitive data
- Disabling logging
TXT

  # 1) Broad exception swallowed
  cat > app/a09_vuln_01_swallow_exception.py <<'PY'
# DURINN_GT id=a09_01_swallow_exception track=sast set=core owasp=A09

def vuln() -> None:
    try:
        1 / 0
    except Exception:
        pass  # BUG: no logging/monitoring
PY

  cat > app/a09_safe_01_log_and_reraise.py <<'PY'
import logging

logger = logging.getLogger(__name__)

def safe() -> None:
    try:
        1 / 0
    except Exception as e:
        logger.exception("error")
        raise e
PY

  # 2) Fail-open on exception without audit
  cat > app/a09_vuln_02_fail_open_no_log.py <<'PY'
# DURINN_GT id=a09_02_fail_open_no_log track=sast set=core owasp=A09

def vuln() -> bool:
    try:
        raise RuntimeError("boom")
    except Exception:
        return True
PY

  cat > app/a09_safe_02_fail_closed_with_log.py <<'PY'
import logging

logger = logging.getLogger(__name__)

def safe() -> bool:
    try:
        raise RuntimeError("boom")
    except Exception:
        logger.exception("blocked")
        return False
PY

  # 3) Disable logging globally
  cat > app/a09_vuln_03_disable_logging.py <<'PY'
# DURINN_GT id=a09_03_disable_logging track=sast set=core owasp=A09
import logging

logging.disable(logging.CRITICAL)
PY

  cat > app/a09_safe_03_logging_enabled.py <<'PY'
import logging

logging.disable(logging.NOTSET)
PY

  # 4) Logger disabled
  cat > app/a09_vuln_04_logger_disabled.py <<'PY'
# DURINN_GT id=a09_04_logger_disabled track=sast set=core owasp=A09
import logging

logger = logging.getLogger(__name__)
logger.disabled = True
PY

  cat > app/a09_safe_04_logger_enabled.py <<'PY'
import logging

logger = logging.getLogger(__name__)
logger.disabled = False
PY

  # 5) Log password in plaintext
  cat > app/a09_vuln_05_log_password.py <<'PY'
# DURINN_GT id=a09_05_log_password track=sast set=core owasp=A09
import logging

logger = logging.getLogger(__name__)

def vuln(username: str, password: str) -> None:
    logger.info("login %s %s", username, password)
PY

  cat > app/a09_safe_05_log_redacted.py <<'PY'
import logging

logger = logging.getLogger(__name__)

def safe(username: str, password: str) -> None:
    _ = password
    logger.info("login %s [REDACTED]", username)
PY

  # 6) Log auth token
  cat > app/a09_vuln_06_log_auth_token.py <<'PY'
# DURINN_GT id=a09_06_log_auth_token track=sast set=core owasp=A09
import logging

logger = logging.getLogger(__name__)

def vuln(token: str) -> None:
    logger.warning("token=%s", token)
PY

  cat > app/a09_safe_06_log_token_hash.py <<'PY'
import hashlib
import logging

logger = logging.getLogger(__name__)

def safe(token: str) -> None:
    token_hash = hashlib.sha256(token.encode()).hexdigest()[:8]
    logger.warning("token_hash=%s", token_hash)
PY

  # 7) Log request headers including Authorization
  cat > app/a09_vuln_07_log_headers.py <<'PY'
# DURINN_GT id=a09_07_log_headers track=sast set=core owasp=A09
import logging

logger = logging.getLogger(__name__)

def vuln(headers: dict) -> None:
    logger.info("headers=%s", headers)
PY

  cat > app/a09_safe_07_log_headers_redacted.py <<'PY'
import logging

logger = logging.getLogger(__name__)

def safe(headers: dict) -> None:
    h = dict(headers)
    if "Authorization" in h:
        h["Authorization"] = "[REDACTED]"
    logger.info("headers=%s", h)
PY

  # 8) Empty except block around auth
  cat > app/a09_vuln_08_empty_except_auth.py <<'PY'
# DURINN_GT id=a09_08_empty_except_auth track=sast set=core owasp=A09

def vuln() -> bool:
    try:
        raise ValueError("bad")
    except:
        return False  # BUG: no monitoring
PY

  cat > app/a09_safe_08_except_with_log.py <<'PY'
import logging

logger = logging.getLogger(__name__)

def safe() -> bool:
    try:
        raise ValueError("bad")
    except Exception:
        logger.exception("auth error")
        return False
PY

  # 9) Print stack trace to user (info exposure + no monitoring)
  cat > app/a09_vuln_09_stacktrace_print.py <<'PY'
# DURINN_GT id=a09_09_stacktrace_print track=sast set=core owasp=A09
import traceback

def vuln() -> str:
    try:
        1 / 0
    except Exception:
        return traceback.format_exc()
PY

  cat > app/a09_safe_09_generic_error.py <<'PY'

def safe() -> str:
    try:
        1 / 0
    except Exception:
        return "internal error"
PY

  # 10) Ignore return value of security check
  cat > app/a09_vuln_10_ignore_security_check.py <<'PY'
# DURINN_GT id=a09_10_ignore_security_check track=sast set=core owasp=A09

def check_mfa(user) -> bool:
    return False

def vuln(user) -> None:
    check_mfa(user)  # BUG: ignore result
    return None
PY

  cat > app/a09_safe_10_enforce_security_check.py <<'PY'

def check_mfa(user) -> bool:
    return bool(getattr(user, "mfa_ok", False))

def safe(user) -> None:
    if not check_mfa(user):
        raise PermissionError("mfa required")
PY

  cat > fp_bait/a09_bait_redacted_log.py <<'PY'
import logging

logger = logging.getLogger(__name__)

def safe(username: str, password: str) -> None:
    _ = password
    logger.info("login user=%s password=[REDACTED]", username)
PY

  cat > fp_bait/a09_bait_exception_logging.py <<'PY'
import logging

logger = logging.getLogger(__name__)

def safe():
    try:
        1 / 0
    except Exception:
        logger.exception("error")
PY

  git add -A
  git commit -m "Add A09 calibration sample case" >/dev/null
  git switch main >/dev/null
}

# ---------------------------------------------------------------------------
# Branch: OWASP 2021 A10 (Server-Side Request Forgery)
# ---------------------------------------------------------------------------
make_a10() {
  local branch="owasp2021-a10-calibration-sample"
  if branch_exists "${branch}"; then
    echo "[skip] branch already exists: ${branch}"
    return 0
  fi

  echo "[make] ${branch}"
  git switch -c "${branch}" >/dev/null

  rm -rf app fp_bait
  mkdir -p app fp_bait

  cat > app/README_CASE.md <<'TXT'
A10 calibration case branch (SSRF)

Contains direct and indirect server-side request patterns.
TXT

  # 1) requests.get(user_url)
  cat > app/a10_vuln_01_requests_get_user_url.py <<'PY'
# DURINN_GT id=a10_01_requests_get_user_url track=sast set=core owasp=A10
import requests

def vuln(url: str):
    return requests.get(url)
PY

  cat > app/a10_safe_01_requests_allowlist.py <<'PY'
import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = {"example.com"}

def safe(url: str):
    p = urlparse(url)
    if p.scheme not in {"http", "https"}:
        raise ValueError("bad scheme")
    if p.hostname not in ALLOWED_HOSTS:
        raise ValueError("bad host")
    return requests.get(url)
PY

  # 2) urllib.request.urlopen(user_url)
  cat > app/a10_vuln_02_urlopen_user_url.py <<'PY'
# DURINN_GT id=a10_02_urlopen_user_url track=sast set=core owasp=A10
import urllib.request

def vuln(url: str):
    return urllib.request.urlopen(url)
PY

  cat > app/a10_safe_02_urlopen_allowlist.py <<'PY'
import urllib.request
from urllib.parse import urlparse

ALLOWED_HOSTS = {"example.com"}

def safe(url: str):
    p = urlparse(url)
    if p.hostname not in ALLOWED_HOSTS:
        raise ValueError("bad host")
    return urllib.request.urlopen(url)
PY

  # 3) http.client connection to user-controlled host
  cat > app/a10_vuln_03_httpclient_user_host.py <<'PY'
# DURINN_GT id=a10_03_httpclient_user_host track=sast set=core owasp=A10
import http.client

def vuln(host: str):
    c = http.client.HTTPConnection(host)
    c.request("GET", "/")
    return c.getresponse()
PY

  cat > app/a10_safe_03_httpclient_allowlist.py <<'PY'
import http.client

ALLOWED_HOSTS = {"example.com"}

def safe(host: str):
    if host not in ALLOWED_HOSTS:
        raise ValueError("bad host")
    c = http.client.HTTPConnection(host)
    c.request("GET", "/")
    return c.getresponse()
PY

  # 4) socket connection to user-controlled host
  cat > app/a10_vuln_04_socket_connect_user_host.py <<'PY'
# DURINN_GT id=a10_04_socket_connect_user_host track=sast set=core owasp=A10
import socket

def vuln(host: str, port: int):
    return socket.create_connection((host, port))
PY

  cat > app/a10_safe_04_socket_allowlist.py <<'PY'
import socket

ALLOWED_HOSTS = {"example.com"}

def safe(host: str, port: int):
    if host not in ALLOWED_HOSTS:
        raise ValueError("bad host")
    return socket.create_connection((host, port))
PY

  # 5) curl via shell
  cat > app/a10_vuln_05_curl_shell.py <<'PY'
# DURINN_GT id=a10_05_curl_shell track=sast set=core owasp=A10
import subprocess

def vuln(url: str) -> None:
    subprocess.run("curl " + url, shell=True, check=False)
PY

  cat > app/a10_safe_05_curl_no_shell.py <<'PY'
import subprocess

def safe(url: str) -> None:
    subprocess.run(["curl", url], shell=False, check=False)
PY

  # 6) Allow file:// scheme
  cat > app/a10_vuln_06_allow_file_scheme.py <<'PY'
# DURINN_GT id=a10_06_allow_file_scheme track=sast set=core owasp=A10
from urllib.parse import urlparse

def vuln(url: str) -> str:
    p = urlparse(url)
    if p.scheme in {"http", "https", "file"}:
        return "ok"
    return "no"
PY

  cat > app/a10_safe_06_block_file_scheme.py <<'PY'
from urllib.parse import urlparse

def safe(url: str) -> str:
    p = urlparse(url)
    if p.scheme not in {"http", "https"}:
        return "no"
    return "ok"
PY

  # 7) Weak hostname validation (substring)
  cat > app/a10_vuln_07_weak_host_validation.py <<'PY'
# DURINN_GT id=a10_07_weak_host_validation track=sast set=core owasp=A10
from urllib.parse import urlparse

def vuln(url: str) -> bool:
    p = urlparse(url)
    return "example.com" in (p.hostname or "")
PY

  cat > app/a10_safe_07_strict_host_validation.py <<'PY'
from urllib.parse import urlparse

ALLOWED = {"example.com"}

def safe(url: str) -> bool:
    p = urlparse(url)
    return (p.hostname or "") in ALLOWED
PY

  # 8) Metadata IP target
  cat > app/a10_vuln_08_metadata_ip.py <<'PY'
# DURINN_GT id=a10_08_metadata_ip track=sast set=core owasp=A10
METADATA_URL = "http://169.254.169.254/latest/meta-data/"
PY

  cat > app/a10_safe_08_no_metadata_ip.py <<'PY'
METADATA_URL = ""
PY

  # 9) URL built from user-controlled host
  cat > app/a10_vuln_09_build_url_from_user_host.py <<'PY'
# DURINN_GT id=a10_09_build_url_from_user_host track=sast set=core owasp=A10

def vuln(host: str) -> str:
    return "http://" + host + "/api"
PY

  cat > app/a10_safe_09_build_url_allowlist.py <<'PY'
ALLOWED_HOSTS = {"example.com"}

def safe(host: str) -> str:
    if host not in ALLOWED_HOSTS:
        raise ValueError("bad host")
    return "http://" + host + "/api"
PY

  # 10) requests.get with redirects (default) and user URL
  cat > app/a10_vuln_10_requests_redirects.py <<'PY'
# DURINN_GT id=a10_10_requests_redirects track=sast set=core owasp=A10
import requests

def vuln(url: str):
    return requests.get(url, allow_redirects=True)
PY

  cat > app/a10_safe_10_requests_no_redirects.py <<'PY'
import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = {"example.com"}

def safe(url: str):
    p = urlparse(url)
    if p.hostname not in ALLOWED_HOSTS:
        raise ValueError("bad host")
    return requests.get(url, allow_redirects=False)
PY

  cat > fp_bait/a10_bait_allowlisted_request.py <<'PY'
import requests

def safe(url: str):
    # Safe placeholder used for internal-only allowlisted calls.
    return requests.get(url)
PY

  cat > fp_bait/a10_bait_hostname_check.py <<'PY'
from urllib.parse import urlparse

def safe(url: str) -> str:
    # Safe: parses hostname, doesn't fetch.
    p = urlparse(url)
    return p.hostname or ""
PY

  git add -A
  git commit -m "Add A10 calibration sample case" >/dev/null
  git switch main >/dev/null
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
make_a01
make_a02
make_a03
make_a04
make_a05
make_a06
make_a07
make_a08
make_a09
make_a10

cat <<'OUT'

✅ Done. Local branches created (skipping any that already existed).

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
