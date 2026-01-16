# Durinn Calibration Suite (Python)

This repository is a **branch-per-case** Python micro-suite designed to create **useful disagreement** between static analyzers (Semgrep / Snyk Code / Sonar) for triage calibration.

## What this is for

Your pipeline learns weights from clusters that overlap GT (true positives) vs clusters that do not (false positives). A calibration suite should therefore include:

- Real vulnerabilities (**TP opportunities**) with in-repo GT markers.
- Safe-but-realistic code that *looks* suspicious (**FP opportunities**) so tools can be wrong.
- A mix of easy + harder patterns so tools disagree.

## Ground truth markers

Vulnerable files include comments like:

```py
# DURINN_GT id=a07_01_hardcoded_password track=sast set=core owasp=A07
```

Your pipeline's GT scorer can extract these markers and write `gt_score.json` under the suite run output.

## Branches

Running `bash scripts/bootstrap_branches.sh` creates one branch per OWASP 2021 Top 10 category:

- `owasp2021-a01-calibration-sample` (Broken Access Control)
- `owasp2021-a02-calibration-sample` (Cryptographic Failures)
- `owasp2021-a03-calibration-sample` (Injection)
- `owasp2021-a04-calibration-sample` (Insecure Design)
- `owasp2021-a05-calibration-sample` (Security Misconfiguration)
- `owasp2021-a06-calibration-sample` (Vulnerable & Outdated Components)
- `owasp2021-a07-calibration-sample` (Identification & Authentication Failures)
- `owasp2021-a08-calibration-sample` (Software & Data Integrity Failures)
- `owasp2021-a09-calibration-sample` (Security Logging & Monitoring Failures)
- `owasp2021-a10-calibration-sample` (Server-Side Request Forgery)

Each branch contains:

- 10 vulnerable examples (with `DURINN_GT` markers)
- safe twins (near-identical “fixed” versions)
- a couple of FP-bait files (safe, but suspicious-looking)

## Quickstart

1) Create branches + commits:

```bash
bash scripts/bootstrap_branches.sh
```

2) Push all branches to GitHub:

```bash
git push -u origin main
git push origin --all
```

## Safety

All secrets/credentials in this repo are **fake** (e.g., `DURINN_TEST_SECRET_DO_NOT_USE`).
Do **not** copy these patterns into production code.
