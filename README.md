# Durinn Calibration Suite (Sample)

This repository is a **branch-per-case** Python micro-suite designed to create **useful disagreement** between static analyzers (Semgrep / Snyk Code / Sonar) for triage calibration.

## What this is for

Your pipeline learns tool weights from clusters that overlap GT (true positives) vs clusters that do not (false positives). A calibration suite should therefore include:

- Real vulnerabilities (**TP opportunities**) with in-repo GT markers.
- Safe-but-realistic code that *looks* suspicious (**FP opportunities**) so tools can be wrong.
- A mix of easy + harder patterns so tools disagree.

## Ground truth markers

Vulnerable lines include comments like:

```py
# DURINN_GT id=a07_01_hardcoded_password track=sast set=core owasp=A07
```

Your pipeline's GT scorer extracts these markers and writes `gt_score.json` under the suite run output.

## Branches

This sample script creates a few branches:

- `owasp2021-a07-calibration-sample`
- `owasp2021-a03-calibration-sample`

Each branch contains vulnerable examples (with markers) plus safe twins and FP-bait.

## Quickstart

1) Create branches + commits:

```bash
bash scripts/bootstrap_branches.sh
```

2) Create a GitHub repo and push all branches (instructions printed by the script).

## Safety

All secrets/credentials in this repo are **fake** (e.g., `DURINN_TEST_SECRET_DO_NOT_USE`).
Do **not** copy these patterns into production code.
