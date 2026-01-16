# Durinn Calibration Suite (Python)

This repository is a **branch-per-case** Python micro-suite designed to create **useful disagreement** between static analyzers (Semgrep / Snyk Code / Sonar) so the Durinn pipeline can learn a **deterministic triage ranking calibration**.

If your scanners already agree on everything, calibration has nothing to learn. This repo intentionally includes:

- **Real, obvious vulnerabilities** (true-positive opportunities)
- **Safe “look-alike” twins** (false-positive opportunities)
- A small number of **harder variants** that some tools may miss (false-negative opportunities)

> Safety note: all “secrets” are fake placeholders like `DURINN_TEST_SECRET_DO_NOT_USE`. Do not copy patterns from `app/*vuln*` into production.

---

## How the repo is organized

### Branch-per-case

Each OWASP Top 10 2021 category is implemented as its own branch:

- `owasp2021-a01-calibration-sample`
- `owasp2021-a02-calibration-sample`
- `owasp2021-a03-calibration-sample`
- `owasp2021-a04-calibration-sample`
- `owasp2021-a05-calibration-sample`
- `owasp2021-a06-calibration-sample`
- `owasp2021-a07-calibration-sample`
- `owasp2021-a08-calibration-sample`
- `owasp2021-a09-calibration-sample`
- `owasp2021-a10-calibration-sample`

Each branch contains:

- `app/` – the **10 vulnerable** examples and their **safe twins**
- `fp_bait/` – 1–2 **safe but suspicious-looking** files (designed to trigger false positives)

### Ground truth markers

Each vulnerable example contains a single ground-truth marker comment like:

```py
# DURINN_GT id=a07_01_hardcoded_password track=sast set=core owasp=A07
```

The Durinn pipeline extracts these markers and writes per-case ground truth into:

```
cases/<case_id>/gt/gt_score.json
```

That ground truth is then used to compute cluster-level `gt_overlap`.

---

## How this repo is used by the Durinn pipeline

At a high level:

1) The pipeline scans a case (a branch) using multiple tools.
2) Findings are clustered into “clusters” (a cluster is a group of similar findings).
3) Each cluster becomes one row in `triage_dataset.csv` (suite-level).
4) The pipeline learns a small calibration file `triage_calibration.json` from the suite dataset.
5) Ranking uses that calibration to compute a stable score per cluster.

Key artifacts (produced under `runs/suites/<suite_id>/analysis/`):

- `_tables/triage_dataset.csv` – training data for calibration
- `triage_calibration.json` – learned weights (suite-local)
- triage queue / triage features tables – include `triage_score_v1`
- eval outputs compare baseline vs agreement vs calibrated

---

## Calibration math (Goal 2B)

Calibration is learned from the suite-wide dataset:

```
runs/suites/<suite_id>/analysis/_tables/triage_dataset.csv
```

Each row represents a cluster and includes (at least):

- `tools_json` – the set/list of tools that produced findings in this cluster
- `gt_overlap` – whether this cluster overlaps any GT vulnerability (1 or 0)

### Which cases are included

Only cases that have GT are used:

- **Included:** `cases/<case_id>/gt/gt_score.json` exists
- **Excluded:** no GT file (we don’t want to learn from unlabeled data)

### Tool-level TP/FP counts

For each tool **t**, we count across all clusters in all included cases:

- **TP\_t** = number of clusters where **t is present** and `gt_overlap = 1`
- **FP\_t** = number of clusters where **t is present** and `gt_overlap = 0`

In set notation:

- TP\_t = |{ c : t ∈ tools(c) and gt_overlap(c)=1 }|
- FP\_t = |{ c : t ∈ tools(c) and gt_overlap(c)=0 }|

### Smoothed precision (Beta prior)

Raw precision `TP/(TP+FP)` is unstable on small datasets, so we use smoothing:

```
p_t = (TP_t + α) / (TP_t + FP_t + α + β)
```

Defaults:

- α = 1
- β = 1

This is equivalent to a Beta(α,β) prior over tool precision.

### Convert precision to a weight

We convert `p_t` to a weight `w_t` using **log-odds** (a.k.a. the logit):

1) Clamp precision to avoid infinities:

```
p_t_clamped = clamp(p_t, p_min, p_max)
```

Defaults:

- p_min = 0.01
- p_max = 0.99

2) Compute weight:

```
w_t = log( p_t_clamped / (1 - p_t_clamped) )
```

Intuition:

- p=0.50 → w=0.0 (neutral)
- p>0.50 → positive weight
- p<0.50 → negative weight

### Worked example

If a tool has TP=32 and FP=3, with α=1, β=1:

- p = (32+1) / (32+3+1+1) = 33/37 ≈ 0.8919
- w = log(0.8919 / 0.1081) ≈ 2.1102

---

## Ranking math (triage_score_v1)

When `triage_calibration.json` exists, each cluster receives a score:

### Base score (tool evidence)

```
base = Σ_{t ∈ tools(cluster)} w_t
```

### Agreement bonus

If multiple tools agree on the same cluster, we add a small bonus:

```
agreement_bonus = λ * max(tool_count - 1, 0)
```

Default:

- λ = 0.50

### Severity bonus

A small per-severity bump (optional but helps break ties):

```
severity_bonus(HIGH)=0.25
severity_bonus(MEDIUM)=0.10
severity_bonus(LOW)=0.00
severity_bonus(UNKNOWN)=0.00
```

### Final score

```
triage_score_v1 = base + agreement_bonus + severity_bonus
```

Sorting rule:

1) Sort by `triage_score_v1` descending.
2) If ties remain, fall back to the pipeline’s deterministic tie-break (file/line/cluster id).

---

## Evaluation metrics (what “better” means)

The pipeline reports metrics at K = [1,3,5,10,25] for multiple strategies (baseline / agreement / calibrated).

### Precision@K

Out of the top K clusters, how many overlap GT:

```
Precision@K = (# of top-K clusters with gt_overlap=1) / K
```

### Coverage@K

How much of the ground truth you “hit” in the top K results.

Implementation details can vary depending on whether you count *unique GT items* or *overlapping clusters*, but the idea is:

- Coverage@K increases when true vulnerabilities appear earlier in the ranked list.

### Macro vs micro

- **Macro:** compute per-case metrics and average across cases.
- **Micro:** pool all clusters across cases then compute a single metric.

---

## Creating / updating the branches

Generate all sample branches locally:

```bash
bash scripts/bootstrap_branches.sh
```

Push everything:

```bash
git push -u origin main
git push origin --all
```

### Adding a new example (rules of thumb)

For each new vulnerability you add, try to add three siblings:

1) A vulnerable example (with one `DURINN_GT` marker)
2) A safe twin (same shape, but fixed)
3) An FP-bait variant (safe, but suspicious-looking)

That mix is what makes calibration learn something useful.

---

## Safety

- This repo is **not meant to run as an application**.
- Do not use the insecure patterns as copy/paste material.
- Any secrets/keys in this repo are fake placeholders.
