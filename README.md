# AppSec Take-Home Assignment


The solution scans a target directory, produces raw findings, suppresses known findings using an explicit baseline file, and generates a human-readable triage report.

---

## Requirements

* Docker
* Python 3.x

---

## Project Structure

```text
appsec-takehome/
├── artifacts/
│   ├── secrets.raw.json
│   ├── secrets.filtered.json
│   └── triage.md
├── config/
│   └── gitleaks.toml
├── scripts/
│   ├── scan_secrets.py
│   └── triage_report.py
├── testdata/
├── baseline.json
├── run.sh
└── README.md
```

---

## One-Command Run

```bash
./run.sh
```

The command performs the following steps:

1. Runs Gitleaks against `testdata/`
2. Generates `artifacts/secrets.raw.json`
3. Applies baseline suppression
4. Generates `artifacts/secrets.filtered.json`
5. Generates `artifacts/triage.md`
6. Returns the appropriate exit code

---

## Generated Artifacts

### artifacts/secrets.raw.json

Contains all findings returned by Gitleaks.

### artifacts/secrets.filtered.json

Contains only findings that are not present in `baseline.json`.

### artifacts/triage.md

Contains:

* Counts by severity
* Counts by category
* Top 5 prioritized findings
* Suppressed vs new findings summary

---

## Baseline Suppression

The baseline file explicitly contains findings that are known and accepted.

Workflow:

```text
Raw Findings
      ↓
Apply Baseline Suppression
      ↓
Filtered Findings
      ↓
Generate Triage Report
```

Only filtered findings affect the final exit code.

---

## Exit Codes

| Exit Code | Meaning                                                  |
| --------- | -------------------------------------------------------- |
| 0         | No new findings detected. Baseline findings are allowed. |
| 1         | One or more new non-baseline findings detected.          |
| Other     | Runtime or execution error.                              |

---

## Triage Report Ordering

Findings in `artifacts/triage.md` are ordered deterministically using:

1. Severity (highest priority first)
2. File path (ascending alphabetical order)
3. Secret value (final tie-breaker)

Only the top five findings are included in the report.

---

## Tuning Choices

The Gitleaks configuration includes explicit tuning choices:

* Added custom detection rules to create deterministic findings for testing.
* Excluded generated artifacts from scanning to avoid rescanning output files.
* Used an explicit baseline file to suppress known and accepted findings.
* Added deterministic sorting and prioritization to improve review efficiency.

---

## Generate Reports Individually

Run secrets scan:

```bash
python3 scripts/scan_secrets.py
```

Generate triage report only:

```bash
python3 scripts/triage_report.py
```

