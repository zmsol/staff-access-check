# 🔒 SaaS Audit Cleanse

**The 5-second SOC 2 user access review utility.**

The soul-crushing exercise of manually cross-referencing hundreds of user rows across multiple SaaS apps via Excel `VLOOKUP` to prep for a SOC 2 audit — automated in one command.

**Value:** Zero infrastructure footprint. Runs locally on your machine, matching users dynamically while maintaining absolute data privacy boundaries.

---

## The Problem

Audit prep means exporting CSVs from every SaaS platform (Slack, GitHub, Okta, Google Workspace...), opening the HR payroll export, and spending hours on `VLOOKUP` gymnastics. One missed terminated employee with active GitHub access = compliance finding.

```
HR Payroll (500 rows)    x    Slack (300 users)
                          x    GitHub (200 users)
                          x    Okta (400 users)
                          =    3,200 manual cross-references
                          =    At least one miss
```

## What It Does

Drop your SaaS export CSVs alongside your HR master payroll file into one folder. Run one command. Get a styled HTML report showing exactly which accounts are orphaned and which belong to terminated/on-leave employees.

```
$ python saas_audit_cleanse.py ./audit_folder_2026Q2/
[*] Audit folder: <obfuscated>
[*] HR records loaded: 487
[*] 6 SaaS platform files found
[*] Matching 1,234 SaaS records against 487 HR records ...
    v Compliant:  1,128
    W Stale:       89
    x Orphaned:     17
[V] Report written to: <audit_folder>/access_review_report.html
```

## Matching Engine

| Priority | Method | Classification |
|----------|--------|----------------|
| 1 | Exact email match, HR status = Active | **Compliant** |
| 2 | Exact email match, HR status = Terminated/Leave | **Stale** -- access should be revoked |
| 3 | No email match, but fuzzy name match >= 85% (rapidfuzz) | **Orphaned** -- personal account risk |
| 4 | No match at all | **Orphaned** -- no HR record found |

Fuzzy matching catches employees using personal email addresses on corporate SaaS platforms.

## Security & Privacy

- **Zero telemetry** -- no `requests`, no `urllib`, no HTTP, no sockets
- **100% local** -- all processing in memory via `pandas` + `rapidfuzz`
- **Path locked** -- every CSV is `Path.resolve()`'d and verified via `.relative_to()` against the audit folder
- **No exfiltration** -- the HTML report never leaves your machine unless you choose to share it

---

## Quick Start

```bash
pip install pandas rapidfuzz

# Prepare your audit folder
ls ./audit/
# hr_master.csv   slack_users.csv   github_users.csv   okta_users.csv

# Run the audit
python saas_audit_cleanse.py ./audit/

# Open the report
open ./audit/access_review_report.html
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All SaaS users matched to active HR records -- clean |
| 1 | Orphaned or stale accounts found -- review the HTML report |

---

## Why This Exists

Every SaaS platform has its own user export format. Every HR system has its own status taxonomy. Manual cross-referencing doesn't scale, and the cost of a missed offboarding gap is a qualified audit finding.

SaaS Audit Cleanse exists because *building manual bridges between applications introduces risk* -- and audit evidence shouldn't be an Excel file on someone's desktop.

**Built by [ZM Solutions](https://zmsol.github.io)** -- we fix the operational gaps that off-the-shelf software can't.
*Built by [Z&M Solutions](https://zmsol.github.io) — operational systems for professional teams.*
