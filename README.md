# Staff Access Check

Find ex-employees who still have access to your company apps.

## The problem

When someone leaves your company, their access to Slack, GitHub, Okta, Google Workspace, and other SaaS tools needs to be cut off. Doing that by hand means exporting CSVs from every platform, opening your HR payroll file, and cross-referencing hundreds of rows in Excel. One missed terminated employee with active GitHub access is a compliance finding waiting to happen.

## What Staff Access Check does

Drop your SaaS export CSVs and your HR master file into one folder, run one command, and get a clean HTML report showing exactly which accounts are active, stale (employed but should be reviewed), or orphaned (no HR record at all). No VLOOKUP gymnastics, no hours of manual work.

## Who it's for

Companies preparing for SOC 2 or other compliance audits, HR teams handling offboarding, and IT administrators who need to prove that terminated employees no longer have system access.

## Privacy & security

- **Zero telemetry** — no usage data, no phone home, no tracking
- **100% local** — all processing happens in memory on your machine
- **No HTTP, no sockets, no cloud APIs** — nothing leaves your computer
- **No exfiltration** — the HTML report stays on your machine unless you choose to share it
- Every file path is locked to your audit folder — no accidental access to other data

## How to use

```bash
# Install dependencies
pip install pandas rapidfuzz

# Put your files in one folder
# hr_master.csv, slack_users.csv, github_users.csv, okta_users.csv

# Run the audit
python staff_access_check.py ./audit/

# Open the report
open ./audit/access_review_report.html
```

The report classifies every account as Compliant, Stale, or Orphaned so you know exactly who needs access revoked.

## License

MIT. Audit-ready access reviews that keep your data private.
