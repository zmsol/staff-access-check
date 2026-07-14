#!/usr/bin/env python3
"""
saas_audit_cleanse.py — SaaS License & Access Compliance Auditor

Cross-references corporate SaaS user rosters against a master active HR
payroll CSV to catch orphaned licenses, stale/inactive access, and other
SOC 2 compliance risks.

Zero telemetry enforced: no networking libraries imported.  All processing
is 100 % local in memory.

Usage:
  python saas_audit_cleanse.py /path/to/audit_folder

The audit folder must contain:
  - hr_master.csv  (fields: first_name, last_name, email, status)
  - One or more SaaS CSV files (any name, any number of columns —
    the tool auto-detects email-like and name-like columns).

Output:
  access_review_report.html  — placed in the same audit folder.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import pandas as pd
import rapidfuzz

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_HR_FILENAME: str = "hr_master.csv"
_REPORT_FILENAME: str = "access_review_report.html"
_FUZZY_THRESHOLD: float = 85.0

_EMAIL_ALIASES: Tuple[str, ...] = (
    "email", "e-mail", "mail", "email address", "user email",
    "user_email", "emailaddress", "e mail", "email_addr", "emailaddr",
)
_NAME_ALIASES: Tuple[str, ...] = (
    "name", "full name", "full_name", "display name", "display_name",
    "user name", "username", "user_name",
)
_FIRST_NAME_ALIASES: Tuple[str, ...] = (
    "first name", "first_name", "firstname", "given name", "given_name",
    "fname",
)
_LAST_NAME_ALIASES: Tuple[str, ...] = (
    "last name", "last_name", "lastname", "surname", "family name",
    "family_name", "lname",
)

# ---------------------------------------------------------------------------
# Path obfuscation — masks absolute system host paths in all diagnostic
# output so exception/log messages never reveal the running user's
# directory tree.
# ---------------------------------------------------------------------------

_HOME_DIR: str = str(Path.home())
_KNOWN_PATH_PREFIXES: List[Tuple[str, str]] = [
    (_HOME_DIR, "<home>"),
]
_cwd = str(Path.cwd().resolve())
if _cwd != _HOME_DIR and _cwd.startswith("/"):
    _KNOWN_PATH_PREFIXES.append((_cwd, "<cwd>"))
_KNOWN_PATH_PREFIXES.sort(key=lambda x: -len(x[0]))


def _obfuscate_path(msg: str) -> str:
    """Replace any occurrence of a known host-path prefix with a safe
    symbolic label so exception/log text never reveals absolute system
    paths."""
    for prefix, label in _KNOWN_PATH_PREFIXES:
        msg = msg.replace(prefix, label)
    msg = re.sub(
        r"""(?x)
        (?:
          /home/[^/\s"']+(?:/[^\s"']*)?
          |
          /Users/[^/\s"']+(?:/[^\s"']*)?
          |
          /tmp/[^\s"']*
          |
          /var/folders/[^\s"']*
        )""",
        "<obfuscated>",
        msg,
    )
    return msg


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class HRRecord:
    """A single employee row from the HR master payroll CSV."""

    first_name: str
    last_name: str
    email: str
    status: str  # "Active", "Terminated", "On Leave", etc.


@dataclass
class SaaSUser:
    """A single user row from a SaaS platform export CSV."""

    platform: str
    email: str
    name: str
    first_name: str
    last_name: str
    raw_row: Dict[str, Any]
    source_file: str


@dataclass
class MatchResult:
    """Outcome of matching one SaaS user against HR records."""

    saas_user: SaaSUser
    hr_match: Optional[HRRecord]
    match_method: str
    match_score: float
    classification: str  # "ok", "orphaned", "stale"


# ---------------------------------------------------------------------------
# Safe path helpers
# ---------------------------------------------------------------------------


def _resolve_folder(raw: str) -> Path:
    """Resolve and validate the input folder path.

    Ensures the path is absolute, exists, and is a directory.  All error
    messages are path-obfuscated to avoid leaking the host tree.
    """
    try:
        p = Path(raw).resolve(strict=False)
    except Exception as exc:
        print(
            f"[!] Failed to resolve folder: {_obfuscate_path(str(exc))}",
            file=sys.stderr,
        )
        sys.exit(1)

    if not p.is_dir():
        print("[!] Input path does not exist or is not a directory.", file=sys.stderr)
        sys.exit(1)

    return p


def _resolve_csv(folder: Path, filename: str) -> Optional[Path]:
    """Resolve a CSV file path inside *folder*; return ``None`` if absent.
    All error messages are path-obfuscated."""
    candidate = (folder / filename).resolve()
    try:
        candidate.relative_to(folder)
    except ValueError:
        safe = _obfuscate_path(str(candidate))
        print(
            f"[!] Security error: file '{safe}' escapes the audit folder.",
            file=sys.stderr,
        )
        sys.exit(1)
    return candidate if candidate.is_file() else None


def _validate_paths(folder: Path) -> Path:
    """Ensure the folder contains hr_master.csv; return its resolved path."""
    hr_path = _resolve_csv(folder, _HR_FILENAME)
    if hr_path is None:
        print(
            f"[!] HR master file '{_HR_FILENAME}' not found in the audit folder.",
            file=sys.stderr,
        )
        sys.exit(1)
    return hr_path


# ---------------------------------------------------------------------------
# CSV parsing helpers
# ---------------------------------------------------------------------------


def _normalise_col(col: str) -> str:
    return re.sub(r"\s+", " ", col.strip().lower())


def _find_column(df: pd.DataFrame, aliases: Tuple[str, ...]) -> Optional[str]:
    norm_map = {_normalise_col(c): c for c in df.columns}
    for alias in aliases:
        norm = _normalise_col(alias)
        if norm in norm_map:
            return norm_map[norm]
    return None


def _load_hr(path: Path) -> List[HRRecord]:
    """Load the HR master CSV and return validated records.  Error messages
    are path-obfuscated."""
    try:
        df = pd.read_csv(path, dtype=str, keep_default_na=False)
    except Exception as exc:
        print(
            f"[!] Failed to read HR CSV: {_obfuscate_path(str(exc))}",
            file=sys.stderr,
        )
        sys.exit(1)

    df.columns = [_normalise_col(c) for c in df.columns]
    required = {"first_name", "last_name", "email", "status"}
    missing = required - set(df.columns)
    if missing:
        print(
            f"[!] HR CSV missing required columns: {', '.join(sorted(missing))}",
            file=sys.stderr,
        )
        sys.exit(1)

    records: List[HRRecord] = []
    for _, row in df.iterrows():
        records.append(
            HRRecord(
                first_name=str(row["first_name"]).strip(),
                last_name=str(row["last_name"]).strip(),
                email=str(row["email"]).strip().lower(),
                status=str(row["status"]).strip(),
            )
        )
    return records


def _load_saas_csv(path: Path, platform: str) -> List[SaaSUser]:
    """Load a single SaaS CSV into a list of user records.  Error messages
    use filename only, never the full path."""
    try:
        df = pd.read_csv(path, dtype=str, keep_default_na=False)
    except Exception as exc:
        print(
            f"  [!] Skipping '{path.name}' — read error: {_obfuscate_path(str(exc))}",
            file=sys.stderr,
        )
        return []

    if df.empty:
        print(f"  [!] Skipping '{path.name}' — empty file.", file=sys.stderr)
        return []

    raw_cols = list(df.columns)
    df.columns = [_normalise_col(c) for c in df.columns]

    email_col = _find_column(df, _EMAIL_ALIASES)
    name_col = _find_column(df, _NAME_ALIASES)
    fname_col = _find_column(df, _FIRST_NAME_ALIASES)
    lname_col = _find_column(df, _LAST_NAME_ALIASES)

    if email_col is None and name_col is None and fname_col is None:
        print(
            f"  [!] Skipping '{path.name}' — no email/name column detected "
            f"(columns: {raw_cols}).",
            file=sys.stderr,
        )
        return []

    users: List[SaaSUser] = []
    for _, row in df.iterrows():
        email = str(row.get(email_col, "")).strip().lower() if email_col else ""
        name_raw = str(row.get(name_col, "")).strip() if name_col else ""
        first_name = str(row.get(fname_col, "")).strip() if fname_col else ""
        last_name = str(row.get(lname_col, "")).strip() if lname_col else ""

        if not first_name and not last_name and name_raw:
            tokens = name_raw.strip().split(None, 1)
            first_name = tokens[0] if len(tokens) >= 1 else ""
            last_name = tokens[1] if len(tokens) >= 2 else ""

        raw_row: Dict[str, Any] = {}
        for orig_col, val in zip(raw_cols, row.values):
            raw_row[orig_col] = str(val)

        users.append(
            SaaSUser(
                platform=platform,
                email=email or "",
                name=name_raw,
                first_name=first_name,
                last_name=last_name,
                raw_row=raw_row,
                source_file=path.name,
            )
        )

    return users


# ---------------------------------------------------------------------------
# Matching engine
# ---------------------------------------------------------------------------


def _normalise_name_token(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower().strip())


def _fuzzy_name_score(saas_user: SaaSUser, hr: HRRecord) -> float:
    saas_first = _normalise_name_token(saas_user.first_name)
    saas_last = _normalise_name_token(saas_user.last_name)
    hr_first = _normalise_name_token(hr.first_name)
    hr_last = _normalise_name_token(hr.last_name)

    if not saas_first and not saas_last:
        return 0.0

    scores: List[float] = []
    if saas_first and hr_first:
        scores.append(rapidfuzz.fuzz.token_sort_ratio(saas_first, hr_first))
    if saas_last and hr_last:
        scores.append(rapidfuzz.fuzz.token_sort_ratio(saas_last, hr_last))
    if saas_first and saas_last and hr_first and hr_last:
        scores.append(
            rapidfuzz.fuzz.token_sort_ratio(
                f"{saas_first} {saas_last}",
                f"{hr_first} {hr_last}",
            )
        )
    if saas_user.name and (hr_first or hr_last):
        combined_hr = f"{hr_first} {hr_last}".strip()
        if combined_hr:
            scores.append(
                rapidfuzz.fuzz.token_sort_ratio(
                    _normalise_name_token(saas_user.name),
                    _normalise_name_token(combined_hr),
                )
            )
    return max(scores) if scores else 0.0


def _match(
    saas_user: SaaSUser,
    hr_records: List[HRRecord],
) -> MatchResult:
    """Find the best HR match for a single SaaS user."""
    # 1. Exact email
    if saas_user.email:
        for hr in hr_records:
            if hr.email == saas_user.email:
                classification = "ok" if _is_active(hr.status) else "stale"
                return MatchResult(
                    saas_user=saas_user,
                    hr_match=hr,
                    match_method="email",
                    match_score=100.0,
                    classification=classification,
                )
    # 2. Fuzzy name match
    best_score = 0.0
    best_hr: Optional[HRRecord] = None
    for hr in hr_records:
        score = _fuzzy_name_score(saas_user, hr)
        if score > best_score:
            best_score = score
            best_hr = hr
    if best_score >= _FUZZY_THRESHOLD and best_hr is not None:
        return MatchResult(
            saas_user=saas_user,
            hr_match=best_hr,
            match_method="fuzzy",
            match_score=round(best_score, 1),
            classification="orphaned",
        )
    # 3. No match
    return MatchResult(
        saas_user=saas_user,
        hr_match=None,
        match_method="none",
        match_score=0.0,
        classification="orphaned",
    )


def _is_active(status: str) -> bool:
    return status.strip().lower() in {"active", "full-time", "contractor"}


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_EM_DASH = "\u2014"
_LOCK_EMOJI = "\U0001F512"
_RED_SQUARE = "\U0001F7E5"
_YELLOW_SQUARE = "\U0001F7E1"
_CHECK_MARK = "\u2705"
_CHECK = "\u2713"
_WARN = "\u26A0"
_CROSS = "\u2717"
_BULLET = "\u2022"
_RIGHT_ARROW = "\u2192"

_SENTINEL_NA = _EM_DASH


def _build_html(
    results: List[MatchResult],
    platforms: List[str],
    audit_folder_label: str,
) -> str:
    """Generate the standalone HTML audit report.

    The ``audit_folder_label`` is already path-obfuscated at the call site
    so no absolute host path appears in the generated HTML.
    """
    orphaned = [r for r in results if r.classification == "orphaned"]
    stale = [r for r in results if r.classification == "stale"]
    ok_count = len([r for r in results if r.classification == "ok"])
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def _row(r: MatchResult, idx: int) -> str:
        saas = r.saas_user
        hr = r.hr_match
        hr_info = (
            f"{hr.first_name} {hr.last_name} &lt;{hr.email}&gt; [{hr.status}]"
            if hr
            else _SENTINEL_NA
        )
        method_icon = {
            "email": "\U0001f4e7",
            "fuzzy": "\U0001f50d",
            "none": "\u274c",
        }.get(r.match_method, "")
        row_class = "orphaned" if r.classification == "orphaned" else "stale"
        email_display = saas.email if saas.email else _SENTINEL_NA
        return textwrap.dedent(f"""\
        <tr class='{row_class}'>
          <td>{idx}</td>
          <td>{saas.platform}</td>
          <td>{saas.source_file}</td>
          <td>{email_display}</td>
          <td>{saas.first_name} {saas.last_name}</td>
          <td>{hr_info}</td>
          <td>{method_icon} {r.match_method} ({r.match_score:.0f}%)</td>
        </tr>""")

    orphaned_rows = "\n".join(_row(r, i + 1) for i, r in enumerate(orphaned))
    stale_rows = "\n".join(_row(r, i + 1) for i, r in enumerate(stale))
    platform_list = ", ".join(sorted(set(platforms)))

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC 2 Access Review Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #f5f7fa; color: #1a1a2e; padding: 2rem; }}
  h1, h2, h3 {{ margin-bottom: 0.5rem; }}
  .summary {{ background: #fff; border-radius: 12px; padding: 1.5rem 2rem; box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 2rem; }}
  .summary-grid {{ display: flex; gap: 1.5rem; flex-wrap: wrap; margin-top: 1rem; }}
  .stat-card {{ flex: 1; min-width: 120px; background: #f8f9fc; border-radius: 10px; padding: 1rem; text-align: center; }}
  .stat-card .num {{ font-size: 2rem; font-weight: 700; }}
  .stat-card .label {{ font-size: 0.85rem; color: #6b7280; margin-top: 0.25rem; }}
  .stat-card.danger .num {{ color: #dc2626; }}
  .stat-card.warning .num {{ color: #d97706; }}
  .stat-card.ok .num {{ color: #16a34a; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 12px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.08); margin-bottom: 2.5rem; }}
  th, td {{ padding: 0.75rem 1rem; text-align: left; font-size: 0.9rem; }}
  th {{ background: #1e293b; color: #fff; font-weight: 600; position: sticky; top: 0; }}
  tr:nth-child(even) {{ background: #f8fafc; }}
  tr.orphaned {{ border-left: 4px solid #dc2626; }}
  tr.stale {{ border-left: 4px solid #d97706; }}
  td {{ vertical-align: top; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; }}
  .badge-orphaned {{ background: #fee2e2; color: #dc2626; }}
  .badge-stale {{ background: #fef3c7; color: #d97706; }}
  .badge-ok {{ background: #dcfce7; color: #16a34a; }}
  .meta {{ color: #6b7280; font-size: 0.85rem; margin-bottom: 1.5rem; }}
  footer {{ text-align: center; color: #9ca3af; font-size: 0.8rem; margin-top: 3rem; }}
</style>
</head>
<body>

<h1>{_LOCK_EMOJI} SOC 2 Access Review Report</h1>
<div class="meta">Generated: {now} &middot; Audit folder: {audit_folder_label}</div>
<div class="meta">Platforms: {platform_list}</div>

<div class="summary">
  <h2>Summary</h2>
  <div class="summary-grid">
    <div class="stat-card danger">
      <div class="num">{len(orphaned)}</div>
      <div class="label">Orphaned Accounts</div>
    </div>
    <div class="stat-card warning">
      <div class="num">{len(stale)}</div>
      <div class="label">Stale / Inactive Access</div>
    </div>
    <div class="stat-card ok">
      <div class="num">{ok_count}</div>
      <div class="label">Compliant Users</div>
    </div>
    <div class="stat-card">
      <div class="num">{len(results)}</div>
      <div class="label">Total SaaS Records</div>
    </div>
  </div>
</div>

{"<h2>" + _RED_SQUARE + " Orphaned Accounts</h2>" if orphaned else ""}
{"<p>No HR match found " + _EM_DASH + " potential ungoverned license or offboarding gap.</p>" if orphaned else ""}
{'<table><thead><tr><th>#</th><th>Platform</th><th>Source File</th><th>Email</th><th>Name</th><th>Closest HR Record</th><th>Match</th></tr></thead><tbody>' + orphaned_rows + '</tbody></table>' if orphaned else ""}

{"<h2>" + _YELLOW_SQUARE + " Stale / Inactive Access</h2>" if stale else ""}
{"<p>HR record exists but the employee is not in an active status " + _EM_DASH + " access should be revoked or reviewed.</p>" if stale else ""}
{'<table><thead><tr><th>#</th><th>Platform</th><th>Source File</th><th>Email</th><th>Name</th><th>HR Record</th><th>Match</th></tr></thead><tbody>' + stale_rows + '</tbody></table>' if stale else ""}

{"<h2>" + _CHECK_MARK + " All Clear</h2><p>Every SaaS user was matched to an active HR record. No orphaned or stale accounts detected.</p>" if not orphaned and not stale else ""}

<footer>
  Report generated by <strong>SaaS Audit Cleanse</strong> &middot; Zero telemetry &middot; Local processing only
</footer>

</body>
</html>"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description=textwrap.dedent(
            """\
            Cross-reference SaaS user rosters against an HR master payroll
            CSV to detect orphaned licenses and stale/inactive access for
            SOC 2 compliance reviews.

            Zero telemetry """ + _EM_DASH + """ no network calls of any kind.
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "folder",
        type=str,
        help=(
            "Path to the audit folder containing hr_master.csv and one or "
            "more SaaS platform CSV exports."
        ),
    )
    args = parser.parse_args()

    folder = _resolve_folder(args.folder)
    hr_path = _validate_paths(folder)

    # Use obfuscated labels for user-facing path display.
    folder_label = _obfuscate_path(str(folder))
    print(f"[*] Audit folder: {folder_label}")
    print(f"[*] HR master:    {_HR_FILENAME}")

    hr_records = _load_hr(hr_path)
    print(f"[*] HR records loaded: {len(hr_records)}")

    saas_files: List[Path] = []
    try:
        for child in sorted(folder.iterdir()):
            resolved = child.resolve()
            try:
                resolved.relative_to(folder)
            except ValueError:
                continue
            if (
                resolved.is_file()
                and resolved.suffix.lower() == ".csv"
                and resolved.name != _HR_FILENAME
            ):
                saas_files.append(resolved)
    except PermissionError as exc:
        print(
            f"[!] Cannot list folder contents: {_obfuscate_path(str(exc))}",
            file=sys.stderr,
        )
        sys.exit(1)

    if not saas_files:
        print("[!] No SaaS CSV files found alongside hr_master.csv.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] SaaS platform files found: {len(saas_files)}")
    for f in saas_files:
        print(f"    {_BULLET} {f.name}")

    all_saas_users: List[SaaSUser] = []
    for f in saas_files:
        platform = f.stem.replace("_", " ").replace("-", " ").strip().lower()
        users = _load_saas_csv(f, platform)
        print(f"    {f.name}: {len(users)} user(s) loaded")
        all_saas_users.extend(users)

    if not all_saas_users:
        print("[!] No SaaS user records could be parsed.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Matching {len(all_saas_users)} SaaS records against "
          f"{len(hr_records)} HR records {_RIGHT_ARROW}")

    results: List[MatchResult] = []
    for su in all_saas_users:
        results.append(_match(su, hr_records))

    orphaned = [r for r in results if r.classification == "orphaned"]
    stale = [r for r in results if r.classification == "stale"]
    ok = [r for r in results if r.classification == "ok"]
    platforms = sorted({r.saas_user.platform for r in results})

    print(f"    {_CHECK} Compliant:  {len(ok)}")
    print(f"    {_WARN} Stale:      {len(stale)}")
    print(f"    {_CROSS} Orphaned:   {len(orphaned)}")

    html = _build_html(results, platforms, folder_label)
    report_path = (folder / _REPORT_FILENAME).resolve()
    try:
        report_path.relative_to(folder)
    except ValueError:
        print("[!] Security error: report path escapes audit folder.", file=sys.stderr)
        sys.exit(1)

    try:
        report_path.write_text(html, encoding="utf-8")
    except OSError as exc:
        print(
            f"[!] Failed to write report: {_obfuscate_path(str(exc))}",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"[{_CHECK}] Report written to: <audit_folder>/{_REPORT_FILENAME}")

    if orphaned or stale:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
