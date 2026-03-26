#!/usr/bin/env python3
"""
interpret.py — rl-protect report task interpreter

Extracts a specific slice of an rl-protect JSON report and prints it as
structured terminal output. Each subcommand targets a specific area of the
report, providing fast and deterministic extraction without parsing large
JSON blobs inline.

Usage:
    python interpret.py <task> [--package <purl>] [--report <path>] [--no-error-code]

Tasks:
    vulnerabilities     List all CVEs across all packages (or a specific one).
    indicators          List behavior indicators and file classifications.
    malware             List malicious/suspicious file classifications.
    overrides           Show full audit trail for all assessment and policy overrides.
    governance          Show governance allow/block decisions.
    dependencies        List direct dependencies and their scan status.
    errors              List packages that could not be scanned.

Options:
    --package <purl>    Filter output to a specific package PURL substring match.
    --report  <path>    Path to the report file. Default: rl-protect.report.json
    --no-error-code     Suppress exit code 1 (REJECT found). Exit code 2 is never suppressed.
    --json              Output results as JSON instead of formatted terminal tables.

Exit codes:
    0   Task completed. No REJECT recommendations found in filtered output.
    1   One or more REJECT recommendations found in filtered output.
    2   Report file not found, invalid JSON, or unknown task.
"""

import argparse
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CVSS_LABEL = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.0, "low"),
]

STATUS_ICON         = {"pass": "✅", "warning": "⚠️", "fail": "❌"}
STATUS_LABEL        = {"pass": "PASS", "warning": "WARN", "fail": "FAIL"}
ASSESSMENTS         = ["secrets", "licenses", "vulnerabilities", "hardening", "tampering", "malware", "repository"]
RECOMMENDATION_ICON = {"APPROVE": "🟢", "REJECT": "🔴"}

# Display priority when multiple categories share the same worst grade.
# Repository is handled separately — it is always final if present and non-pass.
ASSESSMENT_PRIORITY = ["malware", "tampering", "vulnerabilities", "secrets", "hardening", "licenses"]


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def cvss_label(score: float) -> str:
    for threshold, label in CVSS_LABEL:
        if score >= threshold:
            return label
    return "unknown"


def load_report(path: Path) -> dict:
    if not path.exists():
        raise RuntimeError(f"report file not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON in {path}: {exc}") from exc


def get_packages(report: dict) -> list:
    return report.get("analysis", {}).get("report", {}).get("packages", [])


def get_errors(report: dict) -> list:
    return report.get("analysis", {}).get("report", {}).get("errors", [])


def filter_packages(packages: list, purl_filter: str) -> list:
    if not purl_filter:
        return packages
    f = purl_filter.lower()
    return [p for p in packages if f in p.get("purl", "").lower()]


def sha256_of(hashes: list) -> str:
    for algo, val in hashes:
        if algo.lower() == "sha256":
            return val
    return "—"


def format_date(ts: str) -> str:
    return ts[:10] if ts else "—"


def meaningful_override(entry: dict) -> dict | None:
    """Return the override dict if it changed the status, otherwise None."""
    override = entry.get("override")
    if override and override.get("to_status") != entry.get("status"):
        return override
    return None


def has_meaningful_overrides(assessment: dict) -> bool:
    return any(meaningful_override(assessment.get(k, {})) for k in ASSESSMENTS)


# ---------------------------------------------------------------------------
# Unicode display-width helpers  (identical to summarize.py)
# ---------------------------------------------------------------------------

_DOUBLE_WIDTH_RANGES = [
    (0x1100,  0x115F),
    (0x2600,  0x27BF),   # Misc Symbols + Dingbats: ⚠ ✅ ❌ ❓ and friends
    (0x2E80,  0x303E),
    (0x3041,  0x33BF),
    (0x3400,  0x9FFF),
    (0xA000,  0xA4CF),
    (0xAC00,  0xD7AF),
    (0xF900,  0xFAFF),
    (0xFE10,  0xFE1F),
    (0xFE30,  0xFE4F),
    (0xFF01,  0xFF60),
    (0xFFE0,  0xFFE6),
    (0x1B000, 0x1B0FF),
    (0x1F004, 0x1F004),
    (0x1F0CF, 0x1F0CF),
    (0x1F200, 0x1F2FF),
    (0x1F300, 0x1F9FF),
    (0x1FA00, 0x1FAFF),
    (0x20000, 0x2EBEF),
    (0x2F800, 0x2FA1F),
]

_VS16 = 0xFE0F


def char_width(c: str) -> int:
    cp = ord(c)
    if cp == _VS16:
        return 0
    for lo, hi in _DOUBLE_WIDTH_RANGES:
        if lo <= cp <= hi:
            return 2
    return 1


def dw(s: str) -> int:
    return sum(char_width(c) for c in s)


def rpad(s: str, width: int) -> str:
    return s + " " * max(0, width - dw(s))


# ---------------------------------------------------------------------------
# Box-drawing table renderer
# ---------------------------------------------------------------------------

def render_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    """Render a multi-column Unicode box-drawing table with dynamic column widths."""
    n = len(headers)
    col_w = [dw(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row[:n]):
            col_w[i] = max(col_w[i], dw(str(cell)))

    def hdiv(left, mid, right):
        return left + mid.join("─" * (w + 2) for w in col_w) + right

    def data_row(cells):
        padded = list(cells) + [""] * (n - len(cells))
        parts  = [f" {rpad(str(c), w)} " for c, w in zip(padded, col_w)]
        return "│" + "│".join(parts) + "│"

    out = [hdiv("┌", "┬", "┐")]
    out.append(data_row(headers))
    out.append(hdiv("├", "┼", "┤"))
    for row in rows:
        out.append(data_row(row))
    out.append(hdiv("└", "┴", "┘"))
    return out


def pkg_header(purl: str, rec: str) -> str:
    icon = RECOMMENDATION_ICON.get(rec, "❓")
    return f"{icon} {rec}  →  {purl}"


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------

def task_vulnerabilities(packages: list) -> int:
    any_reject   = False
    any_override = False
    found_any    = False
    first_out    = True

    for pkg in packages:
        purl       = pkg.get("purl", "unknown")
        analysis   = pkg.get("analysis", {})
        rec        = analysis.get("recommendation", "—")
        report_url = analysis.get("report", "")
        vulns      = analysis.get("vulnerabilities", {})
        if rec == "REJECT":
            any_reject = True
        if not vulns:
            continue

        found_any = True
        ov_entry  = analysis.get("assessment", {}).get("vulnerabilities", {})
        ov        = meaningful_override(ov_entry)
        if ov:
            any_override = True

        if not first_out:
            print()
        first_out = False

        print(pkg_header(purl, rec))

        rows = []
        for cve_id, vuln in vulns.items():
            score = vuln.get("cvss", {}).get("baseScore", 0.0)
            flags = ", ".join(vuln.get("exploit", [])) or "—"
            rows.append([cve_id, f"{score:.2f} ({cvss_label(score)})", flags, vuln.get("summary", "—")])
        for line in render_table(["CVE / GHSA", "CVSS", "Exploit flags", "Summary"], rows):
            print(line)

        if ov:
            audit  = ov.get("audit", {})
            to_s   = STATUS_LABEL.get(ov.get("to_status", "—"), ov.get("to_status", "—"))
            author = audit.get("author", "—")
            date   = format_date(audit.get("timestamp", ""))
            reason = audit.get("reason", "—")
            print(f"  † Vulnerabilities overridden to {to_s} by {author} on {date} — \"{reason}\"")
        if report_url:
            print(f"  More info: {report_url}")

    if not found_any:
        print("No vulnerabilities found.")
    elif any_override:
        print()
        print("  † Policy override applied — run interpret.py overrides for the full audit trail.")

    return 1 if any_reject else 0


def task_indicators(packages: list) -> int:
    any_reject = False

    for i, pkg in enumerate(packages):
        purl            = pkg.get("purl", "unknown")
        analysis        = pkg.get("analysis", {})
        rec             = analysis.get("recommendation", "—")
        indicators      = analysis.get("indicators", {})
        classifications = analysis.get("classifications", [])
        violations      = analysis.get("policy", {}).get("violations", {})
        if rec == "REJECT":
            any_reject = True

        if i > 0:
            print()
        print(pkg_header(purl, rec))

        # Indicators
        print()
        print("  Indicators")
        if indicators:
            rows = [
                [ind_id, ind.get("description", "—"), str(ind.get("occurrences", "—"))]
                for ind_id, ind in indicators.items()
            ]
            for line in render_table(["ID", "Description", "Occurrences"], rows):
                print(line)
        else:
            print("  (No indicators found.)")

        # File classifications
        flagged = [c for c in classifications if c.get("status") in ("Malicious", "Suspicious")]
        print()
        print("  File classifications")
        if flagged:
            rows = [
                [c.get("status", "—"), c.get("result", "—"), sha256_of(c.get("hashes", []))]
                for c in flagged
            ]
            for line in render_table(["Status", "Classification", "SHA-256"], rows):
                print(line)
        else:
            print("  (No malicious or suspicious files found.)")

        # Policy violations
        print()
        print("  Policy violations")
        if violations:
            rows = []
            for rule_id, v in violations.items():
                ov     = v.get("override")
                ov_str = f"Yes — by {ov.get('audit', {}).get('author', '—')}" if ov else "No"
                rows.append([rule_id, v.get("description", "—"), str(v.get("violations", "—")), ov_str])
            for line in render_table(["Rule", "Description", "Count", "Override"], rows):
                print(line)
        else:
            print("  (No policy violations found.)")

    return 1 if any_reject else 0


def task_malware(packages: list) -> int:
    any_reject = False

    for i, pkg in enumerate(packages):
        purl            = pkg.get("purl", "unknown")
        analysis        = pkg.get("analysis", {})
        rec             = analysis.get("recommendation", "—")
        report_url      = analysis.get("report", "")
        classifications = analysis.get("classifications", [])
        assessment      = analysis.get("assessment", {})
        malware_a       = assessment.get("malware", {})
        tampering_a     = assessment.get("tampering", {})
        governance      = analysis.get("policy", {}).get("governance", [])
        blocks          = [g for g in governance if g.get("status") == "blocked"]
        flagged         = [c for c in classifications if c.get("status") in ("Malicious", "Suspicious")]
        if rec == "REJECT":
            any_reject = True

        if i > 0:
            print()
        print(pkg_header(purl, rec))

        # Malicious files
        print()
        if flagged:
            print("  Malicious files detected")
            rows = [
                [c.get("status", "—"), c.get("result", "—"), sha256_of(c.get("hashes", []))]
                for c in flagged
            ]
            for line in render_table(["Status", "Classification", "SHA-256"], rows):
                print(line)
        else:
            print("  (No malicious or suspicious files found.)")

        # Assessment
        m_icon = STATUS_ICON.get(malware_a.get("status", "pass"), "❓")
        t_icon = STATUS_ICON.get(tampering_a.get("status", "pass"), "❓")
        print()
        print("  Assessment")
        rows = [
            ["Malware",   f"{m_icon} {malware_a.get('label', '—')}"],
            ["Tampering", f"{t_icon} {tampering_a.get('label', '—')}"],
        ]
        for line in render_table(["Check", "Result"], rows):
            print(line)

        # Governance blocks
        if blocks:
            print()
            print("  Governance blocks")
            rows = [
                [b.get("status", "—"), b.get("reason", "—"), b.get("author", "—"), format_date(b.get("timestamp", ""))]
                for b in blocks
            ]
            for line in render_table(["Status", "Reason", "Author", "Date"], rows):
                print(line)

        if report_url:
            print(f"  More info: {report_url}")

    return 1 if any_reject else 0


def task_overrides(packages: list) -> int:
    any_reject = False
    first_out  = True

    for pkg in packages:
        purl       = pkg.get("purl", "unknown")
        analysis   = pkg.get("analysis", {})
        rec        = analysis.get("recommendation", "—")
        assessment = analysis.get("assessment", {})
        violations = analysis.get("policy", {}).get("violations", {})
        if rec == "REJECT":
            any_reject = True

        # Include all overrides in the audit trail (even no-ops)
        assessment_overrides = [
            (key, assessment[key])
            for key in ASSESSMENTS
            if assessment.get(key, {}).get("override")
        ]
        policy_overrides = [
            (rule_id, v)
            for rule_id, v in violations.items()
            if v.get("override")
        ]

        if not assessment_overrides and not policy_overrides:
            continue

        if not first_out:
            print()
        first_out = False

        print(pkg_header(purl, rec))

        if assessment_overrides:
            print()
            print("  Assessment overrides")
            rows = []
            for key, data in assessment_overrides:
                orig  = STATUS_LABEL.get(data.get("status", "—"), data.get("status", "—"))
                ov    = data["override"]
                to_s  = STATUS_LABEL.get(ov.get("to_status", "—"), ov.get("to_status", "—"))
                audit = ov.get("audit", {})
                rows.append([
                    key.capitalize(), orig, to_s,
                    audit.get("author", "—"),
                    format_date(audit.get("timestamp", "")),
                    audit.get("reason", "—"),
                ])
            for line in render_table(["Assessment", "Original", "Override", "Author", "Date", "Reason"], rows):
                print(line)

        if policy_overrides:
            print()
            print("  Policy overrides")
            rows = []
            for rule_id, v in policy_overrides:
                orig  = STATUS_LABEL.get(v.get("status", "—"), v.get("status", "—"))
                ov    = v["override"]
                to_s  = STATUS_LABEL.get(ov.get("to_status", "—"), ov.get("to_status", "—"))
                audit = ov.get("audit", {})
                rows.append([
                    rule_id, orig, to_s,
                    audit.get("author", "—"),
                    format_date(audit.get("timestamp", "")),
                    audit.get("reason", "—"),
                ])
            for line in render_table(["Rule", "Original", "Override", "Author", "Date", "Reason"], rows):
                print(line)

    if first_out:
        print("No overrides found.")

    return 1 if any_reject else 0


def task_governance(packages: list) -> int:
    any_reject = False
    first_out  = True

    for pkg in packages:
        purl       = pkg.get("purl", "unknown")
        analysis   = pkg.get("analysis", {})
        rec        = analysis.get("recommendation", "—")
        governance = analysis.get("policy", {}).get("governance", [])
        if rec == "REJECT":
            any_reject = True
        if not governance:
            continue

        if not first_out:
            print()
        first_out = False

        print(pkg_header(purl, rec))
        rows = [
            [g.get("status", "—"), g.get("reason", "—"), g.get("author", "—"), format_date(g.get("timestamp", ""))]
            for g in governance
        ]
        for line in render_table(["Status", "Reason", "Author", "Date"], rows):
            print(line)

    if first_out:
        print("No governance decisions found.")

    return 1 if any_reject else 0


def task_dependencies(packages: list) -> int:
    any_reject    = False
    scanned_purls = {p.get("purl", ""): p for p in packages}

    for i, pkg in enumerate(packages):
        purl       = pkg.get("purl", "unknown")
        analysis   = pkg.get("analysis", {})
        rec        = analysis.get("recommendation", "—")
        deps       = pkg.get("dependencies", [])
        dependents = pkg.get("dependents", 0)
        if rec == "REJECT":
            any_reject = True

        if i > 0:
            print()
        print(pkg_header(purl, rec))

        if not deps:
            print("  (No dependencies declared.)")
            if dependents:
                print(f"  {dependents} package{'s' if dependents != 1 else ''} "
                      f"{'rely' if dependents != 1 else 'relies'} on this")
            continue

        scanned_count = sum(1 for d in deps if d in scanned_purls)
        print(f"  {len(deps)} direct dependenc{'y' if len(deps) == 1 else 'ies'} · {scanned_count} scanned")

        rows        = []
        risk_notes  = []
        for dep_purl in deps:
            dep_pkg = scanned_purls.get(dep_purl)
            if dep_pkg:
                dep_analysis = dep_pkg.get("analysis", {})
                dep_rec      = dep_analysis.get("recommendation", "—")
                dep_assess   = dep_analysis.get("assessment", {})
                statuses     = [dep_assess.get(k, {}).get("status", "pass") for k in ASSESSMENTS]
                worst        = "fail" if "fail" in statuses else ("warning" if "warning" in statuses else "pass")
                worst_label  = STATUS_LABEL.get(worst, worst)
                ov_mark      = " †" if has_meaningful_overrides(dep_assess) else ""
                rec_cell     = dep_rec + ov_mark
                if dep_rec == "REJECT" or worst == "fail":
                    repo = dep_assess.get("repository", {})
                    if repo.get("status", "pass") != "pass":
                        risk_notes.append((dep_purl, dep_rec, worst_label, repo.get("label", "—")))
                    else:
                        for k in ASSESSMENT_PRIORITY:
                            if dep_assess.get(k, {}).get("status") == worst:
                                risk_notes.append((dep_purl, dep_rec, worst_label, dep_assess[k].get("label", "—")))
                                break
            else:
                dep_rec, worst_label, rec_cell = "—", "—", "—"

            rows.append([dep_purl, "Yes" if dep_pkg else "No", rec_cell, worst_label])

        for line in render_table(["Package", "Scanned", "Recommendation", "Worst status"], rows):
            print(line)

        if risk_notes:
            print()
            print("  Risk in dependency tree")
            for dep_purl, dep_rec, worst, label in risk_notes:
                print(f"  ❌ {dep_purl} — {dep_rec} / {worst} — {label}")

        if dependents:
            print(f"  {dependents} package{'s' if dependents != 1 else ''} "
                  f"{'rely' if dependents != 1 else 'relies'} on this")

    return 1 if any_reject else 0


def task_errors(report: dict) -> int:
    errors = get_errors(report)
    if not errors:
        print("No scan errors found.")
        return 0

    rows = [
        [e.get("purl", "unknown"), str(e.get("error", {}).get("code", "—")), str(e.get("error", {}).get("info", "—"))]
        for e in errors
    ]
    for line in render_table(["Package", "Error", "Detail"], rows):
        print(line)
    return 0


# ---------------------------------------------------------------------------
# JSON output functions
# ---------------------------------------------------------------------------

def task_vulnerabilities_json(packages: list) -> dict:
    result = {"task": "vulnerabilities", "packages": []}
    any_reject = False
    for pkg in packages:
        purl = pkg.get("purl", "unknown")
        analysis = pkg.get("analysis", {})
        rec = analysis.get("recommendation", "—")
        report_url = analysis.get("report", "")
        vulns = analysis.get("vulnerabilities", {})
        if rec == "REJECT":
            any_reject = True
        if not vulns:
            continue
        ov_entry = analysis.get("assessment", {}).get("vulnerabilities", {})
        ov = meaningful_override(ov_entry)
        pkg_data = {
            "purl": purl,
            "recommendation": rec,
            "report_url": report_url,
            "vulnerabilities": [
                {
                    "id": cve_id,
                    "cvss": vuln.get("cvss", {}).get("baseScore", 0.0),
                    "cvss_label": cvss_label(vuln.get("cvss", {}).get("baseScore", 0.0)),
                    "exploit_flags": vuln.get("exploit", []),
                    "summary": vuln.get("summary", ""),
                }
                for cve_id, vuln in vulns.items()
            ],
            "override": None,
        }
        if ov:
            audit = ov.get("audit", {})
            pkg_data["override"] = {
                "to_status": ov.get("to_status", ""),
                "author": audit.get("author", ""),
                "date": format_date(audit.get("timestamp", "")),
                "reason": audit.get("reason", ""),
            }
        result["packages"].append(pkg_data)
    result["exit_code"] = 1 if any_reject else 0
    return result


def task_indicators_json(packages: list) -> dict:
    result = {"task": "indicators", "packages": []}
    any_reject = False
    for pkg in packages:
        purl = pkg.get("purl", "unknown")
        analysis = pkg.get("analysis", {})
        rec = analysis.get("recommendation", "—")
        indicators = analysis.get("indicators", {})
        classifications = analysis.get("classifications", [])
        violations = analysis.get("policy", {}).get("violations", {})
        if rec == "REJECT":
            any_reject = True
        flagged = [c for c in classifications if c.get("status") in ("Malicious", "Suspicious")]
        pkg_data = {
            "purl": purl,
            "recommendation": rec,
            "indicators": [
                {"id": ind_id, "description": ind.get("description", ""), "occurrences": ind.get("occurrences", 0)}
                for ind_id, ind in indicators.items()
            ],
            "classifications": [
                {"status": c.get("status", ""), "result": c.get("result", ""), "sha256": sha256_of(c.get("hashes", []))}
                for c in flagged
            ],
            "policy_violations": [
                {
                    "rule_id": rule_id,
                    "description": v.get("description", ""),
                    "count": v.get("violations", 0),
                    "override": f"by {v['override'].get('audit', {}).get('author', '')}" if v.get("override") else None,
                }
                for rule_id, v in violations.items()
            ],
        }
        result["packages"].append(pkg_data)
    result["exit_code"] = 1 if any_reject else 0
    return result


def task_malware_json(packages: list) -> dict:
    result = {"task": "malware", "packages": []}
    any_reject = False
    for pkg in packages:
        purl = pkg.get("purl", "unknown")
        analysis = pkg.get("analysis", {})
        rec = analysis.get("recommendation", "—")
        report_url = analysis.get("report", "")
        classifications = analysis.get("classifications", [])
        assessment = analysis.get("assessment", {})
        malware_a = assessment.get("malware", {})
        tampering_a = assessment.get("tampering", {})
        governance = analysis.get("policy", {}).get("governance", [])
        blocks = [g for g in governance if g.get("status") == "blocked"]
        flagged = [c for c in classifications if c.get("status") in ("Malicious", "Suspicious")]
        if rec == "REJECT":
            any_reject = True
        pkg_data = {
            "purl": purl,
            "recommendation": rec,
            "report_url": report_url,
            "classifications": [
                {"status": c.get("status", ""), "result": c.get("result", ""), "sha256": sha256_of(c.get("hashes", []))}
                for c in flagged
            ],
            "assessment": {
                "malware": {"status": malware_a.get("status", "pass"), "label": malware_a.get("label", "")},
                "tampering": {"status": tampering_a.get("status", "pass"), "label": tampering_a.get("label", "")},
            },
            "governance_blocks": [
                {"status": b.get("status", ""), "reason": b.get("reason", ""), "author": b.get("author", ""), "date": format_date(b.get("timestamp", ""))}
                for b in blocks
            ],
        }
        result["packages"].append(pkg_data)
    result["exit_code"] = 1 if any_reject else 0
    return result


def task_overrides_json(packages: list) -> dict:
    result = {"task": "overrides", "packages": []}
    any_reject = False
    for pkg in packages:
        purl = pkg.get("purl", "unknown")
        analysis = pkg.get("analysis", {})
        rec = analysis.get("recommendation", "—")
        assessment = analysis.get("assessment", {})
        violations = analysis.get("policy", {}).get("violations", {})
        if rec == "REJECT":
            any_reject = True
        assessment_overrides = [
            (key, assessment[key])
            for key in ASSESSMENTS
            if assessment.get(key, {}).get("override")
        ]
        policy_overrides = [
            (rule_id, v)
            for rule_id, v in violations.items()
            if v.get("override")
        ]
        if not assessment_overrides and not policy_overrides:
            continue
        pkg_data = {
            "purl": purl,
            "recommendation": rec,
            "assessment_overrides": [],
            "policy_overrides": [],
        }
        for key, data in assessment_overrides:
            ov = data["override"]
            audit = ov.get("audit", {})
            pkg_data["assessment_overrides"].append({
                "assessment": key,
                "original_status": data.get("status", ""),
                "override_status": ov.get("to_status", ""),
                "author": audit.get("author", ""),
                "date": format_date(audit.get("timestamp", "")),
                "reason": audit.get("reason", ""),
            })
        for rule_id, v in policy_overrides:
            ov = v["override"]
            audit = ov.get("audit", {})
            pkg_data["policy_overrides"].append({
                "rule_id": rule_id,
                "original_status": v.get("status", ""),
                "override_status": ov.get("to_status", ""),
                "author": audit.get("author", ""),
                "date": format_date(audit.get("timestamp", "")),
                "reason": audit.get("reason", ""),
            })
        result["packages"].append(pkg_data)
    result["exit_code"] = 1 if any_reject else 0
    return result


def task_governance_json(packages: list) -> dict:
    result = {"task": "governance", "packages": []}
    any_reject = False
    for pkg in packages:
        purl = pkg.get("purl", "unknown")
        analysis = pkg.get("analysis", {})
        rec = analysis.get("recommendation", "—")
        governance = analysis.get("policy", {}).get("governance", [])
        if rec == "REJECT":
            any_reject = True
        if not governance:
            continue
        pkg_data = {
            "purl": purl,
            "recommendation": rec,
            "decisions": [
                {"status": g.get("status", ""), "reason": g.get("reason", ""), "author": g.get("author", ""), "date": format_date(g.get("timestamp", ""))}
                for g in governance
            ],
        }
        result["packages"].append(pkg_data)
    result["exit_code"] = 1 if any_reject else 0
    return result


def task_dependencies_json(packages: list) -> dict:
    result = {"task": "dependencies", "packages": []}
    any_reject = False
    scanned_purls = {p.get("purl", ""): p for p in packages}
    for pkg in packages:
        purl = pkg.get("purl", "unknown")
        analysis = pkg.get("analysis", {})
        rec = analysis.get("recommendation", "—")
        deps = pkg.get("dependencies", [])
        dependents = pkg.get("dependents", 0)
        if rec == "REJECT":
            any_reject = True
        scanned_count = sum(1 for d in deps if d in scanned_purls)
        pkg_data = {
            "purl": purl,
            "recommendation": rec,
            "dependency_count": len(deps),
            "scanned_count": scanned_count,
            "dependents": dependents,
            "dependencies": [],
            "risk_notes": [],
        }
        for dep_purl in deps:
            dep_pkg = scanned_purls.get(dep_purl)
            dep_entry = {"purl": dep_purl, "scanned": bool(dep_pkg)}
            if dep_pkg:
                dep_analysis = dep_pkg.get("analysis", {})
                dep_rec = dep_analysis.get("recommendation", "—")
                dep_assess = dep_analysis.get("assessment", {})
                statuses = [dep_assess.get(k, {}).get("status", "pass") for k in ASSESSMENTS]
                worst = "fail" if "fail" in statuses else ("warning" if "warning" in statuses else "pass")
                dep_entry["recommendation"] = dep_rec
                dep_entry["worst_status"] = worst
                dep_entry["has_overrides"] = has_meaningful_overrides(dep_assess)
                if dep_rec == "REJECT" or worst == "fail":
                    repo = dep_assess.get("repository", {})
                    if repo.get("status", "pass") != "pass":
                        pkg_data["risk_notes"].append({
                            "purl": dep_purl,
                            "recommendation": dep_rec,
                            "worst_status": worst,
                            "label": repo.get("label", ""),
                        })
                    else:
                        for k in ASSESSMENT_PRIORITY:
                            if dep_assess.get(k, {}).get("status") == worst:
                                pkg_data["risk_notes"].append({
                                    "purl": dep_purl,
                                    "recommendation": dep_rec,
                                    "worst_status": worst,
                                    "label": dep_assess[k].get("label", ""),
                                })
                                break
            else:
                dep_entry["recommendation"] = None
                dep_entry["worst_status"] = None
                dep_entry["has_overrides"] = False
            pkg_data["dependencies"].append(dep_entry)
        result["packages"].append(pkg_data)
    result["exit_code"] = 1 if any_reject else 0
    return result


def task_errors_json(report: dict) -> dict:
    errors = get_errors(report)
    return {
        "task": "errors",
        "exit_code": 0,
        "errors": [
            {"purl": e.get("purl", "unknown"), "code": e.get("error", {}).get("code", ""), "detail": e.get("error", {}).get("info", "")}
            for e in errors
        ],
    }


TASKS_JSON = {
    "vulnerabilities": task_vulnerabilities_json,
    "indicators":      task_indicators_json,
    "malware":         task_malware_json,
    "overrides":       task_overrides_json,
    "governance":      task_governance_json,
    "dependencies":    task_dependencies_json,
}


# ---------------------------------------------------------------------------
# Argument parsing and dispatch
# ---------------------------------------------------------------------------

TASKS = {
    "vulnerabilities": task_vulnerabilities,
    "indicators":      task_indicators,
    "malware":         task_malware,
    "overrides":       task_overrides,
    "governance":      task_governance,
    "dependencies":    task_dependencies,
}


def parse_args(argv: list) -> tuple:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("task")
    p.add_argument("--package", default="")
    p.add_argument("--report", type=Path, default=Path("rl-protect.report.json"))
    p.add_argument("--no-error-code", action="store_true")
    p.add_argument("--json", action="store_true", dest="json_output")
    a = p.parse_args(argv[1:])
    return a.task, a.package, a.report, a.no_error_code, a.json_output


def main():
    task, purl_filter, report_path, no_error_code, json_output = parse_args(sys.argv)
    try:
        report = load_report(report_path)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)

    if task == "errors":
        if json_output:
            result = task_errors_json(report)
            print(json.dumps(result, indent=2))
            sys.exit(0 if no_error_code else result["exit_code"])
        code = task_errors(report)
        sys.exit(0 if no_error_code else code)

    if task not in TASKS:
        print(f"Error: unknown task '{task}'. Valid tasks: {', '.join(TASKS)}", file=sys.stderr)
        sys.exit(2)

    packages = get_packages(report)
    packages = filter_packages(packages, purl_filter)

    if not packages:
        msg = "No packages found" + (f" matching '{purl_filter}'" if purl_filter else "") + "."
        if json_output:
            print(json.dumps({"task": task, "exit_code": 0, "packages": [], "message": msg}, indent=2))
        else:
            print(msg)
        sys.exit(0)

    if json_output:
        result = TASKS_JSON[task](packages)
        print(json.dumps(result, indent=2))
        sys.exit(0 if no_error_code else result["exit_code"])

    exit_code = TASKS[task](packages)
    sys.exit(0 if no_error_code else exit_code)


if __name__ == "__main__":
    main()
