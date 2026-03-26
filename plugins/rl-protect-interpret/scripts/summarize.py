#!/usr/bin/env python3
"""
summarize.py — rl-protect report summarizer

Reads an rl-protect JSON report and prints a compact terminal summary of every
package: recommendation, per-assessment status, override flags, and scan errors.

Usage:
    python summarize.py [report.json] [--json] [--no-error-code]

Arguments:
    report.json     Path to the rl-protect JSON report file.
                    Defaults to rl-protect.report.json in the current directory.

Options:
    --json          Output results as JSON instead of formatted terminal tables.
    --no-error-code Suppress exit code 1 (REJECT found).

Output:
    Unicode box-drawing table printed to stdout (default), or JSON with --json.

Exit codes:
    0   All packages APPROVE or no packages found.
    1   One or more packages REJECT.
    2   Report file not found or invalid JSON.
"""

import argparse
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ASSESSMENTS = ["secrets", "licenses", "vulnerabilities", "hardening", "tampering", "malware", "repository"]

STATUS_ICON = {
    "pass":    "✅",
    "warning": "⚠️",
    "fail":    "❌",
}

RECOMMENDATION_ICON = {
    "APPROVE": "🟢",
    "REJECT":  "🔴",
}

# Default column widths for the two-column assessment table.
# lc = left cell (label), rc = right cell (value), both include 1 char of right-padding.
# Box invariant: every row and the top/bottom border must be exactly (lc + rc + 3) chars wide.
#   box_top:      ┌ + ─*(lc+rc+1) + ┐  = lc+rc+3 ✓
#   two-col row:  │_label_│_value_│    = 1+lc+1+rc+1 = lc+rc+3 ✓
#   single-col:   │_content_│          = 1+(lc+rc+1)+1 = lc+rc+3 ✓  (content_w = lc+rc+1)
DEFAULT_LC = 17   # "Vulnerabilities " = 15 + 2 (space + divider padding) → 17 fits
DEFAULT_RC = 54   # fits typical assessment labels with room for "†" override marker


# ---------------------------------------------------------------------------
# Unicode display-width helpers
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

_VS16 = 0xFE0F   # Variation Selector-16: makes emoji double-width; zero width itself


def char_width(c: str) -> int:
    """Terminal display width of a single character (0, 1, or 2)."""
    cp = ord(c)
    if cp == _VS16:
        return 0
    for lo, hi in _DOUBLE_WIDTH_RANGES:
        if lo <= cp <= hi:
            return 2
    return 1


def dw(s: str) -> int:
    """Terminal display width of a string."""
    return sum(char_width(c) for c in s)


def rpad(s: str, width: int) -> str:
    """Right-pad s to exactly `width` terminal columns using spaces."""
    return s + " " * max(0, width - dw(s))


# ---------------------------------------------------------------------------
# Text wrapping (display-width aware)
# ---------------------------------------------------------------------------

def wrap(text: str, width: int) -> list[str]:
    """Word-wrap text to fit within `width` terminal columns."""
    if dw(text) <= width:
        return [text]
    words = text.split(" ")
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = (current + " " + word) if current else word
        if dw(candidate) <= width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [text]



# ---------------------------------------------------------------------------
# Report loading
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Package formatting
# ---------------------------------------------------------------------------

def format_package(pkg: dict) -> list[str]:
    """
    Return a list of terminal lines for one package using Unicode box-drawing.

    Layout:
      {rec_icon} {recommendation}  {purl}     ← plain line above the box
      ┌─────────────────┬───────────────────┐
      │ Assessment      │ Result            │ ← fixed-width table
      ├─────────────────┴───────────────────┤
      │ † Override note (if any)            │
      └─────────────────────────────────────┘
        More info: {url}                       ← plain line below the box
    """
    purl           = pkg.get("purl", "unknown")
    analysis       = pkg.get("analysis", {})
    recommendation = analysis.get("recommendation", "—")
    report_url     = analysis.get("report", "")
    assessment     = analysis.get("assessment", {})

    rec_icon = RECOMMENDATION_ICON.get(recommendation, "❓")
    rec_text = f"{rec_icon} {recommendation}"

    # Collect assessment rows
    rows: list[tuple[str, str]] = []
    overrides: list[str] = []
    for key in ASSESSMENTS:
        if key not in assessment:
            continue
        data         = assessment[key]
        status       = data.get("status", "pass")
        label        = data.get("label", "—")
        icon         = STATUS_ICON.get(status, "❓")
        override     = data.get("override")
        has_override = bool(override and override.get("to_status") != data.get("status"))
        if has_override:
            overrides.append(key)
        value = f"{icon} {label}" + (" †" if has_override else "")
        rows.append((key.capitalize(), value))

    # ------------------------------------------------------------------
    # Compute box dimensions — fixed width, no longer driven by purl length
    # ------------------------------------------------------------------
    box_w     = DEFAULT_LC + DEFAULT_RC + 1
    lc        = DEFAULT_LC
    rc        = DEFAULT_RC
    content_w = box_w - 2   # usable columns in single-col rows

    # Override annotation (word-wrapped, inside the box)
    override_lines: list[str] = []
    for raw in wrap(f"† Override on: {', '.join(overrides)}", content_w) if overrides else []:
        override_lines.append(raw)

    # ------------------------------------------------------------------
    # Render
    # ------------------------------------------------------------------
    out: list[str] = []

    # Header above the box: "✅ APPROVE → pkg:npm/axios@1.13.6"
    out.append(f"{rec_text}  →  {purl}")

    out.append(f"┌{'─' * box_w}┐")
    for label, value in rows:
        out.append(f"│ {rpad(label, lc - 1)}│ {rpad(value, rc - 1)}│")

    if override_lines:
        out.append(f"├{'─' * lc}┴{'─' * rc}┤")
        for fl in override_lines:
            out.append(f"│ {rpad(fl, content_w)} │")

    out.append(f"└{'─' * box_w}┘")

    if report_url:
        out.append(f"  More info: {report_url}")

    return out


# ---------------------------------------------------------------------------
# Error table
# ---------------------------------------------------------------------------

def format_errors(errors: list) -> list[str]:
    """Format scan errors as a Unicode table."""
    if not errors:
        return []

    col_p = max(dw("Package"), *(dw(e.get("purl", "")) for e in errors))
    col_c = max(dw("Error"), *(dw(str(e.get("error", {}).get("code", ""))) for e in errors))
    col_i = max(dw("Detail"), *(dw(str(e.get("error", {}).get("info", ""))) for e in errors))

    def row(p, c, i):
        return f"│ {rpad(p, col_p)} │ {rpad(c, col_c)} │ {rpad(i, col_i)} │"

    out = [
        "",
        "Scan errors",
        f"┌{'─' * (col_p + 2)}┬{'─' * (col_c + 2)}┬{'─' * (col_i + 2)}┐",
        row("Package", "Error", "Detail"),
        f"├{'─' * (col_p + 2)}┼{'─' * (col_c + 2)}┼{'─' * (col_i + 2)}┤",
    ]
    for err in errors:
        p = err.get("purl", "unknown")
        c = str(err.get("error", {}).get("code", "—"))
        i = str(err.get("error", {}).get("info", "—"))
        out.append(row(p, c, i))
    out.append(f"└{'─' * (col_p + 2)}┴{'─' * (col_c + 2)}┴{'─' * (col_i + 2)}┘")
    return out


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def format_package_json(pkg: dict) -> dict:
    """Return a JSON-serializable dict for one package."""
    purl           = pkg.get("purl", "unknown")
    analysis       = pkg.get("analysis", {})
    recommendation = analysis.get("recommendation", "—")
    report_url     = analysis.get("report", "")
    assessment     = analysis.get("assessment", {})

    assessment_data = {}
    has_override = False
    for key in ASSESSMENTS:
        if key not in assessment:
            continue
        data     = assessment[key]
        status   = data.get("status", "pass")
        label    = data.get("label", "")
        override = data.get("override")
        overridden = bool(override and override.get("to_status") != status)
        if overridden:
            has_override = True
        entry = {"status": status, "label": label}
        if overridden:
            entry["override"] = {
                "to_status": override.get("to_status", ""),
                "author": override.get("audit", {}).get("author", ""),
                "date": (override.get("audit", {}).get("timestamp", "") or "")[:10],
                "reason": override.get("audit", {}).get("reason", ""),
            }
        assessment_data[key] = entry

    return {
        "purl": purl,
        "recommendation": recommendation,
        "report_url": report_url,
        "assessment": assessment_data,
        "has_override": has_override,
    }


def format_errors_json(errors: list) -> list:
    """Return a JSON-serializable list for scan errors."""
    return [
        {
            "purl": e.get("purl", "unknown"),
            "code": e.get("error", {}).get("code", ""),
            "detail": e.get("error", {}).get("info", ""),
        }
        for e in errors
    ]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args(argv: list):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("report", nargs="?", type=Path, default=Path("rl-protect.report.json"))
    p.add_argument("--no-error-code", action="store_true")
    p.add_argument("--json", action="store_true", dest="json_output")
    return p.parse_args(argv[1:])


def main():
    args = parse_args(sys.argv)
    no_error_code = args.no_error_code
    json_output   = args.json_output
    try:
        report = load_report(args.report)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)
    packages = get_packages(report)
    errors   = get_errors(report)

    if not packages and not errors:
        if json_output:
            print(json.dumps({"packages": [], "errors": [], "summary": {"reject": 0, "warn": 0, "pass": 0, "total": 0}}, indent=2))
        else:
            print("No packages found in report.")
        sys.exit(0)

    n_reject = sum(
        1 for p in packages
        if p.get("analysis", {}).get("recommendation") == "REJECT"
    )
    n_warn = sum(
        1 for p in packages
        if p.get("analysis", {}).get("recommendation") == "APPROVE"
        and any(
            p.get("analysis", {}).get("assessment", {}).get(k, {}).get("status") in ("warning", "fail")
            for k in ASSESSMENTS
        )
    )
    n_pass = len(packages) - n_reject - n_warn
    any_reject = n_reject > 0

    if json_output:
        result = {
            "packages": [format_package_json(pkg) for pkg in packages],
            "errors": format_errors_json(errors),
            "summary": {"reject": n_reject, "warn": n_warn, "pass": n_pass, "total": len(packages)},
        }
        print(json.dumps(result, indent=2))
        sys.exit(0 if (no_error_code or not any_reject) else 1)

    any_override = False

    for i, pkg in enumerate(packages):
        if i > 0:
            print()
        for line in format_package(pkg):
            print(line)
        if pkg.get("analysis", {}).get("recommendation") == "REJECT":
            any_reject = True
        assessment = pkg.get("analysis", {}).get("assessment", {})
        for k in ASSESSMENTS:
            entry    = assessment.get(k, {})
            override = entry.get("override")
            if override and override.get("to_status") != entry.get("status"):
                any_override = True
                break

    for line in format_errors(errors):
        print(line)

    print()
    print(f"  REJECT {n_reject}  ·  WARN {n_warn}  ·  PASS {n_pass}  ·  {len(packages)} total")
    if any_override:
        print("\n  † Policy override changed the recommendation — run interpret.py overrides for the full audit trail.")

    sys.exit(0 if (no_error_code or not any_reject) else 1)


if __name__ == "__main__":
    main()
