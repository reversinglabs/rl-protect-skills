#!/usr/bin/env python3
"""
diff-behavior.py — rl-protect behavior differential analysis

Compares behaviors between two versions of the same package to detect
suspicious changes that may indicate supply chain tampering. Diffs
indicators, file classifications, vulnerabilities, and assessment statuses.

Usage:
    python diff-behavior.py --package <name> [options]

    # Two versions in one report (scanned together):
    python diff-behavior.py --package lodash --report report.json

    # Two separate reports:
    python diff-behavior.py --package lodash --old-report old.json --new-report new.json

Options:
    --package <name>       Package name to compare (substring match, required).
    --report  <path>       Single report containing both versions.
                           Default: rl-protect.report.json
    --old-report <path>    Report file for the old version.
    --new-report <path>    Report file for the new version.
    --old-version <ver>    Pin a specific old version (when more than two are present).
    --new-version <ver>    Pin a specific new version (when more than two are present).
    --reverse              Swap old and new. Use when downgrading to an older version.
    --no-error-code        Suppress exit code 1 (new risks found).
    --json                 Output results as JSON instead of formatted terminal tables.

Exit codes:
    0   No new risks introduced.
    1   New risks detected (new indicators, malware, CVEs, or assessment regressions).
    2   Report file not found, invalid JSON, or unable to match package versions.
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

ASSESSMENTS = ["secrets", "licenses", "vulnerabilities", "hardening", "tampering", "malware"]

STATUS_ICON = {"pass": "✅", "warning": "⚠️", "fail": "❌"}
STATUS_LABEL = {"pass": "PASS", "warning": "WARN", "fail": "FAIL"}
STATUS_RANK = {"pass": 0, "warning": 1, "fail": 2}
RECOMMENDATION_ICON = {"APPROVE": "🟢", "REJECT": "🔴"}

CVSS_LABEL = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.0, "low"),
]


# ---------------------------------------------------------------------------
# Unicode display-width helpers (shared with other scripts)
# ---------------------------------------------------------------------------

_DOUBLE_WIDTH_RANGES = [
    (0x1100,  0x115F),
    (0x2600,  0x27BF),
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


def wrap_text(s: str, max_width: int) -> list[str]:
    """Wrap s into lines of at most max_width display columns, breaking at spaces."""
    if dw(s) <= max_width:
        return [s]
    words = s.split(" ")
    lines: list[str] = []
    current, current_w = "", 0
    for word in words:
        word_w = dw(word)
        if not current:
            current, current_w = word, word_w
        elif current_w + 1 + word_w <= max_width:
            current += " " + word
            current_w += 1 + word_w
        else:
            lines.append(current)
            current, current_w = word, word_w
    if current:
        lines.append(current)
    return lines or [s]


# ---------------------------------------------------------------------------
# Box-drawing table renderer
# ---------------------------------------------------------------------------

def render_table(headers: list[str], rows: list[list[str]],
                 col_max_widths: list[int | None] | None = None) -> list[str]:
    """Render a multi-column Unicode box-drawing table with dynamic column widths.

    col_max_widths: per-column max display width; None entries mean unlimited.
    Cells that exceed their column's max width are wrapped across multiple lines.
    """
    n = len(headers)
    maxw: list[int | None] = list(col_max_widths) + [None] * n if col_max_widths else [None] * n

    col_w = [dw(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row[:n]):
            raw = dw(str(cell))
            col_w[i] = max(col_w[i], raw if maxw[i] is None else min(raw, maxw[i]))

    def hdiv(left, mid, right):
        return left + mid.join("─" * (w + 2) for w in col_w) + right

    def single_line(cells):
        padded = list(cells) + [""] * (n - len(cells))
        parts  = [f" {rpad(str(c), w)} " for c, w in zip(padded, col_w)]
        return "│" + "│".join(parts) + "│"

    def multi_lines(cells):
        padded  = list(cells) + [""] * (n - len(cells))
        wrapped = [
            wrap_text(str(c), maxw[i]) if maxw[i] is not None else [str(c)]
            for i, c in enumerate(padded[:n])
        ]
        height = max(len(w) for w in wrapped)
        lines  = []
        for line_i in range(height):
            parts = [
                f" {rpad(w[line_i] if line_i < len(w) else '', col_w[i])} "
                for i, w in enumerate(wrapped)
            ]
            lines.append("│" + "│".join(parts) + "│")
        return lines

    uses_wrapping = any(m is not None for m in maxw[:n])

    out = [hdiv("┌", "┬", "┐")]
    out.append(single_line(headers))
    out.append(hdiv("├", "┼", "┤"))
    for row in rows:
        out.extend(multi_lines(row) if uses_wrapping else [single_line(row)])
    out.append(hdiv("└", "┴", "┘"))
    return out


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


def parse_purl(purl: str) -> tuple[str, str, str]:
    """Parse a PURL into (type, name, version). Returns ('','','') on failure."""
    # Format: pkg:<type>/<name>@<version>
    if not purl.startswith("pkg:"):
        return ("", "", "")
    rest = purl[4:]
    if "/" not in rest:
        return ("", "", "")
    pkg_type, name_ver = rest.split("/", 1)
    if "@" in name_ver:
        name, version = name_ver.rsplit("@", 1)
    else:
        name, version = name_ver, ""
    return (pkg_type, name, version)


def find_package_versions(packages: list, name_filter: str) -> list:
    """Find all packages matching a name filter, sorted by PURL for consistent ordering."""
    f = name_filter.lower()
    matches = []
    for pkg in packages:
        purl = pkg.get("purl", "")
        pkg_type, name, version = parse_purl(purl)
        # Match against name part (or full PURL for flexibility)
        if f in name.lower() or f in purl.lower():
            matches.append(pkg)
    return sorted(matches, key=lambda p: p.get("purl", ""))


def select_versions(
    old_packages: list,
    new_packages: list,
    name_filter: str,
    old_version: str,
    new_version: str,
    single_report: bool,
) -> tuple[dict, dict]:
    """
    Select the old and new package versions to compare.

    When using a single report, expects exactly two versions of the package
    (or use --old-version/--new-version to disambiguate).

    When using two reports, picks the best match from each.
    """
    if single_report:
        # Both lists point to the same report's packages
        matches = find_package_versions(old_packages, name_filter)
        if not matches:
            raise RuntimeError(f"no packages matching '{name_filter}' found in report.")

        if old_version and new_version:
            old_pkg = _pick_version(matches, old_version, "old")
            new_pkg = _pick_version(matches, new_version, "new")
            return old_pkg, new_pkg

        if len(matches) < 2:
            raise RuntimeError(
                f"found only 1 version of '{name_filter}' in report. "
                f"Need two versions to diff. Scan both versions together or use --old-report/--new-report."
            )

        if len(matches) > 2 and not (old_version or new_version):
            purls = [m.get("purl", "") for m in matches]
            raise RuntimeError(
                f"found {len(matches)} versions of '{name_filter}': {', '.join(purls)}. "
                f"Use --old-version and --new-version to select which two to compare."
            )

        # Exactly two versions — older one first (lexicographic by version string)
        return matches[0], matches[1]
    else:
        # Two separate reports
        old_matches = find_package_versions(old_packages, name_filter)
        new_matches = find_package_versions(new_packages, name_filter)

        if not old_matches:
            raise RuntimeError(f"no packages matching '{name_filter}' found in old report.")
        if not new_matches:
            raise RuntimeError(f"no packages matching '{name_filter}' found in new report.")

        old_pkg = _pick_version(old_matches, old_version, "old") if old_version else old_matches[0]
        new_pkg = _pick_version(new_matches, new_version, "new") if new_version else new_matches[0]

        if len(old_matches) > 1 and not old_version:
            print(f"Note: multiple matches in old report, using {old_pkg.get('purl', '')}. "
                  f"Use --old-version to pick a specific one.", file=sys.stderr)
        if len(new_matches) > 1 and not new_version:
            print(f"Note: multiple matches in new report, using {new_pkg.get('purl', '')}. "
                  f"Use --new-version to pick a specific one.", file=sys.stderr)

        return old_pkg, new_pkg


def _pick_version(matches: list, version: str, label: str) -> dict:
    """Pick a specific version from a list of matches."""
    for m in matches:
        _, _, v = parse_purl(m.get("purl", ""))
        if v == version:
            return m
    # Fallback: substring match
    for m in matches:
        if version in m.get("purl", ""):
            return m
    purls = [m.get("purl", "") for m in matches]
    raise RuntimeError(f"version '{version}' not found for {label} package. Available: {', '.join(purls)}")


# ---------------------------------------------------------------------------
# Diff logic
# ---------------------------------------------------------------------------

def diff_indicators(old_pkg: dict, new_pkg: dict) -> tuple[list, list, list]:
    """
    Compare indicators between old and new versions.

    Returns (added, removed, changed) where:
      added   = [(id, description, occurrences), ...]
      removed = [(id, description, occurrences), ...]
      changed = [(id, description, old_occurrences, new_occurrences), ...]
    """
    old_ind = old_pkg.get("analysis", {}).get("indicators", {})
    new_ind = new_pkg.get("analysis", {}).get("indicators", {})

    old_ids = set(old_ind.keys())
    new_ids = set(new_ind.keys())

    added = []
    for ind_id in sorted(new_ids - old_ids):
        ind = new_ind[ind_id]
        added.append((ind_id, ind.get("description", "—"), str(ind.get("occurrences", "—"))))

    removed = []
    for ind_id in sorted(old_ids - new_ids):
        ind = old_ind[ind_id]
        removed.append((ind_id, ind.get("description", "—"), str(ind.get("occurrences", "—"))))

    changed = []
    for ind_id in sorted(old_ids & new_ids):
        old_occ = old_ind[ind_id].get("occurrences", 0)
        new_occ = new_ind[ind_id].get("occurrences", 0)
        if old_occ != new_occ:
            desc = new_ind[ind_id].get("description", "—")
            changed.append((ind_id, desc, str(old_occ), str(new_occ)))

    return added, removed, changed


def diff_classifications(old_pkg: dict, new_pkg: dict) -> tuple[list, list]:
    """
    Compare file classifications between old and new versions.

    Returns (added, removed) where each entry is a classification dict.
    Only considers Malicious and Suspicious files.
    """
    def key(c: dict) -> str:
        hashes = c.get("hashes", [])
        for algo, val in hashes:
            if algo.lower() == "sha256":
                return val
        return c.get("result", "") + "|" + c.get("status", "")

    old_cls = old_pkg.get("analysis", {}).get("classifications", [])
    new_cls = new_pkg.get("analysis", {}).get("classifications", [])

    old_flagged = {key(c): c for c in old_cls if c.get("status") in ("Malicious", "Suspicious")}
    new_flagged = {key(c): c for c in new_cls if c.get("status") in ("Malicious", "Suspicious")}

    added = [new_flagged[k] for k in sorted(set(new_flagged) - set(old_flagged))]
    removed = [old_flagged[k] for k in sorted(set(old_flagged) - set(new_flagged))]

    return added, removed


def diff_vulnerabilities(old_pkg: dict, new_pkg: dict) -> tuple[list, list]:
    """
    Compare vulnerabilities between old and new versions.

    Returns (added, fixed) where each entry is (cve_id, vuln_dict).
    """
    old_vulns = old_pkg.get("analysis", {}).get("vulnerabilities", {})
    new_vulns = new_pkg.get("analysis", {}).get("vulnerabilities", {})

    old_ids = set(old_vulns.keys())
    new_ids = set(new_vulns.keys())

    added = [(cve_id, new_vulns[cve_id]) for cve_id in sorted(new_ids - old_ids)]
    fixed = [(cve_id, old_vulns[cve_id]) for cve_id in sorted(old_ids - new_ids)]

    return added, fixed


def diff_policy_violations(old_pkg: dict, new_pkg: dict) -> tuple[list, list, list]:
    """
    Compare policy violations between old and new versions.

    Returns (added, removed, changed) where:
      added   = [(rule_id, description, violations_count), ...]
      removed = [(rule_id, description, violations_count), ...]
      changed = [(rule_id, description, old_status, new_status, old_count, new_count), ...]
    """
    old_viol = old_pkg.get("analysis", {}).get("policy", {}).get("violations", {})
    new_viol = new_pkg.get("analysis", {}).get("policy", {}).get("violations", {})

    old_ids = set(old_viol.keys())
    new_ids = set(new_viol.keys())

    added = []
    for rule_id in sorted(new_ids - old_ids):
        v = new_viol[rule_id]
        added.append((rule_id, v.get("description", "—"), str(v.get("violations", 0))))

    removed = []
    for rule_id in sorted(old_ids - new_ids):
        v = old_viol[rule_id]
        removed.append((rule_id, v.get("description", "—"), str(v.get("violations", 0))))

    changed = []
    for rule_id in sorted(old_ids & new_ids):
        old_v = old_viol[rule_id]
        new_v = new_viol[rule_id]
        old_status = old_v.get("status", "pass")
        new_status = new_v.get("status", "pass")
        old_count = old_v.get("violations", 0)
        new_count = new_v.get("violations", 0)
        if old_status != new_status or old_count != new_count:
            changed.append((
                rule_id, new_v.get("description", "—"),
                old_status, new_status,
                str(old_count), str(new_count),
            ))

    return added, removed, changed


def diff_assessments(old_pkg: dict, new_pkg: dict) -> list:
    """
    Compare assessment statuses between old and new versions.

    Returns [(assessment_name, old_status, new_status, old_label, new_label), ...]
    for assessments that changed.
    """
    old_assess = old_pkg.get("analysis", {}).get("assessment", {})
    new_assess = new_pkg.get("analysis", {}).get("assessment", {})

    changes = []
    for key in ASSESSMENTS:
        old_data = old_assess.get(key, {})
        new_data = new_assess.get(key, {})
        old_status = old_data.get("status", "pass")
        new_status = new_data.get("status", "pass")
        if old_status != new_status:
            changes.append((
                key.capitalize(),
                old_status,
                new_status,
                old_data.get("label", "—"),
                new_data.get("label", "—"),
            ))

    return changes


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def sha256_of(hashes: list) -> str:
    for algo, val in hashes:
        if algo.lower() == "sha256":
            return val
    return "—"


def print_diff(old_pkg: dict, new_pkg: dict) -> int:
    """Print the full behavior diff. Returns 1 if new risks detected, 0 otherwise."""
    old_purl = old_pkg.get("purl", "unknown")
    new_purl = new_pkg.get("purl", "unknown")
    old_rec = old_pkg.get("analysis", {}).get("recommendation", "—")
    new_rec = new_pkg.get("analysis", {}).get("recommendation", "—")
    old_rec_icon = RECOMMENDATION_ICON.get(old_rec, "❓")
    new_rec_icon = RECOMMENDATION_ICON.get(new_rec, "❓")

    new_risks = False

    # Header
    print(f"## Behavior diff\n")
    print(f"  Old: {old_rec_icon} {old_rec}  →  {old_purl}")
    print(f"  New: {new_rec_icon} {new_rec}  →  {new_purl}")

    # Recommendation change
    if old_rec != new_rec:
        if new_rec == "REJECT":
            print(f"\n  🔴 Recommendation changed: {old_rec} → {new_rec}")
            new_risks = True
        else:
            print(f"\n  🟢 Recommendation changed: {old_rec} → {new_rec}")

    # Assessment diff
    assess_changes = diff_assessments(old_pkg, new_pkg)
    print(f"\n### Assessment changes\n")
    if assess_changes:
        rows = []
        for name, old_s, new_s, old_l, new_l in assess_changes:
            old_icon = STATUS_ICON.get(old_s, "❓")
            new_icon = STATUS_ICON.get(new_s, "❓")
            direction = ""
            if STATUS_RANK.get(new_s, 0) > STATUS_RANK.get(old_s, 0):
                direction = " ⬆ REGRESSION"
                new_risks = True
            elif STATUS_RANK.get(new_s, 0) < STATUS_RANK.get(old_s, 0):
                direction = " ⬇ improved"
            rows.append([
                name,
                f"{old_icon} {STATUS_LABEL.get(old_s, old_s)}",
                f"{new_icon} {STATUS_LABEL.get(new_s, new_s)}",
                direction,
                new_l,
            ])
        for line in render_table(["Assessment", "Old", "New", "Direction", "Detail"], rows):
            print(line)
    else:
        print("  (No assessment status changes.)")

    # Policy violation diff
    pv_added, pv_removed, pv_changed = diff_policy_violations(old_pkg, new_pkg)
    print(f"\n### Policy violation changes\n")

    if pv_added:
        new_risks = True
        print("  [+] New policy violations")
        rows = [[r[0], r[1], r[2]] for r in pv_added]
        for line in render_table(["Rule", "Description", "Violations"], rows,
                                  col_max_widths=[None, 60, None]):
            print(line)

    if pv_removed:
        print()
        print("  [-] Resolved policy violations")
        rows = [[r[0], r[1], r[2]] for r in pv_removed]
        for line in render_table(["Rule", "Description", "Violations"], rows,
                                  col_max_widths=[None, 60, None]):
            print(line)

    if pv_changed:
        print()
        print("  [~] Changed policy violations")
        rows = []
        for rule_id, desc, old_s, new_s, old_c, new_c in pv_changed:
            old_icon = STATUS_ICON.get(old_s, "❓")
            new_icon = STATUS_ICON.get(new_s, "❓")
            rows.append([
                rule_id, desc,
                f"{old_icon} {STATUS_LABEL.get(old_s, old_s)} ({old_c})",
                f"{new_icon} {STATUS_LABEL.get(new_s, new_s)} ({new_c})",
            ])
        for line in render_table(["Rule", "Description", "Old", "New"], rows,
                                  col_max_widths=[None, 60, None, None]):
            print(line)

    if not pv_added and not pv_removed and not pv_changed:
        print("  (No policy violation changes.)")

    # Indicator diff
    ind_added, ind_removed, ind_changed = diff_indicators(old_pkg, new_pkg)
    print(f"\n### Behavior indicators\n")

    if ind_added:
        new_risks = True
        print("  [+] New indicators (not present in old version)")
        rows = [[i[0], i[1], i[2]] for i in ind_added]
        for line in render_table(["ID", "Description", "Occurrences"], rows,
                                  col_max_widths=[None, 60, None]):
            print(line)

    if ind_removed:
        print()
        print("  [-] Removed indicators (no longer present)")
        rows = [[i[0], i[1], i[2]] for i in ind_removed]
        for line in render_table(["ID", "Description", "Occurrences"], rows,
                                  col_max_widths=[None, 60, None]):
            print(line)

    if ind_changed:
        print()
        print("  [~] Changed indicator occurrences")
        rows = [[i[0], i[1], i[2], i[3]] for i in ind_changed]
        for line in render_table(["ID", "Description", "Old count", "New count"], rows,
                                  col_max_widths=[None, 60, None, None]):
            print(line)

    if not ind_added and not ind_removed and not ind_changed:
        print("  (No indicator changes.)")

    # Classification diff
    cls_added, cls_removed = diff_classifications(old_pkg, new_pkg)
    print(f"\n### Malicious / suspicious file changes\n")

    if cls_added:
        new_risks = True
        print("  [+] New malicious/suspicious files")
        rows = [
            [c.get("status", "—"), c.get("result", "—"), sha256_of(c.get("hashes", []))]
            for c in cls_added
        ]
        for line in render_table(["Status", "Classification", "SHA-256"], rows):
            print(line)

    if cls_removed:
        print()
        print("  [-] Removed malicious/suspicious files")
        rows = [
            [c.get("status", "—"), c.get("result", "—"), sha256_of(c.get("hashes", []))]
            for c in cls_removed
        ]
        for line in render_table(["Status", "Classification", "SHA-256"], rows):
            print(line)

    if not cls_added and not cls_removed:
        print("  (No malicious/suspicious file changes.)")

    # Vulnerability diff
    vuln_added, vuln_fixed = diff_vulnerabilities(old_pkg, new_pkg)
    print(f"\n### Vulnerability changes\n")

    if vuln_added:
        new_risks = True
        print("  [+] New vulnerabilities")
        rows = []
        for cve_id, vuln in vuln_added:
            score = vuln.get("cvss", {}).get("baseScore", 0.0)
            flags = ", ".join(vuln.get("exploit", [])) or "—"
            rows.append([cve_id, f"{score:.2f} ({cvss_label(score)})", flags, vuln.get("summary", "—")])
        for line in render_table(["CVE / GHSA", "CVSS", "Exploit flags", "Summary"], rows,
                                  col_max_widths=[None, None, None, 60]):
            print(line)

    if vuln_fixed:
        print()
        print("  [-] Fixed vulnerabilities")
        rows = []
        for cve_id, vuln in vuln_fixed:
            score = vuln.get("cvss", {}).get("baseScore", 0.0)
            rows.append([cve_id, f"{score:.2f} ({cvss_label(score)})", vuln.get("summary", "—")])
        for line in render_table(["CVE / GHSA", "CVSS", "Summary"], rows,
                                  col_max_widths=[None, None, 60]):
            print(line)

    if not vuln_added and not vuln_fixed:
        print("  (No vulnerability changes.)")

    # Summary
    print()
    if new_risks:
        print("  ⚠ New risks detected in this version update. Review carefully before upgrading.")
    else:
        print("  ✅ No new risks detected. Behaviors are consistent between versions.")

    return 1 if new_risks else 0


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def diff_to_json(old_pkg: dict, new_pkg: dict) -> dict:
    """Build a JSON-serializable diff result. New-risk status is in result["new_risks"]."""
    old_purl = old_pkg.get("purl", "unknown")
    new_purl = new_pkg.get("purl", "unknown")
    old_rec = old_pkg.get("analysis", {}).get("recommendation", "—")
    new_rec = new_pkg.get("analysis", {}).get("recommendation", "—")

    new_risks = False

    result = {
        "old": {"purl": old_purl, "recommendation": old_rec},
        "new": {"purl": new_purl, "recommendation": new_rec},
        "recommendation_changed": old_rec != new_rec,
    }

    if old_rec != new_rec and new_rec == "REJECT":
        new_risks = True

    # Assessment changes
    assess_changes = diff_assessments(old_pkg, new_pkg)
    result["assessment_changes"] = []
    for name, old_s, new_s, old_l, new_l in assess_changes:
        direction = "unchanged"
        if STATUS_RANK.get(new_s, 0) > STATUS_RANK.get(old_s, 0):
            direction = "regression"
            new_risks = True
        elif STATUS_RANK.get(new_s, 0) < STATUS_RANK.get(old_s, 0):
            direction = "improved"
        result["assessment_changes"].append({
            "assessment": name,
            "old_status": old_s,
            "new_status": new_s,
            "old_label": old_l,
            "new_label": new_l,
            "direction": direction,
        })

    # Policy violation changes
    pv_added, pv_removed, pv_changed = diff_policy_violations(old_pkg, new_pkg)
    if pv_added:
        new_risks = True
    result["policy_violation_changes"] = {
        "added": [{"rule_id": r[0], "description": r[1], "violations": r[2]} for r in pv_added],
        "removed": [{"rule_id": r[0], "description": r[1], "violations": r[2]} for r in pv_removed],
        "changed": [
            {"rule_id": r[0], "description": r[1], "old_status": r[2], "new_status": r[3], "old_count": r[4], "new_count": r[5]}
            for r in pv_changed
        ],
    }

    # Indicator changes
    ind_added, ind_removed, ind_changed = diff_indicators(old_pkg, new_pkg)
    if ind_added:
        new_risks = True
    result["indicator_changes"] = {
        "added": [{"id": i[0], "description": i[1], "occurrences": i[2]} for i in ind_added],
        "removed": [{"id": i[0], "description": i[1], "occurrences": i[2]} for i in ind_removed],
        "changed": [{"id": i[0], "description": i[1], "old_count": i[2], "new_count": i[3]} for i in ind_changed],
    }

    # Classification changes
    cls_added, cls_removed = diff_classifications(old_pkg, new_pkg)
    if cls_added:
        new_risks = True
    result["classification_changes"] = {
        "added": [
            {"status": c.get("status", ""), "result": c.get("result", ""), "sha256": sha256_of(c.get("hashes", []))}
            for c in cls_added
        ],
        "removed": [
            {"status": c.get("status", ""), "result": c.get("result", ""), "sha256": sha256_of(c.get("hashes", []))}
            for c in cls_removed
        ],
    }

    # Vulnerability changes
    vuln_added, vuln_fixed = diff_vulnerabilities(old_pkg, new_pkg)
    if vuln_added:
        new_risks = True
    result["vulnerability_changes"] = {
        "added": [
            {
                "id": cve_id,
                "cvss": vuln.get("cvss", {}).get("baseScore", 0.0),
                "cvss_label": cvss_label(vuln.get("cvss", {}).get("baseScore", 0.0)),
                "exploit_flags": vuln.get("exploit", []),
                "summary": vuln.get("summary", ""),
            }
            for cve_id, vuln in vuln_added
        ],
        "fixed": [
            {
                "id": cve_id,
                "cvss": vuln.get("cvss", {}).get("baseScore", 0.0),
                "cvss_label": cvss_label(vuln.get("cvss", {}).get("baseScore", 0.0)),
                "summary": vuln.get("summary", ""),
            }
            for cve_id, vuln in vuln_fixed
        ],
    }

    result["new_risks"] = new_risks
    result["exit_code"] = 1 if new_risks else 0
    return result


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args(argv: list) -> dict:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--package", default="")
    p.add_argument("--report", type=Path, default=None)
    p.add_argument("--old-report", type=Path, default=None, dest="old_report")
    p.add_argument("--new-report", type=Path, default=None, dest="new_report")
    p.add_argument("--old-version", default="", dest="old_version")
    p.add_argument("--new-version", default="", dest="new_version")
    p.add_argument("--reverse", action="store_true")
    p.add_argument("--no-error-code", action="store_true", dest="no_error_code")
    p.add_argument("--json", action="store_true")
    return vars(p.parse_args(argv[1:]))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    opts = parse_args(sys.argv)

    if not opts["package"]:
        print("Error: --package is required.", file=sys.stderr)
        sys.exit(2)

    try:
        # Determine whether we're using one or two reports
        if opts["old_report"] and opts["new_report"]:
            old_report = load_report(opts["old_report"])
            new_report = load_report(opts["new_report"])
            old_packages = get_packages(old_report)
            new_packages = get_packages(new_report)
            single_report = False
        else:
            report_path = opts["report"] or Path("rl-protect.report.json")
            report = load_report(report_path)
            old_packages = get_packages(report)
            new_packages = old_packages
            single_report = True

        old_pkg, new_pkg = select_versions(
            old_packages,
            new_packages,
            opts["package"],
            opts["old_version"],
            opts["new_version"],
            single_report,
        )
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)

    if opts["reverse"]:
        old_pkg, new_pkg = new_pkg, old_pkg

    if opts["json"]:
        result = diff_to_json(old_pkg, new_pkg)
        print(json.dumps(result, indent=2))
        sys.exit(0 if opts["no_error_code"] else result["exit_code"])

    exit_code = print_diff(old_pkg, new_pkg)
    sys.exit(0 if opts["no_error_code"] else exit_code)


if __name__ == "__main__":
    main()
