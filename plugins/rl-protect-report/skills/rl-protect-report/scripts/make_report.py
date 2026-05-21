#!/usr/bin/env python3

import argparse
import json
import re
import sys
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone


def _parse_iso(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("+0000", "+00:00").replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def relative_date(iso_str, reference=None):
    if not iso_str:
        return None
    published = _parse_iso(iso_str)
    try:
        delta = (reference or datetime.now(timezone.utc)) - published
        days = delta.days
        if days < 1:
            return "today"
        if days == 1:
            return "yesterday"
        if days < 7:
            return f"{days} days ago"
        if days < 14:
            return "1 week ago"
        if days < 30:
            return f"{days // 7} weeks ago"
        if days < 60:
            return "1 month ago"
        if days < 365:
            return f"{days // 30} months ago"
        years = days // 365
        return f"{years} year{'s' if years != 1 else ''} ago"
    except (ValueError, TypeError):
        return None


SIGNAL_LABELS = {
    "EXISTS": "⚡ exploit",
    "MALWARE": "☠️ malware",
    "MANDATE": "📋 mandate",
}

ASSESSMENT_ORDER = ["malware", "tampering", "vulnerabilities", "secrets", "hardening", "licenses", "repository"]
ASSESSMENT_NAMES = {
    "malware": "Malware",
    "tampering": "Tampering",
    "vulnerabilities": "Vulnerabilities",
    "secrets": "Secrets",
    "hardening": "Hardening",
    "licenses": "Licenses",
    "repository": "Repository",
}
STATUS_EMOJI = {"pass": "✅", "warning": "⚠️", "fail": "❌"}
STATUS_LABELS = {"reject": "REJECT", "warn": "WARN", "pass": "PASS"}

@dataclass
class ReportConfig:
    level: str = "fail"
    assessment: str = "simplified"
    vulnerabilities: bool = True
    license_info: bool = False
    policy: bool = False
    overrides: bool = False
    show_details: bool = True


TEMPLATES = {
    "concise": ReportConfig(
        assessment="off",
        vulnerabilities=False,
        show_details=False,
    ),
    "expanded": ReportConfig(
        license_info=True,
    ),
    "verbose": ReportConfig(
        level="pass",
        assessment="table",
        policy=True,
        overrides=True,
    ),
}


def get_effective_status(entry):
    return (entry.get("override") or {}).get("to_status") or entry.get("status", "pass")


def short_purl(purl):
    purl = purl.split("?")[0]
    return purl.split("/", 1)[1] if "/" in purl else purl


def build_reverse_deps(all_packages):
    reverse_deps = {}
    for p in all_packages:
        for dep in p.get("dependencies", []):
            reverse_deps.setdefault(dep, []).append(p.get("purl", ""))
    return reverse_deps


def find_inclusion(target_purl, reverse_deps):
    all_paths = []
    queue = deque([[target_purl]])
    while queue:
        path = queue.popleft()
        parents = reverse_deps.get(path[-1], [])
        if not parents:
            all_paths.append(list(reversed(path)))
        else:
            for parent in parents:
                if parent not in path:
                    queue.append(path + [parent])

    if not all_paths or all_paths == [[target_purl]]:
        return None

    shortest = min(all_paths, key=len)
    chain = " → ".join(f"`{short_purl(p)}`" for p in shortest)
    suffix = f" ({len(all_paths)} paths)" if len(all_paths) > 1 else ""
    return f"&nbsp;&nbsp;🔗 {chain}{suffix}"


def meaningful_override(entry):
    override = entry.get("override")
    if override and override.get("to_status") != entry.get("status"):
        return override
    return None


def override_note(entry, show=False):
    if not show:
        return ""
    ov = meaningful_override(entry)
    if not ov:
        return ""
    original = entry.get("status", "").upper()
    author = (ov.get("audit") or {}).get("author", "—")
    return f"<br>*† overridden from {original} by {author}*"


def cvss_dot(score):
    if score >= 9.0:
        return "🔴"
    if score >= 7.0:
        return "🟠"
    if score >= 4.0:
        return "🟡"
    return "🔵"


def classify_package(pkg):
    analysis = pkg.get("analysis", {})
    if analysis.get("recommendation") == "REJECT":
        return "reject"
    for a in analysis.get("assessment", {}).values():
        if a.get("status") in ("warning", "fail"):
            return "warn"
    return "pass"


def partition_packages(packages):
    rejected, warnings_pkgs, passing = [], [], []
    for p in packages:
        c = classify_package(p)
        if c == "reject":
            rejected.append(p)
        elif c == "warn":
            warnings_pkgs.append(p)
        else:
            passing.append(p)
    return rejected, warnings_pkgs, passing


def sort_key_rejected(pkg):
    analysis = pkg.get("analysis", {})
    has_malware = any(
        c.get("status") in ("Malicious", "Suspicious")
        for c in analysis.get("classifications", [])
    )
    has_governance = any(
        g.get("status") == "blocked"
        for g in analysis.get("policy", {}).get("governance", [])
    )
    return (not has_malware, not has_governance)


def sort_key_warnings(pkg):
    vulns = pkg.get("analysis", {}).get("vulnerabilities", {})
    top = max((v.get("cvss", {}).get("baseScore", 0) for v in vulns.values()), default=0)
    return -top


def vuln_table(vulns, report_url=""):
    if not vulns:
        return ""

    def sort_key(item):
        _, v = item
        score = v.get("cvss", {}).get("baseScore", 0)
        exploits = [f for f in v.get("exploit", []) if f in SIGNAL_LABELS]
        return (not exploits, -score, -len(exploits))

    rows = sorted(
        [(cve_id, v) for cve_id, v in vulns.items() if "TRIAGED" not in v.get("exploit", [])],
        key=sort_key,
    )

    if not rows:
        return ""

    counts = {"🔴": 0, "🟠": 0, "🟡": 0, "🔵": 0}
    for _, v in rows:
        counts[cvss_dot(v.get("cvss", {}).get("baseScore", 0))] += 1
    severity_labels = {"🔴": "critical", "🟠": "high", "🟡": "medium", "🔵": "low"}
    severity_summary = "**Vulnerabilities:** " + " · ".join(
        f"{dot} {n} {severity_labels[dot]}"
        for dot, n in counts.items() if n > 0
    )

    lines = [severity_summary, "", "| CVE/GHSA | CVSS | Summary | Signals |", "|----------|------|---------|---------|"]
    for cve_id, v in rows:
        score = v.get("cvss", {}).get("baseScore", 0)
        cve_summary = v.get("summary", "").replace("|", "\\|")
        dot = cvss_dot(score)
        signals = ", ".join(SIGNAL_LABELS[f] for f in v.get("exploit", []) if f in SIGNAL_LABELS)
        lines.append(f"| {cve_id} | {dot} {score:.2f} | {cve_summary} | {signals} |")


    return "\n".join(lines)


def _blockquote(header, lines):
    return "\\\n".join(f"> {p}" for p in [header] + lines)


def malware_block(classifications):
    malicious = list(dict.fromkeys(c.get("result", "") for c in classifications if c.get("status") == "Malicious"))
    suspicious = list(dict.fromkeys(c.get("result", "") for c in classifications if c.get("status") == "Suspicious"))
    if not malicious and not suspicious:
        return ""
    return _blockquote("**Malware**",
        [f"🛑 Threat detected: {name}" for name in malicious] +
        [f"🔶 Threat detected: {name}" for name in suspicious])


def assessment_table(assessment, show_overrides=False):
    if not assessment:
        return ""
    rows = ["| Assessment | Result |", "|---|---|"]
    for key in ASSESSMENT_ORDER:
        a = assessment.get(key, {})
        if not a:
            continue
        status = get_effective_status(a)
        emoji = STATUS_EMOJI.get(status, "✅")
        label = a.get("label", "")
        rows.append(f"| {ASSESSMENT_NAMES[key]} | {emoji} {label}{override_note(a, show_overrides)} |")
    return "\n".join(rows)


def simplified_assessment_block(assessment, show_overrides=False):
    if not assessment:
        return ""
    fails = []
    warnings = []
    for key in ASSESSMENT_ORDER:
        a = assessment.get(key, {})
        if not a:
            continue
        status = get_effective_status(a)
        label = a.get("label", "")
        note = override_note(a, show_overrides).replace("<br>", " ")
        if status == "fail":
            fails.append(f"❌ {ASSESSMENT_NAMES[key]}: {label}{note}")
        elif status == "warning":
            warnings.append(f"⚠️ {ASSESSMENT_NAMES[key]}: {label}{note}")
    if not fails and not warnings:
        return ""
    blocks = []
    if fails:
        blocks.append("\\\n".join(f"> {p}" for p in ["**SAFE Assessment**"] + fails))
    if warnings:
        blocks.append("\\\n".join(f"> {p}" for p in ["**SAFE Assessment**"] + warnings))
    return "\n\n".join(blocks)


def governance_block(governance):
    blocked = [g for g in governance if g.get("status") == "blocked"]
    if not blocked:
        return ""
    return _blockquote("**Governance**",
        [f"🚫 Blocked by governance: {g.get('reason', '')}" for g in blocked])


def policy_block(violations):
    failing = sorted(
        [(rule_id, v) for rule_id, v in violations.items() if get_effective_status(v) == "fail"],
        key=lambda x: x[0],
    )
    if not failing:
        return ""
    lines = []
    for rule_id, v in failing:
        line = f"❌ {rule_id}"
        if desc := v.get("description", ""):
            line += f" — {desc}"
        lines.append(line)
    return _blockquote("**Policy violations**", lines)


def policy_table(violations, show_overrides=False, report_url=""):
    if not violations:
        return ""

    non_passing = [
        (rule_id, v, get_effective_status(v))
        for rule_id, v in violations.items()
        if get_effective_status(v) != "pass"
    ]
    sorted_violations = sorted(non_passing, key=lambda x: (0 if x[2] == "fail" else 1, -x[1].get("violations", 0)))

    if not sorted_violations:
        return ""

    fail_count = sum(1 for _, _, s in sorted_violations if s == "fail")
    warn_count = len(sorted_violations) - fail_count
    parts = []
    if fail_count:
        parts.append(f"❌ {fail_count} failed")
    if warn_count:
        parts.append(f"⚠️ {warn_count} warning{'s' if warn_count != 1 else ''}")
    pol_summary = "**Policy violations:** " + " · ".join(parts)

    rows = []
    for rule_id, v, status in sorted_violations:
        emoji = STATUS_EMOJI.get(status, "")
        description = v.get("description", "")
        count = v.get("violations", 0)
        rows.append(f"| {rule_id} | {emoji} {description}{override_note(v, show_overrides)} | {count} |")

    lines = [pol_summary, "", "| Policy | Description | Count |", "|--------|-------------|-------|"] + rows
    return "\n".join(lines)


def deployment_risk(pkg):
    analysis = pkg.get("analysis", {})
    for c in analysis.get("classifications", []):
        if c.get("status") in ("Malicious", "Suspicious"):
            return "Malware detected"
    for g in analysis.get("policy", {}).get("governance", []):
        if g.get("status") == "blocked":
            return "Governance block"
    assessment = analysis.get("assessment", {})
    for key in ASSESSMENT_ORDER:
        a = assessment.get(key, {})
        if not a:
            continue
        status = get_effective_status(a)
        if status in ("fail", "warning"):
            if key == "vulnerabilities":
                vulns = {k: v for k, v in analysis.get("vulnerabilities", {}).items() if "TRIAGED" not in v.get("exploit", [])}
                if vulns:
                    top_cve = max(vulns.items(), key=lambda x: x[1].get("cvss", {}).get("baseScore", 0))
                    return f"CVE ({top_cve[0]})"
            return ASSESSMENT_NAMES.get(key, key)
    for rule_id, v in analysis.get("policy", {}).get("violations", {}).items():
        if get_effective_status(v) in ("fail", "warning"):
            return f"Policy ({rule_id})"
    return "—"


def suggested_action(pkg):
    analysis = pkg.get("analysis", {})
    status = classify_package(pkg)
    for c in analysis.get("classifications", []):
        if c.get("status") in ("Malicious", "Suspicious"):
            return "Remove immediately"
    for g in analysis.get("policy", {}).get("governance", []):
        if g.get("status") == "blocked":
            return "Policy exception required"
    assessment = analysis.get("assessment", {})
    vuln_status = get_effective_status(assessment.get("vulnerabilities", {}))
    if vuln_status in ("fail", "warning"):
        return "Update to patched version" if status == "reject" else "Update recommended"
    return "Review and remediate" if status == "reject" else "Review findings"


def top_cvss(pkg):
    vulns = pkg.get("analysis", {}).get("vulnerabilities", {})
    active = {k: v for k, v in vulns.items() if "TRIAGED" not in v.get("exploit", [])}
    if not active:
        return None
    top = max(active.values(), key=lambda v: v.get("cvss", {}).get("baseScore", 0))
    score = top.get("cvss", {}).get("baseScore", 0)
    return f"{cvss_dot(score)} {score:.1f}"


def version_update_plan(sorted_rejected, sorted_warnings):
    rows = []
    for priority, pkg in enumerate(sorted_rejected + sorted_warnings, 1):
        status = classify_package(pkg)
        purl = short_purl(pkg.get("purl", "unknown"))
        cvss = top_cvss(pkg) or "—"
        issue = deployment_risk(pkg)
        action = suggested_action(pkg)
        status_cell = "❌ REJECT" if status == "reject" else "⚠️ WARN"
        rows.append(f"| {priority} | `{purl}` | {status_cell} | {cvss} | {issue} | {action} |")
    if not rows:
        return ""
    lines = [
        "| Priority | Package | Status | Highest CVSS | Deployment Risk | Suggested Action |",
        "|----------|---------|--------|--------------|-----------------|------------------|",
    ] + rows
    return "\n".join(lines)


def purl_to_anchor(purl):
    return re.sub(r"[^a-zA-Z0-9]", "-", purl.split("?")[0])


def deployment_risk_label(pkg):
    analysis = pkg.get("analysis", {})
    for g in analysis.get("policy", {}).get("governance", []):
        if g.get("status") == "blocked":
            return "🚫 Governance block"
    assessment = analysis.get("assessment", {})
    for key in ASSESSMENT_ORDER:
        a = assessment.get(key, {})
        if not a:
            continue
        status = get_effective_status(a)
        if status in ("fail", "warning"):
            return f"{STATUS_EMOJI.get(status, '')} {a.get('label', '')}"
    for v in analysis.get("policy", {}).get("violations", {}).values():
        status = get_effective_status(v)
        if status in ("fail", "warning"):
            return f"{STATUS_EMOJI.get(status, '')} Policy violation"
    return "—"


def _summary_row(pkg, status_cell, reverse_deps, link_to_reports):
    purl = pkg.get("purl", "unknown").split("?")[0]
    icon = "🔗" if purl in reverse_deps else "📦"
    report_url = pkg.get("analysis", {}).get("report", "")
    href = report_url if link_to_reports and report_url else f"#{purl_to_anchor(purl)}"
    return f"| {icon} [`{purl}`]({href}) | {status_cell} | {deployment_risk_label(pkg)} |"


def summary_table(sorted_rejected, sorted_warnings, passing, reverse_deps, link_to_reports=False):
    rows = ["| Package | Status | Assessment |", "|---------|--------|------------|"]
    rows += [_summary_row(pkg, "❌ REJECT", reverse_deps, link_to_reports) for pkg in sorted_rejected]
    rows += [_summary_row(pkg, "⚠️ WARN", reverse_deps, link_to_reports) for pkg in sorted_warnings]
    if passing:
        n = len(passing)
        rows.append(f"| *{n} package{'s' if n != 1 else ''}* | ✅ PASS | — |")
    return "\n".join(rows)


def format_package(pkg, config, index=None, total=None, inclusion=None, scan_time=None):
    analysis = pkg.get("analysis", {})
    purl = pkg.get("purl", "unknown").split("?")[0]
    report_url = analysis.get("report", "")

    status = classify_package(pkg)
    counter = f" ({index} of {total})" if index is not None and total is not None else ""
    tags = ""
    if pkg.get("removed"):
        tags += " [REMOVED]"
    if pkg.get("quarantined"):
        tags += " [QUARANTINED]"
    heading = f"#### 📦 **`{purl}`** — {STATUS_LABELS.get(status, '')}{counter}{tags}"
    if inclusion:
        heading += f"<br>{inclusion}"
    parts = [f'<a id="{purl_to_anchor(purl)}"></a>', heading]

    meta = []
    published = relative_date(pkg.get("published"), reference=scan_time)
    if published:
        meta.append(f"📅 Released {published}")
    if config.license_info:
        license_str = pkg.get("license")
        if license_str:
            meta.append(f"⚖️ {license_str}")
    if meta:
        parts.append("\\\n".join(meta))

    m = malware_block(analysis.get("classifications", []))
    if m:
        parts += ["", m]

    g = governance_block(analysis.get("policy", {}).get("governance", []))
    if g:
        parts += ["", g]

    if config.assessment == "table":
        a = assessment_table(analysis.get("assessment", {}), config.overrides)
    elif config.assessment == "simplified":
        a = simplified_assessment_block(analysis.get("assessment", {}), config.overrides)
    else:
        a = ""
    if a:
        parts += ["", a]

    assessment_fail = any(get_effective_status(v) == "fail" for v in analysis.get("assessment", {}).values() if v)
    if not g and not assessment_fail and not config.policy:
        pb = policy_block(analysis.get("policy", {}).get("violations", {}))
        if pb:
            parts += ["", pb]

    if config.vulnerabilities:
        t = vuln_table(analysis.get("vulnerabilities", {}), report_url)
        if t:
            parts += ["", t]

    if config.policy:
        p = policy_table(analysis.get("policy", {}).get("violations", {}), config.overrides, report_url)
        if p:
            parts += ["", p]

    if report_url:
        parts += ["", f"[Full report →]({report_url})"]

    return "\n".join(parts)


def _format_scan_timestamp(iso_str):
    dt = _parse_iso(iso_str)
    if not dt:
        return iso_str if iso_str else None
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _format_duration(duration_str):
    if not duration_str:
        return None
    try:
        parts = duration_str.split(":")
        h, m = int(parts[0]), int(parts[1])
        s = float(parts[2])
        if h > 0:
            return f"{h}h {m}m"
        if m > 0:
            return f"{m}m {int(s)}s"
        return f"{s:.1f}s".rstrip("0").rstrip(".")  + "s" if "." in f"{s:.1f}" else f"{int(s)}s"
    except (IndexError, ValueError):
        return duration_str


def build_report(report_data, config, report_path="rl-protect.report.json", manifest=None):
    analysis_meta = report_data.get("analysis", {})
    report = analysis_meta.get("report", {})
    packages = report.get("packages", [])
    errors = report.get("errors", [])

    rejected, warnings_pkgs, passing = partition_packages(packages)
    reverse_deps = build_reverse_deps(packages)
    sorted_rejected = sorted(rejected, key=sort_key_rejected)
    sorted_warnings = sorted(warnings_pkgs, key=sort_key_warnings)

    overall_emoji = "✅" if not rejected else "❌"
    overall_label = "PASS" if not rejected else "FAIL"
    summary_parts = []
    if rejected:
        summary_parts.append(f"{len(rejected)} rejected")
    if warnings_pkgs:
        summary_parts.append(f"{len(warnings_pkgs)} warning{'s' if len(warnings_pkgs) != 1 else ''}")
    if passing:
        summary_parts.append(f"{len(passing)} passed")
    if errors:
        summary_parts.append(f"{len(errors)} scan error{'s' if len(errors) != 1 else ''}")
    status_value = f"{overall_emoji} {overall_label}"
    if summary_parts:
        status_value += " — " + " · ".join(summary_parts)

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    raw_scan_ts = analysis_meta.get("timestamp")
    scan_ts = _format_scan_timestamp(raw_scan_ts)
    scan_time = _parse_iso(raw_scan_ts)
    duration = _format_duration(analysis_meta.get("duration"))
    profile = (analysis_meta.get("profile") or {}).get("name")

    scan_time_parts = [scan_ts] if scan_ts else []
    if duration:
        scan_time_parts.append(duration)

    scanned_label = manifest if manifest else report_path
    meta_lines = [f"**Scanned:** `{scanned_label}`"]
    if profile:
        meta_lines.append(f"**Profile:** {profile}")
    if scan_time_parts:
        meta_lines.append(f"**Scan time:** {' · '.join(scan_time_parts)}")
    meta_lines.append(f"**Generated:** {generated}")
    meta_lines.append(f"**Status:** {status_value}")

    lines = [
        "# Spectra Assure Community Report",
        "",
        "\\\n".join(meta_lines),
        "",
        "---",
    ]

    if config.show_details:
        toc = ["", "## Contents", ""]
        if packages:
            toc.append("- [Summary](#summary)")
        if rejected:
            toc.append("- [❌ Rejected packages](#-rejected-packages)")
        if warnings_pkgs and config.level in ("warn", "pass"):
            toc.append("- [⚠️ Scan warnings](#️-scan-warnings)")
        if passing and config.level == "pass":
            toc.append("- [✅ Passing packages](#-passing-packages)")
        if rejected or warnings_pkgs:
            toc.append("- [📋 Version Update Plan](#-version-update-plan)")
        if errors:
            toc.append("- [❓ Scan errors](#-scan-errors)")
        toc += ["", "---"]
        lines += toc

    if packages:
        lines += ["", "## Summary", "", summary_table(sorted_rejected, sorted_warnings, passing, reverse_deps, link_to_reports=not config.show_details), ""]

    if config.show_details and rejected:
        lines += ["", "## ❌ Rejected packages", ""]
        for i, pkg in enumerate(sorted_rejected, 1):
            inclusion = find_inclusion(pkg.get("purl", ""), reverse_deps)
            lines += [format_package(pkg, config, i, len(sorted_rejected), inclusion, scan_time=scan_time), "", "---"]

    if config.show_details and warnings_pkgs and config.level in ("warn", "pass"):
        lines += ["", "## ⚠️ Scan warnings", "", "*Packages with issues that did not meet the rejection threshold.*", ""]
        for i, pkg in enumerate(sorted_warnings, 1):
            inclusion = find_inclusion(pkg.get("purl", ""), reverse_deps)
            lines += [format_package(pkg, config, i, len(sorted_warnings), inclusion, scan_time=scan_time), "", "---"]

    if config.show_details and passing and config.level == "pass":
        lines += ["", "## ✅ Passing packages", ""]
        for pkg in passing:
            lines.append(f"- `{pkg.get('purl', 'unknown')}`")
        lines.append("")

    if rejected or warnings_pkgs:
        plan = version_update_plan(sorted_rejected, sorted_warnings)
        if plan:
            lines += ["", "## 📋 Version Update Plan", "", plan, ""]

    if errors:
        lines += ["", "## ❓ Scan errors", ""]
        for e in errors:
            purl = e.get("purl", "unknown")
            info = e.get("error", {}).get("info", "unknown error")
            lines.append(f"- `{purl}` — {info}")
        lines.append("")

    lines += ["", "---", "", "*Generated by [Spectra Assure Community](https://secure.software) · [ReversingLabs](https://www.reversinglabs.com)*"]

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Generate a Markdown report from an rl-protect JSON report.")
    parser.add_argument("--report", default="rl-protect.report.json", metavar="PATH",
                        help="Path to the rl-protect JSON report (default: rl-protect.report.json)")
    parser.add_argument("--manifest", default=None, metavar="PATH",
                        help="Manifest or lock file that was scanned (shown in report header)")
    parser.add_argument("--output", default="rl-protect.report.md", metavar="PATH",
                        help="Path to write the Markdown report (default: rl-protect.report.md). Use - for stdout.")
    parser.add_argument("--template", choices=["concise", "expanded", "verbose"], default=None,
                        help="Report template: concise=summary only, expanded=rejected+warnings, verbose=full detail with policy")
    parser.add_argument("--level", choices=["fail", "warn", "pass"], default=None,
                        help="Expand full detail for: fail=rejected only (default), warn=+warnings, pass=all; overrides --template")
    parser.add_argument("--assessment", choices=["table", "simplified", "off"], default=None,
                        help="Assessment display style (default: simplified); overrides --template")
    parser.add_argument("--no-vulnerabilities", action="store_true",
                        help="Omit the vulnerability table from package sections")
    parser.add_argument("--license", action="store_true",
                        help="Include license information in package sections")
    parser.add_argument("--policy", action="store_true",
                        help="Include policy violations in package sections")
    parser.add_argument("--overrides", action="store_true",
                        help="Include override audit trail in assessment and policy tables")
    parser.add_argument("--no-error-code", action="store_true",
                        help="Exit 0 even when REJECT packages are found (exit 2 for file errors is unaffected)")
    args = parser.parse_args()

    try:
        with open(args.report, encoding="utf-8") as f:
            report_data = json.load(f)
    except FileNotFoundError:
        print(f"error: report file not found: {args.report}", file=sys.stderr)
        sys.exit(2)
    except json.JSONDecodeError as e:
        print(f"error: invalid JSON in {args.report}: {e}", file=sys.stderr)
        sys.exit(2)

    base = TEMPLATES.get(args.template, ReportConfig())
    config = ReportConfig(
        level=args.level if args.level is not None else base.level,
        assessment=args.assessment if args.assessment is not None else base.assessment,
        vulnerabilities=base.vulnerabilities and not args.no_vulnerabilities,
        license_info=base.license_info or args.license,
        policy=base.policy or args.policy,
        overrides=base.overrides or args.overrides,
        show_details=base.show_details,
    )

    md = build_report(report_data, config, report_path=args.report, manifest=args.manifest)

    if args.output == "-":
        sys.stdout.buffer.write((md + "\n").encode("utf-8"))
    else:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(md)
                f.write("\n")
            print(f"Report written to {args.output}")
        except OSError as e:
            print(f"error: could not write report: {e}", file=sys.stderr)
            sys.exit(2)

    packages = report_data.get("analysis", {}).get("report", {}).get("packages", [])
    has_reject = any(p.get("analysis", {}).get("recommendation") == "REJECT" for p in packages)
    if has_reject and not args.no_error_code:
        sys.exit(1)


if __name__ == "__main__":
    main()
