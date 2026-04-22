#!/usr/bin/env python3
"""
deptree.py — rl-protect dependency tree visualizer

Reads an rl-protect JSON report and renders the dependency relationships as an
indented tree using Unicode box-drawing characters. Each node shows the package
PURL, scan status, recommendation, and worst assessment result. Cycles are
detected and marked to prevent infinite recursion.

Usage:
    python deptree.py [--package <purl>] [--report <path>] [--depth <n>] [--reverse]

Options:
    --package <purl>    Root the tree at a specific package (PURL substring match).
                        Without this flag, one tree is printed per top-level package.
    --report  <path>    Path to the report file. Default: rl-protect.report.json
    --depth   <n>       Maximum tree depth to display. Default: unlimited.
    --reverse           Show reverse dependency tree (who depends on this package).
                        Requires --package. Walks upward from the target to find
                        all ancestors, answering "how did this get into my tree?"
    --json              Output results as JSON instead of formatted terminal tree.

Output:
    Markdown printed to stdout with a Unicode tree for each root package.

Exit codes:
    0   Tree rendered. No REJECT recommendations found in displayed packages.
    1   One or more REJECT recommendations found in displayed packages.
    2   Report file not found, invalid JSON, or no packages in report.
"""

import argparse
import json
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ASSESSMENTS = ["secrets", "licenses", "vulnerabilities", "hardening", "tampering", "malware", "repository"]

# Display priority when multiple categories share the same worst grade.
# Repository is handled separately — it is always final if present and non-pass.
ASSESSMENT_PRIORITY = ["malware", "tampering", "vulnerabilities", "secrets", "hardening", "licenses"]

STATUS_ICON  = {"pass": "✅", "warning": "⚠️", "fail": "❌"}
STATUS_LABEL = {"pass": "PASS", "warning": "WARN", "fail": "FAIL"}

RECOMMENDATION_ICON = {"APPROVE": "🟢", "REJECT": "🔴"}


def has_overrides(assessment: dict) -> bool:
    """Return True if any assessment check has a policy override that changed the status."""
    for k in ASSESSMENTS:
        entry = assessment.get(k, {})
        override = entry.get("override")
        if override and override.get("to_status") != entry.get("status"):
            return True
    return False


def load_report(path: Path) -> dict:
    if not path.exists():
        raise RuntimeError(f"report file not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON in {path}: {exc}") from exc


def get_packages(report: dict) -> list:
    """Extract the packages list from the report structure."""
    return report.get("analysis", {}).get("report", {}).get("packages", [])


def filter_packages(packages: list, purl_filter: str) -> list:
    """Return packages whose PURL contains the filter string (case-insensitive)."""
    if not purl_filter:
        return packages
    f = purl_filter.lower()
    return [p for p in packages if f in p.get("purl", "").lower()]


def worst_status(assessment: dict) -> str:
    """Return the worst raw status across all assessment checks."""
    statuses = [assessment.get(k, {}).get("status", "pass") for k in ASSESSMENTS]
    if "fail" in statuses:
        return "fail"
    if "warning" in statuses:
        return "warning"
    return "pass"


def worst_label(assessment: dict) -> str:
    """Return the label of the category selected as final for top-level grade display.

    Repository risk is always final if present and non-pass. Among the remaining
    categories, when multiple share the same worst grade the display priority is:
    Malware, Tampering, Vulnerability, Secrets, Mitigations (Hardening), License.
    """
    repo = assessment.get("repository", {})
    if repo.get("status", "pass") != "pass":
        return repo.get("label", "")

    ws = worst_status(assessment)
    for k in ASSESSMENT_PRIORITY:
        if assessment.get(k, {}).get("status") == ws:
            return assessment.get(k, {}).get("label", "")
    return ""


# ---------------------------------------------------------------------------
# Tree building
# ---------------------------------------------------------------------------

def build_index(packages: list) -> dict:
    """Build a PURL → package dict for fast lookups."""
    return {p.get("purl", ""): p for p in packages}


def build_reverse_index(packages: list) -> dict:
    """Build a reverse dependency map: child PURL → list of parent PURLs."""
    reverse: dict[str, list[str]] = {}
    for pkg in packages:
        parent = pkg.get("purl", "")
        for dep in pkg.get("dependencies", []):
            reverse.setdefault(dep, []).append(parent)
    return reverse


def find_roots(packages: list, index: dict) -> list:
    """
    Return packages that are not listed as a dependency of any other package.

    These are the natural tree roots. If every package is somebody's dependency
    (e.g. a cyclic graph), fall back to all packages.
    """
    all_deps = set()
    for pkg in packages:
        for dep in pkg.get("dependencies", []):
            all_deps.add(dep)

    roots = [p for p in packages if p.get("purl", "") not in all_deps]
    return roots if roots else packages


# ---------------------------------------------------------------------------
# Tree rendering
# ---------------------------------------------------------------------------

def format_node(purl: str, index: dict, *, unscanned: bool = False, cycle: bool = False) -> tuple:
    """
    Format a single tree node as a compact status string.

    Returns (text, has_override) where has_override is True when a ``†``
    marker was appended to the recommendation.

    Examples:
        pkg:npm/express@4.18.2  🟢 APPROVE  ✅ PASS
        pkg:npm/risky@1.0.0     🟢 APPROVE †  ❌ FAIL — 1 severe vuln
        pkg:npm/evil@1.0.0      🔴 REJECT   ❌ FAIL — Malware detected
        pkg:npm/blocked@1.0.0   🔴 REJECT ‡ (Version published 0 days ago)  ✅ PASS
        pkg:npm/unknown@0.1.0   ⚠ not scanned
        pkg:npm/circular@1.0.0  ↻ cycle
    """
    if cycle:
        return f"{purl}  ↻ cycle", False

    if unscanned:
        return f"{purl}  ⚠ not scanned", False

    pkg = index.get(purl)
    if not pkg:
        return f"{purl}  ⚠ not scanned", False

    analysis = pkg.get("analysis", {})
    rec = analysis.get("recommendation", "—")
    rec_icon = RECOMMENDATION_ICON.get(rec, "❓")
    assessment = analysis.get("assessment", {})
    ws = worst_status(assessment)
    ws_icon = STATUS_ICON.get(ws, "❓")
    wl = worst_label(assessment)

    overridden = has_overrides(assessment)
    override_mark = " †" if overridden else ""

    # Detect governance-driven REJECT: recommendation is REJECT but
    # assessments alone would not have caused it.
    governance = analysis.get("policy", {}).get("governance", [])
    gov_blocked = [g for g in governance if g.get("status") == "blocked"]
    if rec == "REJECT" and gov_blocked and ws != "fail":
        reason = gov_blocked[0].get("reason", "governance block")
        ws_display = STATUS_LABEL.get(ws, ws)
        label_part = f" — {wl}" if ws != "pass" and wl else ""
        return f"{purl}  {rec_icon} REJECT ‡ ({reason})  {ws_icon} {ws_display}{label_part}", overridden

    ws_display = STATUS_LABEL.get(ws, ws)
    label_part = f" — {wl}" if ws != "pass" and wl else ""
    return f"{purl}  {rec_icon} {rec}{override_mark}  {ws_icon} {ws_display}{label_part}", overridden


def render_tree(
    purl: str,
    index: dict,
    *,
    prefix: str = "",
    is_last: bool = True,
    visited: set | None = None,
    depth: int = 0,
    max_depth: int = 0,
    lines: list | None = None,
    seen_rejects: set | None = None,
    seen_overrides: set | None = None,
) -> list:
    """
    Recursively render a dependency tree using Unicode box-drawing characters.

    Parameters
    ----------
    purl : str
        The PURL of the current node.
    index : dict
        PURL → package mapping.
    prefix : str
        Accumulated indentation prefix for the current depth.
    is_last : bool
        Whether this node is the last sibling (controls └── vs ├──).
    visited : set
        PURLs already printed in this branch (cycle detection).
    depth : int
        Current depth in the tree.
    max_depth : int
        Maximum depth to render. 0 means unlimited.
    lines : list
        Accumulator for output lines.
    seen_rejects : set
        Accumulator for REJECT PURLs found during rendering.
    seen_overrides : set
        Accumulator for PURLs with policy overrides (marked with †).

    Returns
    -------
    list of str
        The rendered tree lines.
    """
    if lines is None:
        lines = []
    if visited is None:
        visited = set()
    if seen_rejects is None:
        seen_rejects = set()
    if seen_overrides is None:
        seen_overrides = set()

    # Detect cycle
    is_cycle = purl in visited
    is_unscanned = purl not in index

    # Connector
    if depth == 0:
        connector = ""
        child_prefix = ""
    else:
        connector = "└── " if is_last else "├── "
        child_prefix = prefix + ("    " if is_last else "│   ")

    node_text, node_overridden = format_node(purl, index, unscanned=is_unscanned, cycle=is_cycle)
    lines.append(f"{prefix}{connector}{node_text}")
    if node_overridden:
        seen_overrides.add(purl)

    # Track REJECT recommendations
    pkg = index.get(purl)
    if pkg and pkg.get("analysis", {}).get("recommendation") == "REJECT":
        seen_rejects.add(purl)

    # Stop recursion on cycle, unscanned, or depth limit
    if is_cycle or is_unscanned:
        return lines
    if max_depth > 0 and depth >= max_depth:
        deps = (pkg or {}).get("dependencies", [])
        if deps:
            lines.append(f"{child_prefix}└── … {len(deps)} dependencies (depth limit reached)")
        return lines

    visited.add(purl)
    deps = (pkg or {}).get("dependencies", [])

    for i, dep_purl in enumerate(deps):
        is_last_dep = i == len(deps) - 1
        render_tree(
            dep_purl,
            index,
            prefix=child_prefix,
            is_last=is_last_dep,
            visited=set(visited),  # copy so sibling branches don't share state
            depth=depth + 1,
            max_depth=max_depth,
            lines=lines,
            seen_rejects=seen_rejects,
            seen_overrides=seen_overrides,
        )

    return lines


def render_reverse_tree(
    purl: str,
    index: dict,
    reverse_index: dict,
    *,
    prefix: str = "",
    is_last: bool = True,
    visited: set | None = None,
    depth: int = 0,
    max_depth: int = 0,
    lines: list | None = None,
    seen_rejects: set | None = None,
    seen_overrides: set | None = None,
) -> list:
    """
    Recursively render a reverse dependency tree (who depends on this package).

    Walks upward through the reverse_index (child → parents) using the same
    Unicode box-drawing format as render_tree.
    """
    if lines is None:
        lines = []
    if visited is None:
        visited = set()
    if seen_rejects is None:
        seen_rejects = set()
    if seen_overrides is None:
        seen_overrides = set()

    is_cycle = purl in visited
    is_unscanned = purl not in index

    # Connector
    if depth == 0:
        connector = ""
        child_prefix = ""
    else:
        connector = "└── " if is_last else "├── "
        child_prefix = prefix + ("    " if is_last else "│   ")

    node_text, node_overridden = format_node(purl, index, unscanned=is_unscanned, cycle=is_cycle)
    lines.append(f"{prefix}{connector}{node_text}")
    if node_overridden:
        seen_overrides.add(purl)

    pkg = index.get(purl)
    if pkg and pkg.get("analysis", {}).get("recommendation") == "REJECT":
        seen_rejects.add(purl)

    if is_cycle or is_unscanned:
        return lines
    if max_depth > 0 and depth >= max_depth:
        parents = reverse_index.get(purl, [])
        if parents:
            lines.append(f"{child_prefix}└── … {len(parents)} dependents (depth limit reached)")
        return lines

    visited.add(purl)
    parents = reverse_index.get(purl, [])

    for i, parent_purl in enumerate(parents):
        is_last_parent = i == len(parents) - 1
        render_reverse_tree(
            parent_purl,
            index,
            reverse_index,
            prefix=child_prefix,
            is_last=is_last_parent,
            visited=set(visited),
            depth=depth + 1,
            max_depth=max_depth,
            lines=lines,
            seen_rejects=seen_rejects,
            seen_overrides=seen_overrides,
        )

    return lines


def print_reverse_tree(packages: list, index: dict, reverse_index: dict, *, max_depth: int = 0) -> int:
    """
    Print the reverse dependency tree for the given packages.

    Returns exit code 0 (all clear) or 1 (REJECT found in tree).
    """
    any_reject = False

    for i, pkg in enumerate(packages):
        purl = pkg.get("purl", "unknown")

        if i > 0:
            print("\n---\n")

        print(f"### Reverse dependency tree — {purl}\n")
        print("```")

        seen_rejects: set = set()
        seen_overrides: set = set()
        lines = render_reverse_tree(
            purl, index, reverse_index,
            max_depth=max_depth, seen_rejects=seen_rejects, seen_overrides=seen_overrides,
        )
        print("\n".join(lines))

        print("```")

        parents = reverse_index.get(purl, [])
        print(f"\n> {len(parents)} direct dependent{'s' if len(parents) != 1 else ''}.")

        if seen_overrides:
            print("\n† Policy override applied — recommendation differs from raw findings. "
                  "Run `interpret.py overrides` for full audit trail.")

        if seen_rejects:
            any_reject = True
            print(f"\n🔴 **REJECT** found in tree: {', '.join(sorted(seen_rejects))}")

    return 1 if any_reject else 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def print_tree(packages: list, index: dict, *, max_depth: int = 0) -> int:
    """
    Print the full dependency tree for the given root packages.

    Returns exit code 0 (no REJECT) or 1 (REJECT found).
    """
    any_reject = False

    for i, pkg in enumerate(packages):
        purl = pkg.get("purl", "unknown")

        if i > 0:
            print("\n---\n")

        print(f"### Dependency tree — {purl}\n")
        print("```")

        seen_rejects: set = set()
        seen_overrides: set = set()
        lines = render_tree(purl, index, max_depth=max_depth, seen_rejects=seen_rejects, seen_overrides=seen_overrides)
        print("\n".join(lines))

        print("```")

        deps = pkg.get("dependencies", [])
        scanned = sum(1 for d in deps if d in index)
        print(f"\n> {len(deps)} direct dependenc{'y' if len(deps) == 1 else 'ies'}, "
              f"{scanned} scanned.")

        if seen_overrides:
            print("\n† Policy override applied — recommendation differs from raw findings. "
                  "Run `interpret.py overrides` for full audit trail.")

        if seen_rejects:
            any_reject = True
            print(f"\n🔴 **REJECT** found in tree: {', '.join(sorted(seen_rejects))}")

    return 1 if any_reject else 0


def parse_args(argv: list) -> tuple:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--package", default="")
    p.add_argument("--report", type=Path, default=Path("rl-protect.report.json"))
    p.add_argument("--depth", type=int, default=0)
    p.add_argument("--reverse", action="store_true")
    p.add_argument("--no-error-code", action="store_true")
    p.add_argument("--json", action="store_true", dest="json_output")
    a = p.parse_args(argv[1:])
    return a.package, a.report, a.depth, a.reverse, a.no_error_code, a.json_output


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def node_to_json(purl: str, index: dict, *, unscanned: bool = False, cycle: bool = False) -> dict:
    """Return a JSON-serializable dict for a single tree node."""
    if cycle:
        return {"purl": purl, "cycle": True}
    if unscanned or purl not in index:
        return {"purl": purl, "unscanned": True}

    pkg = index[purl]
    analysis = pkg.get("analysis", {})
    rec = analysis.get("recommendation", "—")
    assessment = analysis.get("assessment", {})
    ws = worst_status(assessment)
    wl = worst_label(assessment)
    overridden = has_overrides(assessment)

    governance = analysis.get("policy", {}).get("governance", [])
    gov_blocked = [g for g in governance if g.get("status") == "blocked"]

    node = {
        "purl": purl,
        "recommendation": rec,
        "worst_status": ws,
        "worst_label": wl,
        "has_override": overridden,
    }
    if rec == "REJECT" and gov_blocked and ws != "fail":
        node["governance_block"] = gov_blocked[0].get("reason", "governance block")
    return node


def build_tree_json(
    purl: str,
    index: dict,
    *,
    visited: set | None = None,
    depth: int = 0,
    max_depth: int = 0,
    seen_rejects: set | None = None,
) -> dict:
    """Recursively build a JSON tree structure."""
    if visited is None:
        visited = set()
    if seen_rejects is None:
        seen_rejects = set()

    is_cycle = purl in visited
    is_unscanned = purl not in index
    node = node_to_json(purl, index, unscanned=is_unscanned, cycle=is_cycle)

    pkg = index.get(purl)
    if pkg and pkg.get("analysis", {}).get("recommendation") == "REJECT":
        seen_rejects.add(purl)

    if is_cycle or is_unscanned:
        return node

    if max_depth > 0 and depth >= max_depth:
        deps = (pkg or {}).get("dependencies", [])
        if deps:
            node["truncated_children"] = len(deps)
        return node

    visited.add(purl)
    deps = (pkg or {}).get("dependencies", [])
    if deps:
        node["children"] = [
            build_tree_json(
                dep_purl, index,
                visited=set(visited),
                depth=depth + 1,
                max_depth=max_depth,
                seen_rejects=seen_rejects,
            )
            for dep_purl in deps
        ]

    return node


def build_reverse_tree_json(
    purl: str,
    index: dict,
    reverse_index: dict,
    *,
    visited: set | None = None,
    depth: int = 0,
    max_depth: int = 0,
    seen_rejects: set | None = None,
) -> dict:
    """Recursively build a JSON reverse dependency tree."""
    if visited is None:
        visited = set()
    if seen_rejects is None:
        seen_rejects = set()

    is_cycle = purl in visited
    is_unscanned = purl not in index
    node = node_to_json(purl, index, unscanned=is_unscanned, cycle=is_cycle)

    pkg = index.get(purl)
    if pkg and pkg.get("analysis", {}).get("recommendation") == "REJECT":
        seen_rejects.add(purl)

    if is_cycle or is_unscanned:
        return node

    if max_depth > 0 and depth >= max_depth:
        parents = reverse_index.get(purl, [])
        if parents:
            node["truncated_dependents"] = len(parents)
        return node

    visited.add(purl)
    parents = reverse_index.get(purl, [])
    if parents:
        node["dependents"] = [
            build_reverse_tree_json(
                parent_purl, index, reverse_index,
                visited=set(visited),
                depth=depth + 1,
                max_depth=max_depth,
                seen_rejects=seen_rejects,
            )
            for parent_purl in parents
        ]

    return node


def main():
    purl_filter, report_path, max_depth, reverse, no_error_code, json_output = parse_args(sys.argv)
    try:
        report = load_report(report_path)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)
    packages = get_packages(report)

    if not packages:
        if json_output:
            print(json.dumps({"trees": []}, indent=2))
        else:
            print("No packages found in report.")
        sys.exit(2)

    index = build_index(packages)

    if json_output:
        if reverse:
            if not purl_filter:
                print("Error: --reverse requires --package to specify a starting point.", file=sys.stderr)
                sys.exit(2)
            targets = filter_packages(packages, purl_filter)
            if not targets:
                print(json.dumps({"trees": [], "message": f"No packages found matching '{purl_filter}'."}, indent=2))
                sys.exit(0)
            reverse_idx = build_reverse_index(packages)
            trees = []
            all_rejects = set()
            for pkg in targets:
                purl = pkg.get("purl", "unknown")
                seen_rejects: set = set()
                tree = build_reverse_tree_json(purl, index, reverse_idx, max_depth=max_depth, seen_rejects=seen_rejects)
                parents = reverse_idx.get(purl, [])
                trees.append({
                    "root": purl,
                    "direction": "reverse",
                    "tree": tree,
                    "stats": {"direct_dependents": len(parents), "rejects": sorted(seen_rejects)},
                })
                all_rejects.update(seen_rejects)
            result = {"trees": trees, "exit_code": 1 if all_rejects else 0}
            print(json.dumps(result, indent=2))
            sys.exit(0 if no_error_code else result["exit_code"])
        else:
            if purl_filter:
                roots = filter_packages(packages, purl_filter)
                if not roots:
                    print(json.dumps({"trees": [], "message": f"No packages found matching '{purl_filter}'."}, indent=2))
                    sys.exit(0)
            else:
                roots = find_roots(packages, index)
            trees = []
            all_rejects = set()
            for pkg in roots:
                purl = pkg.get("purl", "unknown")
                seen_rejects: set = set()
                tree = build_tree_json(purl, index, max_depth=max_depth, seen_rejects=seen_rejects)
                deps = pkg.get("dependencies", [])
                scanned = sum(1 for d in deps if d in index)
                trees.append({
                    "root": purl,
                    "direction": "forward",
                    "tree": tree,
                    "stats": {"direct_dependencies": len(deps), "scanned": scanned, "rejects": sorted(seen_rejects)},
                })
                all_rejects.update(seen_rejects)
            result = {"trees": trees, "exit_code": 1 if all_rejects else 0}
            print(json.dumps(result, indent=2))
            sys.exit(0 if no_error_code else result["exit_code"])

    if reverse:
        if not purl_filter:
            print("Error: --reverse requires --package to specify a starting point.", file=sys.stderr)
            sys.exit(2)
        targets = filter_packages(packages, purl_filter)
        if not targets:
            print(f"No packages found matching '{purl_filter}'.")
            sys.exit(0)
        reverse_idx = build_reverse_index(packages)
        exit_code = print_reverse_tree(targets, index, reverse_idx, max_depth=max_depth)
    else:
        if purl_filter:
            roots = filter_packages(packages, purl_filter)
            if not roots:
                print(f"No packages found matching '{purl_filter}'.")
                sys.exit(0)
        else:
            roots = find_roots(packages, index)
        exit_code = print_tree(roots, index, max_depth=max_depth)

    sys.exit(0 if no_error_code else exit_code)


if __name__ == "__main__":
    main()
