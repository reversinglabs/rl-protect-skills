"""Shared fixtures for rl-protect-interpret script tests."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "skills" / "rl-protect-interpret" / "scripts"


# ---------------------------------------------------------------------------
# Runner helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def scripts_dir():
    return SCRIPTS_DIR


@pytest.fixture
def write_report(tmp_path):
    """Write a report dict to a temp JSON file and return its path."""
    def _write(data, filename="report.json"):
        p = tmp_path / filename
        p.write_text(json.dumps(data), encoding="utf-8")
        return str(p)
    return _write


@pytest.fixture
def run(scripts_dir):
    """Run a script by name with the given CLI args.  Returns CompletedProcess."""
    def _run(script, *args):
        cmd = [sys.executable, str(scripts_dir / script), *[str(a) for a in args]]
        return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    return _run


@pytest.fixture
def run_json(run):
    """Run a script with --json and return (parsed_json, CompletedProcess)."""
    def _run_json(script, *args):
        r = run(script, *args, "--json")
        assert r.returncode != 2, f"Script error (exit 2): {r.stderr}"
        data = json.loads(r.stdout)
        return data, r
    return _run_json


# ---------------------------------------------------------------------------
# Reusable package building blocks
# ---------------------------------------------------------------------------

def make_assessment(
    secrets="pass", licenses="pass", vulnerabilities="pass",
    hardening="pass", tampering="pass", malware="pass", repository=None,
    overrides=None,
):
    """Build an assessment dict.  `overrides` is a dict of {check: override_dict}.
    `repository` is omitted from the dict unless explicitly provided, matching
    real report behaviour where repository risk is absent when not applicable.
    """
    overrides = overrides or {}
    checks = {
        "secrets": secrets, "licenses": licenses,
        "vulnerabilities": vulnerabilities, "hardening": hardening,
        "tampering": tampering, "malware": malware,
    }
    if repository is not None:
        checks["repository"] = repository
    labels = {
        "pass": "No issues found",
        "warning": "Potential issues detected",
        "fail": "Critical issues detected",
    }
    out = {}
    for key, status in checks.items():
        entry = {"status": status, "label": labels.get(status, status), "count": 0 if status == "pass" else 1}
        if key in overrides:
            entry["override"] = overrides[key]
        out[key] = entry
    return out


def make_package(
    purl, recommendation="APPROVE", assessment_kw=None,
    vulnerabilities=None, indicators=None, classifications=None,
    dependencies=None, dependents=0, policy_violations=None,
    governance=None, report_url="",
):
    """Build a single package entry for a report."""
    assessment_kw = assessment_kw or {}
    return {
        "purl": purl,
        "downloads": 100000,
        "dependents": dependents,
        "dependencies": dependencies or [],
        "analysis": {
            "recommendation": recommendation,
            "report": report_url,
            "assessment": make_assessment(**assessment_kw),
            "vulnerabilities": vulnerabilities or {},
            "indicators": indicators or {},
            "classifications": classifications or [],
            "policy": {
                "violations": policy_violations or {},
                "governance": governance or [],
            },
        },
    }


def make_report(packages, errors=None):
    """Wrap packages (and optional errors) in the top-level report structure."""
    return {
        "analysis": {
            "report": {
                "packages": packages,
                "errors": errors or [],
            }
        }
    }


# ---------------------------------------------------------------------------
# Pre-built package objects
# ---------------------------------------------------------------------------

CLEAN_PKG = make_package(
    "pkg:npm/safe-lib@1.0.0",
    report_url="https://example.com/report/safe-lib",
)

REJECT_VULN_PKG = make_package(
    "pkg:npm/vuln-lib@2.3.0",
    recommendation="REJECT",
    assessment_kw={"vulnerabilities": "fail"},
    vulnerabilities={
        "CVE-2024-0001": {
            "summary": "Remote code execution via crafted input",
            "cvss": {"baseScore": 9.8},
            "exploit": ["EXISTS", "MALWARE"],
        },
        "CVE-2024-0002": {
            "summary": "Information disclosure",
            "cvss": {"baseScore": 4.3},
            "exploit": [],
        },
    },
    report_url="https://example.com/report/vuln-lib",
)

MALWARE_PKG = make_package(
    "pkg:npm/evil-pkg@6.6.6",
    recommendation="REJECT",
    assessment_kw={"malware": "fail", "tampering": "fail"},
    classifications=[
        {"status": "Malicious", "result": "Trojan.GenericKD", "object": "file", "hashes": [["sha256", "aabbccdd"]]},
        {"status": "Suspicious", "result": "Heuristic.Obfuscated", "object": "file", "hashes": [["sha256", "eeff0011"]]},
        {"status": "Known good", "result": "Clean", "object": "file", "hashes": [["sha256", "11223344"]]},
    ],
    governance=[
        {"status": "blocked", "reason": "Known malware", "author": "security-team", "timestamp": "2024-06-15T10:00:00Z"},
    ],
    report_url="https://example.com/report/evil-pkg",
)

# Real scan data: requests@2.32.1 was removed from PyPI after release,
# triggering a repository FAIL alongside a vulnerabilities WARNING.
# Used to test that repository risk is correctly identified as the final category.
REPOSITORY_PKG = make_package(
    "pkg:pypi/requests@2.32.1?artifact=requests-2.32.1.tar.gz",
    recommendation="REJECT",
    report_url="https://secure.software/pypi/packages/requests/2.32.1/requests-2.32.1.tar.gz",
)
REPOSITORY_PKG["analysis"]["assessment"] = {
    "secrets":         {"status": "pass",    "label": "No sensitive information found",    "count": 0},
    "licenses":        {"status": "pass",    "label": "No license compliance issues",      "count": 0},
    "vulnerabilities": {"status": "warning", "label": "1 medium severity vulnerabilities", "count": 1},
    "hardening":       {"status": "pass",    "label": "No application hardening issues",   "count": 0},
    "tampering":       {"status": "pass",    "label": "No evidence of software tampering", "count": 0},
    "malware":         {"status": "pass",    "label": "No evidence of malware inclusion",  "count": 0},
    "repository":      {"status": "fail",    "label": "Caution: Package removed!",         "count": 0},
}


INDICATOR_PKG = make_package(
    "pkg:npm/sketchy@0.9.0",
    recommendation="REJECT",
    assessment_kw={"tampering": "warning"},
    indicators={
        "IND001": {"description": "Obfuscated code detected", "occurrences": 5},
        "IND002": {"description": "Network access in postinstall", "occurrences": 1},
    },
    classifications=[
        {"status": "Suspicious", "result": "Heuristic.Packed", "object": "file", "hashes": [["sha256", "abcdef01"]]},
    ],
    policy_violations={
        "RULE-01": {"description": "Must not contain obfuscated code", "status": "fail", "violations": 5, "override": None},
        "RULE-02": {
            "description": "Must not access network in install scripts",
            "status": "fail", "violations": 1,
            "override": {
                "to_status": "warning",
                "audit": {"author": "alice@corp.com", "timestamp": "2024-07-01T12:00:00Z", "reason": "Accepted risk for internal tool"},
            },
        },
    },
)

OVERRIDE_PKG = make_package(
    "pkg:npm/overridden@3.0.0",
    recommendation="APPROVE",
    assessment_kw={
        "vulnerabilities": "warning",
        "overrides": {
            "vulnerabilities": {
                "to_status": "pass",
                "audit": {
                    "author": "bob@corp.com",
                    "timestamp": "2024-05-20T09:30:00Z",
                    "reason": "False positive confirmed by vendor",
                },
            },
        },
    },
    policy_violations={
        "RULE-10": {
            "description": "Max CVSS score exceeded",
            "status": "fail", "violations": 1,
            "override": {
                "to_status": "pass",
                "audit": {
                    "author": "carol@corp.com",
                    "timestamp": "2024-05-21T14:00:00Z",
                    "reason": "Not exploitable in our environment",
                },
            },
        },
    },
)

GOVERNANCE_PKG = make_package(
    "pkg:npm/governed@1.0.0",
    recommendation="REJECT",
    governance=[
        {"status": "blocked", "reason": "License not approved", "author": "legal@corp.com", "timestamp": "2024-08-01T08:00:00Z"},
        {"status": "allowed", "reason": "Exception granted for Q4", "author": "cto@corp.com", "timestamp": "2024-09-15T16:00:00Z"},
    ],
)


# ---------------------------------------------------------------------------
# Dependency chain:  parent -> child-a -> grandchild,  parent -> child-b
# ---------------------------------------------------------------------------

DEP_GRANDCHILD = make_package("pkg:npm/grandchild@1.0.0")
DEP_CHILD_A = make_package(
    "pkg:npm/child-a@1.0.0",
    dependencies=["pkg:npm/grandchild@1.0.0"],
)
DEP_CHILD_B = make_package(
    "pkg:npm/child-b@2.0.0",
    recommendation="REJECT",
    assessment_kw={"vulnerabilities": "fail"},
)
DEP_PARENT = make_package(
    "pkg:npm/parent@1.0.0",
    dependencies=["pkg:npm/child-a@1.0.0", "pkg:npm/child-b@2.0.0"],
    dependents=10,
)


# ---------------------------------------------------------------------------
# Cyclic dependency:  cycle-a -> cycle-b -> cycle-c -> cycle-a
# ---------------------------------------------------------------------------

CYCLE_A = make_package(
    "pkg:npm/cycle-a@1.0.0",
    dependencies=["pkg:npm/cycle-b@1.0.0"],
)
CYCLE_B = make_package(
    "pkg:npm/cycle-b@1.0.0",
    dependencies=["pkg:npm/cycle-c@1.0.0"],
)
CYCLE_C = make_package(
    "pkg:npm/cycle-c@1.0.0",
    dependencies=["pkg:npm/cycle-a@1.0.0"],
)


# ---------------------------------------------------------------------------
# Diff versions:  widget v1 (clean) and widget v2 (risky)
# ---------------------------------------------------------------------------

WIDGET_V1 = make_package(
    "pkg:npm/widget@1.0.0",
    indicators={
        "IND-A": {"description": "Uses eval()", "occurrences": 2},
        "IND-B": {"description": "Minified code", "occurrences": 10},
    },
    vulnerabilities={
        "CVE-2023-1111": {"summary": "Old XSS flaw", "cvss": {"baseScore": 5.4}, "exploit": ["FIXABLE"]},
    },
    classifications=[
        {"status": "Suspicious", "result": "Heuristic.MinCode", "object": "file", "hashes": [["sha256", "old111"]]},
    ],
)

WIDGET_V2 = make_package(
    "pkg:npm/widget@2.0.0",
    recommendation="REJECT",
    assessment_kw={"vulnerabilities": "fail", "tampering": "warning"},
    indicators={
        "IND-A": {"description": "Uses eval()", "occurrences": 8},   # changed
        "IND-C": {"description": "Exfiltrates env vars", "occurrences": 1},  # new
        # IND-B removed
    },
    vulnerabilities={
        "CVE-2024-9999": {"summary": "Critical RCE", "cvss": {"baseScore": 10.0}, "exploit": ["EXISTS", "MALWARE"]},
        # CVE-2023-1111 fixed
    },
    classifications=[
        {"status": "Malicious", "result": "Trojan.Stealer", "object": "file", "hashes": [["sha256", "new999"]]},
        # old Suspicious file removed
    ],
    policy_violations={
        "RULE-NEW": {"description": "No data exfiltration", "status": "fail", "violations": 1},
    },
)


# ---------------------------------------------------------------------------
# Unchanged diff versions (identical)
# ---------------------------------------------------------------------------

STABLE_V1 = make_package("pkg:npm/stable@1.0.0")
STABLE_V2 = make_package("pkg:npm/stable@2.0.0")


# ---------------------------------------------------------------------------
# Error entries
# ---------------------------------------------------------------------------

SCAN_ERRORS = [
    {"purl": "pkg:npm/missing@1.0.0", "error": {"code": 404, "info": "Package not found in registry"}},
    {"purl": "pkg:npm/timeout@0.0.1", "error": {"code": 504, "info": "Scan timed out"}},
]


# ---------------------------------------------------------------------------
# Composite report fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def basic_report(write_report):
    return write_report(make_report([CLEAN_PKG]))


@pytest.fixture
def mixed_report(write_report):
    """Report with clean, reject-vuln, malware, indicator, override, and governance packages."""
    return write_report(make_report(
        [CLEAN_PKG, REJECT_VULN_PKG, MALWARE_PKG, INDICATOR_PKG, OVERRIDE_PKG, GOVERNANCE_PKG],
        errors=SCAN_ERRORS,
    ))


@pytest.fixture
def dep_report(write_report):
    """Report with a dependency chain."""
    return write_report(make_report([DEP_PARENT, DEP_CHILD_A, DEP_CHILD_B, DEP_GRANDCHILD]))


@pytest.fixture
def cycle_report(write_report):
    """Report with cyclic dependencies."""
    return write_report(make_report([CYCLE_A, CYCLE_B, CYCLE_C]))


@pytest.fixture
def diff_report(write_report):
    """Single report containing two versions of 'widget'."""
    return write_report(make_report([WIDGET_V1, WIDGET_V2]))


@pytest.fixture
def stable_diff_report(write_report):
    """Single report with two identical-behavior versions."""
    return write_report(make_report([STABLE_V1, STABLE_V2]))


@pytest.fixture
def empty_report(write_report):
    return write_report(make_report([]))


@pytest.fixture
def errors_only_report(write_report):
    return write_report(make_report([], errors=SCAN_ERRORS))
