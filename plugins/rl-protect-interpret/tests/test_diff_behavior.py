"""Tests for diff-behavior.py — behavior differential analysis."""

import json

import pytest

from conftest import (
    WIDGET_V1, WIDGET_V2, STABLE_V1, STABLE_V2,
    make_package, make_report,
)


# ===================================================================
# Basic diff — single report with two versions
# ===================================================================

class TestDiffBasic:

    def test_header_info(self, run_json, diff_report):
        data, _ = run_json("diff-behavior.py", "--package", "widget", "--report", diff_report, "--no-error-code")
        assert data["old"]["purl"] == "pkg:npm/widget@1.0.0"
        assert data["new"]["purl"] == "pkg:npm/widget@2.0.0"
        assert data["old"]["recommendation"] == "APPROVE"
        assert data["new"]["recommendation"] == "REJECT"

    def test_recommendation_changed(self, run_json, diff_report):
        data, _ = run_json("diff-behavior.py", "--package", "widget", "--report", diff_report, "--no-error-code")
        assert data["recommendation_changed"] is True

    def test_new_risks_detected(self, run_json, diff_report):
        data, _ = run_json("diff-behavior.py", "--package", "widget", "--report", diff_report, "--no-error-code")
        assert data["new_risks"] is True


# ===================================================================
# Assessment changes
# ===================================================================

class TestAssessmentDiff:

    def test_regression_detected(self, run_json, diff_report):
        data, _ = run_json("diff-behavior.py", "--package", "widget", "--report", diff_report, "--no-error-code")
        changes = data["assessment_changes"]
        vuln_change = next(c for c in changes if c["assessment"] == "Vulnerabilities")
        assert vuln_change["old_status"] == "pass"
        assert vuln_change["new_status"] == "fail"
        assert vuln_change["direction"] == "regression"

    def test_improvement_detected(self, run_json, write_report):
        v1 = make_package("pkg:npm/improving@1.0.0", assessment_kw={"malware": "fail"})
        v2 = make_package("pkg:npm/improving@2.0.0", assessment_kw={"malware": "pass"})
        rp = write_report(make_report([v1, v2]))
        data, _ = run_json("diff-behavior.py", "--package", "improving", "--report", rp, "--no-error-code")
        change = next(c for c in data["assessment_changes"] if c["assessment"] == "Malware")
        assert change["direction"] == "improved"

    def test_no_changes(self, run_json, stable_diff_report):
        data, _ = run_json("diff-behavior.py", "--package", "stable", "--report", stable_diff_report, "--no-error-code")
        assert data["assessment_changes"] == []
        assert data["new_risks"] is False


# ===================================================================
# Indicator diff
# ===================================================================

class TestIndicatorDiff:

    def test_added_indicators(self, run_json, diff_report):
        data, _ = run_json("diff-behavior.py", "--package", "widget", "--report", diff_report, "--no-error-code")
        added = data["indicator_changes"]["added"]
        ids = {i["id"] for i in added}
        assert "IND-C" in ids  # new in v2

    def test_removed_indicators(self, run_json, diff_report):
        data, _ = run_json("diff-behavior.py", "--package", "widget", "--report", diff_report, "--no-error-code")
        removed = data["indicator_changes"]["removed"]
        ids = {i["id"] for i in removed}
        assert "IND-B" in ids  # gone in v2

    def test_changed_indicator_counts(self, run_json, diff_report):
        data, _ = run_json("diff-behavior.py", "--package", "widget", "--report", diff_report, "--no-error-code")
        changed = data["indicator_changes"]["changed"]
        ind_a = next(c for c in changed if c["id"] == "IND-A")
        assert ind_a["old_count"] == "2"
        assert ind_a["new_count"] == "8"

    def test_no_indicator_changes(self, run_json, stable_diff_report):
        data, _ = run_json("diff-behavior.py", "--package", "stable", "--report", stable_diff_report, "--no-error-code")
        ic = data["indicator_changes"]
        assert ic["added"] == []
        assert ic["removed"] == []
        assert ic["changed"] == []


# ===================================================================
# Classification diff
# ===================================================================

class TestClassificationDiff:

    def test_new_malicious_file(self, run_json, diff_report):
        data, _ = run_json("diff-behavior.py", "--package", "widget", "--report", diff_report, "--no-error-code")
        added = data["classification_changes"]["added"]
        assert len(added) == 1
        assert added[0]["status"] == "Malicious"
        assert added[0]["sha256"] == "new999"

    def test_removed_suspicious_file(self, run_json, diff_report):
        data, _ = run_json("diff-behavior.py", "--package", "widget", "--report", diff_report, "--no-error-code")
        removed = data["classification_changes"]["removed"]
        assert len(removed) == 1
        assert removed[0]["status"] == "Suspicious"
        assert removed[0]["sha256"] == "old111"


# ===================================================================
# Vulnerability diff
# ===================================================================

class TestVulnerabilityDiff:

    def test_new_cve(self, run_json, diff_report):
        data, _ = run_json("diff-behavior.py", "--package", "widget", "--report", diff_report, "--no-error-code")
        added = data["vulnerability_changes"]["added"]
        assert len(added) == 1
        assert added[0]["id"] == "CVE-2024-9999"
        assert added[0]["cvss"] == 10.0
        assert added[0]["cvss_label"] == "critical"
        assert "EXISTS" in added[0]["exploit_flags"]

    def test_fixed_cve(self, run_json, diff_report):
        data, _ = run_json("diff-behavior.py", "--package", "widget", "--report", diff_report, "--no-error-code")
        fixed = data["vulnerability_changes"]["fixed"]
        assert len(fixed) == 1
        assert fixed[0]["id"] == "CVE-2023-1111"

    def test_no_vuln_changes(self, run_json, stable_diff_report):
        data, _ = run_json("diff-behavior.py", "--package", "stable", "--report", stable_diff_report, "--no-error-code")
        vc = data["vulnerability_changes"]
        assert vc["added"] == []
        assert vc["fixed"] == []


# ===================================================================
# Policy violation diff
# ===================================================================

class TestPolicyViolationDiff:

    def test_new_violation(self, run_json, diff_report):
        data, _ = run_json("diff-behavior.py", "--package", "widget", "--report", diff_report, "--no-error-code")
        added = data["policy_violation_changes"]["added"]
        assert len(added) == 1
        assert added[0]["rule_id"] == "RULE-NEW"

    def test_removed_and_changed_violations(self, run_json, write_report):
        v1 = make_package(
            "pkg:npm/pv@1.0.0",
            policy_violations={
                "R1": {"description": "Check A", "status": "fail", "violations": 3},
                "R2": {"description": "Check B", "status": "warning", "violations": 1},
            },
        )
        v2 = make_package(
            "pkg:npm/pv@2.0.0",
            policy_violations={
                "R2": {"description": "Check B", "status": "fail", "violations": 5},
                "R3": {"description": "Check C", "status": "fail", "violations": 1},
            },
        )
        rp = write_report(make_report([v1, v2]))
        data, _ = run_json("diff-behavior.py", "--package", "pv", "--report", rp, "--no-error-code")
        pvc = data["policy_violation_changes"]
        # R1 removed
        assert any(r["rule_id"] == "R1" for r in pvc["removed"])
        # R3 added
        assert any(r["rule_id"] == "R3" for r in pvc["added"])
        # R2 changed (warning->fail, 1->5)
        r2 = next(c for c in pvc["changed"] if c["rule_id"] == "R2")
        assert r2["old_status"] == "warning"
        assert r2["new_status"] == "fail"


# ===================================================================
# Reverse mode
# ===================================================================

class TestDiffReverse:

    def test_reverse_swaps_old_new(self, run_json, diff_report):
        data, _ = run_json("diff-behavior.py", "--package", "widget", "--report", diff_report, "--reverse", "--no-error-code")
        # With --reverse, old and new swap
        assert data["old"]["purl"] == "pkg:npm/widget@2.0.0"
        assert data["new"]["purl"] == "pkg:npm/widget@1.0.0"

    def test_reverse_fixed_becomes_added(self, run_json, diff_report):
        """Reversing should swap added/fixed vulnerabilities."""
        data, _ = run_json("diff-behavior.py", "--package", "widget", "--report", diff_report, "--reverse", "--no-error-code")
        # CVE-2024-9999 was added in v2 → now it's 'fixed' in the reverse direction
        fixed_ids = {v["id"] for v in data["vulnerability_changes"]["fixed"]}
        added_ids = {v["id"] for v in data["vulnerability_changes"]["added"]}
        assert "CVE-2024-9999" in fixed_ids
        assert "CVE-2023-1111" in added_ids


# ===================================================================
# Two separate reports
# ===================================================================

class TestTwoReports:

    def test_separate_reports(self, run_json, write_report):
        old_rp = write_report(make_report([STABLE_V1]), filename="old.json")
        new_rp = write_report(make_report([STABLE_V2]), filename="new.json")
        data, _ = run_json(
            "diff-behavior.py", "--package", "stable",
            "--old-report", old_rp, "--new-report", new_rp, "--no-error-code",
        )
        assert "stable@1.0.0" in data["old"]["purl"]
        assert "stable@2.0.0" in data["new"]["purl"]
        assert data["new_risks"] is False

    def test_separate_reports_with_changes(self, run_json, write_report):
        old_rp = write_report(make_report([WIDGET_V1]), filename="old.json")
        new_rp = write_report(make_report([WIDGET_V2]), filename="new.json")
        data, _ = run_json(
            "diff-behavior.py", "--package", "widget",
            "--old-report", old_rp, "--new-report", new_rp, "--no-error-code",
        )
        assert data["new_risks"] is True
        assert len(data["vulnerability_changes"]["added"]) == 1


# ===================================================================
# Version disambiguation
# ===================================================================

class TestVersionDisambiguation:

    def test_explicit_versions(self, run_json, diff_report):
        data, _ = run_json(
            "diff-behavior.py", "--package", "widget", "--report", diff_report,
            "--old-version", "1.0.0", "--new-version", "2.0.0", "--no-error-code",
        )
        assert "1.0.0" in data["old"]["purl"]
        assert "2.0.0" in data["new"]["purl"]

    def test_three_versions_requires_disambiguation(self, run, write_report):
        v1 = make_package("pkg:npm/multi@1.0.0")
        v2 = make_package("pkg:npm/multi@2.0.0")
        v3 = make_package("pkg:npm/multi@3.0.0")
        rp = write_report(make_report([v1, v2, v3]))
        r = run("diff-behavior.py", "--package", "multi", "--report", rp, "--no-error-code")
        assert r.returncode == 2
        assert "version" in r.stderr.lower()

    def test_three_versions_with_pins(self, run_json, write_report):
        v1 = make_package("pkg:npm/multi@1.0.0")
        v2 = make_package("pkg:npm/multi@2.0.0")
        v3 = make_package("pkg:npm/multi@3.0.0")
        rp = write_report(make_report([v1, v2, v3]))
        data, _ = run_json(
            "diff-behavior.py", "--package", "multi", "--report", rp,
            "--old-version", "1.0.0", "--new-version", "3.0.0", "--no-error-code",
        )
        assert "1.0.0" in data["old"]["purl"]
        assert "3.0.0" in data["new"]["purl"]

    def test_only_one_version_fails(self, run, write_report):
        rp = write_report(make_report([STABLE_V1]))
        r = run("diff-behavior.py", "--package", "stable", "--report", rp, "--no-error-code")
        assert r.returncode == 2
        assert "only 1 version" in r.stderr.lower()


# ===================================================================
# Exit codes
# ===================================================================

class TestDiffExitCodes:

    def test_exit_1_new_risks(self, run, diff_report):
        r = run("diff-behavior.py", "--package", "widget", "--report", diff_report)
        assert r.returncode == 1

    def test_exit_0_no_risks(self, run, stable_diff_report):
        r = run("diff-behavior.py", "--package", "stable", "--report", stable_diff_report)
        assert r.returncode == 0

    def test_exit_code_suppressed(self, run, diff_report):
        r = run("diff-behavior.py", "--package", "widget", "--report", diff_report, "--no-error-code")
        assert r.returncode == 0

    def test_json_exit_code_matches_terminal(self, run, diff_report):
        r_term = run("diff-behavior.py", "--package", "widget", "--report", diff_report)
        r_json = run("diff-behavior.py", "--package", "widget", "--report", diff_report, "--json")
        assert r_term.returncode == r_json.returncode


# ===================================================================
# Error handling
# ===================================================================

class TestDiffErrors:

    def test_missing_package_flag(self, run, diff_report):
        r = run("diff-behavior.py", "--report", diff_report)
        assert r.returncode == 2
        assert "--package" in r.stderr.lower()

    def test_no_match(self, run, diff_report):
        r = run("diff-behavior.py", "--package", "nonexistent", "--report", diff_report)
        assert r.returncode == 2

    def test_missing_report(self, run):
        r = run("diff-behavior.py", "--package", "x", "--report", "/no/such.json")
        assert r.returncode == 2

    def test_invalid_json(self, run, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("NOT JSON", encoding="utf-8")
        r = run("diff-behavior.py", "--package", "x", "--report", str(bad))
        assert r.returncode == 2

    def test_no_args_shows_usage(self, run):
        r = run("diff-behavior.py")
        assert r.returncode == 2


# ===================================================================
# Terminal output
# ===================================================================

class TestDiffTerminal:

    def test_header_present(self, run, diff_report):
        r = run("diff-behavior.py", "--package", "widget", "--report", diff_report, "--no-error-code")
        assert "Behavior diff" in r.stdout
        assert "widget@1.0.0" in r.stdout
        assert "widget@2.0.0" in r.stdout

    def test_sections_present(self, run, diff_report):
        r = run("diff-behavior.py", "--package", "widget", "--report", diff_report, "--no-error-code")
        assert "Assessment changes" in r.stdout
        assert "Behavior indicators" in r.stdout
        assert "Vulnerability changes" in r.stdout

    def test_regression_marker(self, run, diff_report):
        r = run("diff-behavior.py", "--package", "widget", "--report", diff_report, "--no-error-code")
        assert "REGRESSION" in r.stdout

    def test_risk_warning(self, run, diff_report):
        r = run("diff-behavior.py", "--package", "widget", "--report", diff_report, "--no-error-code")
        assert "New risks detected" in r.stdout

    def test_no_risk_message(self, run, stable_diff_report):
        r = run("diff-behavior.py", "--package", "stable", "--report", stable_diff_report, "--no-error-code")
        assert "No new risks detected" in r.stdout


# ===================================================================
# Edge cases
# ===================================================================

class TestDiffEdgeCases:

    def test_package_name_substring_match(self, run_json, diff_report):
        """Should match on substring, case-insensitive."""
        data, _ = run_json("diff-behavior.py", "--package", "WIDGET", "--report", diff_report, "--no-error-code")
        assert "widget" in data["old"]["purl"]

    def test_identical_versions_no_changes(self, run_json, write_report):
        """Two versions with absolutely identical analysis."""
        v1 = make_package("pkg:npm/same@1.0.0",
            indicators={"IND-X": {"description": "test", "occurrences": 3}},
            vulnerabilities={"CVE-0000": {"summary": "test", "cvss": {"baseScore": 1.0}, "exploit": []}},
        )
        v2 = make_package("pkg:npm/same@2.0.0",
            indicators={"IND-X": {"description": "test", "occurrences": 3}},
            vulnerabilities={"CVE-0000": {"summary": "test", "cvss": {"baseScore": 1.0}, "exploit": []}},
        )
        rp = write_report(make_report([v1, v2]))
        data, _ = run_json("diff-behavior.py", "--package", "same", "--report", rp, "--no-error-code")
        assert data["new_risks"] is False
        assert data["vulnerability_changes"]["added"] == []
        assert data["vulnerability_changes"]["fixed"] == []
        assert data["indicator_changes"]["added"] == []
        assert data["indicator_changes"]["removed"] == []
        assert data["indicator_changes"]["changed"] == []

    def test_all_fields_empty(self, run_json, write_report):
        """Both versions have no vulns, indicators, classifications, or violations."""
        v1 = make_package("pkg:npm/bare@1.0.0")
        v2 = make_package("pkg:npm/bare@2.0.0")
        rp = write_report(make_report([v1, v2]))
        data, r = run_json("diff-behavior.py", "--package", "bare", "--report", rp, "--no-error-code")
        assert data["new_risks"] is False
        assert r.returncode == 0
