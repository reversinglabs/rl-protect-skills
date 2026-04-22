"""Tests for summarize.py — full report overview."""

import json

import pytest

from conftest import (
    CLEAN_PKG, REJECT_VULN_PKG, MALWARE_PKG, OVERRIDE_PKG, SCAN_ERRORS,
    REPOSITORY_PKG,
    make_package, make_report,
)


# ===================================================================
# Basic functionality
# ===================================================================

class TestSummaryBasic:

    def test_single_clean_package(self, run_json, basic_report):
        data, r = run_json("summarize.py", basic_report, "--no-error-code")
        assert len(data["packages"]) == 1
        pkg = data["packages"][0]
        assert pkg["purl"] == "pkg:npm/safe-lib@1.0.0"
        assert pkg["recommendation"] == "APPROVE"
        assert r.returncode == 0

    def test_summary_counts(self, run_json, mixed_report):
        data, _ = run_json("summarize.py", mixed_report, "--no-error-code")
        s = data["summary"]
        assert s["total"] == 6
        assert s["reject"] >= 1
        assert s["reject"] + s["warn"] + s["pass"] == s["total"]

    def test_empty_report(self, run_json, empty_report):
        data, r = run_json("summarize.py", empty_report, "--no-error-code")
        assert data["packages"] == []
        assert data["summary"]["total"] == 0
        assert r.returncode == 0

    def test_errors_included(self, run_json, mixed_report):
        data, _ = run_json("summarize.py", mixed_report, "--no-error-code")
        assert len(data["errors"]) == 2
        assert data["errors"][0]["purl"] == "pkg:npm/missing@1.0.0"


# ===================================================================
# Assessment details
# ===================================================================

class TestSummaryAssessment:

    def test_all_assessments_present(self, run_json, basic_report):
        data, _ = run_json("summarize.py", basic_report, "--no-error-code")
        assessment = data["packages"][0]["assessment"]
        expected = {"secrets", "licenses", "vulnerabilities", "hardening", "tampering", "malware"}
        assert set(assessment.keys()) == expected

    def test_assessment_status_and_label(self, run_json, basic_report):
        data, _ = run_json("summarize.py", basic_report, "--no-error-code")
        sec = data["packages"][0]["assessment"]["secrets"]
        assert sec["status"] == "pass"
        assert isinstance(sec["label"], str)
        assert len(sec["label"]) > 0

    def test_reject_package_assessment(self, run_json, write_report):
        rp = write_report(make_report([REJECT_VULN_PKG]))
        data, _ = run_json("summarize.py", rp, "--no-error-code")
        pkg = data["packages"][0]
        assert pkg["recommendation"] == "REJECT"
        assert pkg["assessment"]["vulnerabilities"]["status"] == "fail"


# ===================================================================
# Override handling
# ===================================================================

class TestSummaryOverrides:

    def test_override_in_assessment(self, run_json, write_report):
        rp = write_report(make_report([OVERRIDE_PKG]))
        data, _ = run_json("summarize.py", rp, "--no-error-code")
        pkg = data["packages"][0]
        assert pkg["has_override"] is True
        vuln = pkg["assessment"]["vulnerabilities"]
        assert "override" in vuln
        assert vuln["override"]["author"] == "bob@corp.com"

    def test_no_override_flag(self, run_json, basic_report):
        data, _ = run_json("summarize.py", basic_report, "--no-error-code")
        assert data["packages"][0]["has_override"] is False


# ===================================================================
# Exit codes
# ===================================================================

class TestSummaryExitCodes:

    def test_exit_0_all_approve(self, run, basic_report):
        r = run("summarize.py", basic_report)
        assert r.returncode == 0

    def test_exit_1_has_reject(self, run, mixed_report):
        r = run("summarize.py", mixed_report)
        assert r.returncode == 1

    def test_exit_1_suppressed(self, run, mixed_report):
        r = run("summarize.py", mixed_report, "--no-error-code")
        assert r.returncode == 0

    def test_json_exit_code_matches_terminal(self, run, mixed_report):
        r_term = run("summarize.py", mixed_report)
        r_json = run("summarize.py", mixed_report, "--json")
        assert r_term.returncode == r_json.returncode


# ===================================================================
# Terminal output
# ===================================================================

class TestSummaryTerminal:

    def test_contains_purl(self, run, basic_report):
        r = run("summarize.py", basic_report, "--no-error-code")
        assert "pkg:npm/safe-lib@1.0.0" in r.stdout

    def test_contains_recommendation_icon(self, run, basic_report):
        r = run("summarize.py", basic_report, "--no-error-code")
        assert "APPROVE" in r.stdout

    def test_totals_line(self, run, mixed_report):
        r = run("summarize.py", mixed_report, "--no-error-code")
        assert "REJECT" in r.stdout
        assert "WARN" in r.stdout
        assert "PASS" in r.stdout
        assert "total" in r.stdout

    def test_errors_section(self, run, mixed_report):
        r = run("summarize.py", mixed_report, "--no-error-code")
        assert "Scan errors" in r.stdout
        assert "pkg:npm/missing@1.0.0" in r.stdout

    def test_override_note(self, run, write_report):
        rp = write_report(make_report([OVERRIDE_PKG]))
        r = run("summarize.py", rp, "--no-error-code")
        assert "†" in r.stdout
        assert "override" in r.stdout.lower()

    def test_box_drawing_present(self, run, basic_report):
        r = run("summarize.py", basic_report, "--no-error-code")
        assert "┌" in r.stdout
        assert "└" in r.stdout


# ===================================================================
# Error handling
# ===================================================================

class TestSummaryErrors:

    def test_missing_report_file(self, run):
        r = run("summarize.py", "/nonexistent/report.json")
        assert r.returncode == 2
        assert "not found" in r.stderr.lower()

    def test_invalid_json(self, run, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{broken", encoding="utf-8")
        r = run("summarize.py", str(bad))
        assert r.returncode == 2
        assert "invalid json" in r.stderr.lower()

    def test_errors_only_report(self, run_json, errors_only_report):
        data, _ = run_json("summarize.py", errors_only_report, "--no-error-code")
        assert data["packages"] == []
        assert len(data["errors"]) == 2


# ===================================================================
# Edge cases
# ===================================================================

class TestSummaryEdge:

    def test_many_packages(self, run_json, write_report):
        """Report with 50 packages should work fine."""
        pkgs = [make_package(f"pkg:npm/pkg-{i}@1.0.0") for i in range(50)]
        rp = write_report(make_report(pkgs))
        data, r = run_json("summarize.py", rp, "--no-error-code")
        assert data["summary"]["total"] == 50
        assert r.returncode == 0

    def test_package_with_missing_assessment_keys(self, run_json, write_report):
        """Package with partial assessment should not crash."""
        pkg = {
            "purl": "pkg:npm/sparse@1.0.0",
            "downloads": 0, "dependents": 0, "dependencies": [],
            "analysis": {
                "recommendation": "APPROVE",
                "report": "",
                "assessment": {
                    "secrets": {"status": "pass", "label": "OK", "count": 0},
                    # other assessment keys missing
                },
                "vulnerabilities": {},
                "indicators": {},
                "classifications": [],
                "policy": {"violations": {}, "governance": []},
            },
        }
        rp = write_report(make_report([pkg]))
        data, r = run_json("summarize.py", rp, "--no-error-code")
        assert len(data["packages"]) == 1
        assert "secrets" in data["packages"][0]["assessment"]

    def test_report_url_propagated(self, run_json, basic_report):
        data, _ = run_json("summarize.py", basic_report, "--no-error-code")
        assert data["packages"][0]["report_url"] == "https://example.com/report/safe-lib"


# ===================================================================
# Repository risk — real scan data (requests@2.32.1, removed from PyPI)
# ===================================================================

class TestRepositoryRisk:

    def test_repository_row_present_when_fail(self, run_json, write_report):
        """Repository row appears in assessment output when the category is non-pass."""
        rp = write_report(make_report([REPOSITORY_PKG]))
        data, _ = run_json("summarize.py", rp, "--no-error-code")
        assessment = data["packages"][0]["assessment"]
        assert "repository" in assessment
        assert assessment["repository"]["status"] == "fail"
        assert assessment["repository"]["label"] == "Caution: Package removed!"

    def test_repository_row_absent_for_clean_package(self, run_json, basic_report):
        """Repository row is omitted when the category is absent from the report data."""
        data, _ = run_json("summarize.py", basic_report, "--no-error-code")
        assessment = data["packages"][0]["assessment"]
        assert "repository" not in assessment

    def test_repository_shown_in_terminal(self, run, write_report):
        rp = write_report(make_report([REPOSITORY_PKG]))
        r = run("summarize.py", rp, "--no-error-code")
        assert "Repository" in r.stdout
        assert "Caution: Package removed!" in r.stdout
