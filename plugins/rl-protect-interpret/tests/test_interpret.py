"""Tests for interpret.py — task-based report extraction."""

import json

import pytest


# ===================================================================
# Vulnerabilities task
# ===================================================================

class TestVulnerabilities:

    def test_lists_cves_with_scores(self, run_json, mixed_report):
        data, _ = run_json("interpret.py", "vulnerabilities", "--report", mixed_report, "--no-error-code")
        assert data["task"] == "vulnerabilities"
        pkgs = data["packages"]
        vuln_pkg = next(p for p in pkgs if "vuln-lib" in p["purl"])
        assert len(vuln_pkg["vulnerabilities"]) == 2
        cve1 = next(v for v in vuln_pkg["vulnerabilities"] if v["id"] == "CVE-2024-0001")
        assert cve1["cvss"] == 9.8
        assert cve1["cvss_label"] == "critical"
        assert "EXISTS" in cve1["exploit_flags"]
        assert "MALWARE" in cve1["exploit_flags"]

    def test_cvss_labels_correct(self, run_json, mixed_report):
        data, _ = run_json("interpret.py", "vulnerabilities", "--report", mixed_report, "--no-error-code")
        vuln_pkg = next(p for p in data["packages"] if "vuln-lib" in p["purl"])
        cve2 = next(v for v in vuln_pkg["vulnerabilities"] if v["id"] == "CVE-2024-0002")
        assert cve2["cvss"] == 4.3
        assert cve2["cvss_label"] == "medium"

    def test_no_vulnerabilities(self, run_json, basic_report):
        data, r = run_json("interpret.py", "vulnerabilities", "--report", basic_report, "--no-error-code")
        assert data["packages"] == []
        assert r.returncode == 0

    def test_override_shown(self, run_json, write_report):
        """Vulnerability assessment with a meaningful override."""
        from conftest import make_package, make_report
        pkg = make_package(
            "pkg:npm/ov@1.0.0",
            assessment_kw={
                "vulnerabilities": "warning",
                "overrides": {
                    "vulnerabilities": {
                        "to_status": "pass",
                        "audit": {"author": "tester", "timestamp": "2024-01-01T00:00:00Z", "reason": "FP"},
                    },
                },
            },
            vulnerabilities={"CVE-9999": {"summary": "Test", "cvss": {"baseScore": 3.0}, "exploit": []}},
        )
        rp = write_report(make_report([pkg]))
        data, _ = run_json("interpret.py", "vulnerabilities", "--report", rp, "--no-error-code")
        assert data["packages"][0]["override"] is not None
        assert data["packages"][0]["override"]["author"] == "tester"

    def test_exit_code_1_on_reject(self, run, mixed_report):
        r = run("interpret.py", "vulnerabilities", "--report", mixed_report)
        assert r.returncode == 1

    def test_exit_code_suppressed(self, run, mixed_report):
        r = run("interpret.py", "vulnerabilities", "--report", mixed_report, "--no-error-code")
        assert r.returncode == 0

    def test_terminal_output_contains_cve(self, run, mixed_report):
        r = run("interpret.py", "vulnerabilities", "--report", mixed_report, "--no-error-code")
        assert "CVE-2024-0001" in r.stdout
        assert "9.80" in r.stdout

    def test_package_filter(self, run_json, mixed_report):
        data, _ = run_json("interpret.py", "vulnerabilities", "--report", mixed_report, "--package", "vuln-lib", "--no-error-code")
        assert all("vuln-lib" in p["purl"] for p in data["packages"])

    def test_package_filter_no_match(self, run_json, mixed_report):
        data, r = run_json("interpret.py", "vulnerabilities", "--report", mixed_report, "--package", "nonexistent", "--no-error-code")
        assert data["packages"] == []


# ===================================================================
# Indicators task
# ===================================================================

class TestIndicators:

    def test_lists_indicators(self, run_json, mixed_report):
        data, _ = run_json("interpret.py", "indicators", "--report", mixed_report, "--no-error-code")
        sketchy = next(p for p in data["packages"] if "sketchy" in p["purl"])
        assert len(sketchy["indicators"]) == 2
        ind1 = next(i for i in sketchy["indicators"] if i["id"] == "IND001")
        assert ind1["occurrences"] == 5
        assert "Obfuscated" in ind1["description"]

    def test_classifications_only_flagged(self, run_json, mixed_report):
        data, _ = run_json("interpret.py", "indicators", "--report", mixed_report, "--no-error-code")
        sketchy = next(p for p in data["packages"] if "sketchy" in p["purl"])
        assert len(sketchy["classifications"]) == 1
        assert sketchy["classifications"][0]["status"] == "Suspicious"

    def test_policy_violations_with_override(self, run_json, mixed_report):
        data, _ = run_json("interpret.py", "indicators", "--report", mixed_report, "--no-error-code")
        sketchy = next(p for p in data["packages"] if "sketchy" in p["purl"])
        rule2 = next(v for v in sketchy["policy_violations"] if v["rule_id"] == "RULE-02")
        assert rule2["override"] is not None
        assert "alice" in rule2["override"]

    def test_empty_indicators_still_listed(self, run_json, basic_report):
        """Packages with no indicators still appear in output."""
        data, _ = run_json("interpret.py", "indicators", "--report", basic_report, "--no-error-code")
        assert len(data["packages"]) == 1
        assert data["packages"][0]["indicators"] == []

    def test_terminal_output_contains_table(self, run, mixed_report):
        r = run("interpret.py", "indicators", "--report", mixed_report, "--package", "sketchy", "--no-error-code")
        assert "IND001" in r.stdout
        assert "Obfuscated" in r.stdout


# ===================================================================
# Malware task
# ===================================================================

class TestMalware:

    def test_lists_malicious_files(self, run_json, mixed_report):
        data, _ = run_json("interpret.py", "malware", "--report", mixed_report, "--no-error-code")
        evil = next(p for p in data["packages"] if "evil-pkg" in p["purl"])
        # Only Malicious and Suspicious, not "Known good"
        assert len(evil["classifications"]) == 2
        statuses = {c["status"] for c in evil["classifications"]}
        assert statuses == {"Malicious", "Suspicious"}

    def test_assessment_statuses(self, run_json, mixed_report):
        data, _ = run_json("interpret.py", "malware", "--report", mixed_report, "--no-error-code")
        evil = next(p for p in data["packages"] if "evil-pkg" in p["purl"])
        assert evil["assessment"]["malware"]["status"] == "fail"
        assert evil["assessment"]["tampering"]["status"] == "fail"

    def test_governance_blocks(self, run_json, mixed_report):
        data, _ = run_json("interpret.py", "malware", "--report", mixed_report, "--no-error-code")
        evil = next(p for p in data["packages"] if "evil-pkg" in p["purl"])
        assert len(evil["governance_blocks"]) == 1
        assert evil["governance_blocks"][0]["author"] == "security-team"

    def test_no_malware(self, run_json, basic_report):
        data, _ = run_json("interpret.py", "malware", "--report", basic_report, "--no-error-code")
        pkg = data["packages"][0]
        assert pkg["classifications"] == []
        assert pkg["assessment"]["malware"]["status"] == "pass"


# ===================================================================
# Overrides task
# ===================================================================

class TestOverrides:

    def test_assessment_overrides(self, run_json, mixed_report):
        data, _ = run_json("interpret.py", "overrides", "--report", mixed_report, "--no-error-code")
        ov_pkg = next(p for p in data["packages"] if "overridden" in p["purl"])
        assert len(ov_pkg["assessment_overrides"]) == 1
        ao = ov_pkg["assessment_overrides"][0]
        assert ao["assessment"] == "vulnerabilities"
        assert ao["original_status"] == "warning"
        assert ao["override_status"] == "pass"
        assert ao["author"] == "bob@corp.com"

    def test_policy_overrides(self, run_json, mixed_report):
        data, _ = run_json("interpret.py", "overrides", "--report", mixed_report, "--no-error-code")
        ov_pkg = next(p for p in data["packages"] if "overridden" in p["purl"])
        assert len(ov_pkg["policy_overrides"]) == 1
        po = ov_pkg["policy_overrides"][0]
        assert po["rule_id"] == "RULE-10"
        assert po["author"] == "carol@corp.com"

    def test_no_overrides(self, run_json, basic_report):
        data, _ = run_json("interpret.py", "overrides", "--report", basic_report, "--no-error-code")
        assert data["packages"] == []

    def test_terminal_no_overrides_message(self, run, basic_report):
        r = run("interpret.py", "overrides", "--report", basic_report, "--no-error-code")
        assert "No overrides found" in r.stdout


# ===================================================================
# Governance task
# ===================================================================

class TestGovernance:

    def test_lists_decisions(self, run_json, mixed_report):
        data, _ = run_json("interpret.py", "governance", "--report", mixed_report, "--no-error-code")
        gov_pkg = next(p for p in data["packages"] if "governed" in p["purl"])
        assert len(gov_pkg["decisions"]) == 2
        statuses = {d["status"] for d in gov_pkg["decisions"]}
        assert statuses == {"blocked", "allowed"}

    def test_no_governance(self, run_json, basic_report):
        data, _ = run_json("interpret.py", "governance", "--report", basic_report, "--no-error-code")
        assert data["packages"] == []

    def test_terminal_no_governance_message(self, run, basic_report):
        r = run("interpret.py", "governance", "--report", basic_report, "--no-error-code")
        assert "No governance decisions found" in r.stdout


# ===================================================================
# Dependencies task
# ===================================================================

class TestDependencies:

    def test_lists_deps(self, run_json, dep_report):
        """Without --package filter, all packages are in scope so deps resolve."""
        data, _ = run_json("interpret.py", "dependencies", "--report", dep_report, "--no-error-code")
        pkg = next(p for p in data["packages"] if "parent" in p["purl"])
        assert pkg["dependency_count"] == 2
        assert pkg["scanned_count"] == 2
        dep_purls = {d["purl"] for d in pkg["dependencies"]}
        assert "pkg:npm/child-a@1.0.0" in dep_purls
        assert "pkg:npm/child-b@2.0.0" in dep_purls

    def test_scanned_flag(self, run_json, dep_report):
        data, _ = run_json("interpret.py", "dependencies", "--report", dep_report, "--no-error-code")
        pkg = next(p for p in data["packages"] if "parent" in p["purl"])
        for dep in pkg["dependencies"]:
            assert dep["scanned"] is True

    def test_unscanned_dep(self, run_json, write_report):
        from conftest import make_package, make_report
        pkg = make_package("pkg:npm/top@1.0.0", dependencies=["pkg:npm/ghost@1.0.0"])
        rp = write_report(make_report([pkg]))
        data, _ = run_json("interpret.py", "dependencies", "--report", rp, "--no-error-code")
        dep = data["packages"][0]["dependencies"][0]
        assert dep["scanned"] is False
        assert dep["recommendation"] is None

    def test_filtered_deps_show_as_unscanned(self, run_json, dep_report):
        """When --package filters out deps, they appear as unscanned."""
        data, _ = run_json("interpret.py", "dependencies", "--report", dep_report, "--package", "parent", "--no-error-code")
        pkg = data["packages"][0]
        assert pkg["dependency_count"] == 2
        assert pkg["scanned_count"] == 0  # children filtered out of scope
        for dep in pkg["dependencies"]:
            assert dep["scanned"] is False

    def test_risk_notes_for_reject_dep(self, run_json, dep_report):
        """Risk notes require deps to be in scope (no --package filter)."""
        data, _ = run_json("interpret.py", "dependencies", "--report", dep_report, "--no-error-code")
        pkg = next(p for p in data["packages"] if "parent" in p["purl"])
        assert len(pkg["risk_notes"]) >= 1
        reject_note = next(n for n in pkg["risk_notes"] if "child-b" in n["purl"])
        assert reject_note["recommendation"] == "REJECT"

    def test_no_deps(self, run_json, basic_report):
        data, _ = run_json("interpret.py", "dependencies", "--report", basic_report, "--no-error-code")
        pkg = data["packages"][0]
        assert pkg["dependency_count"] == 0


# ===================================================================
# Errors task
# ===================================================================

class TestErrors:

    def test_lists_errors(self, run_json, mixed_report):
        data, _ = run_json("interpret.py", "errors", "--report", mixed_report, "--no-error-code")
        assert data["task"] == "errors"
        assert len(data["errors"]) == 2
        purls = {e["purl"] for e in data["errors"]}
        assert "pkg:npm/missing@1.0.0" in purls

    def test_no_errors(self, run_json, basic_report):
        data, _ = run_json("interpret.py", "errors", "--report", basic_report, "--no-error-code")
        assert data["errors"] == []

    def test_terminal_no_errors_message(self, run, basic_report):
        r = run("interpret.py", "errors", "--report", basic_report, "--no-error-code")
        assert "No scan errors found" in r.stdout


# ===================================================================
# Error handling and edge cases
# ===================================================================

class TestErrorHandling:

    def test_unknown_task(self, run, basic_report):
        r = run("interpret.py", "bogus", "--report", basic_report)
        assert r.returncode == 2
        assert "unknown task" in r.stderr.lower()

    def test_missing_report(self, run):
        r = run("interpret.py", "vulnerabilities", "--report", "/nonexistent/path.json")
        assert r.returncode == 2
        assert "not found" in r.stderr.lower()

    def test_invalid_json(self, run, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("NOT JSON{{{", encoding="utf-8")
        r = run("interpret.py", "vulnerabilities", "--report", str(bad))
        assert r.returncode == 2
        assert "invalid json" in r.stderr.lower()

    def test_no_args_shows_usage(self, run):
        r = run("interpret.py")
        assert r.returncode == 2

    def test_empty_report(self, run_json, empty_report):
        data, r = run_json("interpret.py", "vulnerabilities", "--report", empty_report, "--no-error-code")
        assert data["packages"] == []
        assert "message" in data

    def test_package_filter_case_insensitive(self, run_json, mixed_report):
        data, _ = run_json("interpret.py", "malware", "--report", mixed_report, "--package", "EVIL-PKG", "--no-error-code")
        assert len(data["packages"]) == 1
        assert "evil-pkg" in data["packages"][0]["purl"]

    def test_json_and_terminal_agree_on_exit_code(self, run, mixed_report):
        """JSON and terminal modes should produce the same exit code."""
        r_term = run("interpret.py", "vulnerabilities", "--report", mixed_report)
        r_json = run("interpret.py", "vulnerabilities", "--report", mixed_report, "--json")
        assert r_term.returncode == r_json.returncode

    def test_report_url_propagated(self, run_json, mixed_report):
        data, _ = run_json("interpret.py", "vulnerabilities", "--report", mixed_report, "--no-error-code")
        vuln_pkg = next(p for p in data["packages"] if "vuln-lib" in p["purl"])
        assert vuln_pkg["report_url"] == "https://example.com/report/vuln-lib"

    def test_all_tasks_produce_valid_json(self, run, mixed_report):
        """Every task should produce valid JSON with --json."""
        for task in ["vulnerabilities", "indicators", "malware", "overrides", "governance", "dependencies", "errors"]:
            r = run("interpret.py", task, "--report", mixed_report, "--json", "--no-error-code")
            data = json.loads(r.stdout)
            assert "task" in data or "exit_code" in data, f"Task {task} produced invalid JSON structure"
