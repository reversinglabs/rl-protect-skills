"""Tests for deptree.py — dependency tree visualization."""

import json

import pytest

from conftest import (
    CYCLE_A, CYCLE_B, CYCLE_C,
    DEP_PARENT, DEP_CHILD_A, DEP_CHILD_B, DEP_GRANDCHILD,
    CLEAN_PKG, REJECT_VULN_PKG, MALWARE_PKG, OVERRIDE_PKG, GOVERNANCE_PKG,
    REPOSITORY_PKG,
    make_package, make_report,
)


# ===================================================================
# Forward tree — basic
# ===================================================================

class TestForwardTree:

    def test_single_root_no_deps(self, run_json, basic_report):
        data, r = run_json("deptree.py", "--report", basic_report, "--no-error-code")
        assert len(data["trees"]) == 1
        tree = data["trees"][0]
        assert tree["root"] == "pkg:npm/safe-lib@1.0.0"
        assert tree["direction"] == "forward"
        assert "children" not in tree["tree"]  # no deps
        assert r.returncode == 0

    def test_dependency_chain(self, run_json, dep_report):
        data, _ = run_json("deptree.py", "--report", dep_report, "--no-error-code")
        # parent is the only root (children are not roots)
        roots = [t["root"] for t in data["trees"]]
        assert "pkg:npm/parent@1.0.0" in roots

        parent_tree = next(t for t in data["trees"] if t["root"] == "pkg:npm/parent@1.0.0")
        top = parent_tree["tree"]
        assert len(top["children"]) == 2

        child_a = next(c for c in top["children"] if "child-a" in c["purl"])
        assert len(child_a["children"]) == 1
        assert "grandchild" in child_a["children"][0]["purl"]

    def test_stats(self, run_json, dep_report):
        data, _ = run_json("deptree.py", "--report", dep_report, "--package", "parent", "--no-error-code")
        stats = data["trees"][0]["stats"]
        assert stats["direct_dependencies"] == 2
        assert stats["scanned"] == 2

    def test_reject_in_tree(self, run_json, dep_report):
        data, _ = run_json("deptree.py", "--report", dep_report, "--package", "parent", "--no-error-code")
        stats = data["trees"][0]["stats"]
        assert "pkg:npm/child-b@2.0.0" in stats["rejects"]

    def test_package_filter(self, run_json, dep_report):
        data, _ = run_json("deptree.py", "--report", dep_report, "--package", "child-a", "--no-error-code")
        assert len(data["trees"]) == 1
        assert data["trees"][0]["root"] == "pkg:npm/child-a@1.0.0"

    def test_package_filter_no_match(self, run, dep_report):
        r = run("deptree.py", "--report", dep_report, "--package", "nonexistent", "--no-error-code", "--json")
        data = json.loads(r.stdout)
        assert data["trees"] == []

    def test_auto_root_detection(self, run_json, dep_report):
        """Without --package, parent should be detected as root."""
        data, _ = run_json("deptree.py", "--report", dep_report, "--no-error-code")
        roots = {t["root"] for t in data["trees"]}
        assert "pkg:npm/parent@1.0.0" in roots
        # children should not be roots
        assert "pkg:npm/child-a@1.0.0" not in roots
        assert "pkg:npm/grandchild@1.0.0" not in roots


# ===================================================================
# Depth limiting
# ===================================================================

class TestDepthLimit:

    def test_depth_1(self, run_json, dep_report):
        data, _ = run_json("deptree.py", "--report", dep_report, "--package", "parent", "--depth", "1", "--no-error-code")
        top = data["trees"][0]["tree"]
        child_a = next(c for c in top["children"] if "child-a" in c["purl"])
        # grandchild should be truncated
        assert "children" not in child_a
        assert child_a.get("truncated_children", 0) == 1

    def test_depth_0_unlimited(self, run_json, dep_report):
        data, _ = run_json("deptree.py", "--report", dep_report, "--package", "parent", "--depth", "0", "--no-error-code")
        top = data["trees"][0]["tree"]
        child_a = next(c for c in top["children"] if "child-a" in c["purl"])
        assert "children" in child_a
        assert len(child_a["children"]) == 1

    def test_invalid_depth(self, run, dep_report):
        r = run("deptree.py", "--report", dep_report, "--depth", "abc")
        assert r.returncode == 2
        assert "invalid int value" in r.stderr.lower()


# ===================================================================
# Cyclic dependencies
# ===================================================================

class TestCyclicTree:

    def test_cycle_detected_json(self, run_json, cycle_report):
        data, _ = run_json("deptree.py", "--report", cycle_report, "--package", "cycle-a", "--no-error-code")
        tree = data["trees"][0]["tree"]
        # cycle-a -> cycle-b -> cycle-c -> cycle-a (cycle)
        assert tree["purl"] == "pkg:npm/cycle-a@1.0.0"
        child_b = tree["children"][0]
        assert "cycle-b" in child_b["purl"]
        child_c = child_b["children"][0]
        assert "cycle-c" in child_c["purl"]
        # cycle-c's child should be cycle-a marked as cycle
        cycle_node = child_c["children"][0]
        assert "cycle-a" in cycle_node["purl"]
        assert cycle_node.get("cycle") is True

    def test_cycle_detected_terminal(self, run, cycle_report):
        r = run("deptree.py", "--report", cycle_report, "--package", "cycle-a", "--no-error-code")
        assert "cycle" in r.stdout.lower()

    def test_cycle_no_infinite_recursion(self, run, cycle_report):
        """Cycle detection prevents infinite loops — script finishes promptly."""
        r = run("deptree.py", "--report", cycle_report, "--no-error-code")
        assert r.returncode == 0

    def test_all_cycle_nodes_as_roots(self, run_json, cycle_report):
        """When all packages are in a cycle, all become roots."""
        data, _ = run_json("deptree.py", "--report", cycle_report, "--no-error-code")
        roots = {t["root"] for t in data["trees"]}
        # All three form a cycle so all are each other's deps — fallback to all as roots
        assert len(roots) == 3

    def test_cycle_from_different_entry_points(self, run_json, cycle_report):
        """Starting from any node in the cycle should still detect the cycle."""
        for node in ["cycle-a", "cycle-b", "cycle-c"]:
            data, _ = run_json("deptree.py", "--report", cycle_report, "--package", node, "--no-error-code")
            tree_str = json.dumps(data)
            assert '"cycle": true' in tree_str, f"Cycle not detected when starting from {node}"


# ===================================================================
# Unscanned dependencies
# ===================================================================

class TestUnscanned:

    def test_unscanned_dep_flagged(self, run_json, write_report):
        pkg = make_package("pkg:npm/top@1.0.0", dependencies=["pkg:npm/ghost@1.0.0"])
        rp = write_report(make_report([pkg]))
        data, _ = run_json("deptree.py", "--report", rp, "--no-error-code")
        top = data["trees"][0]["tree"]
        ghost = top["children"][0]
        assert ghost.get("unscanned") is True

    def test_unscanned_terminal(self, run, write_report):
        pkg = make_package("pkg:npm/top@1.0.0", dependencies=["pkg:npm/ghost@1.0.0"])
        rp = write_report(make_report([pkg]))
        r = run("deptree.py", "--report", rp, "--no-error-code")
        assert "not scanned" in r.stdout


# ===================================================================
# Reverse tree
# ===================================================================

class TestReverseTree:

    def test_reverse_shows_dependents(self, run_json, dep_report):
        data, _ = run_json("deptree.py", "--report", dep_report, "--package", "grandchild", "--reverse", "--no-error-code")
        tree = data["trees"][0]
        assert tree["direction"] == "reverse"
        assert tree["root"] == "pkg:npm/grandchild@1.0.0"
        # grandchild is depended upon by child-a
        top = tree["tree"]
        assert len(top.get("dependents", [])) == 1
        assert "child-a" in top["dependents"][0]["purl"]
        # child-a is depended upon by parent
        child_a_node = top["dependents"][0]
        assert len(child_a_node.get("dependents", [])) == 1
        assert "parent" in child_a_node["dependents"][0]["purl"]

    def test_reverse_requires_package(self, run, dep_report):
        r = run("deptree.py", "--report", dep_report, "--reverse", "--no-error-code")
        assert r.returncode == 2
        assert "--package" in r.stderr

    def test_reverse_stats(self, run_json, dep_report):
        data, _ = run_json("deptree.py", "--report", dep_report, "--package", "grandchild", "--reverse", "--no-error-code")
        stats = data["trees"][0]["stats"]
        assert stats["direct_dependents"] == 1

    def test_reverse_with_cycle(self, run_json, cycle_report):
        data, _ = run_json("deptree.py", "--report", cycle_report, "--package", "cycle-a", "--reverse", "--no-error-code")
        tree_str = json.dumps(data)
        assert '"cycle": true' in tree_str


# ===================================================================
# Node formatting — overrides, governance
# ===================================================================

class TestNodeFormatting:

    def test_override_marker(self, run_json, write_report):
        rp = write_report(make_report([OVERRIDE_PKG]))
        data, _ = run_json("deptree.py", "--report", rp, "--no-error-code")
        node = data["trees"][0]["tree"]
        assert node["has_override"] is True

    def test_governance_block_in_node(self, run_json, write_report):
        """REJECT caused by governance block shows the reason."""
        from conftest import make_package, make_report as mr
        pkg = make_package(
            "pkg:npm/blocked@1.0.0",
            recommendation="REJECT",
            governance=[{"status": "blocked", "reason": "Banned by policy", "author": "admin", "timestamp": "2024-01-01"}],
        )
        rp = write_report(mr([pkg]))
        data, _ = run_json("deptree.py", "--report", rp, "--no-error-code")
        node = data["trees"][0]["tree"]
        assert node.get("governance_block") == "Banned by policy"

    def test_terminal_override_marker(self, run, write_report):
        rp = write_report(make_report([OVERRIDE_PKG]))
        r = run("deptree.py", "--report", rp, "--no-error-code")
        assert "†" in r.stdout

    def test_terminal_governance_marker(self, run, write_report):
        pkg = make_package(
            "pkg:npm/blocked@1.0.0",
            recommendation="REJECT",
            governance=[{"status": "blocked", "reason": "Banned by policy", "author": "admin", "timestamp": "2024-01-01"}],
        )
        rp = write_report(make_report([pkg]))
        r = run("deptree.py", "--report", rp, "--no-error-code")
        assert "‡" in r.stdout
        assert "Banned by policy" in r.stdout


# ===================================================================
# Error handling
# ===================================================================

class TestDeptreeErrors:

    def test_missing_report(self, run):
        r = run("deptree.py", "--report", "/no/such/file.json")
        assert r.returncode == 2

    def test_empty_report(self, run, empty_report):
        r = run("deptree.py", "--report", empty_report, "--no-error-code")
        assert r.returncode == 2

    def test_exit_code_1_on_reject(self, run, dep_report):
        r = run("deptree.py", "--report", dep_report)
        assert r.returncode == 1  # child-b is REJECT

    def test_exit_code_suppressed(self, run, dep_report):
        r = run("deptree.py", "--report", dep_report, "--no-error-code")
        assert r.returncode == 0


# ===================================================================
# Terminal output structure
# ===================================================================

class TestDeptreeTerminal:

    def test_tree_connectors(self, run, dep_report):
        r = run("deptree.py", "--report", dep_report, "--package", "parent", "--no-error-code")
        # Should contain tree drawing characters
        assert any(c in r.stdout for c in ("├──", "└──"))

    def test_markdown_header(self, run, dep_report):
        r = run("deptree.py", "--report", dep_report, "--package", "parent", "--no-error-code")
        assert "### Dependency tree" in r.stdout

    def test_code_fence(self, run, dep_report):
        r = run("deptree.py", "--report", dep_report, "--package", "parent", "--no-error-code")
        assert "```" in r.stdout

    def test_reject_bold_warning(self, run, dep_report):
        r = run("deptree.py", "--report", dep_report, "--package", "parent", "--no-error-code")
        assert "REJECT" in r.stdout


# ===================================================================
# Complex topology
# ===================================================================

class TestComplexTopology:

    def test_diamond_dependency(self, run_json, write_report):
        """Diamond: top -> A, top -> B, A -> shared, B -> shared."""
        shared = make_package("pkg:npm/shared@1.0.0")
        a = make_package("pkg:npm/a@1.0.0", dependencies=["pkg:npm/shared@1.0.0"])
        b = make_package("pkg:npm/b@1.0.0", dependencies=["pkg:npm/shared@1.0.0"])
        top = make_package("pkg:npm/top@1.0.0", dependencies=["pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0"])
        rp = write_report(make_report([top, a, b, shared]))
        data, _ = run_json("deptree.py", "--report", rp, "--package", "top", "--no-error-code")
        tree = data["trees"][0]["tree"]
        # shared appears under both A and B (not a cycle)
        a_node = next(c for c in tree["children"] if "a@" in c["purl"])
        b_node = next(c for c in tree["children"] if "b@" in c["purl"])
        assert "shared" in a_node["children"][0]["purl"]
        assert "shared" in b_node["children"][0]["purl"]
        # Neither should be marked as cycle
        assert a_node["children"][0].get("cycle") is not True
        assert b_node["children"][0].get("cycle") is not True

    def test_self_cycle(self, run_json, write_report):
        """Package that depends on itself."""
        pkg = make_package("pkg:npm/narcissist@1.0.0", dependencies=["pkg:npm/narcissist@1.0.0"])
        rp = write_report(make_report([pkg]))
        data, _ = run_json("deptree.py", "--report", rp, "--package", "narcissist", "--no-error-code")
        tree = data["trees"][0]["tree"]
        assert len(tree["children"]) == 1
        assert tree["children"][0].get("cycle") is True

    def test_deep_chain(self, run_json, write_report):
        """Chain of 20 packages deep."""
        pkgs = []
        for i in range(20):
            deps = [f"pkg:npm/chain-{i+1}@1.0.0"] if i < 19 else []
            pkgs.append(make_package(f"pkg:npm/chain-{i}@1.0.0", dependencies=deps))
        rp = write_report(make_report(pkgs))
        data, _ = run_json("deptree.py", "--report", rp, "--package", "chain-0", "--no-error-code")
        # Walk the chain
        node = data["trees"][0]["tree"]
        depth = 0
        while "children" in node and node["children"]:
            node = node["children"][0]
            depth += 1
        assert depth == 19

    def test_deep_chain_with_depth_limit(self, run_json, write_report):
        pkgs = []
        for i in range(20):
            deps = [f"pkg:npm/chain-{i+1}@1.0.0"] if i < 19 else []
            pkgs.append(make_package(f"pkg:npm/chain-{i}@1.0.0", dependencies=deps))
        rp = write_report(make_report(pkgs))
        data, _ = run_json("deptree.py", "--report", rp, "--package", "chain-0", "--depth", "3", "--no-error-code")
        node = data["trees"][0]["tree"]
        depth = 0
        while "children" in node and node["children"]:
            node = node["children"][0]
            depth += 1
        assert depth == 3
        assert node.get("truncated_children", 0) == 1

    def test_wide_tree(self, run_json, write_report):
        """Package with 30 direct dependencies."""
        deps = [f"pkg:npm/dep-{i}@1.0.0" for i in range(30)]
        dep_pkgs = [make_package(d) for d in deps]
        top = make_package("pkg:npm/wide@1.0.0", dependencies=deps)
        rp = write_report(make_report([top] + dep_pkgs))
        data, _ = run_json("deptree.py", "--report", rp, "--package", "wide", "--no-error-code")
        tree = data["trees"][0]["tree"]
        assert len(tree["children"]) == 30


# ===================================================================
# Repository risk — real scan data (requests@2.32.1, removed from PyPI)
# ===================================================================

class TestRepositoryRisk:

    def test_repository_fail_is_worst_status(self, run_json, write_report):
        rp = write_report(make_report([REPOSITORY_PKG]))
        data, _ = run_json("deptree.py", "--report", rp, "--no-error-code")
        node = data["trees"][0]["tree"]
        assert node["worst_status"] == "fail"

    def test_repository_is_final_label(self, run_json, write_report):
        """Repository FAIL is selected as worst_label even though vulnerabilities is only WARN."""
        rp = write_report(make_report([REPOSITORY_PKG]))
        data, _ = run_json("deptree.py", "--report", rp, "--no-error-code")
        node = data["trees"][0]["tree"]
        assert node["worst_label"] == "Caution: Package removed!"

    def test_repository_causes_reject(self, run_json, write_report):
        rp = write_report(make_report([REPOSITORY_PKG]))
        data, _ = run_json("deptree.py", "--report", rp, "--no-error-code")
        node = data["trees"][0]["tree"]
        assert node["recommendation"] == "REJECT"

    def test_repository_exit_code(self, run, write_report):
        rp = write_report(make_report([REPOSITORY_PKG]))
        r = run("deptree.py", "--report", rp)
        assert r.returncode == 1
