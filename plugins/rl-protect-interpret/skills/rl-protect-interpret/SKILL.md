---
name: rl-protect-interpret
description: Interprets rl-protect JSON reports (rl-protect.report.json). Use when the user asks about vulnerabilities, malware, indicators, policy violations, overrides, governance, dependency trees, or behavior diffs, or when a scan saved a report and the user wants to dig deeper into findings.
---

## Report interpretation (rl-protect JSON)

Use this skill when the user asks questions about a saved `rl-protect.report.json` file.

**This skill uses pre-built Python scripts to extract and format report data. You must always run the appropriate script and present its output to the user. Never read the report file directly, never write your own parsing code, and never summarize report content from memory or context.**

rl-protect reports can be large. Reading them directly is slow, wastes context, and produces inconsistent results. The scripts exist specifically to solve this — use them.

---

### Mandatory script usage

Before responding to any question about a report:

1. Identify the correct script and task from the mapping below.
2. Run the script.
3. Present the script's stdout output to the user as-is.

If you find yourself reading the JSON file, writing parsing code, or interpreting report content without having run a script first — stop and run the correct script instead.

---

### Script location

Scripts are in `${CLAUDE_SKILL_DIR}/scripts/`:

```
${CLAUDE_SKILL_DIR}/scripts/
  summarize.py      — full report overview, all packages
  interpret.py      — targeted extraction by task
  deptree.py        — dependency tree visualization
  diff-behavior.py  — behavior diff between package versions
```

### Report location

Default report path: `rl-protect.report.json` in the working directory. Pass a custom path with `--report={path}` if the user specifies one.

### JSON output

All scripts support `--json` to output structured JSON instead of formatted terminal tables. When `--json` is passed, the script writes a single JSON object to stdout. The JSON output contains the same data as the terminal output but in a machine-readable format suitable for MCP servers and other programmatic consumers.

---

### Scripts

#### summarize.py

Prints a compact Markdown summary of every package in the report: recommendation, all six assessment statuses, override flags, and scan errors. Use this when the user wants an overview or has not asked for a specific task.

```bash
python ${CLAUDE_SKILL_DIR}/scripts/summarize.py [report.json] [--json] --no-error-code
```

#### interpret.py

Extracts a specific slice of the report. Use this for all targeted tasks. Always prefer this over summarize.py when the user asks a specific question.

```bash
python ${CLAUDE_SKILL_DIR}/scripts/interpret.py <task> [--package <purl>] [--report <path>] [--json] --no-error-code
```

Use `--package` to filter output to a specific package when the user names one.

#### deptree.py

Renders package dependency relationships as an indented Unicode tree. Each node shows the package PURL, recommendation, and worst assessment status. Cycles are detected and marked. Unscanned dependencies are flagged. Use this when the user asks to see, visualize, or explore the dependency tree.

```bash
python ${CLAUDE_SKILL_DIR}/scripts/deptree.py [--package <purl>] [--report <path>] [--depth <n>] [--reverse] [--json] --no-error-code
```

- `--package` roots the tree at a specific package (PURL substring match). Without it, trees are printed for all top-level packages (those not listed as a dependency of another).
- `--depth` limits how deep the tree is rendered. Default: unlimited.
- `--reverse` shows the reverse dependency tree — who depends on this package, walking upward to find all ancestors. Requires `--package`. Use this when the user asks "who uses this?", "how did this get into my tree?", or "what depends on X?".
- `--no-error-code` suppresses non-zero exit codes from REJECT findings (exit code 2 for actual errors is unaffected). **Always pass this flag** when running scripts from within Claude Code.
- `--json` outputs structured JSON instead of formatted terminal tables.

#### diff-behavior.py

Compares behaviors between two versions of the same package to detect suspicious changes that may indicate supply chain tampering. Diffs indicators, file classifications, vulnerabilities, and assessment statuses. Use this when the user is updating a package version and wants to understand what changed, or when investigating potential tampering between releases.

```bash
# Two versions in one report (scanned together):
python ${CLAUDE_SKILL_DIR}/scripts/diff-behavior.py --package <name> [--report <path>] [--json] --no-error-code

# Two separate reports (old version vs new version):
python ${CLAUDE_SKILL_DIR}/scripts/diff-behavior.py --package <name> --old-report <old_path> --new-report <new_path> [--json] --no-error-code
```

- `--package` is required. Matches by package name (substring match, case-insensitive).
- `--report` single report containing both versions (e.g. when both were scanned together). Default: `rl-protect.report.json`.
- `--old-report` / `--new-report` separate report files for each version.
- `--old-version` / `--new-version` pin specific versions when more than two are present in the report.
- `--reverse` swaps old and new. **Use this when downgrading** to an older version so that labels and regression detection are correct.
- `--no-error-code` suppresses exit code 1 (new risks found). **Always pass this flag.**

**Workflow for version updates:** When a user is updating a dependency, scan both the current and new versions, then run `diff-behavior.py` to compare. This is the recommended way to detect malicious tampering between releases.

```bash
# 1. Scan both versions together into one report
rl-protect scan pkg:npm/example@1.0.0,pkg:npm/example@2.0.0 --no-tracking --save-report=rl-protect.report.json

# 2. Compare behaviors
python ${CLAUDE_SKILL_DIR}/scripts/diff-behavior.py --package example --report rl-protect.report.json --no-error-code
```

---

### Task mapping

Map every user request to a script invocation using this table. There are no exceptions.

| User asks about | Script invocation |
|---|---|
| CVEs, CVSS scores, exploitability, package safety | `interpret.py vulnerabilities` |
| Suspicious behavior, indicators, unusual code patterns | `interpret.py indicators` |
| Malware, supply chain attacks, malicious files, tampering | `interpret.py malware` |
| Who approved something, override audit trail | `interpret.py overrides` |
| Governance allow/block decisions | `interpret.py governance` |
| Both overrides and governance | run both `interpret.py overrides` and `interpret.py governance` |
| Overview, risk rating, deciding whether to use a package | `summarize.py` |
| Dependencies, what a package depends on, dependency list | `interpret.py dependencies` |
| Dependency tree visualization, show me the tree, explore transitive deps | `deptree.py` |
| Who uses this package, what depends on X, how did this get in my tree | `deptree.py --reverse` |
| Behavior diff, what changed between versions, version update risk, tampering between releases | `diff-behavior.py` |
| Missing packages, scan failures | `interpret.py errors` |

For a specific package risk summary, run all three:

```bash
python ${CLAUDE_SKILL_DIR}/scripts/interpret.py vulnerabilities --package <purl> [--report <path>] --no-error-code
python ${CLAUDE_SKILL_DIR}/scripts/interpret.py malware --package <purl> [--report <path>] --no-error-code
python ${CLAUDE_SKILL_DIR}/scripts/interpret.py overrides --package <purl> [--report <path>] --no-error-code
```

> **Always pass `--no-error-code`** when invoking scripts. This suppresses non-zero exit codes from REJECT findings so the terminal does not color the output as an error. Exit code 2 (file not found, invalid JSON) is never suppressed.

---

### Presenting output

- Present the script's stdout output to the user as-is. Do not reformat, paraphrase, or summarize it further unless the user explicitly asks.
- If a script exits with code 1, prepend this callout before the output: `> ⚠ One or more packages have a REJECT recommendation.`
- If a script exits with code 2, report the error from stderr to the user and stop. Do not attempt to read the report file manually as a fallback.

---

### Schema reference

Listed here for reference only. Do not use this to read or interpret the report directly — run the scripts.

```
analysis.report.packages[]
  .purl                          — package identifier (type/name@version)
  .downloads                     — total download count (popularity signal)
  .dependents                    — number of packages that depend on this one
  .dependencies[]                — list of direct dependency PURLs
  .analysis.recommendation       — APPROVE | REJECT
  .analysis.report               — URL to full report on secure.software
  .analysis.assessment{}         — one entry per check (see checks below)
    .status                      — pass | warning | fail
    .label                       — human-readable finding summary
    .count                       — number of findings (0 = clean)
    .override                    — present when a policy override was applied
      .to_status                 — the status after override
      .audit.author              — who approved the override
      .audit.timestamp           — when the override was approved
      .audit.reason              — stated justification
  .analysis.vulnerabilities{}    — keyed by vulnerability identifier (CVE or GHSA)
    .summary                     — plain-language description
    .cvss.baseScore              — CVSS score (0–10)
    .exploit[]                   — exploit flags: EXISTS, MALWARE, MANDATE, FIXABLE
  .analysis.indicators{}         — keyed by indicator ID
    .description                 — what the indicator detected
    .occurrences                 — how many times it was observed
  .analysis.classifications[]    — file-level malware scan results
    .object                      — type of object scanned (e.g. "file" or "dependency")
    .status                      — Malicious | Suspicious | Known good
    .result                      — malware family / classification string
    .hashes[]                    — [algorithm, value] pairs for the flagged file
  .analysis.policy.violations{}  — keyed by policy rule ID
    .status                      — fail | warning | pass
    .description                 — what the rule checks
    .violations                  — violation count
    .override                    — same structure as assessment override above
  .analysis.policy.governance[]  — org-level allow/block decisions
    .status                      — blocked | allowed
    .author                      — who set the rule
    .timestamp                   — when the rule was set
    .reason                      — stated reason

analysis.report.errors[]
  .purl                          — package that could not be scanned
  .error.code                    — HTTP-style error code
  .error.info                    — human-readable error message
```

---

### General rules

- **Always run a script first.** No exceptions.
- **Never read `rl-protect.report.json` directly** — not even to check if it exists or to peek at its structure.
- **Never write your own code** to parse, summarize, or extract data from the report.
- **Never use report content loaded into context** from a previous turn to answer questions — always re-run the script to ensure fresh, accurate output.
- When an override is present on any finding, the scripts will surface it automatically. Do not suppress or omit override information.
- If `analysis.report.errors[]` is non-empty, the scripts will note failed packages. Always mention them to the user.
- If the scripts folder is missing or a script fails with exit code 2, tell the user and ask them to verify the skill installation. Do not attempt to work around missing scripts.
