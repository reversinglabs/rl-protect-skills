---
name: rl-protect-report
description: Converts an rl-protect JSON report (rl-protect.report.json) into a structured Markdown document. Use when the user wants to generate a report file, export scan findings to Markdown, create a document to review or share, or plan dependency version updates.
---

## Markdown report generation (rl-protect JSON)

Use this skill when the user wants a Markdown file generated from a saved `rl-protect.report.json`.

**This skill uses a pre-built Python script to parse the report and write the Markdown file. Always run the script — never read the report file directly or write your own parsing code.**

---

### Script location

```
${CLAUDE_SKILL_DIR}/scripts/
  make_report.py    — parses rl-protect JSON and writes a Markdown report file
```

### Report location

Default report path: `rl-protect.report.json` in the working directory. Pass a custom path with `--report <path>` if the user specifies one.

### Output location

Default output path: `rl-protect.report.md` in the working directory. Pass a custom path with `--output <path>` if the user specifies one.

---

### Running the script

```bash
python ${CLAUDE_SKILL_DIR}/scripts/make_report.py [options] --no-error-code
```

**Always pass `--no-error-code`** so that a REJECT result does not color the terminal output as an error. Exit code 2 (file not found, invalid JSON) is never suppressed.

#### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--report <path>` | `rl-protect.report.json` | Path to the rl-protect JSON report |
| `--manifest <path>` | *(report path)* | Manifest or lock file that was scanned — shown in the report header in place of the JSON report path |
| `--output <path>` | `rl-protect.report.md` | Path to write the Markdown file. Use `-` for stdout. |
| `--template <concise\|expanded\|verbose>` | *(expanded)* | Report template — sets a preset combination of display options. Individual flags override the template. |
| `--level <fail\|warn\|pass>` | `fail` | Which packages receive full detail. `fail` = rejected only; `warn` = rejected + warnings; `pass` = all packages. Overrides `--template`. |
| `--assessment <table\|simplified\|off>` | `simplified` | Assessment display style in package sections. Overrides `--template`. |
| `--no-vulnerabilities` | off | Omit the vulnerability table from package sections |
| `--license` | off | Include license information in package sections |
| `--policy` | off | Include policy violations in package sections |
| `--overrides` | off | Include override audit trail in assessment and policy tables |
| `--no-error-code` | — | Exit 0 even when REJECT packages are found |

#### Templates

| Template | Sections | Assessment | Vulnerabilities | License | Policy |
|----------|----------|------------|-----------------|---------|--------|
| `concise` | Summary table (linked to Spectra Assure Community) + Version Update Plan, no package detail sections, no TOC | off | no | no | no |
| `expanded` | Rejected packages + TOC | simplified | yes | yes | no |
| `verbose` | Rejected + warnings + passing + TOC | table | yes | yes | yes |

When no `--template` is given the defaults match `expanded`.

#### Examples

```bash
# Default (expanded): rejected packages with simplified assessment and vulnerabilities
python ${CLAUDE_SKILL_DIR}/scripts/make_report.py --no-error-code

# Concise: summary table and version update plan only
python ${CLAUDE_SKILL_DIR}/scripts/make_report.py --template concise --no-error-code

# Verbose: full detail including policy violations and override audit
python ${CLAUDE_SKILL_DIR}/scripts/make_report.py --template verbose --no-error-code

# Template with override: expanded but suppress the vulnerability table
python ${CLAUDE_SKILL_DIR}/scripts/make_report.py --template expanded --no-vulnerabilities --no-error-code

# Custom paths
python ${CLAUDE_SKILL_DIR}/scripts/make_report.py --report scan/results.json --output docs/security-report.md --no-error-code
```

---

### Report structure

The generated Markdown file contains:

1. **Header** — scanned manifest path, scanning profile, scan timestamp and duration, report generation time, overall PASS/FAIL status with counts
2. **Table of contents** — links to each section present in the report
3. **Summary** — compact table of all non-passing packages (📦 direct, 🔗 transitive) with status and deployment risk label; passing packages shown as a count row
4. **Rejected packages** — full per-package detail: SAFE assessment block, malware callout, governance block, vulnerability table; a policy violations callout is shown automatically when policy violations are the sole reason for rejection; full policy violations table shown when `--policy` is set
5. **Scan warnings** — same detail as rejected packages (shown when `--level warn` or `pass`)
6. **Passing packages** — simple list (shown when `--level pass`)
7. **📋 Version Update Plan** — prioritized action table covering all rejected and warning packages with deployment risk, highest CVSS, and suggested action
8. **Scan errors** — packages that could not be scanned
9. **Footer** — Spectra Assure Community attribution

---

### After running

1. Tell the user where the report was written (the script prints the output path).
2. If the report contains REJECT packages, note it: *"One or more packages have a REJECT recommendation."*
3. Offer to show the Summary table or Version Update Plan, or open the file for review.

---

### General rules

- **Always run the script first.** Never read `rl-protect.report.json` directly.
- **Never write your own parsing code** to extract data from the report.
- If the script exits with code 2, report the error from stderr and stop. Do not attempt to read the report file as a fallback.
- If the scripts folder is missing or the script fails unexpectedly, tell the user and ask them to verify the skill installation.
