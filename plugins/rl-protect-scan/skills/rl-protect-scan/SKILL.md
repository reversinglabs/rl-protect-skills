---
name: rl-protect-scan
description: "Supply chain security gate. MUST be invoked BEFORE running any install command (npm install, pip install, gem install), before editing manifest/lock files (package.json, requirements.txt, pyproject.toml, Gemfile), before writing imports/requires for packages not already in the project, and before recommending packages. Also invoke when updating or downgrading package versions. This skill scans packages with rl-protect and gates the action on the result. Never skip — invoke proactively even if the user did not ask for a scan."
---

## Dependency security (rl-protect)

Supply chain attacks are a critical threat. Malicious packages can be injected into public registries and will silently compromise any project that installs them. This skill is a hard gate — no open source package may be added to a project, recommended to the user, or used in generated code unless it has first been scanned and passed.

### Mandatory scan policy

Scanning is a hard gate. Every package must be scanned and pass **before** any install command runs, any import is written, or any recommendation is made.

**Required workflow — follow this exact sequence every time:**

1. **Scan first.** Run `rl-protect scan` on the package PURL(s) before doing anything else.
2. **Check the result.** Read the scan output and determine whether each package received APPROVE or REJECT.
3. **Gate the action on the result:**
   - **APPROVE** → proceed with the install, import, or recommendation.
   - **REJECT** → **stop.** Report the finding to the user. Do not run any install command, do not write any import, and do not recommend the package. Only proceed if the user explicitly acknowledges the risk and instructs you to continue.

**This workflow applies whenever you are about to:**

* Run any install or dependency resolution command (`npm install`, `pip install`, `gem install`)
* Add, update, or remove entries in a manifest or lock file (`package.json`, `requirements.txt`, `pyproject.toml`, `Gemfile`)
* Write code that imports or requires a package not already in the project
* Recommend a package to the user as a solution to a problem
* Scaffold a new project that includes dependencies (e.g. framework starters, boilerplate generators)
* Update a package to a new version — **always use the "Version update (behavior diff)" pattern** to scan both old and new versions and diff their behaviors

**Never:**

* Run an install command before the scan completes and passes
* Assume a package is safe because it is popular, well-known, or was safe in a previous scan
* Skip scanning because the user did not explicitly ask for it — scanning is always implicit
* Proceed if rl-protect is not installed — hand off to `rl-protect-install` first

---

### Connection selection

rl-protect supports multiple saved server connections. By default, the `default` connection is used and no flag is needed.

If the user specifies a connection by name, append `--connect-id={connection-id}` to any scan command:

```bash
rl-protect scan ... --connect-id={connection-id}
```

If it is unclear which connection to use, list configured connections first and ask the user to confirm:

```bash
rl-protect server list
```

Do not guess or infer a connection ID. If none is specified and only one connection exists, use it silently. If multiple connections exist and none is specified, ask the user which to use before scanning.

---

### Profile selection

rl-protect applies a scanning profile that controls assessment severity, governance rules, and policy overrides. The default profile is selected based on the connection type. For Community accounts rl-protect uses its default scanning profile. For Enterprise accounts rl-protect will download the scanning profile from the connected Spectra Assure Portal, defaulting to the organizational profile unless a specific group is configured.

If the user specifies a local profile, append `--profile={path OR keyword}` to any scan command. Valid keywords are `minimal`, `baseline`, and `hardened`:

```bash
rl-protect scan ... --profile={path-to-profile.json OR keyword}
```

If the user asks which local profiles are available or is unsure which to use, look for `*.json` files with an `rl-profile` root key in the `.rl-protect/` folder at the repository root. List them by name and path before scanning.

Do not select a profile on the user's behalf. If no profile is specified, scan without the flag. If the user asks to create or modify a profile, hand off to the `rl-protect-edit-profile` skill.

---

### Scan invocation patterns

**Single new package:**

Scan an open source package PURL before it is used by the project.

```bash
rl-protect scan pkg:{type}/{package}@{version} \
            --no-tracking \
            --fail-only
```

**Multiple new packages:**

Scan a CSV list of open source package PURLs before they are used by the project.

```bash
rl-protect scan pkg:{type}/{package}@{version},... \
            --no-tracking \
            --fail-only
```

**Full manifest scan:**

Scan a package manifest or lock file to assess supply chain risks.

```bash
rl-protect scan {path-to-manifest-or-lock-file} \
            --check-deps=release,develop \
            --no-tracking \
            --fail-only
```

**Version update (behavior diff):**

When the user is updating or downgrading packages, scan all old and new versions together in a single command and run a behavior diff for each package. This is the required workflow for all version changes.

The `diff-behavior.py` script ships with the sibling `rl-protect-interpret` skill. Use Glob to find it: `**/rl-protect-interpret/scripts/diff-behavior.py`

*Single package:*

```bash
# Step 1: Scan both versions in one command
rl-protect scan pkg:{type}/{package}@{old-version},pkg:{type}/{package}@{new-version} \
            --no-tracking \
            --save-report=rl-protect.report.json \
            --fail-only

# Step 2: Run behavior diff
python {path-to-diff-behavior.py} \
            --package {package} \
            --report rl-protect.report.json \
            --no-error-code
```

*Multiple packages (batch):*

When updating multiple packages at once, scan all old and new versions in a single command to avoid repeated network calls, then diff each package against the same report.

```bash
# Step 1: Scan all old+new versions in one command
rl-protect scan pkg:{type}/{package-a}@{old},pkg:{type}/{package-a}@{new},pkg:{type}/{package-b}@{old},pkg:{type}/{package-b}@{new},... \
            --no-tracking \
            --save-report=rl-protect.report.json \
            --fail-only

# Step 2: Diff each package against the same report
python {path-to-diff-behavior.py} --package {package-a} --report rl-protect.report.json --no-error-code
python {path-to-diff-behavior.py} --package {package-b} --report rl-protect.report.json --no-error-code
# ... repeat for each package
```

*Downgrades:*

When moving to an older version, add `--reverse` so that labels and regression detection are correct:

```bash
python {path-to-diff-behavior.py} \
            --package {package} \
            --report rl-protect.report.json \
            --reverse \
            --no-error-code
```

Present each diff output to the user as-is before proceeding with the updates.

If any diff shows new risks (new indicators, malware classifications, assessment regressions, or new policy violations), **stop and report the findings**. Do not proceed with the version change unless the user explicitly acknowledges the risks.

---

**Full manifest scan (save report):**

Scan a package manifest or lock file to assess supply chain risks. This version saves a report so that the user can audit it later. Always use this command when analyzing larger manifests, or when debugging policy violations.

```bash
rl-protect scan {path-to-manifest-or-lock-file} \
            --profile={minimum OR baseline OR hardened} \
            --check-deps=release,develop \
            --save-report=rl-protect.report.json \
            --no-tracking \
            --fail-only
```

---

### Response format

After every scan, present results using the following Markdown structure. All sections are required even if no issues were found.

---

#### Template

```
## `rl-protect` scan report

**Manifest:** `{purl-or-filepath}` · {N} dependencies scanned

---

### {status-line}

{one-sentence summary of the most critical finding, or "All dependencies passed." if no issues.}

---

### Results
*(Omit entirely if all dependencies passed.)*

| Dependency | Version | Status | Issues |
|---|---|---|---|
| {name} | {version} | {✅ PASS / ⚠️ WARN / ❌ FAIL} | {None, or comma-separated check names} |

---

### pkg:{type}/{name}@{version} · issue detail
*(Repeat this section for each dependency with a WARN or FAIL status. Omit entirely if all dependencies passed.)*

| Assessment | Result |
|---|---|
| Secrets | {✅ / ❌ / ⚠️} {unmodified-tool-assessment-message} |
| Licenses | {✅ / ❌ / ⚠️} {unmodified-tool-assessment-message} |
| Vulnerabilities | {✅ / ❌ / ⚠️} {unmodified-tool-assessment-message} |
| Hardening | {✅ / ❌ / ⚠️} {unmodified-tool-assessment-message} |
| Tampering | {✅ / ❌ / ⚠️} {unmodified-tool-assessment-message} |
| Malware | {✅ / ❌ / ⚠️} {unmodified-tool-assessment-message} |
| Repository | {✅ / ❌ / ⚠️} {unmodified-tool-assessment-message} |

> **Policy override:** {description of any assessment overrides, e.g. "Vulnerabilities downgraded `FAIL → WARN`"}
> *(Omit this line if no overrides apply.)*
> More info: {secure.software URL for the package}

---

**FAIL** {N} · **WARN** {N} · **PASS** {N}
```

---

#### Status line rules

| Outcome | Status line |
|---|---|
| Any FAIL | `❌ Build blocked — {N} dependenc{y/ies} must be fixed` |
| WARN only, no FAIL | `⚠️ Build warning — {N} dependenc{y/ies} require review` |
| All PASS | `✅ All clear — no issues detected` |

#### Check result icons

| Icon | Meaning |
|---|---|
| ✅ | No issues found |
| ❌ | FAIL — blocks the build |
| ⚠️ | WARN — requires review, may be overridden by policy |
