---
name: rl-protect-edit-profile
description: Creates or modifies rl-protect scanning profiles (rl-profile JSON). Use when the user wants to configure scan policy, set assessment severity levels, add governance allow/block rules, or apply policy overrides.
---

## Profile editing (rl-protect)

Use this skill when the user wants to create a new profile or change an existing one. Profiles are JSON files that control how rl-protect evaluates packages — what counts as a failure, which packages are always allowed or blocked, and which policy rules are overridden.

### Profile location

The profile is loaded from a file passed to `rl-protect scan` via `--profile={path}`. If the user does not specify a path, rl-protect will use its default profile. Read the file before making any changes if it already exists.

---

### Schema reference

```
rl-profile
  .schema                          — always 1, do not change
  .name                            — human-readable profile name
  .info                            — description string (free text)
  .timestamp                       — ISO-8601, set to current time on every save
  .configuration.policy
    .min_catalogue                 — minimum required catalogue level (integer, 1–10)
    .rl_scan_level                 — scan depth level (integer, 1–10)
    .rl_auto_approval              — auto-approve packages that pass (boolean)
    .assessments{}                 — one entry per check category (see below)
    .governance.community          — age gates and allow/block pattern lists
    .overrides{}                   — keyed by policy rule ID (SQ-prefixed)
```

---

### Assessment configuration

Each assessment can be ignored entirely or configured with per-detection-type severity levels.

**Valid severity values:** `pass` | `warning` | `fail`

```
assessments.secrets
  .ignored                         — true suppresses the entire check

assessments.licenses
  .ignored                         — true suppresses the entire check

assessments.vulnerabilities
  .ignored
  .detections
    .mandate                       — CVEs under active government mandate
    .exploit                       — CVEs with known exploits
    .malware                       — CVEs used in malware campaigns
    .critical                      — CVEs with CVSS ≥ 9.0

assessments.hardening
  .ignored

assessments.tampering
  .ignored
  .ml_hunting                      — ML-based anomaly detections

assessments.malware
  .ignored
  .rl_analyst                      — findings from RL analyst vetting
  .rl_scanner                      — findings from RL scanner
  .suspicious                      — suspicious (unconfirmed) detections
  .dependency
    .develop                       — malicious dependency in dev context
    .release                       — malicious dependency in release context
  .detections                      — affects specified malware types
    .adware
    .riskware
    .protestware
    .spam
```

---

### Governance configuration

Governance rules control package-level allow and block decisions independently of assessment findings.

```
governance.community
  .min_package_age                 — minimum days since first package release (integer)
  .min_version_age                 — minimum days since this version was published (integer)
  .allow[]                         — packages always approved regardless of findings
    .pattern                       — PURL pattern (exact or wildcard, e.g. pkg:npm/lodash@*)
    .audit.author                  — who added the rule
    .audit.timestamp               — when the rule was added
    .audit.reason                  — stated justification
  .block[]                         — packages always rejected regardless of findings
    .pattern                       — PURL pattern
    .audit.author                  — who added the rule
    .audit.timestamp               — when the rule was added
    .audit.reason                  — stated justification
```

**PURL pattern matching:**
- Exact version: `pkg:npm/lodash@4.17.21`
- Wildcard version range: `pkg:npm/ua-parser-js@0.7.*`
- All package versions: `pkg:gem/rack@*`
- Specific artifact: `pkg:pypi/flask@3.1.2?artifact=flask-3.1.2-py3-none-any.whl`

---

### Policy overrides

Overrides suppress or downgrade specific policy rule violations by their SQ-prefixed rule ID.

```
overrides.{SQxxxxx}
  .enabled                         — true to activate the override
  .blocker                         — the status to apply instead: pass | warning
  .apply_to[]                      — scope: "organization" | "group" | "any"
  .audit.author
  .audit.timestamp                 — must use current timestamp in ISO-8601 format
  .audit.reason
```

Setting `blocker` to `pass` means the rule never blocks a scan. Setting it to `warning` downgrades a failure to a warning.

---

### Tasks

---

#### Create a new profile

**Trigger:** user wants to create a profile from scratch, or no profile file exists.

**Steps:**
1. Ask the user for a profile name and any initial settings they want to configure.
2. Generate a valid profile JSON with `schema: 1` and the current timestamp.
3. Set sensible defaults for any fields the user did not specify (see defaults below).
4. Write the file and confirm the path.

**Default values for new profiles:**

| Field | Default |
|---|---|
| `min_catalogue` | `5` |
| `rl_scan_level` | `5` |
| `rl_auto_approval` | `false` |
| All assessment `.ignored` | `false` |
| `vulnerabilities.detections.mandate` | `fail` |
| `vulnerabilities.detections.exploit` | `fail` |
| `vulnerabilities.detections.malware` | `fail` |
| `vulnerabilities.detections.critical` | `fail` |
| `malware.rl_analyst` | `fail` |
| `malware.rl_scanner` | `fail` |
| `malware.suspicious` | `warning` |
| `malware.dependency.release` | `fail` |
| `malware.dependency.develop` | `warning` |
| `min_package_age` | `90` |
| `min_version_age` | `3` |

---

#### Configure assessment severity

**Trigger:** user wants to change what counts as a failure or warning for a specific check, or wants to ignore a check entirely.

**Steps:**
1. Identify which assessment and detection type the user wants to change.
2. Confirm the new severity value (`pass`, `warning`, or `fail`).
3. Update only the affected field. Do not alter other assessments.
4. Update `.timestamp` to the current time in ISO-8601 format.
5. Write the file and show a summary of what changed.

**Output summary format:**

```
### Profile updated — {profile name}

| Assessment | Detection | Previous | New |
|---|---|---|---|
| {assessment name} | {detection type or "ignored"} | {old value} | {new value} |
```

---

#### Add a governance rule

**Trigger:** user wants to always allow or always block a specific package or version range.

**Steps:**
1. Ask for: the PURL pattern, whether it is an allow or block rule, and a reason.
2. Check whether a rule for the same pattern already exists. If so, warn the user and ask whether to replace it.
3. Populate `audit.author` from context if known, otherwise ask. Prefer emails. Set `audit.timestamp` to the current time in ISO-8601 format.
4. Append the rule to the appropriate list (`allow[]` or `block[]`).
5. Update `.timestamp` and write the file.

**Output summary format:**

```
### Governance rule added — {profile name}

| Field | Value |
|---|---|
| Action | {Allow / Block} |
| Pattern | {purl pattern} |
| Reason | {reason} |
| Author | {author} |
```

---

#### Remove a governance rule

**Trigger:** user wants to remove an existing allow or block rule.

**Steps:**
1. List all current rules in the relevant list and ask the user to confirm which to remove.
2. Remove the matching entry by pattern.
3. Update `.timestamp` and write the file.

---

#### Add or update a policy override

**Trigger:** user wants to suppress or downgrade a specific policy rule violation by its SQ rule ID.

**Steps:**
1. Ask for: the SQ rule ID, the target status (`pass` or `warning`), the scope (`organization`, `group`, or `any`), and a reason.
2. If an override for that rule ID already exists, show the current values and ask the user to confirm the update.
3. Set `enabled: true`, populate the audit fields, and update `.timestamp` in ISO-8601 format.
4. Write the file and confirm.

**Output summary format:**

```
### Policy override saved — {profile name}

| Field | Value |
|---|---|
| Rule | {SQxxxxx} |
| Overridden to | {pass / warning} |
| Scope | {organization / group / any} |
| Reason | {reason} |
| Author | {author} |
```

---

#### Show current profile

**Trigger:** user wants to review what is currently configured in the profile.

Read the profile file and present it in this format:

```
### Profile — {name}

**Scan settings**
| Setting | Value |
|---|---|
| Min catalogue level | {min_catalogue} |
| Scan level | {rl_scan_level} |
| Auto-approval | {Yes / No} |

**Assessment configuration**
| Assessment | Ignored | Detection severities |
|---|---|---|
| Secrets | {Yes/No} | — |
| Licenses | {Yes/No} | — |
| Vulnerabilities | {Yes/No} | mandate: {v} · exploit: {v} · malware: {v} · critical: {v} |
| Hardening | {Yes/No} | — |
| Tampering | {Yes/No} | ml_hunting: {v} |
| Malware | {Yes/No} | analyst: {v} · scanner: {v} · suspicious: {v} · dep/release: {v} · dep/develop: {v} |

**Governance**
- Min package age: {N} days · Min version age: {N} days
- Allow rules: {N}  ·  Block rules: {N}

**Policy overrides:** {N} active
```

Follow with a table of governance rules and overrides if any exist.

---

### General rules

- Always read the existing profile before making changes. Never overwrite fields the user did not ask to change.
- Always update `.timestamp` to the current ISO-8601 time on every write.
- Never set `.schema` to any value other than `1`.
- When adding audit entries, always require a `reason`. Do not allow empty reason strings.
- If the user tries to set a severity value other than `pass`, `warning`, or `fail`, reject it and list the valid options.
- If the user tries to ignore all six assessments simultaneously, warn them that this would result in every package passing regardless of content.
- After every write, confirm the file path and summarize only the fields that were changed.
