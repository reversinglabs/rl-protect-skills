# rl-protect-skills

Claude Code skills for [Spectra Assure](https://www.reversinglabs.com/products/software-supply-chain-security) — supply chain security powered by [rl-protect](https://docs.secure.software/).

These skills teach Claude Code to scan open source dependencies for malware, vulnerabilities, and policy violations before they enter your project, and to interpret the results.

---

## Skills

### `rl-protect-install`
Installs the rl-protect CLI from PyPI and configures it for first use. Handles Python and pip detection, installation, PATH verification, and hands off to `rl-protect-connect` on completion.

### `rl-protect-connect`
Connects rl-protect to a Spectra Assure Community (free) or Spectra Assure Portal (enterprise) account. Handles token setup, named connections, proxy configuration, and post-connect verification.

### `rl-protect-scan`
Scans packages and manifest files for supply chain risk before dependency changes are made. Supports single packages, CSV lists, and full manifest scans. Presents findings as a structured report inline in Claude Code.

### `rl-protect-interpret`
Interprets saved `rl-protect.report.json` files to answer questions about vulnerabilities, malware, behavior indicators, policy violations, overrides, governance blocks, and dependency trees. Supports forward and reverse dependency tree visualization to trace how a package entered the tree.

### `rl-protect-edit-profile`
Creates and modifies rl-protect scanning profiles. Supports configuring assessment severity levels, adding governance allow/block rules, and managing policy overrides with a full audit trail.

---

## Requirements

- [Claude Code](https://claude.ai/download) version 1.0.33 or later
- Python 3.8 or later and pip (required for `rl-protect-install`)
- A [Spectra Assure Community](https://secure.software) account (free) or Spectra Assure Portal (enterprise) license

---

## Installation

### Step 1 — Add the marketplace

```bash
/plugin marketplace add ReversingLabs/rl-protect-skills
```

### Step 2 — Install the skills you need

```bash
/plugin install rl-protect-install@rl-protect-skills
/plugin install rl-protect-connect@rl-protect-skills
/plugin install rl-protect-scan@rl-protect-skills
/plugin install rl-protect-interpret@rl-protect-skills
/plugin install rl-protect-edit-profile@rl-protect-skills
```

### Step 3 — Activate

```bash
/reload-plugins
```

### Keeping skills up to date

Enable auto-update through the `/plugin` interface, or update manually:

```bash
/plugin marketplace update ReversingLabs/rl-protect-skills
```

### Verifying installation

```bash
/skills
```

All installed `rl-protect-*` skills should appear in the list.

---

## Quick start

### 1. Install rl-protect

Ask Claude Code:

```
Install rl-protect
```

Claude will check for an existing installation, install from PyPI if needed, and guide you through first-time connection setup.

### 2. Connect to Spectra Assure

```
Connect rl-protect to my Spectra Assure Community account
```

Claude will ask for your token and configure the connection. For Enterprise accounts, it will also ask for your Portal URL and organization name.

### 3. Scan before installing a package

```
I want to add lodash@4.17.21 to the project
```

Claude will run rl-protect automatically before making any changes and report back with a pass/warn/fail summary.

### 4. Review a saved report

```
Show me a vulnerability summary from the rl-protect report
```

Claude will read `rl-protect.report.json` and extract CVE details, CVSS scores, exploit flags, and any policy overrides.

### 5. Edit a scanning profile

```
Set exploit vulnerabilities to fail in my scanning profile
```

Claude will update the appropriate field in your profile file and confirm what changed.

---

## Repository structure

```
rl-protect-skills/
├── README.md
├── LICENSE
├── .claude-plugin/
│   └── marketplace.json
└── plugins/
    ├── rl-protect-install/
    ├── rl-protect-connect/
    ├── rl-protect-scan/
    ├── rl-protect-interpret/
    │   ├── .claude-plugin/
    │   │   └── plugin.json
    │   ├── SKILL.md
    │   └── scripts/
    │       ├── summarize.py
    │       ├── interpret.py
    │       └── deptree.py
    └── rl-protect-edit-profile/
```

Each plugin follows the same structure: a `.claude-plugin/plugin.json` manifest and a `skills/{name}/SKILL.md` instruction file.

---

## Supported ecosystems

| Ecosystem | Manifest files |
|---|---|
| npm | `package.json` |
| PyPI | `requirements.txt`, `pyproject.toml`, `setup.cfg` |
| RubyGems | `Gemfile`, `gemspec` |

---

## License

MIT — see [LICENSE](LICENSE).

---

## About

Published by [ReversingLabs](https://www.reversinglabs.com). Spectra Assure and rl-protect are products of ReversingLabs.
