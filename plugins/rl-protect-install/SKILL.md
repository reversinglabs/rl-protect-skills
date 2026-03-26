---
name: rl-protect-install
description: Installs the rl-protect CLI from PyPI and configures it for first use. Use when the user wants to set up rl-protect, when rl-protect is not found on PATH, or when the user asks how to get started with Spectra Assure supply chain scanning.
---

## rl-protect installation

Use this skill when the user wants to install rl-protect, or when any other skill fails because `rl-protect` is not found on PATH. After installation, hand off to the `rl-protect-connect` skill to configure the first server connection.

---

### Step 1 — Check if rl-protect is already installed

Before installing, check whether rl-protect is already available:

```bash
rl-protect --version
```

If this succeeds, inform the user of the installed version and ask whether they want to upgrade or proceed directly to connection setup via `rl-protect-connect`. Do not reinstall unless the user asks.

---

### Step 2 — Check Python and pip

rl-protect is distributed as a Python wheel and requires Python 3.8 or later.

```bash
python --version
```

If `python` is not found, try `python3`:

```bash
python3 --version
```

Use whichever command succeeds for all subsequent steps. If neither is found, stop and tell the user:

> "Python 3.8 or later is required to install rl-protect. Please install Python from https://www.python.org/downloads/ and try again."

Confirm pip is available:

```bash
python -m pip --version
```

If pip is missing, stop and tell the user:

> "pip is required but was not found. Run `python -m ensurepip --upgrade` to install it, then try again."

---

### Step 3 — Install rl-protect

Install the latest release from PyPI:

```bash
python -m pip install rl-protect
```

If the user is in a managed or restricted environment and the above fails with a permissions error, suggest installing into the user's local site-packages instead:

```bash
python -m pip install --user rl-protect
```

If the user is working inside a virtual environment, use the environment's Python directly — no additional flags are needed.

---

### Step 4 — Verify installation

Confirm the install succeeded and rl-protect is available on PATH:

```bash
rl-protect --version
```

If this fails after a `--user` install, the user's local bin directory may not be on PATH. Diagnose with:

```bash
python -m site --user-base
```

Then advise the user to add `{user-base}/bin` (macOS/Linux) or `{user-base}\Scripts` (Windows) to their PATH, and to restart their terminal or shell session before retrying.

---

### Step 5 — First-time configuration

Once installation is confirmed, hand off to the `rl-protect-connect` skill to set up the first server connection:

> "rl-protect is installed. Let's connect it to your Spectra Assure account. Do you have a Community (free) account or an Enterprise Portal account?"

The `rl-protect-connect` skill will handle the rest based on the user's answer.

---

### Upgrading

**Trigger:** user asks to update or upgrade rl-protect to the latest version.

```bash
python -m pip install --upgrade rl-protect
```

After upgrading, run `rl-protect --version` to confirm the new version and report it to the user. Existing connections and configuration are preserved across upgrades.

---

### General rules

- Always check for an existing installation before attempting to install.
- Never install into the system Python with `sudo` or elevated privileges unless the user explicitly requests it.
- If installation fails for any reason other than permissions, show the full pip error output to the user and stop — do not attempt workarounds.
- Always confirm the version after install or upgrade before proceeding to connection setup.
- If the user is in a virtual environment, note that in the confirmation summary.
