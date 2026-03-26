---
name: rl-protect-connect
description: Configures the rl-protect tool by connecting it to a Spectra Assure Community (free) or Spectra Assure Portal account (enterprise). Use when the user wants to set up rl-protect, add or update a server connection, or provide an API token.
---

## rl-protect configuration

Use this skill when the user wants to connect rl-protect to a Spectra Assure account. There are two account types with different required arguments. Always identify which account type applies before running any command.

---

### Account types

| | Community | Enterprise |
|---|---|---|
| Token prefix | `rlcmm-*` | `rls3c-*` |
| Server required | No | Yes |
| Org required | No | Yes |
| Group required | No | Optional |

---

### Tasks

---

#### Connect — Community account

**Trigger:** user provides a token starting with `rlcmm-`, or says they have a free or community account.

**Required inputs:** `--rl-token`
**Optional inputs:** `--connection-id`, `--ca-path`, proxy settings

**Command:**

```bash
rl-protect server connect \
            --rl-token={token} \
            --save-token
```

With a named connection (use when the user wants to manage multiple connections):

```bash
rl-protect server connect {connection-id} \
            --rl-token={token} \
            --save-token
```

**Always include `--save-token`** so the token is persisted to the config file and does not need to be supplied on every scan.

---

#### Connect — Enterprise account

**Trigger:** user provides a token starting with `rls3c-`, or mentions a portal URL or organisation name.

**Required inputs:** `--rl-server`, `--rl-org`, `--rl-token`
**Optional inputs:** `--connection-id`, `--rl-group`, `--ca-path`, proxy settings

**Command:**

```bash
rl-protect server connect \
            --rl-server={portal-url} \
            --rl-org={organisation} \
            --rl-token={token} \
            --save-token
```

With an optional group and named connection:

```bash
rl-protect server connect {connection-id} \
            --rl-server={portal-url} \
            --rl-org={organisation} \
            --rl-group={group} \
            --rl-token={token} \
            --save-token
```

**Always include `--save-token`** so the token is persisted to the config file.

---

#### Update an existing connection

**Trigger:** user wants to change a token, server URL, org, or any other setting on an existing connection.

Use the same flags as `connect`. The `connection-id` must match the existing connection name. If no connection ID was set, the target is the `default` connection.

```bash
rl-protect server update {connection-id} \
            --rl-token={new-token} \
            --save-token
```

---

#### Remove a connection

**Trigger:** user wants to delete a saved connection.

```bash
rl-protect server remove {connection-id}
```

If no connection ID is specified, the `default` connection is removed.

---

#### List connections

**Trigger:** user wants to see what connections are configured, or is unsure which connection is active.

```bash
rl-protect server list
```

---

#### Proxy configuration

If the user mentions a proxy, append these flags to any `connect` or `update` command:

| Flag | Value |
|---|---|
| `--proxy-server` | Local proxy URL |
| `--proxy-port` | Proxy port |
| `--proxy-user` | Proxy username |
| `--proxy-password` | Proxy password |

---

#### Custom CA or config path

| Flag | When to use |
|---|---|
| `--ca-path` | User has a custom Certificate Authority store (common in enterprise environments with TLS inspection) |
| `--config-path` | User wants to use a non-default config file location |

---

### Information gathering

Before running any command, confirm any missing required inputs with the user. Do not substitute placeholder values.

**For Community:** if no token is provided, ask:
> "Please provide your Spectra Assure Community token. It starts with `rlcmm-`."

**For Enterprise:** if any of server, org, or token are missing, ask for all three together:
> "Please provide your Spectra Assure Portal URL, organization name, and PAT token (starts with `rls3c-`)."

Never log, echo, or include tokens in any response text or summary after the command has run. Treat tokens as secrets.

---

### Post-connect verification

After any `connect` or `update` command completes successfully, confirm the connection is working by listing configured connections:

```bash
rl-protect server list
```

Then report the result to the user in this format:

```
### rl-protect connection configured

| Setting | Value |
|---|---|
| Connection | {connection-id or "default"} |
| Account type | {Community / Enterprise} |
| Server | {portal URL or "Spectra Assure Community"} |
| Organisation | {org or "—"} |
| Token saved | Yes |
```

---

### General rules

- Always use `--save-token`. Never run a connect command without it.
- Never store, repeat, or summarise a token value in any response.
- If the user supplies a token with an unrecognised prefix, ask them to confirm whether it is a Community (`rlcmm-*`) or Enterprise (`rls3c-*`) token before proceeding.
- If `rl-protect server list` shows an existing connection with the same ID, warn the user before running `connect` and suggest using `update` instead.
- Do not add `--rl-server`, `--rl-org`, or `--rl-group` flags to Community account commands — they are not valid for that account type.
