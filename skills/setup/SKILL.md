---
name: setup
description: Set up and check Sophos API credentials for the Sophos Fusion skills. Use when no profile exists, a script reports no_credentials or auth_failed, someone wants to add, switch, or test a tenant, or a partner or organization credential needs a target tenant. Stores credentials in environment variables or a 0600 profile file (1Password op:// references supported), detects tenant, partner, or organization credentials and their region, and ends with a self-test.
license: MIT
---

# Setup: credentials and the self-test

Scripts live in `${CLAUDE_SKILL_DIR}/scripts/`. If that shows literally, it means the folder holding this file.

## What the person needs first

A Sophos API credential (client ID and client secret) from the Sophos Central API credentials page. A Super Admin role works. The self-test lists what the credential can do.

## Never handle the secret in chat

Do not ask the person to paste a client secret into the conversation, and do not put one in a command you write. Give them one of these to run themselves:

```bash
# Prompt for the secret in their own terminal (input hidden)
node ${CLAUDE_SKILL_DIR}/scripts/profile.mjs add --name lab --kind test --client-id <client-id> --prompt

# Or a 1Password reference: the secret stays in 1Password
node ${CLAUDE_SKILL_DIR}/scripts/profile.mjs add --name lab --kind test --client-id <client-id> --client-secret-op "op://Vault/Item/client_secret"

# Or an environment variable they already set
node ${CLAUDE_SKILL_DIR}/scripts/profile.mjs add --name lab --kind test --client-id <client-id> --secret-env MY_SECRET_VAR
```

Ask them to run it in a terminal of their own, then tell you when it is done. You only need the profile name.

Profiles go to `~/.config/sophos-fusion-skills/profiles.json` (folder 0700, file 0600). `SOPHOS_FUSION_CONFIG_DIR` moves it.

Environment variables work too and win over profiles: `SOPHOS_FUSION_CLIENT_ID`, `SOPHOS_FUSION_CLIENT_SECRET`, and optionally `SOPHOS_FUSION_TENANT_ID` and `SOPHOS_FUSION_PROFILE_KIND`.

## Test or production

Every profile is `test` or `production`. The default is `production`, on purpose.

- On a test profile, a write needs `--yes`.
- On a production profile, a write needs `--yes --production`, and you name the tenant to the person before asking.

Ask which one it is. Only mark a tenant `test` when the person says it is a lab or test tenant.

## Partner and organization credentials

The self-test tells you the credential type. Tenant credentials reach one tenant. Partner and organization credentials reach many, so they need a target:

```bash
node ${CLAUDE_SKILL_DIR}/scripts/profile.mjs tenants --profile mssp --search acme
node ${CLAUDE_SKILL_DIR}/scripts/profile.mjs add --name mssp --tenant <tenant-uuid>
```

Any script also takes `--tenant <uuid>` for one command. The scripts check the tenant is one the credential can see, and route by the region Sophos reports for it.

## The self-test

```bash
node ${CLAUDE_SKILL_DIR}/scripts/profile.mjs test --profile lab
```

It gets a token, calls whoami, picks the target tenant and its region, runs one read-only Fusion query (object counts), and summarizes permissions. Pass the gate only when every step is ok.

Read the `abilities` block. If `importPlaybooks`, `manageInstances`, or `manageConnections` is false, the credential's role is too narrow for deployment. Reads and validation still work.

| Self-test message | Meaning |
| ----------------- | ------- |
| `auth_failed` | wrong client ID or secret, or the credential was deleted |
| `tenant_required` | partner or organization credential with no target tenant |
| `tenant_not_visible` | the target tenant ID is not one this credential can reach |
| `tenant_not_on_fusion` | Sophos Fusion does not hold that tenant, or this credential cannot reach it there. Not retried |
| `secret_unavailable` | the op:// reference did not resolve (is `op` signed in?) |

## Other commands

`list`, `show` (which credential a command would use, no network), `use --name` (default), `remove --name`, `whoami`, `op-check` (checks op:// references resolve without printing them). All print JSON.
