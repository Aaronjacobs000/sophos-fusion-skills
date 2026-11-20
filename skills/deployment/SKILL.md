---
name: deployment
description: Put a validated Sophos Fusion template or connector on a tenant safely, and take it off again. Use when someone wants to import, install, deploy, configure, or remove a playbook or connector, create connections, configured playbooks (instances), trigger filters, or schedules, enable or publish, list or export what is on a tenant, or clean up test copies. Imports a ZZTest_ copy by default, creates instances disabled, records everything in a ledger, reads every write back, and rolls back a whole run.
license: MIT
---

# Deployment: test copies, disabled instances, ledger, rollback

Scripts live in `${CLAUDE_SKILL_DIR}/scripts/`. If that shows literally, it means the folder next to this file. Object types are explained in [objects.md](references/objects.md).

```bash
D=${CLAUDE_SKILL_DIR}/scripts
```

## Before any write

- The template passed the `validation` skill (offline and tenant). `import` refuses a file with offline errors.
- You know the profile, its kind, and the tenant. For production, name the tenant to the person.
- Every write command below needs the person's yes for that step, then `--yes` (and `--production` on a production profile). Without them the script sends nothing and exits 3.

## The usual path

```bash
node $D/ledger.mjs start --label "<what this run is for>"
node $D/deploy.mjs check template.yaml                                  # read-only: duplicates and versions
node $D/deploy.mjs import template.yaml --yes                           # test copy ZZTest_<name>, read back, export-diff
node $D/deploy.mjs instance-create --template ZZTest_<name> --name "ZZ Test <name>" --trigger generic --yes
node $D/deploy.mjs counts                                               # before and after, to show nothing else changed
```

`import` reports the new ID, the ledger entry, a read-back, and an export-and-diff against the file (tenant fields ignored). The gate is `readBack.found: true` and `diff.matches: true`.

`instance-create` always creates the instance disabled and reads that back. It binds the only connection of each connector the template uses, and asks you to choose with `--connections` when there are several.

Trigger options:

```bash
--trigger generic [--usage other|schedule|notification]
--trigger platform --source case --events Update --filter "<CEL>"
--trigger actions --category response --context case --action-name "Block case IPs"
```

Instance inputs: `--inputs '{"configuration": {...}}'` or `--inputs @inputs.json`.

## Optional steps

```bash
node $D/deploy.mjs set-filter --instance <id> --filter "<CEL>" --yes             # the instance's Only When filter
node $D/deploy.mjs schedule-create --instance <id> --name "ZZ Test weekly" --cron "0 7 * * 1" --time-zone Australia/Sydney --yes   # created paused
node $D/deploy.mjs connection-create --connector <name> --name "ZZ Test <name>" --auth-type None --yes
```

Schedules are created paused. `--start` creates one running; that is a separate approval.

## Enable and publish are their own steps

```bash
node $D/deploy.mjs enable --instance <id> --yes
node $D/deploy.mjs disable --instance <id> --yes
node $D/deploy.mjs publish --template <name> --version <x.y.z> --yes
```

An enabled instance runs whenever its trigger fires. Ask separately, and say what will trigger it. A Generic Trigger instance only runs when someone starts it or a schedule fires, so enabling one for a test run is low risk. Imports already publish their version; `publish` is for drafts.

## Changing objects that already existed

The scripts change and delete only objects in the ledger. To change something that was on the tenant before (an instance the person built in the console), the person must ask for that object by name; then add `--allow-existing`.

## Real deployments

`--as-is` imports under the real name and lets instance, connection, and schedule names drop the `ZZ Test ` prefix. Use it only when the person asks for a real deployment. On a production profile it also needs `--production`.

## Clean up

```bash
node $D/ledger.mjs plan                  # read-only: what rollback would delete, in order
node $D/ledger.mjs rollback --yes        # newest first, children before parents, each delete read back
node $D/ledger.mjs runs                  # live objects per run
```

Rollback refuses objects recorded on a different tenant, and skips any object whose name changed since it was recorded. The gate is `remaining: 0` and counts back where they started.

## Read and export

```bash
node $D/deploy.mjs list --kind templates|connectors|connections|instances|schedules [--custom] [--search x]
node $D/deploy.mjs export --template <name> --out file.yaml [--clean]
node $D/deploy.mjs show --kind instance --id <id>                         # one object in full: trigger, filter, inputs, connections
node $D/deploy.mjs diff template.yaml                                    # compare the file with the tenant copy
```

Exports of Sophos's own templates are for study. Do not commit them.

## When a write answers with an error

A write that gets a 5xx, times out, or loses its connection is never sent again: it may have worked. The script looks for the object by name, and records it in the ledger if it is there. Read back before you try again.

## Report

Say what is on the tenant now (names, IDs, enabled or not), the ledger run ID, the counts before and after, and how to remove it.
