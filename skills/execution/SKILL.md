---
name: execution
description: Run a Sophos Fusion playbook through the API and read what happened. Use when someone wants to test, run, or trigger a playbook, watch a run, read its log, or find out why a run failed or ended Completed with outcome UNKNOWN. Runs Generic Trigger instances with parameters or a test event, polls to the end, reads logs, flags secrets in them, and explains REAUTH_REQUIRED and the Generic Trigger test twin.
license: MIT
---

# Execution: run, watch, read, diagnose

Scripts live in `${CLAUDE_SKILL_DIR}/scripts/`. If that shows literally, it means the folder next to this file. States and log fields: [runs.md](references/runs.md).

```bash
R=${CLAUDE_SKILL_DIR}/scripts/run.mjs
```

## What the API can run

Only enabled Generic Trigger instances. A User Initiated instance answers REAUTH_REQUIRED, and a platform-event instance runs when its events happen.

To test any template through the API, use its test twin: a second instance of the same template with a Generic Trigger (`deploy.mjs instance-create --trigger generic`), run with a test event in the parameters. Templates written with the `authoring` skill carry a Generic Trigger hint for this.

Instances are created disabled, and Fusion will not run a disabled one (PB12). Enabling is a deployment step with its own approval.

## Before a run

- Lookup-only templates are the safe ones to run. A notify template writes inside Fusion (a case comment), so run it only against a test case the person names.
- A response template runs only with `dry_run` on, only when the person approves, and only on a test tenant. Never turn dry run off in a test the person has not asked for by name.
- Parameters must not hold a secret, a webhook URL, or personal data. Fusion keeps the log permanently. The script refuses secret-looking values.
- Parameters must not hold `${`: Fusion evaluates run parameters as templates and the call fails. The script refuses them.

## Run it (a write: ask first)

```bash
node $R execute --instance <id> --params '{"configuration": {"dry_run": true}}' --watch --yes
node $R execute --instance <id> --event @sample-event.json --watch --yes     # a test event, for example {"case": {...}}
```

`--event` merges the file into the parameters, so a Generic Trigger twin sees `inputs.case` the way the platform trigger would. `targetResource` defaults to an empty string, which Fusion accepts.

## Watch, read, diagnose (read-only)

```bash
node $R watch --execution <id>
node $R show --execution <id>          # inputs, outputs, outcome, task events
node $R logs --execution <id>          # task by task, with secret-looking strings flagged
node $R diagnose --execution <id>      # plain-language reading
node $R list --instance <id>
```

`diagnose` calls out:

- Completed with outcome UNKNOWN: Fusion marks a run Completed even when a step failed quietly. Fix the template's outcome.
- `no such key`: a read of a skipped task or a missing field. Guard it.
- `undeclared reference`: a task in a loop read from outside, or a typo.
- CEL syntax or type errors.
- connection problems: missing, unbound, or rejected credentials.
- REAUTH_REQUIRED, with the test twin route.
- secret-looking strings in the log. They cannot be deleted: rotate the secret and add `nolog: true` to the step.
- the API client ID in the log, listed apart as an identifier. Fusion records it as the creator or updater of what the credential changed. It is not a secret, so tell the user nothing needs rotating.

## Cancel (a write)

```bash
node $R cancel --execution <id> --yes
```

## After the test

Disable the instance or roll back the ledger run with the `deployment` skill. Report the execution ID, its state and outcome, and what the diagnosis found.
