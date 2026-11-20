---
name: playbooks
description: Entry point for Sophos Fusion automation. Use it when someone wants to build, check, deploy, run, or fix a Sophos Fusion playbook or custom connector (SOAR automation, playbook templates, configured playbooks, connections, CEL filters, triggers on cases, detections, health, or identity events). It decides which phase comes next, runs the phases in order, stops when a check fails, and carries names and IDs from one phase to the next. It calls no API itself.
license: MIT
---

# Sophos Fusion playbooks: start here

You coordinate. The other skills in this plugin do the work:

| Phase | Skill | Produces |
| ----- | ----- | -------- |
| Credentials | `setup` | a working profile, the target tenant, its region |
| Write | `authoring` | `template.yaml` and `cel-cases.json` |
| Custom connector | `connectors` | `connector.yaml`, one live action result |
| Check | `validation` | offline findings, the tenant's DSL check, a CEL truth table |
| Deploy | `deployment` | a test copy on the tenant, a disabled instance, a ledger run ID |
| Run | `execution` | an execution ID, its outcome, a diagnosis |

Load the skill for a phase before you start it. Do not call scripts from here.

## Pick the route

Read the request and pick the first line that fits.

- No profile yet, or a credential error: `setup`, then come back.
- "Write", "build", "make a playbook that...": `authoring`, then `validation`. Stop there unless the person asked to deploy.
- The playbook needs a vendor API that no connector covers: `connectors` first, then `authoring`.
- "Check", "validate", "why won't this import": `validation`.
- "Deploy", "import", "install", "set up on the tenant": `validation`, then `deployment`.
- "Run", "test it", "try it": `deployment` (if it is not on the tenant yet), then `execution`.
- "It failed", "it says Completed but did nothing": `execution` (diagnose), then `authoring` to fix, then `validation`.
- "Clean up", "remove the test copies": `deployment` (ledger rollback).

When the request covers several phases, run them in the order of the table. Each phase has a gate. Do not start the next phase until the gate passes.

| Gate | Passes when |
| ---- | ----------- |
| setup | `profile.mjs test` reports every step ok |
| validation (offline) | 0 errors. Warnings explained to the person |
| validation (tenant) | 0 errors from the tenant check |
| validation (CEL cases) | every case PASS |
| deployment | import read back, export diff matches, instance read back disabled |
| execution | the run reached a final state and the diagnosis is understood |

If a gate fails, stop, say what failed in one or two lines, and offer the fix. Never skip a gate to get to the next phase.

## Carry these between phases

Keep a short running record and pass it on. Do not make the person repeat it.

- profile name, its kind (test or production), tenant ID, region
- file paths of the template, the cases file, and any connector
- template name on the tenant (test copies start `ZZTest_`) and version
- connector and connection names and IDs
- instance ID, and whether it is enabled
- ledger run ID
- execution IDs

## Writes need a yes, every time

Reads are free. Writes are not. A write is anything that creates, changes, deletes, runs, or makes Fusion call a vendor: imports, connections, instances, filters, schedules, enable, publish, delete, rollback, playbook runs, connector action tests, and the connection check.

Before each write:

1. Say what it will do, on which tenant, in one line. For a production profile, name the tenant (name and ID) and say it is production.
2. Wait for the person to approve that specific write. Approval of an earlier write does not cover the next one. A general "go ahead" at the start covers only what was listed then.
3. Only then run the command with `--yes` (and `--production` on a production profile).

The scripts refuse writes without those flags (exit code 3) and send nothing. Never add the flags to get past a refusal the person has not approved.

## Defaults that keep tenants safe

- Imports are test copies: name `ZZTest_<name>`, title `ZZ Test <title>`.
- Instances are created disabled. Enabling is its own step and its own approval.
- Every created object goes in the ledger, so `ledger.mjs rollback` can remove a whole run.
- Response playbooks carry `dry_run` (default true) and a `max_` cap. Fusion has no platform dry run.
- Never put a secret, a webhook URL, or personal data in run parameters or connector test inputs. Fusion keeps execution logs, with request and response bodies, permanently.

## Finish with a short report

Say what was done, on which tenant, what is still on the tenant (with the ledger run ID), and the next step. Keep it to a few lines.
