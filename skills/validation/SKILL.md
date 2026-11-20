---
name: validation
description: Check a Sophos Fusion playbook template or connector before it goes near a tenant, and again on the tenant. Use after writing or changing template.yaml or connector.yaml, before any import, when an import or run fails, or when someone asks whether a playbook or CEL expression is right. Three levels - offline rules with no credentials, the tenant's own DSL check, and CEL cases run in Fusion's engine as a truth table. Read-only.
license: MIT
---

# Validation: three levels

Scripts live in `${CLAUDE_SKILL_DIR}/scripts/`. If that shows literally, it means the folder next to this file.

```bash
V=${CLAUDE_SKILL_DIR}/scripts/validate.mjs
```

Run the levels in order. Stop at the first that fails, fix, and run it again.

## Level 1: offline (no credentials, no network)

```bash
node $V offline path/to/template.yaml          # one or more files
node $V all path/to/folder                     # every YAML file and cel-cases.json under a folder
```

It checks: YAML parses; the fields a Playbook or Connector needs; versions; names; every CEL expression and `${...}` template parses; task references resolve, in scope and in order; reads of tasks that can be skipped or fail are guarded; tasks in loops are not read from outside; connectors, playbooks, and interfaces used are declared; secret-bearing steps have `nolog`; response playbooks have `dry_run` (default true), a `max_` cap, and gated actions; no fixed credentials, tenant IDs, or personal data. Connectors also: https only, declared hosts, declared parameters.

Each finding has a rule ID, a level, the YAML path, and the line. Rule IDs and fixes: [rules.md](references/rules.md).

The gate is 0 errors. Warnings are allowed; explain each one to the person. `--strict` fails on warnings too.

Many checks catch problems Fusion's own validator lets through. It only warns about undeclared references and syntax errors in expressions, and does not notice skipped-task reads, forward reads, or unknown action names. Those runs then fail.

## Level 2: on the tenant (read-only)

```bash
node $V tenant path/to/template.yaml --profile lab
```

It resolves the template's connectors, playbooks, and interfaces on the tenant, runs Fusion's `playbookValidateDSLV2` on the dsl block, and maps its line numbers back to the file. Warnings that mean the run will fail (syntax errors, undeclared references, reserved names, duplicate names) count as errors. It then checks every action exists on the connector version and that inputs match the action.

`tenant.connector` errors usually mean the template names a version the tenant does not have. Use the version `catalog.mjs connector` shows.

For a template that uses a custom connector, import the connector first (a test copy) and validate the template's test copy against it. The deployment skill's import does that mapping.

## Level 3: CEL cases in Fusion's engine (read-only)

```bash
node $V cel path/to/cel-cases.json --profile lab
node $V cel path/to/cel-cases.json --offline    # parse only, no tenant
```

Each case runs through `evaluateExpr`. The truth table prints on stderr and comes back in the JSON. The gate is every case PASS. File format: [cel-cases.md](references/cel-cases.md).

## The connection check (a write)

```bash
node $V connection --connector ZZTest_Acme --auth-type None --config '{"base_url":"https://..."}' --yes
```

This runs the connector's `validate` action against the vendor through `validateConnectionInput`. It creates nothing, but it calls the vendor with the given credentials, so treat it as a write: ask first.

## Report

Give the counts (errors, warnings, cases passed) and the first few findings with their lines. Do not paste the whole JSON.
