---
name: authoring
description: Write a Sophos Fusion playbook template (template.yaml) from a plain-language request, using the real connectors, actions, triggers, event shapes, interfaces, and CEL functions on the tenant. Use when someone asks for a new playbook, wants to change one, or needs a CEL filter or expression for a Fusion trigger or task. Builds in dry run and a per-run cap for response playbooks, nolog for steps that carry secrets, guarded reads, and an outcome, and writes a CEL cases file for testing.
license: MIT
---

# Authoring: from a request to template.yaml

Scripts live in `${CLAUDE_SKILL_DIR}/scripts/` and references in `${CLAUDE_SKILL_DIR}/references/`. If those show literally, they mean the folders next to this file.

Everything here is read-only. Discovery reads the tenant; scaffolding writes local files.

## 1. Pin down the request

Settle these before writing anything. Ask only for what you cannot infer.

- **Tier.** lookup (reads only), notify (writes inside Fusion: a case comment, a notification), or response (changes something outside Fusion: blocks, isolates, disables, resets).
- **Trigger.** What starts it: a platform event (case, detection, health, identity finding, playbook execution), a person in the console (User Initiated), or a schedule or API call (Generic Trigger).
- **Scope.** Which events, which cases, which entities. This becomes the trigger filter and the inputs.
- **Output.** What the person should see when it ran.

## 2. Look up what exists

Use the tenant's real names. Never guess a connector, action, input, or function name.

```bash
C=${CLAUDE_SKILL_DIR}/scripts/catalog.mjs
node $C connectors --search "add a comment to a case"     # meaning search
node $C connector --name Taegis.Case                       # actions, inputs, outputs, connections
node $C connector --name Taegis.Case --action addComment   # one action in full
node $C triggers                                           # sources, events, contexts
node $C event-shape --source case                          # the event a playbook receives, with a sample
node $C functions --search case                            # Fusion's CEL functions, with examples
node $C interfaces --search Block                          # call: targets
node $C templates --search Case                            # Sophos's templates, good to learn from
node $C template --name Taegis.LookUpFileHash              # one template's structure
```

`dependencyEntry` in the output is the exact `Name:version` line for the template's `connectors`, `playbooks`, or `interfaces` list.

If no connector covers the vendor, stop and use the `connectors` skill first.

## 3. Start from a skeleton

```bash
node ${CLAUDE_SKILL_DIR}/scripts/scaffold.mjs playbook --name CaseOwnerNote --title "Case owner note" \
  --tier notify --trigger platform --source case --events Update --out ./case-owner-note
```

The skeleton already validates. It has a Generic Trigger hint (the only kind the API can run), a `settings` task with safe defaults, guarded outputs, and an outcome. Response skeletons add `dry_run` and `max_targets`.

Template names use letters, digits, and underscores. Do not start them with `Taegis.`, which Sophos uses.

## 4. Write the tasks

Read [template-dsl.md](references/template-dsl.md) for the structure and [cel.md](references/cel.md) for expressions. The rules that cause most failed runs:

- **Every string is CEL.** `title: inputs.x` reads a value. For literal text use YAML single quotes (`'Closed'`) or a CEL string inside double quotes (`"'Closed'"`). A string holding `${...}` is a template.
- **Guard every read of a task that can be skipped or fail.** A task with a `condition` or `optional: true` may leave no results. Read it as `step.?outputs.x.orValue(default)` or behind `has(step, 'outputs.x')`. Fusion's validator only warns; the run then fails with "no such key".
- **Tasks inside a loop or branch are invisible outside it.** Copy values out through the block task's `variables`.
- **Task names:** lower case, digits, underscores, unique. Not a CEL word (`loop`, `if`, `int`, `string`, `map`, and others break every expression).
- **Put `nolog: true` on any step whose request or response carries a password, token, key, or signed or webhook URL.** Fusion keeps execution logs, bodies included, permanently.
- **Response tier:** an input `dry_run` (boolean, default true), an integer input starting `max_` that caps one run, and every changing action gated with `!...dry_run` in its condition. Report what a dry run would have done in `outcomeMessage`.
- **Always set `outcomeStatus` and `outcomeMessage`.** Without them a run that failed quietly shows as Completed, outcome UNKNOWN.
- No tenant IDs, credentials, or personal data in the file. Read the tenant from the event or `TDR.tenant`.

Triggers and event fields: [triggers-and-events.md](references/triggers-and-events.md). Connector calls and connections: [connector-calls.md](references/connector-calls.md). Interfaces: [interfaces.md](references/interfaces.md). Outputs and outcomes: [outputs.md](references/outputs.md). Error messages: [errors.md](references/errors.md).

## 5. Write the CEL cases

Every expression that decides something (the trigger filter, each condition, each computed value) gets cases in `cel-cases.json` next to the template. Point at the expression in the template with `from` so the cases cannot drift from it:

```json
{
  "template": "template.yaml",
  "cases": [
    { "name": "fires when the case closes", "from": "triggerHints[0].config.filter", "inputsFile": "sample-event.json", "expect": true },
    { "name": "skipped lookup gives an empty list", "from": "task:collect.let.names", "bindings": { "lookup": {} }, "expect": [] }
  ]
}
```

`bindings` stand in for earlier tasks' results. Build test events from `catalog.mjs event-shape`. Use example data only: documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), example.com, all-zero UUIDs.

## 6. Hand over

Pass the template and cases file to the `validation` skill. Fix what it finds and run it again until it passes.
