# Offline rule IDs

Every finding has one of these IDs. Errors block the gate. Warnings are reported.

## Files and structure

| Rule | Level | Means | Fix |
| ---- | ----- | ----- | --- |
| `yaml.parse` | error | not valid YAML, or more than one document | fix the YAML |
| `yaml.shape` | error | not a map | |
| `kind.unknown` | error | `kind` is not Playbook or Connector | |
| `field.required` | error | a required field is missing | add it |
| `field.recommended` | warning | `documentation`, `triggerHints`, or `dsl.name` missing | add it |
| `field.type` | error | `type` is not a known template type | `None` for custom templates |
| `name.template` / `name.connector` | error | name has spaces or odd characters | letters, digits, underscores, dots |
| `version.semver` | error | not major.minor.patch | quote it: `"1.0.0"` |
| `dsl.shape`, `dsl.tasks`, `dsl.keys` | error / warning | dsl missing, empty, or with unknown keys | |

## Dependencies

| Rule | Level | Means |
| ---- | ----- | ----- |
| `deps.format` | error | a `connectors`, `playbooks`, or `interfaces` entry is not `Name:version` |
| `deps.duplicate` | warning | listed twice |
| `deps.unused` | warning | declared, never used |
| `deps.connector-undeclared` | error | an `action:` uses a connector the template does not list |
| `deps.playbook-undeclared` | error | an `exec:` target is not listed |
| `deps.interface-undeclared` | error | a `call:` target is not listed |

## Triggers

| Rule | Level | Means |
| ---- | ----- | ----- |
| `trigger.type` | error | not actions, platform, or generic |
| `trigger.source` | error | unknown platform source |
| `trigger.events` | error / warning | unknown event for the source; warning for Identity Findings `updated` |
| `trigger.filter` | warning | platform hint with no filter: runs on every event |
| `trigger.category`, `trigger.context`, `trigger.name` | error / warning | User Initiated hint fields |
| `trigger.usage` | error | Generic usage not notification, schedule, or other |

## Tasks

| Rule | Level | Means |
| ---- | ----- | ----- |
| `task.shape` | error | a task is not a map |
| `task.name` | error / warning | missing, not lower case, duplicated, a CEL name (overlapping identifier), or a CEL reserved word |
| `task.keys` | warning | unknown key (Fusion ignores it) |
| `task.kind` | error / warning | more than one of action, call, exec; or a task that does nothing |
| `task.action` | error | `action` is not `Connector.action` |
| `task.loop`, `task.branch` | error | range without for, while without do, if without then, switch without case |
| `task.sleep` | error | not a duration or an expression |
| `task.retry` | warning | `retry` on a task that is not an action |

## Expressions and references

| Rule | Level | Means | Fix |
| ---- | ----- | ----- | --- |
| `cel.syntax` | error | an expression or `${...}` part does not parse | for literal text use YAML single quotes |
| `ref.undeclared` | error | reads a name that is not a task, `inputs`, `TDR`, or `tenant` | fix the name |
| `ref.forward` | error | reads a task that runs later | reorder |
| `ref.nested` | error | reads a task inside a loop or branch from outside it | copy the value out through the block's `variables` |
| `ref.scope` | error | reads a task that is not in scope | |
| `ref.self` | error | a task reads its own results | |
| `ref.loop-item` | error | reads `loop.value` outside the loop | |
| `ref.skipped` | error | reads a task with a `condition` or `optional: true` without a guard | `task.?outputs.x.orValue(d)` or `has(task, 'outputs.x')` |
| `ref.connector` | error / warning | a connector template reads an unknown name or an undeclared parameter | |

A read counts as guarded when the same expression has `has(task, ...)` or an optional read of that task, when the reading task's condition (or an enclosing block's) does, or when both tasks share the same condition.

## Safety conventions

| Rule | Level | Means |
| ---- | ----- | ----- |
| `secret.nolog` | error | a step that sends or reads a password, token, key, webhook, or signature has no `nolog: true` |
| `response.dry-run` | error | a response playbook without a boolean `dry_run` input defaulting to true |
| `response.cap` | error | no integer `max_` input with a default, or nothing reads it |
| `response.gate` | error | a changing action whose condition does not check `dry_run` |
| `data.hardcoded-secret` | error (warning in documentation) | a token, key pair, private key, or webhook URL in the file |
| `data.personal` | error (warning in documentation) | an email address outside example domains |
| `data.tenant-id` | error | an exported `tenantId`, or a fixed tenant ID in a tenant input |

A playbook is response tier when a trigger hint is User Initiated `response`, it is tagged `Type:Response`, its type is `ResponseAction`, or it calls an action that isolates, blocks, disables, resets, revokes, locks, quarantines, purges, scans, or similar.

## Connectors

| Rule | Level | Means |
| ---- | ----- | ----- |
| `connector.method` | error | not http, taegis, central, or ldap |
| `connector.auth` | error | empty or unknown auth types |
| `connector.actions`, `connector.action-name`, `connector.action-doc` | error / warning | missing, invalid, duplicate, or undocumented actions |
| `connector.config`, `connector.url`, `connector.http-method` | error / warning | http actions need config, an https URL, and a method |
| `connector.outputs` | warning | an action maps no outputs |
| `connector.hosts` | error | a host the actions call is not in the documentation |
| `connector.validate` | warning | no validate action |
