# Triggers and event shapes

A template suggests triggers with `triggerHints`. The configured playbook (instance) holds the real trigger. `catalog.mjs triggers` lists what the tenant offers; `catalog.mjs event-shape --source <source>` shows an event's fields with a sample to build test events from.

## The three trigger types

| Type (hint `type`) | Console name | Starts when | API can run it |
| ------------------ | ------------ | ----------- | -------------- |
| `platform` | Platform Events | an event happens on the tenant | no, events start it |
| `actions` | User Initiated | a person runs it from the console | no: the API answers REAUTH_REQUIRED |
| `generic` | Generic Trigger | someone runs it, the API runs it, or a schedule fires | yes |

Only Generic Trigger instances run through `executePlaybookInstanceV2`. So give every template a Generic Trigger hint. Its instance is the test twin: the same template, run by the execution skill with a test event in the parameters.

## Hint shapes

```yaml
triggerHints:
    - isProactiveResponse: false
      type: platform
      config:
        source: case
        events: [Update]
        filter: "casePrimaryStatusName(inputs) == 'closed'"
      celHints:
        - name: Closed cases
          expr: "casePrimaryStatusName(inputs) == 'closed'"
    - isProactiveResponse: false
      type: actions
      config:
        category: response        # or lookup
        context: case             # where the action appears
        name: Block case IPs      # what people see
    - isProactiveResponse: false
      type: generic
      config:
        usage: other              # or schedule, or notification
```

`celHints` are filter suggestions the console offers. Keep `isProactiveResponse: false`: only Sophos's own tenant may set it to true, and a customer import that sets it fails. `usage: schedule` marks a template as one that runs on a schedule.

## Platform sources and events

Read from the Fusion schema on 21/11/2026. Event names keep the case shown.

| Source | Events | The event arrives as |
| ------ | ------ | -------------------- |
| `case` | Create, Update, Delete, Detections Added, Detections Removed, Events Added, Events Removed, Assets Added, Assets Removed, Searches Added, Searches Removed, Comment Added, Comment Updated, Comment Deleted, File Added, File Deleted, Link Added, Link Updated, Link Deleted | `inputs.case`, event name in `inputs.event` |
| `alert2` (detections) | create, update | `inputs.alert2` |
| `health` | create, update, delete | `inputs.health` |
| `identityFindings` | created, updated, closed, reopened | `inputs.identityFindings` |
| `execution` (playbook runs) | completed, failed | `inputs.execution` |
| `investigationNotification` | Create, Update, Alerts Added, and more | older case model |
| `investigation` | create, update, delete | older case model |
| `auto-investigation` | create, update | |
| `tenant`, `tenantlabel`, `tenantuser` | create, update, delete | |
| `playbookAction` | execute, bulk_execute | |

Partner tenants also get Create Draft on the case sources.

Two traps:

- Identity Findings `updated` fires on posture re-checks, often several times a day for the same finding. Anything that acts should use `created`.
- A filter that evaluates false creates no run at all, so a filter that is too narrow fails silently. Test filters with CEL cases.

## Case events

The case record carries id, shortId, title, tenantId, type, severity, primaryStatus {id, name, title, isClosed}, primaryVerdict {id, name, title}, assigneeId, detectionEvidence [{id, isGenesis}], keyFindings, tags, closeReason, closedAt, createdById, updatedById, contributorIds, and `delta` (updatedFields, changes {field: {before, after}}, comment, file, link). When an API credential made the change, the ID fields hold its client ID.

Read it through the `case*` functions rather than paths: `caseId(inputs)`, `casePrimaryVerdictName(inputs)`, `caseFieldChanged(inputs, 'primaryStatus.id')`, `size(caseDetectionEvidence(inputs))`.

Status and verdict names differ between tenants. An MDR tenant closes cases as `true_positive_malicious`, `true_positive_benign`, `false_positive`, or `inconclusive`. An XDR tenant uses `confirmed_security_incident`, `threat_mitigated`, `authorized_activity`, `not_vulnerable`, `false_positive`, `inconclusive`, and `informational`. Run the Case reference lookup example on the tenant to get its list, and make verdict lists an input.

## How instances store triggers

The deployment script builds these. They are here so an export or a list reads clearly.

```json
{ "usage": { "value": "other" } }
{ "source": { "value": "case", "events": ["Update"] }, "filter": { "value": "<CEL>" } }
{ "category": { "value": "response", "context": { "value": "case" } }, "filter": { "value": "true" }, "name": "Block case IPs" }
```

## Schedules

A schedule runs a Generic Trigger instance on a cron expression in a time zone, with its own inputs. The deployment script creates schedules paused unless asked otherwise.

## Tenant-wide trigger filters

`playbookTriggerFilters` on a tenant are platform circuit breakers (for example, one per noisy detection rule). They are not per-playbook filters. These scripts read them but never create them. A playbook's own filter is the instance trigger's `filter`.
