# Fusion error messages and what they mean

Seen on the Fusion API on 21/11/2026 unless noted. "Validator" means `playbookValidateDSLV2`.

## While validating or importing

| Message | Cause | Fix |
| ------- | ----- | --- |
| `dsl must contain at least one task` | empty `tasks` | add a task |
| `error resolving connector X: ... C5: unable to get connector from database` | the connector named in an action is not on the tenant | import it, or fix the name |
| `error resolving playbook: PB21: Unable to get playbook: record not found` | an `exec:` target is missing, or not passed to the validator | import it; the tenant check passes the IDs |
| `interface X called, but missing from required interfaces` | `call:` without an `interfaces` entry | declare it |
| `undeclared reference to 'x'` (warning) | a name that is not a task, or a task inside a loop read from outside | fails at run time; fix the reference |
| `Syntax error: ...` (warning) | the string did not parse as CEL | fails at run time; quote literals with YAML single quotes |
| `overlapping identifier for name 'int'` (warning) | a task named like a CEL name | rename the task |
| `reserved identifier: loop` (warning) | a task named like a CEL reserved word | rename the task |
| `task name 'a' is not unique` (warning) | two tasks share a name | rename one |
| `unexpected task dsl statement: x` (warning) | an unknown task key | remove it |
| `retry can only be used with a function task` (warning) | `retry` on a non-action task | remove it |
| `Task name does not conform to naming standard` (warning) | not lower case and underscores | rename |

The validator lets a wrong action name and a read of a later task through. Both fail at run time. The tenant check in the validation skill catches them.

## While running

| Message or state | Cause | Fix |
| ---------------- | ----- | --- |
| `PB12: playbook not enabled` | the instance is disabled | enable it (its own approval), or run a Generic Trigger twin |
| `REAUTH_REQUIRED` | API run of a User Initiated instance | run a Generic Trigger instance of the same template |
| `no such key: ...` | read of a skipped task, or a field the vendor did not return | guard the read |
| `undeclared reference to ...` | as above | fix the reference |
| `type conversion error` / `found no matching overload` | wrong type passed to a function | convert with `int()`, `double()`, `string()` |
| Completed, outcome UNKNOWN | no `outcomeStatus`, or a step failed quietly | set an outcome that reads the steps |
| a call fails on `${` | run parameters are evaluated as templates | remove `${` from parameters |

## Connectors and connections

| Message | Cause | Fix |
| ------- | ----- | --- |
| `graphql: invalid action: validate` (validateConnectionInput) | the connector has no `validate` action | add one, or skip the connection check |
| `connector doesn't support auth type X` | wrong `authType` for the connection | use one from the connector's `authTypes` |
| `no such key: x: ${config.x}` | a connection parameter the connector needs is missing | set it in the connection `config` |
| `cannot test connection without the connection ID` (verifyConnectorActionV2) | no existing connection given | create one first |
| `invalid action: name. reason: action name split on '.'` | action name without the connector | use `Connector.action` |

## Platform answers

| Answer | Meaning |
| ------ | ------- |
| HTTP 503 `tenant ... not found or not accessible` | Fusion does not hold that tenant for this credential. The same every time; not retried |
| HTTP 429 | rate limited. Reads and writes wait for Retry-After (at most 60 s) and try again |
| HTTP 5xx on a write | the write may or may not have happened. Never repeated: read back first |
| a 3xx redirect | refused. Nothing is sent to the new address |
