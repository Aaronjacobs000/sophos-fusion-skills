# Runs, states, and logs

## States

| State | Meaning |
| ----- | ------- |
| Scheduled, Started | still going |
| Completed | finished. Check the outcome: Completed does not mean every step worked |
| Failed | a non-optional step failed, or an output or outcome expression failed |
| Canceled | cancelled |
| TimedOut | ran too long |
| Dropped | the platform dropped it |
| PendingApproval | waiting for someone to approve it in the console |
| Denied | approval refused |

## Outcome status

`SUCCESS`, `FAIL`, `PARTIAL`, or `UNKNOWN`, set by the template's `outcomeStatus`. UNKNOWN on a Completed run usually means the template sets no outcome, or a step failed quietly.

## Trigger fields on a run

`triggerCategory` and `triggerContext` say what started it: `generic` / `other` for an API or console run, `platform` / `case` for a case event, `platform` / `execution` for a Playbook Execution event (use that as a loop guard).

## The log

`playbookExecutionLogs` returns one entry per task, plus a start and an end entry. Each entry's `message` holds:

| Field | Holds |
| ----- | ----- |
| `task` | task name |
| `taskType` | let, action, exec, call, loop, ... |
| `status` | `{Completion: Success or Failure, Error: text}` |
| `inputs`, `outputs`, `variables` | the task's values |
| `request`, `response` | for connector calls: URL, body, and response body |
| `isOptional`, `noLog` | as set on the task |

A task with `nolog: true` has no values in its entry. Everything else stays in the log for good: deleting the instance or template does not remove it, and the API cannot.

## A run started by the API

`executePlaybookInstanceV2` takes the instance ID, `parameters` (they override the instance inputs, and are evaluated as templates), `targetResource` (required; an empty string works), and an optional `reason`. It returns the execution at once with state Started. Poll `playbookExecution` until a final state.
