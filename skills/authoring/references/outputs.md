# Outputs and outcomes

## outputs

`dsl.outputs` is a map of names to expressions, evaluated after the last task. It is what the run returns, what a parent playbook reads through `exec:`, and what the console shows. Describe the same keys in the template's `outputs` JSON Schema.

A read of a task that was skipped fails the whole run with "no such key", even after every task succeeded. Guard every output that reads a conditional or optional task:

```yaml
    outputs:
        noted: has(add_note, 'outputs.comment')
        detections: settle_count.?variables.detections.orValue(0)
```

## outcomeStatus and outcomeMessage

Set both, always.

- `outcomeStatus` gives `'SUCCESS'`, `'FAIL'`, `'PARTIAL'`, or `'UNKNOWN'`.
- `outcomeMessage` gives one line a person can act on.

Without them, Fusion marks a run Completed with outcome UNKNOWN even when a step failed or a lookup answered "not found". The Playbook Execution trigger and the console then show nothing wrong. Read the step results:

```yaml
    outcomeStatus: "has(add_note, 'outputs.comment') ? 'SUCCESS' : 'FAIL'"
    outcomeMessage: "has(add_note, 'outputs.comment') ? 'Noted ' + caseShortId(inputs) : 'Could not add the note to ' + caseShortId(inputs)"
```

For a response playbook in a dry run, report success and say what would have changed:

```yaml
    outcomeMessage: "settings.variables.dry_run ? 'Dry run: would block ' + string(size(plan.variables.planned)) + ' addresses' : ..."
```

## summary

`dsl.summary` is an optional string shown with lookup results in the console. Sophos's lookup templates fill it from the Taegis.Secureworks summarize action.

## Seeing them

`run.mjs show --execution <id>` returns inputs, outputs, outcome, and task events. `run.mjs diagnose` reads them for you.
