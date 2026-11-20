# CEL cases files

A `cel-cases.json` next to a template lists expressions with sample inputs and the result each should give. Offline, every expression is parsed. On a tenant, each runs in Fusion's engine.

```json
{
  "template": "template.yaml",
  "cases": [
    {
      "name": "fires when the case closes",
      "from": "triggerHints[0].config.filter",
      "inputsFile": "sample-event.json",
      "expect": true
    },
    {
      "name": "the cap keeps the first addresses",
      "from": "task:plan.let.planned",
      "inputs": {},
      "bindings": {
        "settings": { "variables": { "cap": 2 } },
        "collect": { "variables": { "eligible": ["203.0.113.1", "203.0.113.2", "203.0.113.3"] } }
      },
      "expect": ["203.0.113.1", "203.0.113.2"]
    },
    { "name": "division fails", "expression": "1 / 0", "expectError": true }
  ]
}
```

## Fields

| Field | Notes |
| ----- | ----- |
| `template` | Path to the template, relative to the cases file. Needed for `from` |
| `name` | Shown in the truth table |
| `from` | Where the expression is in the template. A path (`triggerHints[0].config.filter`, `dsl.outcomeMessage`, `dsl.outputs.noted`) or `task:<name>.<field>[.<key>]` (`task:add_note.condition`, `task:collect.let.names`, `task:add_note.inputs.comment`) |
| `expression` | The expression itself, instead of `from` |
| `inputs` / `inputsFile` | What `inputs` holds: the event, the instance configuration, run parameters |
| `bindings` | Values for earlier tasks, by task name: `{ "lookup": { "outputs": { ... } } }`. An empty object `{}` stands for a task that was skipped |
| `expect` | The result. Compared as JSON, key order ignored |
| `expectError` | `true` when the expression should fail |

`from` keeps cases in step with the template: change the expression, and the cases test the new one.

## How bindings work

`evaluateExpr` binds only `inputs`. The runner wraps the expression in `cel.bind(<task>, <value>, ...)` for each binding, and wraps each `${...}` part of a template the same way. So bindings can stand in for any task results, including a skipped task (`{}`), which is how to test guards.

## Sample data

Use example values only: IPs from 192.0.2.0/24, 198.51.100.0/24, and 203.0.113.0/24; example.com addresses; all-zero UUIDs (`00000000-0000-4000-8000-000000000001`). Build events from `catalog.mjs event-shape --source <source>`.
