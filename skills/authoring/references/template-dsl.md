# The playbook template format

A Sophos Fusion playbook template is one YAML file with `kind: Playbook`. The platform keeps its versions; a configured playbook (an instance) runs one of them.

Facts marked *measured* were checked against the Fusion API on 21/11/2026.

## Top-level fields

| Field | Required | Notes |
| ----- | -------- | ----- |
| `apiVersion` | yes | `v0.0.1` |
| `kind` | yes | `Playbook` |
| `name` | yes | Letters, digits, underscores, in dot-separated parts. `Taegis.` is Sophos's prefix: do not use it |
| `version` | yes | Semantic version. Import a higher version to add one |
| `title`, `description` | yes | What people see in the console |
| `documentation` | recommended | Markdown shown in the console |
| `changeNotes`, `changeNotesMarkdown` | no | Shown with the version |
| `tags` | no | `Type:Response`, `Type:Enrichment`, `Type:Notification`, `Category:...` |
| `connectorCategories` | no | Console grouping, for example `Generic` |
| `connectors` | when used | `Name:version` for every connector an `action:` task uses |
| `playbooks` | when used | `Name:version` for every playbook an `exec:` task runs |
| `interfaces` | when used | `Name:version` for every interface a `call:` task uses |
| `triggerHints` | recommended | The triggers the console offers for this template. See [triggers-and-events.md](triggers-and-events.md) |
| `inputs` | no | JSON Schema of the instance's configuration. Defaults fill the console form |
| `outputs` | no | JSON Schema of what the run returns |
| `dsl` | yes | The program |
| `type` | no | `None`, `ResponseAction`, `ContextualLookup`, or `System`. Custom templates use `None` |

Exports also carry `tenantId`, `icon`, `featureCodes`, `licenseCapabilities`, and visibility flags. Fusion sets these. Remove `tenantId` before sharing a file.

## The dsl block

```yaml
dsl:
    name: CaseOwnerNote
    description: One line
    tasks:
        - name: first_step
          ...
    outputs:
        key: expression
    outcomeStatus: expression giving 'SUCCESS', 'FAIL', 'PARTIAL' or 'UNKNOWN'
    outcomeMessage: expression giving a string
    summary: expression giving a string (optional)
```

## How a field is read

- A string is one CEL expression: `inputs.case.title`.
- A string holding `${...}` is a template: `"Case ${caseShortId(inputs)} closed"`. Each `${...}` is CEL.
- A scalar in YAML single quotes is a literal string and is not evaluated: `fields: 'id title'`. *Measured* in validation and at run time.
- An empty string is an empty literal. A string of spaces is a syntax error.
- Numbers, booleans, and null are literals.
- Strings nested in maps and lists under `let`, `variables`, and `inputs` follow the same rules. A bare word in a list is a reference, not text: `[assets, events]` reads two undeclared names.

## Task types

Every task has a `name` (lower case, digits, underscores, unique in the playbook). A task does one of these:

| Keys | What it does |
| ---- | ------------ |
| `let: {var: expr}` | Sets variables, read later as `task.variables.var` |
| `action: Connector.actionName` + `inputs` | Calls a connector action. Results in `task.outputs` |
| `exec: PlaybookName` + `inputs` | Runs another playbook. Its outputs in `task.outputs` |
| `call: InterfaceName` + `inputs` | Calls an interface; the instance picks the implementation |
| `range: expr` + `for: [tasks]` | Runs the tasks once per item. The item is `task.value` (rename it with `value: name`) |
| `while: expr` + `do: [tasks]` | Repeats while the expression is true |
| `if: expr` + `then: [tasks]` (+ `else:`) | Branch |
| `switch: expr` + `case: {label: [tasks], default: [tasks]}` | Multi-way branch |
| `sleep: 30s` | Waits. A duration, or an expression that gives one |

Block tasks (loops and branches) can declare `variables:` with starting values. A `let` inside the block updates those variables: that is how a loop collects results.

```yaml
        - name: collect
          variables:
            names: []
          range: get_users.?outputs.users.orValue([])
          for:
              - name: add_name
                let:
                    names: collect.variables.names + [collect.value.name]
```

## Keys any task may carry

| Key | Effect |
| --- | ------ |
| `condition` | Skip the task when false. A skipped task has no `outputs` or `variables` |
| `optional: true` | A failure does not stop the run. The task may then have no outputs |
| `retry: n` | Retry an action that fails. Only on `action:` tasks: Fusion warns and ignores it elsewhere (*measured*) |
| `nolog: true` | Keep the step's request, response, and values out of the execution log. Later steps still read its results |
| `description` | Shown in logs |

Fusion warns "unexpected task dsl statement" on any other key and ignores it.

## What a task can read

- `inputs`: the instance configuration, the run parameters, and the trigger event (`inputs.case`, `inputs.event`, and so on).
- `TDR`: platform values (`TDR.tenant`, `TDR.URL`, `TDR.API`, `TDR.user`).
- `tenant`: the tenant record.
- Earlier tasks, by name: `task.outputs.x`, `task.variables.x`, `task.status`.
- Inside a block: the block task itself (`loop.value`, `loop.variables.x`) and earlier tasks in the block.

Not visible, and the run fails with "undeclared reference" (Fusion's validator only warns):

- tasks inside a loop or branch, from outside it
- names that are not tasks

Fusion's validator does not flag a read of a task that runs later. The value does not exist yet when it runs. The offline validator flags it (`ref.forward`).

## Names that break things

- A task named like a CEL type or name (`int`, `string`, `map`, `list`, `type`, `inputs`) makes every expression in the playbook fail with "overlapping identifier" (*measured*).
- A task named like a CEL reserved word (`loop`, `if`, `for`, `let`, `while`, `in`, and others) can never be read: "reserved identifier" (*measured*).

## Versions

Importing a template under a name that exists adds a version when the version number is higher. Imports publish the version they create (*measured*). Instances pin a version (`versionStrategy: Fixed`) or follow one (`FollowMinorVersion`, `FollowMajorVersion`, `FollowHeadVersion`).
