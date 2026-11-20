# CEL in Sophos Fusion

Fusion uses the Common Expression Language for trigger filters, conditions, task inputs, variables, outputs, and connector templates. The language reference is at https://github.com/google/cel-spec/blob/master/doc/langdef.md. This page covers what is specific to Fusion. Facts marked *measured* were checked with `evaluateExpr` and `playbookValidateDSLV2` on 21/11/2026.

## Test an expression

```bash
node <plugin>/skills/validation/scripts/validate.mjs cel cel-cases.json
```

`evaluateExpr` binds only `inputs`. To test an expression that reads other tasks, give their values as `bindings` in the cases file; the runner wraps the expression in `cel.bind(...)` for each one.

## Syntax Fusion accepts

- Optional selection: `x.?field` and `list[?0]` give an optional. Finish with `.orValue(default)` or `.hasValue()`.
- Optional entries in literals: `{?'key': opt}`, `[?opt]`.
- Macros: `has(x.y)`, `list.all(v, pred)`, `exists`, `exists_one`, `map(v, expr)`, `map(v, filter, expr)`, `filter(v, pred)`.
- `cel.bind(name, value, expr)` names a value inside an expression (*measured*).
- Two-argument `has(x, 'a.b.c')` checks a path in one go. It also takes `[0]` steps: `has(x, 'outputs.items[0].id')`.

## Fusion's functions

`catalog.mjs functions --search <prefix>` lists them with examples. About 390 exist. The families you will use most:

| Family | Reads | Examples |
| ------ | ----- | -------- |
| `case*` | a case event (`inputs.case`) | `caseId`, `caseShortId`, `caseTitle`, `caseTenantId`, `casePrimaryStatusName`, `casePrimaryVerdictName`, `casePrimaryVerdictTitle`, `caseFieldChanged(inputs, 'field')`, `caseDetectionEvidence`, `caseComment` |
| `detection*` / `alert*` | a detection record | `detectionId`, `detectionTitle`, `detectionSeverity` (0 to 1), `detectionSeverityNice`, `detectionIPs`, `detectionHostnames`, `detectionUsernames`, `detectionEntity(d, 'key')` |
| `finding*` | an identity finding | `findingSeverity`, `findingIdentityPrimaryUsername`, `findingCheck` |
| `tenant*` | the tenant record | `tenantName`, `tenantHasService`, `tenantIsPartner` |
| `entityValue(inputs, 'key')` | a User Initiated entity | returns a list |
| helpers | | `unique`, `flatten`, `merge`, `append`, `join`, `slice`, `sortBy`, `groupBy`, `toString`, `toTimestamp`, `isIP`, `isPrivateIP`, `ipInNetwork`, `toURLQuery`, `decodeJSON`, `encodeJSON`, `regex.extract`, `format` |

The `detection*` functions take any detection record, not only `inputs`: `detectionIPs(d)` works on each item from `Taegis.GetCaseDetections` (*measured*).

## Quirks worth knowing

| Behavior | Measured result | What to do |
| -------- | --------------- | ---------- |
| `has(x, 'path')` on a JSON null | false, as if missing | fine for guards |
| `x.?field.orValue(d)` on a JSON null | null, not `d` | add `!= null` when a field can be null |
| `string(null)` | `"null"` | check for null first |
| `toString('x')` | `"\"x\""` (adds quotes) | use `string()` for strings |
| `isIP('2001:db8::1')` | true, although the docs say IPv4 | add `!ip.contains(':')` for IPv4 only |
| `isPrivateIP` | true for RFC 1918, loopback, link-local IPv4 | |
| `list.slice(a, b)` past the end | error | `size(l) > n ? l.slice(0, n) : l` |
| `1/0` | error "division by zero" | |
| `size(list[?5])` | error: optional has no size | `.orValue(...)` first |
| a task named `int`, `string`, `map` | every expression fails, "overlapping identifier" | rename |
| a task named `loop`, `if`, `for` | "reserved identifier" wherever it is read | rename |
| run parameters holding `${` | Fusion evaluates them and the call fails | never pass `${` in parameters |

## Identity Findings severities

Severity is a number from 0 to 1. 0.6 and above is high or critical. The dormant account checks share category `DORMANT_RESOURCE`; credential leaks are `CREDENTIAL_LEAK`. Compare categories with `.toLower()` or exact case.

## Writing filters that fire once

An Update event fires for every change. To act once when something happens, test the change, not only the state:

```
casePrimaryStatusName(inputs) == 'closed' && (caseFieldChanged(inputs, 'primaryStatus.id') || caseFieldChanged(inputs, 'primaryStatusId'))
```

`caseFieldChanged` reads `inputs.case.delta.updatedFields` (*measured*).

## Loop guard for execution triggers

A playbook triggered by Playbook Execution events can trigger itself. Guard it:

```
inputs.execution.triggerContext != 'execution'
```
