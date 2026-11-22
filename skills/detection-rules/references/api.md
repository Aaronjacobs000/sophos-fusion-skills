# Rule API calls, and what was measured

All calls go to the Sophos Fusion GraphQL endpoint with the tenant in `X-Tenant-ID`. Detection search, Data Lake Search and the case rule calls are documented. The custom rule calls, the case import and Rule Logs are not. Dates are when a lab tenant last showed each fact.

| Call | Kind | Documented | Used by |
| --- | --- | --- | --- |
| `validateQLFilter(qlFilter: {query}, optionalEventType)` | read | no | `tenant-check`, `install` |
| `searchRules(query: {query, global: true, ruleSources: "WATCHLIST, DETECTOR, DWL"}, page, count)` | read | no | `tenant-check` (Sophos's own rules) |
| `rule(id)`, `rules(page, count, ruleType: QL)`, `detailedRulesCount` | read | no | read-back, `list`, `counts` |
| `createCustomQLRule(input, qlFilter)` | write | no | `install` |
| `enableRule(id)`, `disableRule(id)`, `deleteRule(ruleID, hard)` | write | no | `enable`, `disable`, rollback |
| `createSearch`, `search`, `searchResults` | Data Lake Search | yes | `search-test` |
| `detectionSearch(in: {cql_query, limit, offset})` | read | yes (Detections v2) | `detections` |
| `caseRule(s)`, `caseTemplate(s)`, `createCaseRule`, `updateCaseRule`, `deleteCaseRule`, `deleteCaseTemplate` | case rules | yes (Cases v2) | `case-rule.mjs`, rollback |
| `importInvestigationResources(input: {file})` | write | no | `case-rule.mjs install` |
| `getAllRuleLogs(args: {rule}, pagination)` | read | no | `case-rule.mjs logs` |

## createCustomQLRule

```text
input:    name, description, severity, confidence 0.5, eventType, enabled: false, createAlert: true, attackCategories
qlFilter: { query }
```

- `eventType` is the rule API's `RuleEventType`: the schema ID without `scwx.` (`thirdpartyalert`, `auth`, `nids`), with `management_event` for `scwx.managementevent`. It is not the QL name: `thirdparty` in a query, `thirdpartyalert` here.
- `createAlert` saved as false when it wasn't sent (20/11/2026), so it is always sent as true.
- Any `testShould` or `testShouldNot` value made the save fail: "failed to evaluate test: hyperscan container has not been built, call Build()" (20/11/2026). The same answer came from `validateQLFilter` with test values. So the skill never sends them.
- Read back with `rule(id)`: `enabled` false, `createAlert` true, and the query equal once whitespace is collapsed: the API stores a multi-line query with each run of whitespace as one space (22/11/2026).

## validateQLFilter

- Some refusals come back as GraphQL errors ("ql filter validation failed: this query does not apply to any event type" for an unknown field or `hostname`; "pipeline functions are not supported"), others in the answer's `errors` ("Invalid schema FROM netflow expected nids"; "Invalid enum, severity is 4, expected ..."). The skill reads both and maps each to its rule.
- It passes backreferences and lookarounds in `MATCHES_REGEX` (20/11/2026), so the offline check stays.

## searchRules

- Pages start at 1; page 0 answers as page 1 (22/11/2026).
- A rule names a sensor type in its `filters` (key ending `.sensor_type`, a regex pattern) or in its `qlFilter` query. A rule that names none matches every sensor type on its schema. On 22/11/2026 the lab had 16 global Sophos rules on `thirdpartyalert`, 6 of them on any sensor type.

## Detections

Each custom detection carries the tag `alertRule:<rule id>` and the rule's name as its title. `detections` searches `FROM detection WHERE metadata.creator.rule.rule_id = '<id>'`. In the library's build run each rule fired on its lines within about two minutes; the first copy of one login line made no detection, and the same line sent again did.

## deleteRule

`deleteRule(ruleID, hard: true)` after `disableRule`; when the hard delete errors, a soft delete. A soft-deleted rule reads back with `deleted: true`, which rollback counts as gone. Detections stay.
