# Closed case detection note

When a case closes with a verdict on your list, adds one comment to the case:

> Automated note: CSE00042 closed as Threat Mitigated with 7 detections.

It writes only that comment, inside Sophos Fusion. It calls nothing outside it.

## Trigger

Platform Events, source Case, event Update, with a filter that fires once, on the update that closes the case:

```
casePrimaryStatusName(inputs) == 'closed' && (caseFieldChanged(inputs, 'primaryStatus.id') || caseFieldChanged(inputs, 'primaryStatusId'))
```

The verdict check is a step, not part of the filter, so the outcome message says why a closed case got no note.

## Inputs

| Input | Default |
| ----- | ------- |
| `configuration.verdicts` | `true_positive_malicious`, `true_positive_benign`, `confirmed_security_incident`, `threat_mitigated` |
| `configuration.comment_prefix` | `Automated note` |
| `configuration.internal` | `false` |

Run the Case reference lookup example to see your tenant's verdict names.

## How the count is found

The step `count_detections` asks the case for `detectionsEvidenceCount` (only that field, so the log stays small). If that lookup fails, the count falls back to the evidence list in the event.

## Tested

- Offline and tenant DSL checks pass.
- 15 CEL cases pass in Fusion's engine against `sample-event.json`, a made-up case event shaped from the platform's CaseEvent schema.
- Run live on 21/11/2026 on a test tenant, as a `ZZTest_` copy on a platform instance whose filter also named one test case. Reopening the case started no run. Closing it as Threat Mitigated started one run within a second. The run ended Completed with outcome SUCCESS and added one comment, `Automated note: <case ID> closed as Threat Mitigated with 0 detections.` The case had no detection evidence, and the count came from the case lookup.
- The execution log keeps the trigger event, and the event names whoever changed the case. In the test that was the API credential the scripts use, so `run.mjs diagnose` flagged its client ID as secret-looking. The secret itself was not in the log.

## Deploy

Import it as a test copy and create a disabled platform instance with the deployment skill. Enable it only on a tenant where an extra comment on closed cases is fine.
