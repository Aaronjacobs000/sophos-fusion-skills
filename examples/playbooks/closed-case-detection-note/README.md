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
- Not run live: a live run would comment on a real case. The filter and payload were tested with synthetic events only, so check the first real close on a test case before relying on it.

## Deploy

Import it as a test copy and create a disabled platform instance with the deployment skill. Enable it only on a tenant where an extra comment on closed cases is fine.
