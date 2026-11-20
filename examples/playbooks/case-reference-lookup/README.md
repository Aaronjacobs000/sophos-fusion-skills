# Case reference lookup

Lists the case types, primary statuses, and closing verdicts a tenant uses. Read-only.

## Why

Verdict names differ between tenants. MDR tenants close cases as `true_positive_malicious` and `true_positive_benign`; XDR tenants use names such as `threat_mitigated` and `confirmed_security_incident`. A trigger filter with the wrong name never fires. Run this once per tenant and copy `closed_verdict_names` into your filters and inputs.

## What it calls

Three read actions on the platform `Taegis.Case` connection: `getTypes`, `getPrimaryStatuses`, and `getPrimaryVerdicts` (for the closed status). Nothing is changed. The execution log keeps the responses, which hold only reference data.

## Try it

```bash
V=skills/validation/scripts/validate.mjs; D=skills/deployment/scripts; R=skills/execution/scripts/run.mjs
node $V offline examples/playbooks/case-reference-lookup/template.yaml
node $V tenant  examples/playbooks/case-reference-lookup/template.yaml --profile lab
node $V cel     examples/playbooks/case-reference-lookup/cel-cases.json --profile lab

# Each of these is a write: approve each one
node $D/deploy.mjs import examples/playbooks/case-reference-lookup/template.yaml --profile lab --yes
node $D/deploy.mjs instance-create --template ZZTest_CaseReferenceLookup --name "ZZ Test case reference lookup" --trigger generic --profile lab --yes
node $D/deploy.mjs enable --instance <id> --profile lab --yes
node $R execute --instance <id> --watch --profile lab --yes
node $D/ledger.mjs rollback --profile lab --yes
```

A run on a test tenant ended Completed, SUCCESS, "Found 4 case types, 5 statuses, and 7 closing verdicts" (21/11/2026).

## Notes

- `source` in the outputs is written in YAML single quotes, so Fusion returns it as literal text. The live run confirmed that.
- The verdict lookup has a condition, so every read of it is guarded with `.?outputs...orValue([])`.
- The template offers Generic Trigger usage Other and usage Schedule, so it can run on a schedule as well.
