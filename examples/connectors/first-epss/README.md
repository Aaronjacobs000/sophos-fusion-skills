# FIRST EPSS connector

Exploit Prediction Scoring System scores for CVE IDs, from the public FIRST API at api.first.org. No key, no personal data.

## Actions

| Action | Inputs | Outputs |
| ------ | ------ | ------- |
| `validate` | none | `outcome` |
| `getScores` | `cves` (up to 100) | `scores` [{cve, epss, percentile, date}], `total`, `outcome` |
| `getScoresOnDate` | `cves`, `date` (YYYY-MM-DD) | the same, as published on that date |

Inputs are cleaned before they reach the URL: trimmed, upper-cased, kept only if shaped like a CVE ID, capped at 100.

## Use it in a playbook

```yaml
connectors:
    - FirstEpss:1.0.0
dsl:
    tasks:
        - name: epss
          action: FirstEpss.getScores
          inputs:
            cves: "['CVE-2021-44228']"
```

## Tested live (21/11/2026)

On a test tenant, as `ZZTest_FirstEpss` with a connection of auth type None:

- `getScores` for CVE-2021-44228 returned EPSS 0.99999, percentile 1.
- `validate` returned success, and so did the connection check (`validateConnectionInput`).
- `verify` ran `getScoresOnDate` from the local file for CVE-2023-4863 on 2026-11-01 and returned 0.99979.

The connection and connector were then rolled back and read back as gone.

## Try it

```bash
D=skills/deployment/scripts
node $D/ledger.mjs start --label "EPSS test" --profile lab
node $D/deploy.mjs import examples/connectors/first-epss/connector.yaml --profile lab --yes
node $D/deploy.mjs connection-create --connector ZZTest_FirstEpss --name "ZZ Test FIRST EPSS" --auth-type None --profile lab --yes
node skills/connectors/scripts/connector.mjs test-action --connection <id> --action getScores --inputs '{"cves":["CVE-2021-44228"]}' --profile lab --yes
node $D/ledger.mjs rollback --profile lab --yes
```

EPSS data is published by FIRST (https://www.first.org/epss). Check its terms before production use.
