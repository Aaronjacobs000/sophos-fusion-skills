# Calling connectors from a playbook

## The task

```yaml
        - name: add_note
          condition: check.variables.matches
          action: Taegis.Case.addComment
          retry: 2
          inputs:
            tenant_id: caseTenantId(inputs)
            caseId: caseId(inputs)
            comment: "'Reviewed by automation'"
```

- `action` is `Connector.actionName`. The connector name can hold dots (`Taegis.Case`); the last part is the action.
- Declare the connector in the template: `connectors: [Taegis.Case:1.0.5]`. Get the exact line from `catalog.mjs connector --name Taegis.Case` (`dependencyEntry`).
- Results are in `add_note.outputs`, shaped by the action's output schema.
- `retry` only works on action tasks.

`Taegis.Secureworks` (the summarize action) is available to every playbook without a connectors entry.

## Inputs Fusion does not check

Fusion's validator accepts any action name on a known connector, and any input name. A wrong one fails at run time. The tenant check in the validation skill looks each action up and compares the inputs with the action's schema and with the inputs its config reads.

Platform actions read some inputs they do not declare. Most Sophos platform actions take `tenant_id` this way and fall back to `TDR.tenant`. Pass `caseTenantId(inputs)` or the event's tenant so partner-level events act on the right tenant.

## Connections

A connection holds the credentials and settings for one connector. An instance binds the connections its template needs (`connections: [id, ...]`). Platform connectors (Taegis.Case, Taegis.Alert, Taegis.SophosFirewall, and so on) usually have one connection already, created by the platform. Third-party connectors need a connection made with the vendor's credentials.

The deployment script binds the only connection of each connector automatically and asks when there are several.

## What the execution log keeps

For every successful connector call, Fusion's execution log keeps the request URL, the request body, and the response body. Request headers are not kept, so a connection's stored credentials are safe. Deleting the instance or template does not delete its logs, and the API cannot delete them.

So a step whose URL, body, or response carries a secret (a password, a token, a signed URL, a webhook address) needs `nolog: true`. Later steps still read its outputs. The offline validator flags steps that look secret-bearing without it.

## Mocks do not intercept

Connections accept `useMock` and `mocks`, but in a playbook run the real vendor API is called anyway. Do not rely on mocks for a safe test. Use `dry_run` and lookup-only actions.
