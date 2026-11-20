# Interfaces

An interface is a contract with several implementations. Sophos ships interfaces such as `Taegis.BlockIP`, `Taegis.IsolateHost`, `Taegis.DisableUser`, `Taegis.RevokeUserSessions`, and `Taegis.SendNotificationMessage`, with one implementation per vendor (Sophos Firewall, Microsoft Teams, and so on). List them with `catalog.mjs interfaces`.

## Calling one

```yaml
interfaces:
    - Taegis.SendNotificationMessage:1.1.1
dsl:
    tasks:
        - name: notify
          call: Taegis.SendNotificationMessage
          nolog: true
          inputs:
            message: "'Case closed'"
```

- Declare it in `interfaces`, or Fusion's validator errors: "missing from required interfaces".
- The configured playbook chooses the implementations and their connections. An instance cannot be saved without that binding.
- The call runs inline. It creates no separate execution record.
- The outputs are a list, one entry per implementation: `{playbook, playbook_title, playbook_version, connections, outputs: {success, message, error}}`.
- `nolog: true` on the call also drops the link to the implementation's log. Use it when the implementation posts to a webhook URL, which Sophos's notification implementations do.

## When to use one

Use an interface when the same playbook should work across vendors the customer chooses. Use a direct `action:` when the playbook targets one product.

## Binding in an instance

The deployment script takes interface bindings as JSON:

```bash
node deploy.mjs instance-create ... --interfaces '[{"interface":"<interface id>","version":"<version id>","playbook":"<implementation version id>","connections":["<connection id>"]}]'
```

Get the IDs from `catalog.mjs interfaces` and `deploy.mjs list --kind connections`.
