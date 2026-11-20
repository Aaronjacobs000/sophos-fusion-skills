---
name: connectors
description: Write a custom Sophos Fusion connector (connector.yaml) when no connector on the tenant covers a vendor API, then test one action live. Use when a playbook needs an HTTP API that catalog search does not find, or someone asks to build, fix, or test a Fusion connector. Covers auth types, actions, CEL output mapping, declared hosts, a connection, and one live action call.
license: MIT
---

# Connectors: a custom HTTP connector

Scripts live in `${CLAUDE_SKILL_DIR}/scripts/`. The connector format is in [connector-dsl.md](references/connector-dsl.md). If those paths show literally, they mean the folders next to this file. The deployment and validation scripts are in the sibling skill folders (`${CLAUDE_PLUGIN_ROOT}/skills/<skill>/scripts/`, or two levels up from here).

## 1. Make sure you need one

Search first. Sophos ships about 86 connectors, including a generic HTTP fetch and webhook.

```bash
node ${CLAUDE_PLUGIN_ROOT}/skills/authoring/scripts/catalog.mjs connectors --search "<what the API does>"
```

Write a connector only when nothing fits. Reuse is safer and supported.

## 2. Read the vendor's API docs

Note for each call: method, URL, query and body, auth (none, API key header, basic, OAuth client credentials), the response fields you need, and the status codes that mean success. Note every host the connector will call.

## 3. Start from a skeleton

```bash
node ${CLAUDE_SKILL_DIR}/scripts/connector.mjs scaffold --name Acme_Inventory --title "Acme inventory" \
  --base-url https://api.acme.example/v2 --auth APIKey --out ./acme-inventory/connector.yaml
```

The skeleton validates as written: a `validate` action (Fusion runs it to check a connection), one GET action, a Hosts section in the documentation, and output mapping.

## 4. Write the actions

- One action per API call. Name them `getThing`, `listThings`, `createThing`.
- Declare inputs as JSON Schema, with `required`.
- Build the URL from a fixed `https://` host. A URL from a connection parameter (`${config.base_url}/...`) is fine when the customer's host varies; declare that parameter.
- Map outputs with templates over `status`, `body`, and `headers`: `outcome: "${status.code == 200 ? 'success' : 'failure'}"`.
- Set `error` to an empty string on success and a message otherwise.
- Clean inputs before they reach a URL: filter, trim, cap list sizes. See the example connector.
- Credentials belong in the connection, never in the connector. Use `authTypes` and `authDefaults`.
- List every host in a "Hosts" section of `documentation`. The validator checks this.
- Say in `documentation` what requests send and what responses return. Fusion logs successful calls' URLs and bodies permanently, so a playbook calling an action that returns secrets needs `nolog: true` on that step.

## 5. Validate offline

```bash
node ${CLAUDE_PLUGIN_ROOT}/skills/validation/scripts/validate.mjs offline ./acme-inventory/connector.yaml
```

## 6. Test one action live (each step needs approval)

Use a test profile. Each command below is a write: say what it does, get a yes for it, then add `--yes`.

```bash
D=${CLAUDE_PLUGIN_ROOT}/skills/deployment/scripts
node $D/ledger.mjs start --label "Acme connector test"
node $D/deploy.mjs import ./acme-inventory/connector.yaml --yes          # imports ZZTest_Acme_Inventory
node $D/deploy.mjs connection-create --connector ZZTest_Acme_Inventory --name "ZZ Test Acme" \
  --auth-type APIKey --credentials-env <field>=ACME_API_KEY --yes          # value from an env var; field names in connector-dsl.md
node ${CLAUDE_SKILL_DIR}/scripts/connector.mjs test-action --connection <id> --action getThing --inputs '{"id":"123"}' --yes
node $D/ledger.mjs rollback --yes                                         # removes the connection, then the connector
```

`test-action` runs the action exactly as imported. To try an edited action before importing a new version, use `verify` with the local file and the existing connection:

```bash
node ${CLAUDE_SKILL_DIR}/scripts/connector.mjs verify ./acme-inventory/connector.yaml --connection <id> --action getThing --inputs '{"id":"123"}' --yes
```

Both calls reach the vendor for real. Test with harmless values: a public record, a read-only call. Never send a secret or personal data as an action input.

The connection check (`validate.mjs connection`) runs the connector's `validate` action against the vendor, so it is a write too.

## 7. Hand over

Give the `authoring` skill the connector name, version, and actions. Templates list it as `ZZTest_Acme_Inventory:1.0.0` while testing; the deployment script maps a template's custom connectors to their test copies on import.
