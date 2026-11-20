# The connector format

A connector is one YAML file with `kind: Connector`. The example in `examples/connectors/first-epss/` is a complete one.

## Top-level fields

| Field | Required | Notes |
| ----- | -------- | ----- |
| `apiVersion` | yes | `v0.0.1` |
| `kind` | yes | `Connector` |
| `name` | yes | Letters, digits, underscores, in dot-separated parts. Not `Taegis.` |
| `version` | yes | Semantic version |
| `title`, `description` | yes | |
| `documentation` | recommended | Markdown. Include a "Hosts" section listing every host called |
| `method` | yes | `http` for custom connectors |
| `authTypes` | yes | One or more of: None, APIKey, Basic, OAuthClientCreds, OAuthPassword, OAuthJWT, Raw, Custom, and others Fusion lists |
| `authDefaults` | no | Prefills the connection form, for example `apiKeyAuth: {header: Authorization, value: "Bearer <API-Key>"}` |
| `parameters` | no | JSON Schema of connection settings (a base URL, a region). Read as `config.<name>` |
| `actions` | yes | The calls |
| `vendorName`, `vendorProduct`, `vendorVersion` | no | Console grouping |
| `tags`, `categories` | no | |

## An action

```yaml
    - name: getScores
      description: One line
      inputs:                       # JSON Schema of what playbooks pass
        type: object
        required: [cves]
        properties:
            cves: { type: array, items: { type: string } }
      outputs:                      # JSON Schema of what playbooks get back
        type: object
        properties:
            scores: { type: array }
      config:
        method: GET                 # GET, POST, PUT, PATCH, DELETE
        url: "https://api.example.org/v1/items?id=${inputs.id.toURLQuery()}"
        contentType: application/json
        headers:
            - name: Accept
              value: application/json
        body: "${encodeJSON({'q': inputs.q})}"          # for POST, PUT, PATCH
        error: "${status.code == 200 ? '' : 'API answered ' + string(status.code)}"
        outputs:
            scores: "${body.?data.orValue([])}"
```

Other `config` keys Sophos's connectors use: `httpParameters` (query parameters as a map), `query` and `variables` (for GraphQL APIs), `retries` (`{max-count, max-wait}`).

## Templates in config

Every string in `config` is literal text unless it holds `${...}`. Each `${...}` is CEL and can read:

| Name | Holds |
| ---- | ----- |
| `inputs` | the action inputs from the playbook |
| `config` | the connection's parameters |
| `status` | the response status, `status.code` |
| `body` | the parsed response body |
| `headers` | the response headers |
| `auth` | auth values (Sophos connectors only) |
| `TDR` | platform values: `TDR.API`, `TDR.tenant` |

Keep braces out of strings inside `${...}`, for example in regular expressions: write `[0-9]+` rather than `[0-9]{4}`.

`cel.bind(name, value, expr)` helps when a value is used twice:

```
${cel.bind(ids, inputs.cves.filter(c, c.matches('^CVE-[0-9]+-[0-9]+$')), ids.slice(0, size(ids) > 100 ? 100 : size(ids)).join(','))}
```

## The validate action

Name one action `validate`. Fusion runs it when someone tests a connection in the console, and `validateConnectionInput` runs it before a connection is created. Make it a cheap read that proves the host and the credentials work, and return `outcome`.

## Connections

A connection is created from a connector with an `authType`, `config` (parameter values), and `credentials`.

- `None` takes no credentials. The example connector uses it.
- `OAuthClientCreds` takes `clientId`, `clientSecret`, and `scopes` in `credentials`, plus `authUrl` on the connection. This shape works with Sophos's own API connectors.
- Other auth types take fields shaped like the connector's `authDefaults` (`apiKeyAuth`, `basicAuth`, and so on). The tested path in this plugin is `None`; check another type's field names against the console's connection form before relying on them.

The deployment script reads credential values from environment variables (`--credentials-env apiKey=ACME_API_KEY`), never from arguments.

## What the validator checks

https only; every literal host declared in the documentation; URLs from parameters use declared parameters; templates parse; no fixed Authorization or API key headers; known auth types; unique action names; a validate action.
