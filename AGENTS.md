# AGENTS.md

Guide for any coding agent working with this repository, whether you are using the skills or changing them.

## About this repository

Seven agent skills for Sophos Fusion automation, plus the Node scripts they call. The scripts talk to the Sophos Fusion GraphQL API with the user's Sophos API credential. There is no MCP server and nothing to install: Node 22 or later runs everything.

Start with `skills/playbooks/SKILL.md`. It routes to the other six.

| Skill | Scripts |
| ----- | ------- |
| `playbooks` | none (it routes) |
| `setup` | `skills/setup/scripts/profile.mjs` |
| `authoring` | `skills/authoring/scripts/catalog.mjs`, `scaffold.mjs` |
| `connectors` | `skills/connectors/scripts/connector.mjs` |
| `validation` | `skills/validation/scripts/validate.mjs` |
| `deployment` | `skills/deployment/scripts/deploy.mjs`, `ledger.mjs` |
| `execution` | `skills/execution/scripts/run.mjs` |

Skill files write paths as `${CLAUDE_SKILL_DIR}` (the folder holding that SKILL.md) and `${CLAUDE_PLUGIN_ROOT}` (the repository root). Claude Code fills these in. In other assistants, read them as those two folders.

## Rules when using the skills

1. **Ask before every write.** Imports, connections, instances, filters, schedules, enable, publish, delete, rollback, playbook runs, connector action tests, and connection checks all change a tenant or make Fusion call a vendor. Describe the write, wait for the user to approve that one, then add `--yes`. On a production profile, name the tenant first and add `--production` too. Scripts refuse writes without these flags (exit 3) and send nothing.
2. **Never handle a client secret in chat.** The user enters it in their own terminal (`profile.mjs add --prompt`), an environment variable, or a 1Password `op://` reference.
3. **Keep secrets and personal data out of run parameters and connector test inputs.** Fusion keeps execution logs, request and response bodies included, permanently.
4. **Test on a test tenant, with test copies.** Imports default to `ZZTest_` copies; instances are created disabled; rollback removes a ledger run.
5. **No response actions in tests** unless the user asks for one by name. Response playbooks run with `dry_run` on.

## Script conventions

- Every script has `--help`, and every command has `<command> --help`.
- stdout is JSON only: `{"ok": true, "command": "...", ...}` or `{"ok": false, "error": {"code", "message"}}`. Messages go to stderr.
- Exit codes: 0 ok, 1 failed, 2 usage, 3 write refused by the gate.
- Credentials: `--profile <name>`, or `SOPHOS_FUSION_CLIENT_ID` and `SOPHOS_FUSION_CLIENT_SECRET`. Partner and organization credentials also need `--tenant <uuid>` or a profile tenant.

## Working on the code

```
lib/            shared modules: HTTP safety, retries, auth, GraphQL, CLI frame, ledger,
                CEL parser, dsl walker, offline rules, tenant check, CEL cases, diagnosis
skills/*/       SKILL.md, scripts/, references/
examples/       three playbooks and one connector, each with a README and CEL cases
test/           node:test suites, fixtures, a scripted fetch mock
tools/          manifest check and the live smoke test
vendor/yaml/    the yaml 2.9.1 parser (ISC), unmodified
```

- Node 22+, ES modules, no runtime dependencies. Do not add an npm dependency; vendor a permissively licensed one under `vendor/` with its license if you must.
- Tests: `node --test`. They mock fetch and need no credentials. Add tests with every change.
- Offline checks of the examples: `node skills/validation/scripts/validate.mjs all examples`.
- Manifests: `node tools/check-manifests.mjs`.
- Safety lives in the scripts, not in hooks. Keep it there: the `--yes` and `--production` gate in `lib/cli.mjs`, the host allowlist and redirect refusal in `lib/http.mjs`, the no-retry rule for writes in `lib/retry.mjs`, redaction in `lib/redact.mjs`.
- Only Sophos hosts are called: `id.sophos.com`, `api.central.sophos.com`, `api-<region>.central.sophos.com`, `api.taegis.sophos.com`. Do not widen the allowlist.
- Writing style for docs: US spelling, the Oxford comma, short sentences, no em dashes, lead with what the reader does.

## Live testing

`tools/live-smoke.mjs` runs a full cycle against a real tenant: catalog reads, tenant validation of every example, CEL cases, test-copy imports and export diffs, a disabled instance, one lookup-only run, a paused schedule, a connector test against a public API, and rollback, with object counts before and after. It needs a test profile and `--yes`, and never runs in CI.
