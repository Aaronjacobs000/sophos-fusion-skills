# Changelog

All notable changes to this project are listed here. Versions follow semantic versioning.

## 0.1.0 (2026-11-21)

First release.

- Seven skills: `playbooks` (routing), `setup`, `authoring`, `connectors`, `validation`, `deployment`, and `execution`.
- Node 22 scripts with no install step: profiles and self-test, tenant catalog lookups, playbook and connector scaffolds, offline validation, the tenant DSL check, CEL cases in Fusion's engine, imports with export-and-diff, connections, disabled instances, filters, paused schedules, enable and publish, a ledger with rollback, playbook runs with log reading and diagnosis, and live connector action tests.
- Safety in the scripts: `--yes` on every write, `--production` on production profiles, test copies by default, disabled instances, read-back after every write, no retry of writes after a 5xx or timeout, a Sophos host allowlist, refused redirects, and redaction.
- Examples: Case reference lookup (lookup, Generic Trigger), Closed case detection note (notify, case events), Block case IPs on Sophos Firewall (response, User Initiated, dry run on), and a FIRST EPSS connector.
- Packaging for Claude Code (tested), Codex, Cursor, GitHub Copilot, Gemini, and the Agent Plugins format (untested).
