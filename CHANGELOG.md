# Changelog

All notable changes to this project are listed here. Versions follow semantic versioning.

## Unreleased

- CI runs on Ubuntu while the repository is private and adds macOS and Windows once it is public. A manual run with `full_matrix` set adds them sooner.
- Windows: profile and ledger writes retry a rename that Windows refuses while another process holds the file, and the ledger lock waits while Windows finishes removing the old lock folder. Files saved with CRLF line endings validate the same as LF files, and `.gitattributes` checks text files out with LF.
- Tests run on Windows: the mocked fetch and the lock test import by file URL, the 1Password stub is node with a preload instead of a `#!` script, and the 0600 mode check is skipped where Windows has no POSIX modes.
- The README shows the Sophos logo, with the white version in dark mode. The Claude Code, Codex, and Cursor manifests name an icon: a square PNG of the Sophos brandmark, with transparent padding, for Claude Code, and the brandmark SVG for Codex and Cursor. `tools/check-manifests.mjs` checks that each icon file exists and fits its format.
- The Closed case detection note example ran live on a test case: one run and one comment, with the template and instance removed afterward.
- `run.mjs logs` and `diagnose` list the API client ID apart, as an identifier, when an event in the log carries it, for example as a case's creator. Output shows it as `[client ID]`. Real secrets are still flagged wherever they sit.

## 0.1.0 (2026-11-21)

First release.

- Seven skills: `playbooks` (routing), `setup`, `authoring`, `connectors`, `validation`, `deployment`, and `execution`.
- Node 22 scripts with no install step: profiles and self-test, tenant catalog lookups, playbook and connector scaffolds, offline validation, the tenant DSL check, CEL cases in Fusion's engine, imports with export-and-diff, connections, disabled instances, filters, paused schedules, enable and publish, a ledger with rollback, playbook runs with log reading and diagnosis, and live connector action tests.
- Safety in the scripts: `--yes` on every write, `--production` on production profiles, test copies by default, disabled instances, read-back after every write, no retry of writes after a 5xx or timeout, a Sophos host allowlist, refused redirects, and redaction.
- Examples: Case reference lookup (lookup, Generic Trigger), Closed case detection note (notify, case events), Block case IPs on Sophos Firewall (response, User Initiated, dry run on), and a FIRST EPSS connector.
- Packaging for Claude Code (tested), Codex, Cursor, GitHub Copilot, Gemini, and the Agent Plugins format (untested).
- Review fixes before release: an env var tenant override now needs `--production` like `--tenant`, an `--allow-existing` import can't ledger a connector that was already there, the dry-run rule requires a term that turns dry run off, `deploy diff --prefix` applies the prefix, and bad numeric flags are usage errors.
