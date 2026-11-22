# Changelog

All notable changes to this project are listed here. Versions follow semantic versioning.

## 0.2.0 (2026-11-22)

Two new skills, for Sophos NG-SIEM custom parsers and the detection rules that use them.

- `parsers`: sample lines go into a private workspace outside any repository and are masked before the agent reads them. `parser.mjs` drafts a parser with the library's generator, checks it offline on the vendored emulator (lint, every line, `expected.json`), then read-only in the tenant's own engine (`parserSchemas`, `validateParser`, built-in parsers that already take the lines, and every line engine against emulator, field by field). `install` creates the parsers disabled as `ZZTest_` copies, parent first, and sends the code again with `updateParser`, because `createParser` saves the console's template instead. `enable` is its own write and needs a passing tenant check on the same code within 24 hours. `verify-ingest` reruns the parsers on real Data Lake records and compares fields. `contribute` builds a library entry from new synthetic samples and refuses lines copied from the user's.
- `detection-rules`: `rules.mjs` scaffolds a rule set for a parser folder, checks it offline on the parser's own samples (fields, enums, regex limits, the sensor type pin, no IOC-only rules, and `tests.json`), runs `validateQLFilter` and reads Sophos's own rules on the schema, search-tests each query in Data Lake against the rules run offline on the same records with matches per day, installs rules off as `ZZ Test` copies with `createAlert` on, and enables one rule at a time under a 1,000-a-day volume check. `case-rule.mjs` scaffolds and checks an automatic case rule for the set, installs it in Test state (import, then one more save), reads its Rule Logs, and sets Enabled or Test as their own writes.
- The ledger has four new kinds: `parser`, `detectionRule`, `caseRule` and `caseTemplate`. Rollback deletes a case rule before its template and both before the detection rules, disables parsers and rules before deleting them, and deletes child parsers before their parent. A parser counts as gone only when a parser list read without error lacks it.
- `lib/search.mjs` runs Data Lake searches. `createSearch` needs no `--yes` (it changes no configuration) and is never sent twice for one search.
- The library's `studio/core` and `studio/app/plan.js` are vendored unmodified in `vendor/xdr-siem-library`, pinned to library commit 343762c, with a sha256 per file in `VENDORED.md`. `tools/sync-library.mjs` re-syncs them from a clone, `tools/check-vendor.mjs` checks the hashes in CI, and a weekly workflow fails when the library's main branch differs.
- Examples: the library's OpenCanary parsers (with a `test-confirms.json` for the flattened child), its four OpenCanary detection rules, and its one-case-per-source-IP case rule.
- `validate.mjs all` also checks parser and rule folders. `profile.mjs test` reports whether custom parsers and rules can be read. `tools/live-smoke.mjs --suite parsers|rules` runs the new cycles on a test tenant.
- String options take values that start with a dash, so `--earliest -7d` works as well as `--earliest=-7d`.

### Other changes since 0.1.0

- CI runs on Ubuntu while the repository is private and adds macOS and Windows once it is public. A manual run with `full_matrix` set adds them sooner.
- Windows: profile and ledger writes retry a rename that Windows refuses while another process holds the file, and the ledger lock waits while Windows finishes removing the old lock folder. Files saved with CRLF line endings validate the same as LF files, and `.gitattributes` checks text files out with LF.
- Tests run on Windows: the mocked fetch and the lock test import by file URL, the 1Password stub is node with a preload instead of a `#!` script, and the 0600 mode check is skipped where Windows has no POSIX modes.
- The README shows the Sophos logo, with the white version in dark mode. The Claude Code, Codex, and Cursor manifests name an icon: a square PNG of the Sophos brandmark, with transparent padding, for Claude Code, and the brandmark SVG for Codex and Cursor. `tools/check-manifests.mjs` checks that each icon file exists and fits its format.
- The Closed case detection note example ran live on a test case: one run and one comment, with the template and instance removed afterward.
- `run.mjs logs` and `diagnose` list the API client ID apart, as an identifier, when an event in the log carries it, for example as a case's creator. Output shows it as `[client ID]`. Real secrets are still flagged wherever they sit.
- Redaction also covers object keys, and registered values are replaced longest first, so one inside another can't leave part of it showing.
- `run.mjs diagnose` reads the log of a run whose instance and template were deleted. Fusion answers "record not found" for such a run but keeps its log, and diagnose used to stop at "No execution with that ID", skipping the log and its secret check.
- `profile.mjs add --prompt` ends at the first line, so a pasted secret that includes the Enter keystroke no longer keeps a trailing return or waits for a second Enter.
- Ctrl-C at that prompt now exits. It used to print "Canceled" and then hang, because the terminal was left reading.
- `tools/check-manifests.mjs` reads JPEG icon sizes, so a valid square JPEG icon for Claude Code passes. Formats it can't read, such as GIF or WebP, are named in the problem.
- It also reads an SVG `viewBox` written in single quotes or with spaces around `=`, which it used to report as unreadable.
- The CEL reference had `isCaseClosed(inputs)` wrong. Measured on a real close event, it reads only `case.primaryStatus.isClosed`, so it is true on real events and false on test events that leave that field out. The example's sample event now carries it.
- The README gives the Windows route for linking the skills: directory junctions from Command Prompt, because Git Bash's `ln -s` makes copies and a copied skill can't load the shared `lib/` code.
- On Windows the ledger is kept in `%LOCALAPPDATA%\sophos-fusion-skills`, the usual place for per-user state, instead of `%USERPROFILE%\.local\state\sophos-fusion-skills`. macOS and Linux are unchanged, and `SOPHOS_FUSION_STATE_DIR` still moves it everywhere.
- `run.mjs cancel` returns a `canceled` key instead of `cancelled`, to match Fusion's own spelling.
- The setup docs and the self-test point to the API Credentials page in Sophos Fusion.

## 0.1.0 (2026-11-21)

First release.

- Seven skills: `playbooks` (routing), `setup`, `authoring`, `connectors`, `validation`, `deployment`, and `execution`.
- Node 22 scripts with no install step: profiles and self-test, tenant catalog lookups, playbook and connector scaffolds, offline validation, the tenant DSL check, CEL cases in Fusion's engine, imports with export-and-diff, connections, disabled instances, filters, paused schedules, enable and publish, a ledger with rollback, playbook runs with log reading and diagnosis, and live connector action tests.
- Safety in the scripts: `--yes` on every write, `--production` on production profiles, test copies by default, disabled instances, read-back after every write, no retry of writes after a 5xx or timeout, a Sophos host allowlist, refused redirects, and redaction.
- Examples: Case reference lookup (lookup, Generic Trigger), Closed case detection note (notify, case events), Block case IPs on Sophos Firewall (response, User Initiated, dry run on), and a FIRST EPSS connector.
- Packaging for Claude Code (tested), Codex, Cursor, GitHub Copilot, Gemini, and the Agent Plugins format (untested).
- Review fixes before release: an env var tenant override now needs `--production` like `--tenant`, an `--allow-existing` import can't ledger a connector that was already there, the dry-run rule requires a term that turns dry run off, `deploy diff --prefix` applies the prefix, and bad numeric flags are usage errors.
