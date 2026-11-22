---
name: parsers
description: Build a custom parser for Sophos NG-SIEM in Sophos Fusion from a customer's sample log lines, test it offline and in the tenant's own engine, install it off, turn it on, and confirm it on real ingest. Use when someone wants to parse, normalize, or map a log source Sophos doesn't parse (a custom parser, a parent and child parsers, CEF, LEEF, JSON, key=value, syslog, XML), check why lines stay generic, or share a parser with the Unofficial Sophos Fusion XDR and SIEM Library. Samples are masked and stay on the machine.
license: MIT
---

# Parsers: samples to a parser running in the tenant

Scripts live in `${CLAUDE_SKILL_DIR}/scripts/`. If that shows literally, it means the folder next to this file. The parser language is in [syntax.md](references/syntax.md), the API calls and what was measured in [api.md](references/api.md), and how the tests work in [testing.md](references/testing.md).

```bash
PS=${CLAUDE_SKILL_DIR}/scripts/parser.mjs
```

The parser API is undocumented. Every write is read back, and the engine in the tenant, not the emulator, is the authority.

## Samples stay on the machine

- Ask for a file of sample lines. If the person pastes lines into the chat, say they skip masking and ask for a file instead.
- `samples add` copies them into a private workspace (outside any repository) and writes a masked copy. Read only `masked.log`. Never read `raw.log`, and never print a sample value.
- Masking swaps addresses for documentation ones (192.0.2.x, 2001:db8::), emails for `userN@example.com`, host and user names for `hostN` and `userN`, MAC addresses, and secrets and long tokens. Keys, structure, times and event codes stay. Masking turns private addresses into documentation ones, so logic that tests for RFC 1918 behaves differently on masked lines; `verify-ingest` on real records catches that.
- `--raw` keeps the lines unmasked. Use it only when the person asks.

```bash
node $PS samples add acme.log                      # prints the workspace, line count, format guess, masked counts
node $PS samples from-tenant --where "original_data contains 'Acme'" --earliest -24h   # read-only Data Lake search of generic records
```

## The usual path

```bash
node $PS scaffold --samples <workspace>/masked.log --vendor Acme --product EdgeWall --out ~/parsers/acme-edgewall
node $PS check ~/parsers/acme-edgewall                 # lint, emulator, expected.json, fields per line
node $PS tenant-check ~/parsers/acme-edgewall          # read-only, in the tenant's engine
node $PS install ~/parsers/acme-edgewall --yes         # ZZTest_ copies, disabled
node $PS enable --id <parent id> --yes                 # its own approval; parents first
node $PS enable --id <child id> --yes
node $PS verify-ingest ~/parsers/acme-edgewall --source-where "original_data contains 'Acme'"
```

Keep the parser folder outside any repository: its `samples.log` holds the masked lines.

### 1. Scaffold

`scaffold` runs the library's generator on the masked lines. It writes a standalone parser, or a parent plus one child per event type when event types go to different schemas, in the library's layout: `meta.json`, `<NAME>.parser.txt`, `samples.log`, `expected.json`. Pass `--schema scwx.auth` (or another) to force a standalone parser's schema.

### 2. Edit and check

Edit the parsers with [syntax.md](references/syntax.md). `check` lints them, runs every line in the emulator, and reports per line the parser path, the schema, the fields set, and enum fields by member name. `blocked 1` means NotBlocked on the HTTP schema, so read enums by name.

- `!SAMPLE=` lines must be lines of `samples.log`, so no unmasked line reaches the tenant's parser code.
- Each child needs a line in `test-confirms.json`: a PATTERN regex (RE2) that matches exactly the lines the child takes. The tenant's test call runs one unsaved parser, so tenant-check runs each child flattened with its parent under that pattern. `check` proves the pattern picks the same lines as the child's own confirm.
- `expected` rewrites `expected.json` from the emulator. Read the diff after.

Gate: `check` reports 0 errors.

### 3. Tenant check (read-only)

`tenant-check` saves nothing. It:

- reads `parserSchemas`: a schema the tenant lacks is an error, one the vendored schema data lacks is a warning;
- lists existing parsers, and name clashes with the folder's parsers or their `ZZTest_` copies;
- runs `validateParser` on every script, children alone and flattened;
- runs `sampleParser` with no parser of ours, to see whether a built-in parser takes the lines already. If one does, say so and stop unless the person wants a parser anyway;
- runs every line through the script the emulator says takes it, and compares the engine's record with the emulator's field by field. A line another parser took runs again, up to `--retries` times.

`--library <clone>` also names library entries that claim the lines in the emulator. `--show-values` prints the differing values; leave it off unless the person asks.

Gate: `ok: true`, every line `routeOk`, and every entry under `differences` explained to the person. A pass is recorded, and `enable` needs one on the same code within 24 hours.

### 4. Install, then enable

`install` creates each parser disabled, parent first, as a `ZZTest_` copy unless `--as-is`. `createParser` saves the console's new-parser template instead of the code sent, so install sends the code with `updateParser` while the parser is disabled and reads it back byte for byte. If it still differs, install deletes the parser and fails. Every parser goes in the ledger the moment it has an ID.

`enable` is its own write and its own approval. Before asking, tell the person:

- matching lines are normalized differently, tenant-wide, at once;
- generic events continue;
- Sophos detectors (IP and Domain Watchlist, DGA, and Sophos rules that match any sensor type on the schema) start running on the new records;
- on a tenant Sophos MDR monitors, the MDR team works those detections, so tell them first.

`enable` refuses a parser whose live code differs from the local file or from what install saved, one with no passing tenant-check on that code, and a child whose parent is still disabled. `disable` refuses a parent with enabled children.

`update-code <folder> --id <n> --yes` sends a disabled, ledger-owned parser's code again. Run tenant-check again after it.

### 5. Confirm on real ingest

`verify-ingest` searches Data Lake for records whose `normalizer_revision` names the installed parsers, waits up to `--wait` (30 minutes) for every parser that writes a schema to have records, reruns the folder's parsers on each record's `original_data`, and compares fields. It prints field names and counts; `--show-values` adds one example pair. `--source-where` also counts the source's records still in generic.

Parsers take lines about three minutes after they go on (2 minutes 50 seconds in the lab on 22/11/2026). Only lines that arrive after that are normalized, and records a parent made alone before its child was active are counted apart (`madeBeforeChildActive`), not as differences.

`--earliest` bounds the event time the parser set, not the ingest time. Lines that carry an old time of their own (a replay, or synthetic test lines) need a wider window, such as `--earliest -14d`.

Gate: records from every schema-writing parser, `parserPathDiffers: 0`, and no unexplained `differences`.

## What this skill refuses

- Changing a parser it didn't create: no edits to console-made parsers, no Override Global Parser, no children under built-in parsers (a later version).
- Enabling a parser whose live code differs from the local file, or that has no passing tenant check for that code.
- A sample workspace or parser folder inside a git work tree, unless git ignores the path.
- Printing raw sample values, or putting sample lines in run parameters, the ledger, logs or issue text.
- Sending lines to an HTTP Ingest integration. Ingest checks use the source's own traffic.
- Contributing any line from the person's samples, raw or masked.

## Clean up

```bash
node ${CLAUDE_SKILL_DIR}/../deployment/scripts/ledger.mjs plan
node ${CLAUDE_SKILL_DIR}/../deployment/scripts/ledger.mjs rollback --yes
```

Rollback disables and deletes each child, then the parent, and counts a parser as gone only when a parser list read without error lacks it. Data already normalized stays. Deleted parsers can't be recovered, which is fine for test copies.

## Share with the library (opt-in)

The library takes no customer logs, even sanitized ones. To contribute:

1. Write a new `samples.log` from the vendor's public log format docs, with documentation addresses and example.com names only.
2. In the folder's `meta.json`, set `author`, `license`, `docs` (the vendor's docs links), `sample_source` (`synthetic` or `vendor-docs`), `summary` and `notes`.
3. Run `contribute`:

```bash
node $PS contribute ~/parsers/acme-edgewall --samples synthetic.log --out ~/library-entry
```

It refuses a line equal to any line in the sample workspaces, or one that shares half or more of its values with one. It rewrites each `!SAMPLE=` line from the synthetic samples, runs the library's checks from the vendored copy, writes the entry folder and the issue-form bundle, and gives the upload link. Nothing is posted. The library's checks on its main branch are the authority.

## Report

Say what was built, the tenant-check result in one line (lines routed, differences), what is installed and whether it is on, the ledger run ID, and the next step.
