---
name: detection-rules
description: Write custom detection rules in Sophos Fusion for a log source that reaches Sophos NG-SIEM through a custom parser, and an automatic case rule that groups their detections. Use when someone wants to detect, alert on, or open cases for events from a custom-parser source (a QL rule, a custom detection, a case rule, Rule Logs), test a rule against Data Lake, check its volume, or share rules with the Unofficial Sophos Fusion XDR and SIEM Library. Tests offline on the parser's own samples, then in Data Lake Search, installs rules off and case rules in Test state.
license: MIT
---

# Detection rules: rules and a case rule for a custom parser's records

Scripts live in `${CLAUDE_SKILL_DIR}/scripts/`. If that shows literally, it means the folder next to this file. The query language is in [ql.md](references/ql.md), case rules in [case-rules.md](references/case-rules.md), and the API calls in [api.md](references/api.md).

```bash
DR=${CLAUDE_SKILL_DIR}/scripts
```

The input is a parser folder from the `parsers` skill (or a library parser entry). Rules match its `sensor_type` on its schema, and only that: rules on Sophos products or built-in integrations are refused.

## The usual path

```bash
node $DR/rules.mjs fields --parser ~/parsers/acme-edgewall
node $DR/rules.mjs scaffold --parser ~/parsers/acme-edgewall --title "Acme EdgeWall admin activity" --out ~/rules/acme-admin
node $DR/rules.mjs check ~/rules/acme-admin --parser ~/parsers/acme-edgewall
node $DR/rules.mjs tenant-check ~/rules/acme-admin          # read-only
node $DR/rules.mjs search-test ~/rules/acme-admin --earliest=-7d   # read-only, needs the parser on and ingesting
node $DR/rules.mjs install ~/rules/acme-admin --parser ~/parsers/acme-edgewall --yes
node $DR/rules.mjs enable --id <rule id> --yes              # one rule at a time, each its own approval
node $DR/rules.mjs detections --rule <rule id> --earliest=-1h
```

Write relative times with `=` or as a separate word: `--earliest=-7d` and `--earliest -7d` both work.

### 1. Write the rules

`fields` lists what the parser's records set, per schema, with each enum's members and the ones seen. `scaffold` writes the library's layout: `meta.json`, `rules.yaml` and `tests.json`.

In `rules.yaml`, each rule is the Create Rule form's fields: `name` (it becomes each detection's title), `description`, `severity` (critical, high, medium, low, informational), `mitre` (technique IDs), `query`, and `enabled_by_default`. Fill in `volume` in `meta.json`: how many detections a day to expect, and when there are more.

Each query:

- reads one schema, with no pipeline and no EARLIEST or LATEST;
- pins the sensor type with a top-level `sensor_type = '...'`;
- adds a condition beyond the sensor type;
- isn't a bare list of IPs, domains or hashes (Sophos's watchlists cover those);
- compares enums by member name in quotes (`severity = 'HIGH'`, never `severity = 4`);
- uses `!IN`, never `NOT IN`, and no backreference or lookaround in `MATCHES_REGEX`.

In `tests.json`, list under `triggers` the lines of the parser's `samples.log` each rule must trigger, and under `quiet` lines no rule may. Each line triggers one rule at most.

### 2. Check offline

`check` parses each query with the vendored reader, checks fields, enums and regex against the engine's limits, runs the parser on its samples and the rules on the records, and holds `tests.json` exactly.

Gate: 0 errors.

### 3. Tenant check (read-only)

`tenant-check` runs `validateQLFilter` on each query (it rejects fields the schema lacks, `hostname`, a second schema and pipelines, and maps each error to its rule), and reads Sophos's own rules on the schema with `searchRules`. A sensor type a Sophos rule names is an error: it comes from a Sophos product or built-in integration. A MITRE technique shared with a Sophos rule that matches every sensor type is a warning: check Detector Explorer before going on.

Gate: 0 errors, warnings explained.

### 4. Search test (read-only)

`search-test` runs each query in Data Lake Search over the window (7 days by default), plus one search for every record of the sensor types, runs the rules offline on those same records, and needs the two to agree. It reports matches per day per rule. With no records of the sensor type, there is nothing to test against: get the parser on and ingesting first.

The window bounds each record's event time, so test lines that carry an old time of their own need a wider one (`--earliest -14d`).

Gate: `agree: true` and records found. The result is saved for `enable`.

### 5. Install, then enable

`install` checks offline again, runs `validateQLFilter`, refuses a name already on the tenant, and creates each rule with `enabled: false` and `createAlert: true`, as `ZZ Test <name>` unless `--as-is`. Each one is read back (off, createAlert on, query equal) and recorded in the ledger. No `testShould` or `testShouldNot` is sent: any test value made the save fail in the lab.

`enable` turns on one rule and is its own approval. Before asking, tell the person: an enabled rule makes a detection for every matching event; detections can't be deleted; custom detections are theirs to work, not Sophos MDR's; and Sophos turns a rule off above 5,000 detections an hour or 100,000 a day.

`enable` needs a search-test of that rule's exact query on the tenant in the last 7 days, and refuses when it estimated more than 1,000 matches on its busiest day, or found no records, unless `--allow-volume` (the person accepts the volume).

`detections` lists what a rule made: title, severity, time, and the cases each detection is in.

## A case rule (optional)

```bash
node $DR/case-rule.mjs scaffold --rules ~/rules/acme-admin --group-by source-ip --out ~/rules/acme-admin-case
node $DR/case-rule.mjs check ~/rules/acme-admin-case
node $DR/case-rule.mjs install ~/rules/acme-admin-case --yes     # Test state, ZZTest_ copy
node $DR/case-rule.mjs logs --id <case rule id>
node $DR/case-rule.mjs enable --id <case rule id> --yes          # its own approval
node $DR/case-rule.mjs test-state --id <case rule id> --yes
```

`scaffold` writes `case-rule.yaml`, as Automatic Cases exports a rule with its template: a filter on the custom detector `app:event-filter-ql` and this set's rule titles only, a `group_by` (source IP, host or user) salted with the case rule's name so no other rule adds to its cases, state TEST, and a Security Case template with no assignee. Case rules act only on Medium and higher detections, so Low and Informational rules are left out.

`install` refuses a case rule or template name already on the tenant. By default it imports the file, then saves the rule once more with `updateCaseRule` (an imported rule opened no case until that save). `--method create` imports the template, then creates the rule after the tenant's last rule. Either way it reports whether any other case rule moved. In test mode the filter names the `ZZ Test` copies of the rules.

In Test state the rule writes Rule Logs only. Read them with `logs`: "case would have successfully been created but rule is in test mode" means it would have opened a case.

Before `enable`, tell the person: a case rule turned on takes the detections that already fit it, not only new ones, and cases it opens are Managed By Self, so Sophos MDR doesn't work them.

See [case-rules.md](references/case-rules.md) for the fields and the lab results.

## What this skill refuses

- Rules on Sophos products or built-in integrations: the sensor type must come from a custom parser.
- Suppression rules, which can silence Sophos detections before playbooks see them.
- Threshold rules: the rule builder takes one query on one schema, with no count or window.
- IOC-only rules: Sophos's IP and Domain Watchlists cover those.
- `testShould` and `testShouldNot`. Tests stay in `tests.json`.
- A case rule whose filter could reach other detectors or other rules' detections, names a Low or Informational rule, or lacks the salted `group_by`.
- Partner-level case rules (`is_global`) and assignees.
- Enabling a rule over 1,000 matches a day without `--allow-volume`.

## Clean up

```bash
node ${CLAUDE_SKILL_DIR}/../deployment/scripts/ledger.mjs rollback --yes
```

Rollback deletes the case rule, then its template, then each detection rule (disabled, then hard deleted, falling back to a soft delete), and reads each one back. A deleted rule kept firing on new events in the lab for at least two hours, so when the parser stays on, tell the person that detections can keep coming for a while. Detections, events and cases can't be deleted: list the cases the rules opened (`detections`) and leave closing them to the person.

## Share with the library (opt-in)

A rule entry's `parser` must be a library parser entry, so a new source contributes its parser first, in its own pull request (the `parsers` skill). Then:

```bash
node $DR/rules.mjs contribute ~/rules/acme-admin --parser-entry <library clone>/parsers/acme/edgewall --out ~/library-entry
node $DR/case-rule.mjs contribute ~/rules/acme-admin-case --out ~/library-entry
```

Set `author`, `license`, `docs`, `mdr_note`, `summary`, `notes` and `tested` in `meta.json` first; the checks say what is missing. `tests.json` line numbers must point at the library entry's synthetic `samples.log`, never the person's samples. The script writes the folder outside any repository and gives the upload link. Rule entries have no issue form, and the library reviews every rule pull request by hand. Nothing is posted.

## Report

Say which rules were checked and search-tested (matches a day), what is installed and whether it is on, the case rule's state and what its Rule Logs show, the ledger run ID, and the next step.
