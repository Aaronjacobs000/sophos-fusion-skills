# The rule query language, for custom detection rules

A custom detection rule is one query on one schema. The docs: [Custom detection rules](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Detections/DetectionRules/CustomDetectionRules/). The vendored reader (`studio/core/ql.js`) covers the part rules use, and `rules.mjs check` runs it on the parser's samples.

## Shape

```text
from thirdparty
where sensor_type = 'OpenCanary'
  and alert_category = 'Login attempt'
  and severity != 'HIGH'
```

- `FROM` one schema, by its QL name: `auth`, `antivirus`, `apicall`, `cloudaudit`, `dhcp`, `dnsquery`, `email`, `encrypt`, `filemod`, `generic`, `http`, `managementevent`, `netflow`, `nids`, `process`, `registry`, `thirdparty`. Write `FROM thirdparty`, never `FROM thirdpartyalert`: rules take it, but Data Lake Search refuses it (23/11/2026), so `check` refuses it too.
- `WHERE` conditions, joined with `AND`, `OR`, `NOT` and parentheses.
- No pipeline (`| aggregate ...`), no `EARLIEST` or `LATEST`: a rule matches one event at a time, as it arrives.

## Operators

`=`, `!=`, `<`, `<=`, `>`, `>=`, `IN (...)`, `!IN (...)`, `CONTAINS`, `!CONTAINS`, `MATCHES` (a glob with `*` and `?`), `!MATCHES`, `MATCHES_REGEX`, `!MATCHES_REGEX`, `IS NULL`, `IS NOT NULL`. Operators and values are case-insensitive.

- `'...'` strings are taken as written. `e'...'` strings read backslash escapes, the only way to put a quote in one.
- `NOT IN` is a syntax error. Write `!IN`.
- A field missing from the event matches `!=` (lab, 20/11/2026), in Data Lake Search and in a live rule.

## Fields and enums

- Use the fields the parser's records set: `rules.mjs fields --parser <dir>`. `validateQLFilter` refuses a field the schema lacks.
- An enum field takes its member's name in quotes: `severity = 'HIGH'`. A number is refused ("Invalid enum, severity is 4, expected CRITICAL, HIGH, INFO, LOW, MEDIUM, UNKNOWN_SEVERITY", 22/11/2026).
- `hostname` can't be matched in a rule. On auth, netflow and dnsquery, neither can the geo and blacklist summaries.
- Never match `sensor_id`, `host_id`, `tenant_id` or `sensor_tenant`: they differ in every tenant. Match `sensor_type`.
- Logical types such as `@ip` search across schemas, which a rule can't.

## Regex

`MATCHES_REGEX` and `!MATCHES_REGEX` refuse backreferences, lookarounds, atomic groups and possessive quantifiers. `validateQLFilter` passes backreferences and lookarounds (20/11/2026), so the offline check is the one that catches them. Rules and Data Lake Search use different regex engines, so run a regex rule live as well as in a search.

## What a rule set needs

- Each query pins the sensor type with a top-level `sensor_type = '...'` (or `sensor_type IN (...)`), from `meta.json` `sensor_types`.
- Each query has a condition beyond the sensor type.
- No query is only a list of IPs, domains or hashes.
- Each sample line triggers one rule at most, so one event makes one detection.

## Severity and volume

| Severity | Score sent | Band in the docs |
| --- | --- | --- |
| critical | 0.8 | 0.8 to 1 |
| high | 0.6 | 0.6 to 0.799 |
| medium | 0.4 | 0.4 to 0.599 |
| low | 0.2 | 0.2 to 0.399 |
| informational | 0.1 | 0 to 0.199 |

Each score is its band's floor; 0.4 and 0.6 behaved as Medium and High in the lab. Case rules act only on Medium and higher.

Sophos turns a rule off above 5,000 detections an hour or 100,000 a day. `enable` refuses a rule whose search-test found more than 1,000 matches on its busiest day, without `--allow-volume`.
