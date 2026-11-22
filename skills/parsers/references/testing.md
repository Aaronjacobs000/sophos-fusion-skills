# How the parser tests work

Three levels, each closer to the truth than the last. The tenant's engine is the authority.

| Level | Command | What runs | Writes |
| --- | --- | --- | --- |
| Offline | `check`, `expected` | The library's emulator on `samples.log` | Nothing |
| Tenant, read-only | `tenant-check` | The tenant's engine on `samples.log`, through `validateParser` and `sampleParser` | Nothing |
| Real ingest | `verify-ingest` | Data Lake records the installed parsers made from the source's own traffic | Nothing |

## The emulator against the engine

The emulator is the library's reading of the Sophos docs, checked against a lab tenant where the docs are silent. It is not the Sophos engine. It doesn't know the tenant's built-in parsers, which can take the same lines first, and its schema data can lag the tenant's (on 22/11/2026 the lab listed `xdr.findings.detectionfinding`, which the vendored data lacks).

`tenant-check` runs every line in both and compares them field by field:

- The engine answers enum fields with numbers. They are turned into member names with the vendored schema data before the comparison, so `severity 4` reads as `HIGH`.
- Platform fields (`resource_id`, `tenant_id`, `ingest_time_usec`, `normalizer`, `visibility`, and the like) are skipped.
- Empty values on both sides (`""`, `0`, `false`, empty lists, an enum's zero member) count as unset.
- A field the engine fills when the parser leaves it unset (`sensor_id`, `sensor_type`, `event_time_usec`, `event_time_fidelity`) is not a difference.
- A line with no time of its own gets each side's own ingest time, so that isn't a difference either.

Each difference is a path and a kind: `differ`, `engineOnly`, or `emulatorOnly`. Explain every one to the person before install. `--show-values` prints the values.

## Children are tested flattened

`sampleParser` runs one unsaved parser. A child saved under a saved parent can't be tested: on 22/11/2026, `sampleParser` and `validateParser` with the `parentId` of a saved, disabled parent answered "parent ... not found", with `runDisabled` true or false. So each child runs as one script:

```text
!CONFIRMWITH=PATTERN
!CONFIRMSTRING=<the child's line in test-confirms.json>
!SCHEMA=<the child's schema>
!TRIMALLOFF                      (when either parser has it)

<the parent's statements>
<the child's statements>
```

The PATTERN has to take exactly the lines the child takes, which `check` proves in the emulator. For the OpenCanary example, the child takes logtype 2000 and up, so its pattern matches `"logtype": 2000` to `999999` beside `node_id`.

`test-confirms.json` is local. It never goes to the tenant as saved code and never into a contribution.

## Routing and retries

Each line runs through the script the emulator says takes it. Lines the emulator gives to none of the folder's parsers run through each top-level parser, and must stay with none of them in the engine too.

When the engine gives a line to another parser, the line runs again, up to `--retries` (3) more times, as the library's lab harness does: overlapping confirm strings make the engine's choice inconsistent.

## Built-in claims

`tenant-check` first runs `sampleParser` with no parser of ours, so only the tenant's own parsers run. Any line that leaves `Master` went to a built-in or existing parser. Say so and ask whether the person still wants a parser.

## Masking

`samples add` masks before the agent reads a line. The masking keeps structure, keys, timestamps and event codes, so the emulator gives the same schema and field names on masked lines as on raw ones (a unit test holds this on a fixture). It changes values: a private address becomes a documentation one, so a parser that tests `IS_PRIVATE_IP()` behaves differently on masked lines. `verify-ingest` runs on the real records and catches what masking hides.

Masking is pattern-based. A user name inside free text (`msg=Bad password for jsmith`) can slip through. Read `masked.log` before going on, and mask more by hand if needed.

## Real ingest

`verify-ingest` searches for records whose `normalizer_revision` contains an installed parser's name, then reruns the folder's parsers on each record's `original_data` with the record's own ingest time.

- A record whose path is the parent alone, where the emulator says parent then child, came in before the child was active. It is counted as `madeBeforeChildActive`, not as a difference.
- `--source-where` counts the source's records still in generic, for lines the parsers didn't take yet.

Data Lake Search's `earliest` bounds the event time, so a record whose line carries an old time sits outside a `-1h` window even when it arrived a minute ago. Widen `--earliest` for replayed or synthetic lines.

The search reads at most 10,000 records (`capped` says when it hit that).
