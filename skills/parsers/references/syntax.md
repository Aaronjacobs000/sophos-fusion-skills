# The parser language, condensed

The Sophos docs are the source: [Custom parsers](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/CustomParsers/) and the [schema pages](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Integrations/CustomParsers/Schemas/). This page condenses them, with what the library's emulator does where the docs are silent and what a lab tenant showed. Run `parser.mjs check` after every edit: the lint knows every function, field, and enum.

## Shape of a parser

```text
!SAMPLE=<one line of samples.log>
!CONFIRMWITH=PATTERN
!CONFIRMSTRING=<RE2 regex that picks this parser's lines>
!SCHEMA=scwx.auth
!TRIMALLOFF

# comments start with #
m = originalData$|user=(?P<user>\S+) from (?P<src>\S+)
sensorType$ = "Acme EdgeWall"
targetUserName$ = m["user"]
sourceAddress$ = m["src"]
eventTimeUsec$ = DATETIME(t, "2006-01-02T15:04:05Z07:00")
```

- Directives come first, one per line: `!SAMPLE`, `!CONFIRMWITH` (`PATTERN` or `EXPRESSION`), `!CONFIRMSTRING`, `!SCHEMA`, `!TRIMALLOFF`, `!SANITIZEALLOFF`, `!DISABLED`, `!IMPORT`, `!IMPORTONLY`, `!PARENT`.
- `!SCHEMA` is one of the schema IDs: `scwx.generic`, `scwx.auth`, `scwx.antivirus`, `scwx.apicall`, `scwx.cloudaudit`, `scwx.dhcp`, `scwx.dnsquery`, `scwx.email`, `scwx.encrypt`, `scwx.filemod`, `scwx.http`, `scwx.managementevent`, `scwx.netflow`, `scwx.nids`, `scwx.process`, `scwx.registry`, `scwx.thirdpartyalert`. `parser.mjs tenant-check` reads the tenant's own list.
- Fields that end in `$` are schema fields (`targetUserName$`) or engine variables (`originalData$`). Other names are local variables.
- A statement reads only variables set above it. The engine refuses a parser that reads a variable before any statement sets it, even in an IF branch it doesn't take.

## Confirm strings

- `PATTERN`: an RE2 regex tested on the whole raw line. Don't anchor it with `^`: the docs don't say whether it runs before or after the syslog header is split off.
- `EXPRESSION`: an expression over variables, for children: `eventType$=="alert"`. A child's confirm sees the variables its parent set.
- Two parsers whose confirms match the same line make selection inconsistent, per the docs. `tenant-check` names built-in parsers that already take the lines.

## Parents and children

- A parent recognizes every line from the source, sets shared variables and `$` fields, and stays on `scwx.generic`. Its children each take one event type to one schema.
- A child is saved with the parent's ID (`parentId`). Children of a built-in parser need `!PARENT=` and the console's Set Global Parent option; these skills don't make them yet.
- The tenant's test call takes one unsaved parser, so a child is tested flattened: the parent's statements, then the child's, under a PATTERN confirm from `test-confirms.json`.

## Reading the line

| Form | What it does |
| --- | --- |
| `m = x\|regex` | Match `x` against an RE2 regex. `m["name"]` is a named group, `""` when it doesn't match |
| `JSON(text)` | Parse JSON. `j["$.a.b"]` reads a JSONPath |
| `CEF(line)`, `LEEF(line)` | Parse a CEF or LEEF line into header and extension fields |
| `SPLIT_NAME_VALUES(text, delimiter, separator, quote)` | key=value text into a map |
| `SPLIT(text, separator)` | Text into a list |
| `URL_PARSE(url)` | A URL's parts |

XML has no helper: read it with capture patterns. Save an XML source as format `UNSTRUCTURED` (the API has CEF, LEEF, JSON, and UNSTRUCTURED only).

RE2 has no lookahead, lookbehind, backreference, or possessive quantifier, and repeat counts go up to 1000.

## Functions

`ADDFIELD`, `BASE64_DECODE`, `CEF`, `CONTAINS`, `DATETIME`, `FLATTEN`, `IDX_OF_TLD`, `INT`, `IS_PRIVATE_IP`, `IS_VALID_IP`, `JSON`, `LEEF`, `LENGTH`, `LOWERCASE`, `OBJKEYS`, `OBJVALS`, `OBJVALUES`, `PARSE_ERROR`, `REPLACE`, `REPLACE_REGEX`, `SANITIZE_ALL`, `SPLIT`, `SPLIT_NAME_VALUES`, `STRING`, `TENANT_LOOKUP`, `TRIM`, `TRIM_ALL`, `UPPERCASE`, `URL_PARSE`, `VALIDATE_ALL_JSONPATHS_EXIST`. `STRLEN` is deprecated: use `LENGTH(value)` or `LENGTH(value, "bytes")`.

- `IF cond THEN a ELSE b` is an expression, and nests.
- `INT(text, 10)` parses a number. `STRING(x)` makes text.
- `DATETIME(value, layout)` uses Go time layouts (`2006-01-02 15:04:05.000000`, `Jan _2 15:04:05`). A layout with no year reads as year 0, and one with no zone reads as UTC.
- `TRIM_ALL()` runs on every value unless `!TRIMALLOFF`, and strips braces and brackets from JSON values. JSON sources set `!TRIMALLOFF`.

## Fields and enums

- `eventTimeUsec$` is microseconds. A time ahead of ingest moves back by whole hours (a time zone set wrong) when that brings it within 50 minutes before ingest; any other future time becomes the ingest time.
- Enum fields take a member name in quotes (`actionResult$ = "FAILED"`); the engine fails the event for a value that isn't a member. `check` lists enum fields per line by member name.
- Leftover keys go in `eventMetadata$` or a schema's `additionalData$` key-value record.
- `sensorType$` names the source. Detection rules match on it, so keep it stable once rules exist.

## Restricted syntax

- Sophos Fusion won't save a parser with `*=` anywhere in it, even in a comment or a regex. Write the `=` as `[=]`.
- A `!PARENT` line saves only with Set Global Parent turned on.
- `runIsolated` is gone from the test call (16/10/2026).
