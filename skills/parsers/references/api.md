# Parser API calls, and what was measured

All calls go to the Sophos Fusion GraphQL endpoint (`https://api.taegis.sophos.com/graphql`) with the tenant in `X-Tenant-ID`. The parser calls are undocumented: the Sophos docs cover parsers only in the console. Data Lake Search is documented (Search GraphQL). Dates are when a lab tenant last showed each fact.

## Reads

| Call | Use | Notes |
| --- | --- | --- |
| `allParsers` | list, clash check, rollback read | `id name parentId disabled overrideGlobal`. The only proof a parser is gone. |
| `parser(filter: {id})` | read back code | A deleted parser reads as "Internal server error", the same as a failed read (16/10/2026). Never read as gone. |
| `parserSchemas` | schemas the tenant takes | 18 on 22/11/2026, including `xdr.findings.detectionfinding`. |
| `validateParser(unvalidatedParser: {code, parentId, name})` | syntax in the real engine | Answers `{ok, message}`; the message names the line and column. Saves nothing. |
| `sampleParser(messages, parser, runDisabled)` | run lines in the real engine | Saves nothing ("Testing does not save the script", per the docs). `results { schema extractors errors fields variables }`, with `fields` as `[{destination, value}]` and enums as numbers. |
| `createSearch`, `search`, `searchResults` | Data Lake Search | `createSearch` is a mutation that changes no configuration: no `--yes`, and never resent after a 5xx. A search over two schemas (`from generic, thirdparty`) returned only the columns they share (22/11/2026), so `verify-ingest` searches each schema on its own. `earliest` bounds the event time, not the ingest time. |

Measured on 22/11/2026:

- `sampleParser` with no parser runs only the tenant's own parsers. A line no parser takes answers schema `(None)` and extractors `Master`.
- `sampleParser` and `validateParser` with the `parentId` of a saved, disabled parent answer "tenant parser parent invalid for merge ... parent ... not found", with `runDisabled` true or false. Children are tested flattened. With `runDisabled: true` and no parser sent, the saved, disabled parent didn't run either.
- `validateParser` passes a child's code on its own (`parentId` 0).
- The engine's extractors read `Master -> <name>`, with the name sent in the unsaved parser.

## Writes

| Call | Input | Notes |
| --- | --- | --- |
| `createParser(parser:)` | `name, type (PARENT, CHILD, STANDALONE), format (CEF, LEEF, JSON, UNSTRUCTURED), schema, code, parentId, disabled: true, overrideGlobal: false` | Saves the console's new-parser template, not the code sent (16/10, 20/11, 22/11/2026). |
| `updateParser(id:, updatedParser:)` | `{code}` or `{disabled}` | Install sends the code this way while the parser is disabled, then reads it back. |
| `deleteParser(id:)` | | Deleted parsers can't be recovered. |

- The read type has no schema, type or format fields, so read-back compares name, `parentId`, `disabled` and the code, which carries `!SCHEMA`.
- `format: "XML"` is refused ("Value XML does not exist in ParserFormatType enum", 22/11/2026). An XML source saves as `UNSTRUCTURED`, and its code saved the same way as any other: template first, then the code with `updateParser`.
- `authzPermissions` has no parser object. The docs say Super Admins and Admins manage parsers, so the self-test reports whether `allParsers` reads.
- Changes to a deployed (enabled) parser take effect at once, per the docs, so `update-code` works only on a disabled parser.

## Turning a parser on

- Normalization of matching lines changes tenant-wide at once. Generic events continue.
- Sophos detectors (IP and Domain Watchlist, DGA, and Sophos rules that match any sensor type on the schema) run on the new records.
- Every child must be disabled or deleted before its parent can be disabled, per the docs. Rollback disables and deletes each child before the parent.
- A parser takes lines about three minutes after it goes on. On 22/11/2026 a parent and child enabled at 01:29:58 UTC first normalized a line sent at 01:32:48; every line sent before that stayed generic with no parser in its path. Lines that arrived before a parser went on stay as they were.
