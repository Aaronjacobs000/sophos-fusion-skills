# Fusion automation objects

| Object | What it is | Created by | Removed by |
| ------ | ---------- | ---------- | ---------- |
| Template (playbook) | The YAML program, with versions. Sophos's are global and read-only | `importPlaybookV2` | `deletePlaybook` |
| Template version | One published version. Imports publish the version they add | import, `createPlaybookVersion` (draft) | `deletePlaybookVersion` (drafts only) |
| Connector | The API description, with versions | `importConnector` | `deleteConnector` |
| Connection | Credentials and settings for one connector | `createConnection` | `deleteConnection` |
| Instance (configured playbook) | A template version plus trigger, inputs, connections, and interface bindings | `createPlaybookInstance` | `deletePlaybookInstance` |
| Schedule | Runs a Generic Trigger instance on a cron expression | `createPlaybookSchedule` | `deletePlaybookSchedule` |
| Execution | One run, with events and a log | a trigger, a schedule, or `executePlaybookInstanceV2` | never: logs cannot be deleted |
| Trigger filter (tenant) | A platform circuit breaker that suppresses events tenant-wide | the platform | not touched by these scripts |

## Dependencies

Delete children first: schedules, then instances, then connections, then templates, then connectors. A connector with connections, or a template with instances, may refuse to delete. The ledger's rollback order handles this.

## Names

Test copies use the `ZZTest_` prefix for templates and connectors (they allow only letters, digits, underscores, and dots), and `ZZ Test ` for instances, connections, and schedules. They sort to the end of console lists and are easy to find and remove.

## Read-back

A write's success answer is not proof. After every write the scripts read the object back and compare what matters (name, version, enabled). Reads can lag writes by a few seconds, so read-back polls for up to 30 s (`SOPHOS_FUSION_READBACK_MS` changes that).

## The ledger

`~/.local/state/sophos-fusion-skills/ledger.json` (`SOPHOS_FUSION_STATE_DIR` moves it). Each run holds the objects created under it: kind, ID, name, tenant, profile, parent, time, and status (live, deleted, gone, delete_failed). Do not delete the file while it lists live objects.
