# Examples

Each example passes the offline checks and Sophos Fusion's own DSL check, and comes with a CEL cases file.

| Example | Tier | Trigger | What it does |
| ------- | ---- | ------- | ------------ |
| [case-reference-lookup](playbooks/case-reference-lookup/) | lookup | Generic Trigger | Lists the tenant's case types, statuses, and closing verdicts |
| [closed-case-detection-note](playbooks/closed-case-detection-note/) | notify | Platform Events (case Update) | Comments on a case closed as a true positive, with its detection count |
| [case-ip-threat-feed-block](playbooks/case-ip-threat-feed-block/) | response | User Initiated, with a Generic Trigger twin | Adds a case's public detection IPs to a Sophos Firewall threat feed, dry run on |
| [first-epss](connectors/first-epss/) | connector | | EPSS scores for CVE IDs from the FIRST public API |

Check them all offline:

```bash
node skills/validation/scripts/validate.mjs all examples
```
