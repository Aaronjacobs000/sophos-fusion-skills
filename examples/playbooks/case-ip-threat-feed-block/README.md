# Block case IPs on Sophos Firewall

An analyst runs this from a case. It collects the public IPv4 addresses in the case's detections, drops excluded ones, caps the list, and adds the rest to one Sophos Firewall's MDR threat feed.

**Dry run is on by default.** A dry run changes nothing and reports the addresses it would add.

## Safety built in

- `dry_run` input, default `true`. The firewall step's condition starts with `!settings.variables.dry_run`.
- `max_indicators`, default 10, held between 1 and 100. Extra addresses are reported as `over_cap`.
- Only public IPv4: private, loopback, and link-local addresses are dropped, and so are IPv6 addresses (Fusion's `isIP` accepts IPv6, so the template also checks for `:`).
- `excluded_ips` for your own egress addresses.
- Detections below `min_severity` (default 0.6) are ignored.

## Triggers

- **User Initiated**, category Response, context Case: how analysts run it.
- **Generic Trigger**, usage Other: the test twin. Fusion's API cannot run User Initiated instances (it answers REAUTH_REQUIRED), so tests go through a second instance of the same template with a Generic Trigger, given a test case event in the parameters:

```bash
node skills/deployment/scripts/deploy.mjs instance-create --template ZZTest_CaseIpThreatFeedBlock \
  --name "ZZ Test block case IPs twin" --trigger generic --inputs @examples/playbooks/case-ip-threat-feed-block/test-event.json --yes
node skills/execution/scripts/run.mjs execute --instance <id> --event @examples/playbooks/case-ip-threat-feed-block/test-event.json --watch --yes
```

`test-event.json` keeps `dry_run: true`. Only run the twin on a test tenant, with a test case, after the person approves it.

## What it calls

- `Taegis.GetCaseDetections` (a Sophos platform playbook) to read the case's detections.
- `Taegis.SophosFirewall.createThreatFeedIndicator`, only when dry run is off. Its URL takes `firewallId`, which the action's input schema does not list.

## Tested

- Offline and tenant DSL checks pass.
- 17 CEL cases pass in Fusion's engine, including the dry run gate, the cap, and the address filter.
- Not run live, by design: it is a response playbook. The test twin path is documented here, not exercised.
