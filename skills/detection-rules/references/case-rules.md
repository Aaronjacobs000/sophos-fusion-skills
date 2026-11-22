# Automatic case rules

The docs: [Automatic cases](https://docs.sophos.com/fusion/customer/help/en-us/ManageYourProducts/XDRSecOps/Cases/AutomaticCases/), and the [Cases GraphQL API](https://developer.sophos.com/graphql/cases-v2/mutations/create-case-rule/).

## case-rule.yaml

Two YAML documents, as Automatic Cases exports a rule with its template:

```yaml
apiVersion: v0.0.1
kind: rule
name: opencanary_one_case_per_source_ip      # letters, digits, underscores
title: OpenCanary, one case per source IP
type: STATIC
order: 90                                    # ignored by the import: the rule goes after yours
state: TEST
filter: from detection where metadata.creator.detector.detector_id = 'app:event-filter-ql' and title in ('Rule one', 'Rule two')
append_filter: ""
group_by:
    - ${alertSourceIPs(inputs).map(ip, ip + ' opencanary_one_case_per_source_ip')}
group_count: 1
skip_alert_prioritization: true
is_global: false
template_name: opencanary_honeypot
---
apiVersion: v0.0.1
kind: template
name: opencanary_honeypot
title: OpenCanary honeypot
investigation:
    type: SECURITY_INVESTIGATION
    title: OpenCanary honeypot activity from one source IP
    status: OPEN
    priority: "3"
    generate_key_findings: false
    usages:
        - AUTO_INVESTIGATION
```

What the check holds you to:

- The filter reads `from detection`, with a top-level `metadata.creator.detector.detector_id = 'app:event-filter-ql'` (custom detections only) and a top-level `title = '...'` or `title in (...)` naming this set's rules. Each custom detection's title is its rule's name.
- Every title names a Medium or higher rule. Case rules skip Low and Informational detections.
- Each `group_by` expression carries the case rule's name, so no other case rule can add to its cases: grouping isn't tied to a rule. `scaffold` writes `alertSourceIPs(inputs)`, `alertHostnames(inputs)` or `alertUsernames(inputs)`, each salted with the name.
- `state: TEST`, `is_global: false`, and a template with no assignee (user IDs differ in every tenant).

## Install

Default (`--method import`): `importInvestigationResources` with the file, then one `updateCaseRule` that sends every field back without the order.

- The import creates the template and the rule linked by name, keeps the file's state, and puts the rule after the tenant's own rules whatever the file's order.
- An imported rule opened no case until that save (lab runs T3b to T3d, 21/11/2026), and worked after it (T3f, 22/11/2026, and the library's build run).

`--method create`: import the template alone, then `createCaseRule` at the order after the tenant's last rule. `createCaseRule` inserts at the order it is given and moves the tenant's rules from there down one, so the install never gives it a lower order.

Both refuse a case rule or template name already on the tenant, read the rule back, and report whether any other case rule's order, state or save time changed.

## Test state and Rule Logs

In Test state the rule writes Rule Logs and opens nothing. "case would have successfully been created but rule is in test mode" for a detection means it would have opened a case for it (lab, 22/11/2026, for a Medium OpenCanary detection). `case-rule.mjs logs --id <id>` reads them (`getAllRuleLogs`, undocumented).

## Enabled

A case rule turned on takes the detections that already fit it, not only new ones: in the library's build run it opened two cases within 6 seconds from earlier detections. A closed case isn't matched again; the next detection opens a new one. Cases it opens are Managed By Self, and Sophos MDR doesn't work them.

To close a test case, set it to closed with the Authorized Activity verdict and a note such as "Lab test, synthetic data". The scripts don't close cases: that is the person's call.

## Rollback

`deleteCaseRule`, then `deleteCaseTemplate`, each read back until it no longer reads. Cases the rule opened stay.
