// Skeleton files that already follow the conventions and pass offline validation.

import { UsageError } from './errors.mjs';

function yamlString(s) {
  return JSON.stringify(String(s));
}

/** A connector skeleton that passes offline validation. */
export function scaffoldConnector({ name, title, baseUrl, auth = 'None', vendor = 'Vendor', product = 'Product' }) {
  const u = new URL(baseUrl);
  if (u.protocol !== 'https:') throw new UsageError('--base-url must be https.');
  const host = u.host;
  const base = `${u.origin}${u.pathname.replace(/\/+$/, '')}`;
  const authDefaults = auth === 'APIKey' ? `authDefaults:\n    apiKeyAuth:\n        header: Authorization\n        param: ""\n        value: Bearer <API-Key>\n` : '';
  return `apiVersion: v0.0.1
kind: Connector
name: ${name}
version: 1.0.0
title: ${yamlString(title)}
description: ${yamlString(`Calls ${host}.`)}
documentation: |
    # Overview
    Say what this connector is for and which playbooks use it.

    # Hosts
    This connector calls one host, over HTTPS:
    - ${host}

    # Authentication
    ${auth === 'None' ? 'None. Create the connection with auth type None.' : `${auth}. The connection holds the credential; the connector never does.`}

    # Data
    List what requests send and what responses return, so reviewers can check
    that no secret or personal data passes through it.
tags: []
categories:
    - Generic
method: http
vendorName: ${yamlString(vendor)}
vendorProduct: ${yamlString(product)}
authTypes:
    - ${auth}
${authDefaults}actions:
    - name: validate
      description: Check that ${host} answers
      inputs:
        type: object
        properties: {}
      outputs:
        type: object
        properties:
            outcome:
                type: string
      config:
        method: GET
        url: ${base}/
        contentType: application/json
        headers: []
        error: "\${has(status, 'code') && status.code >= 200 && status.code < 300 ? '' : 'The API answered ' + string(status.?code.orValue(0))}"
        outputs:
            outcome: "\${has(status, 'code') && status.code >= 200 && status.code < 300 ? 'success' : 'failure'}"
    - name: getItem
      description: Read one item by ID
      inputs:
        type: object
        required:
            - id
        properties:
            id:
                title: Item ID
                type: string
      outputs:
        type: object
        properties:
            item:
                type: object
            outcome:
                type: string
      config:
        method: GET
        url: "${base}/items/\${inputs.id.toURLQuery()}"
        contentType: application/json
        headers: []
        error: "\${has(status, 'code') && status.code == 200 ? '' : 'The API answered ' + string(status.?code.orValue(0))}"
        outputs:
            item: "\${body}"
            outcome: "\${has(status, 'code') && status.code == 200 ? 'success' : 'failure'}"
`;
}


const TIERS = ['lookup', 'notify', 'response'];
const TRIGGERS = ['generic', 'platform', 'actions'];

/**
 * A playbook template skeleton with the conventions built in:
 * - every tier: guarded reads, an outcomeStatus and outcomeMessage
 * - response tier: dry_run (default true), max_targets cap, and a plan step
 *   that applies the cap; the action step goes after it, gated on dry_run
 */
export function scaffoldPlaybook({ name, title, tier = 'lookup', trigger = 'generic', source = 'case', events = ['Update'], context = 'case' }) {
  if (!TIERS.includes(tier)) throw new UsageError(`--tier must be one of ${TIERS.join(', ')}.`);
  if (!TRIGGERS.includes(trigger)) throw new UsageError(`--trigger must be one of ${TRIGGERS.join(', ')}.`);
  const hints = [];
  if (trigger === 'platform') {
    hints.push(`    - isProactiveResponse: false
      type: platform
      config:
        source: ${source}
        events:
${events.map((e) => `            - ${e}`).join('\n')}
        filter: "true"`);
  }
  if (trigger === 'actions') {
    hints.push(`    - isProactiveResponse: false
      type: actions
      config:
        category: ${tier === 'response' ? 'response' : 'lookup'}
        context: ${context}
        name: ${JSON.stringify(title)}`);
  }
  // Every template gets a Generic Trigger hint: it is the only kind the API can run, so it is the test twin.
  hints.push(`    - isProactiveResponse: false
      type: generic
      config:
        usage: other`);
  const responseInputs = tier === 'response'
    ? `                dry_run:
                    title: Dry run
                    description: Report what would change, and change nothing. Turn off to act.
                    type: boolean
                    default: true
                max_targets:
                    title: Most targets per run
                    type: integer
                    default: 5
                    minimum: 1
                    maximum: 50
                targets:
                    title: Targets
                    description: What the playbook acts on. Replace with the real input.
                    type: array
                    items:
                        type: string
                    default: []
`
    : `                note:
                    title: Note
                    type: string
                    default: ''
`;
  const tasks = tier === 'response'
    ? `        - name: settings
          description: Read the configuration once, with safe defaults
          let:
            dry_run: inputs.?configuration.dry_run.orValue(true) != false
            cap: "int(inputs.?configuration.max_targets.orValue(5)) < 1 ? 1 : int(inputs.?configuration.max_targets.orValue(5))"
            targets: inputs.?configuration.targets.orValue([])
        - name: plan
          description: Apply the per-run cap
          let:
            planned: "size(settings.variables.targets) > settings.variables.cap ? settings.variables.targets.slice(0, settings.variables.cap) : settings.variables.targets"
        # Add the action step here. Keep this condition on it, so a dry run
        # and an empty plan never reach the vendor:
        #   condition: "!settings.variables.dry_run && size(plan.variables.planned) > 0"
        # Add nolog: true if the step sends or returns a secret.
    outputs:
        dry_run: settings.variables.dry_run
        planned: plan.variables.planned
    outcomeStatus: "'SUCCESS'"
    outcomeMessage: "settings.variables.dry_run ? 'Dry run: would act on ' + string(size(plan.variables.planned)) + ' targets' : 'Acted on ' + string(size(plan.variables.planned)) + ' targets'"`
    : `        - name: settings
          description: Read the configuration once, with safe defaults
          let:
            note: inputs.?configuration.note.orValue('')
        # Add lookup or notify steps here. Read an optional or conditional
        # step's results with step.?outputs.field.orValue(default).
    outputs:
        note: settings.variables.note
    outcomeStatus: "'SUCCESS'"
    outcomeMessage: "'Done'"`;
  const tag = { lookup: 'Type:Enrichment', notify: 'Type:Notification', response: 'Type:Response' }[tier];
  return `apiVersion: v0.0.1
kind: Playbook
name: ${name}
version: 1.0.0
title: ${JSON.stringify(title)}
description: ${JSON.stringify(`${title}.`)}
documentation: |
    # Overview
    Say what this playbook does, what it reads, and what it changes.

    # Trigger
    ${trigger === 'generic' ? 'Generic Trigger: run by hand, by the API, or on a schedule.' : trigger === 'platform' ? `Platform Events, source ${source}. Set a filter so it runs only when needed.` : `User Initiated, context ${context}.`}

    # Inputs
    List each input, its default, and what it changes.
changeNotes: First version
tags:
    - ${tag}
connectorCategories:
    - Generic
triggerHints:
${hints.join('\n')}
inputs:
    type: object
    properties:
        configuration:
            title: Configuration
            type: object
            properties:
${responseInputs}dsl:
    name: ${name}
    description: ${JSON.stringify(title)}
    tasks:
${tasks}
type: None
`;
}
