import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { validateFile, validateText } from '../lib/rules.mjs';
import { ROOT } from './helpers/scenario.mjs';

const fx = (p) => path.join(ROOT, 'test', 'fixtures', p);
const rules = (r) => new Set(r.findings.map((f) => f.rule));
const has = (r, rule, re) => r.findings.some((f) => f.rule === rule && (!re || re.test(f.message)));

describe('offline validator: good files', () => {
  const files = [
    'examples/playbooks/case-reference-lookup/template.yaml',
    'examples/playbooks/closed-case-detection-note/template.yaml',
    'examples/playbooks/case-ip-threat-feed-block/template.yaml',
    'examples/connectors/first-epss/connector.yaml',
    'test/fixtures/good/notify-loop.yaml',
  ];
  for (const f of files) {
    test(`${f} has no errors or warnings`, () => {
      const r = validateFile(path.join(ROOT, f));
      assert.equal(r.errors, 0, JSON.stringify(r.findings, null, 1));
      assert.equal(r.warnings, 0, JSON.stringify(r.findings, null, 1));
    });
  }

  test('findings carry the path and line', () => {
    const r = validateFile(fx('bad/kitchen-sink.yaml'));
    const f = r.findings.find((x) => x.rule === 'cel.syntax' && /expected a value/.test(x.message));
    assert.ok(f.line > 1);
    assert.match(f.path, /^dsl\.tasks\[\d+\]\.let\.v$/);
  });
});

describe('offline validator: playbook rules', () => {
  const r = validateFile(fx('bad/kitchen-sink.yaml'));

  test('structure, names and versions', () => {
    assert.ok(has(r, 'data.tenant-id', /Remove tenantId/));
    assert.ok(has(r, 'name.template'));
    assert.ok(has(r, 'version.semver'));
    assert.ok(has(r, 'deps.format', /Name:major/));
    assert.ok(has(r, 'task.name', /lower case/));
    assert.ok(has(r, 'task.name', /collides with a CEL name/));
    assert.ok(has(r, 'task.name', /used twice/));
    assert.ok(has(r, 'task.keys', /frobnicate/));
    assert.ok(has(r, 'task.sleep'));
  });

  test('trigger hints', () => {
    assert.ok(has(r, 'trigger.source', /nosuch/));
    assert.ok(has(r, 'trigger.events', /Exploded/));
    assert.ok(has(r, 'cel.syntax', /trigger filter/));
    assert.ok(has(r, 'trigger.category'));
    assert.ok(has(r, 'trigger.usage'));
    assert.ok(has(r, 'trigger.type', /weird/));
  });

  test('CEL syntax and task references', () => {
    assert.ok(has(r, 'cel.syntax', /does not parse/));
    assert.ok(has(r, 'ref.forward', /runs later/));
    assert.ok(has(r, 'ref.undeclared', /nosuch/));
    assert.ok(has(r, 'ref.nested', /loop or branch/));
    assert.ok(has(r, 'ref.loop-item', /each_item\.value/));
    assert.ok(has(r, 'task.name', /reserved word/));
    assert.ok(has(r, 'ref.skipped', /skippable\.outputs\.body/));
    assert.ok(r.findings.some((f) => f.rule === 'ref.skipped' && f.path === 'dsl.outputs.out'));
  });

  test('connectors, secrets and data', () => {
    assert.ok(has(r, 'deps.connector-undeclared', /Acme\.Thing/));
    assert.ok(has(r, 'secret.nolog', /skippable/));
    assert.ok(has(r, 'data.hardcoded-secret', /bearer_token/));
    assert.ok(has(r, 'data.tenant-id', /fixed tenant ID/));
  });

  test('personal data in an evaluated field is an error, in documentation a warning', () => {
    const email = ['jane.citizen', 'contoso.com'].join('@');
    const base = fs.readFileSync(path.join(ROOT, 'examples/playbooks/case-reference-lookup/template.yaml'), 'utf8');
    const inField = base.replace("source: 'Fusion case reference data'", `source: "'${email}'"`);
    const inDocs = base.replace('# Overview', `# Overview\n    Contact ${email}.`);
    const a = validateText(inField);
    const b = validateText(inDocs);
    assert.ok(a.findings.some((f) => f.rule === 'data.personal' && f.level === 'error'));
    assert.ok(b.findings.some((f) => f.rule === 'data.personal' && f.level === 'warning'));
    assert.equal(b.errors, 0);
  });

  test('guarded reads of skipped tasks are not flagged', () => {
    const g = validateFile(fx('good/notify-loop.yaml'));
    assert.ok(!rules(g).has('ref.skipped'));
  });

  test('nolog clears the secret rule', () => {
    const text = fs.readFileSync(fx('bad/kitchen-sink.yaml'), 'utf8').replace('action: Taegis.Webhook.post', 'action: Taegis.Webhook.post\n          nolog: true');
    assert.ok(!validateText(text).findings.some((f) => f.rule === 'secret.nolog' && /skippable/.test(f.message)));
  });
});

describe('offline validator: response tier', () => {
  const r = validateFile(fx('bad/response-no-guards.yaml'));
  test('needs a boolean dry_run that defaults to true', () => assert.ok(has(r, 'response.dry-run', /type: boolean with default: true/)));
  test('needs an integer max_ cap', () => assert.ok(has(r, 'response.cap', /max_/)));
  test('needs the action gated on dry_run', () => assert.ok(has(r, 'response.gate', /isolateEndpoint/)));
  test('the example response playbook passes all three', () => {
    const ok = validateFile(path.join(ROOT, 'examples/playbooks/case-ip-threat-feed-block/template.yaml'));
    assert.ok(![...rules(ok)].some((x) => x.startsWith('response.')));
  });
});

describe('offline validator: connector rules', () => {
  const r = validateFile(fx('bad/connector-bad.yaml'));
  test('plain http is refused', () => assert.ok(has(r, 'connector.url', /plain http/)));
  test('every called host must be declared', () => assert.ok(has(r, 'connector.hosts', /api\.undeclared\.example/)));
  test('URLs from parameters must use declared parameters', () => assert.ok(has(r, 'connector.url', /config\.nothere/)));
  test('templates must parse', () => assert.ok(has(r, 'cel.syntax', /unclosed/)));
  test('no credentials in the connector', () => assert.ok(has(r, 'data.hardcoded-secret', /Authorization/)));
  test('auth types and methods are checked', () => {
    assert.ok(has(r, 'connector.auth', /Magic/));
    assert.ok(has(r, 'connector.http-method'));
    assert.ok(has(r, 'connector.action-name', /used twice/));
    assert.ok(has(r, 'connector.validate'));
  });
});

describe('offline validator: categories', () => {
  test('a connector category Fusion does not list is an error', () => {
    const text = fs.readFileSync(path.join(ROOT, 'examples/playbooks/case-reference-lookup/template.yaml'), 'utf8').replace('connectorCategories:\n    - Generic', 'connectorCategories:\n    - Firewall');
    assert.ok(validateText(text).findings.some((f) => f.rule === 'field.category' && /Invalid Connector Categories/.test(f.message)));
  });
});

describe('offline validator: fields only Sophos may set', () => {
  test('isProactiveResponse: true and Sophos-only flags fail the import, so they are errors', () => {
    const base = fs.readFileSync(path.join(ROOT, 'examples/playbooks/case-ip-threat-feed-block/template.yaml'), 'utf8');
    const text = base.replace('- isProactiveResponse: false\n      type: actions', '- isProactiveResponse: true\n      type: actions').replace('type: None\n', 'type: None\nisCentralTenantVisible: true\n');
    const r = validateText(text);
    assert.ok(r.findings.some((f) => f.rule === 'trigger.proactive'));
    assert.ok(r.findings.some((f) => f.rule === 'field.sophos-only' && /isCentralTenantVisible/.test(f.message)));
  });
});

describe('offline validator: files that are not templates', () => {
  test('YAML that does not parse', () => {
    const r = validateFile(fx('bad/not-yaml.yaml'));
    assert.equal(r.ok, false);
    assert.ok(has(r, 'yaml.parse'));
  });
  test('an unknown kind', () => assert.ok(has(validateFile(fx('bad/wrong-kind.yaml')), 'kind.unknown')));
  test('more than one document', () => assert.ok(has(validateText('kind: Playbook\n---\nkind: Playbook\n'), 'yaml.parse', /2 YAML documents/)));
});
