import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { requireWrite } from '../lib/cli.mjs';
import { GateError } from '../lib/errors.mjs';
import { saveProfile, selectProfile } from '../lib/profiles.mjs';
import { readLedger } from '../lib/ledger.mjs';
import { validateText, skipsInDryRun } from '../lib/rules.mjs';
import { makeTestCopy, normalizeForDiff, diffValues } from '../lib/template.mjs';
import { loadYaml } from '../lib/yamlx.mjs';
import { setQuiet } from '../lib/log.mjs';
import { authRules, runScript, tempDir, ROOT } from './helpers/scenario.mjs';

setQuiet(true);

const SAVED = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const OTHER = 'bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee';

describe('SOPHOS_FUSION_TENANT_ID over a saved profile counts like --tenant', () => {
  const setup = () => {
    const dir = tempDir();
    saveProfile('mssp', { clientId: 'cid-0001', clientSecret: 'secret-0001', kind: 'test', tenantId: SAVED }, { SOPHOS_FUSION_CONFIG_DIR: dir });
    return dir;
  };

  test('another tenant from the environment needs --production', () => {
    const dir = setup();
    const p = selectProfile({ name: 'mssp', env: { SOPHOS_FUSION_CONFIG_DIR: dir, SOPHOS_FUSION_TENANT_ID: OTHER } });
    assert.equal(p.tenantId, OTHER);
    assert.throws(() => requireWrite({ yes: true }, p, 'x'), (e) => e instanceof GateError && e.details.needs.includes('--production') && /SOPHOS_FUSION_TENANT_ID/.test(e.message) && e.message.includes(OTHER));
    assert.doesNotThrow(() => requireWrite({ yes: true, production: true }, p, 'x'));
  });

  test('the saved tenant, from the profile or the environment, needs only --yes', () => {
    const dir = setup();
    assert.doesNotThrow(() => requireWrite({ yes: true }, selectProfile({ name: 'mssp', env: { SOPHOS_FUSION_CONFIG_DIR: dir } }), 'x'));
    assert.doesNotThrow(() => requireWrite({ yes: true }, selectProfile({ name: 'mssp', env: { SOPHOS_FUSION_CONFIG_DIR: dir, SOPHOS_FUSION_TENANT_ID: SAVED.toUpperCase() } }), 'x'));
  });

  test('an environment credential keeps its own tenant as its own', () => {
    const p = selectProfile({ env: { SOPHOS_FUSION_CLIENT_ID: 'a', SOPHOS_FUSION_CLIENT_SECRET: 'b', SOPHOS_FUSION_PROFILE_KIND: 'test', SOPHOS_FUSION_TENANT_ID: SAVED } });
    assert.doesNotThrow(() => requireWrite({ yes: true }, p, 'x'));
    assert.throws(() => requireWrite({ yes: true, tenant: OTHER }, p, 'x'), GateError);
  });

  test('the real script refuses it before sending anything', () => {
    const dir = setup();
    const r = runScript('skills/deployment/scripts/ledger.mjs', ['rollback', '--profile', 'mssp', '--yes'], { rules: authRules(), configDir: dir, env: { SOPHOS_FUSION_TENANT_ID: OTHER } });
    assert.equal(r.status, 3, r.stdout);
    assert.deepEqual(r.json.error.details.needs, ['--yes', '--production']);
    assert.equal(r.calls.length, 0);
  });
});

describe('an import never records the object its duplicate check found', () => {
  test('even when the connector list leaves that connector out', () => {
    const stateDir = tempDir();
    const file = 'examples/connectors/first-epss/connector.yaml';
    const conn = (version) => ({ id: 'C0', name: 'FirstEpss', isGlobal: false, tags: [], head: { id: `C0-${version}`, version, title: 'FIRST EPSS', authTypes: ['None'] }, versions: [{ id: `C0-${version}`, version }], connections: [] });
    const rules = [
      ...authRules(),
      { match: { op: 'connector' }, responses: [{ json: { data: { connector: conn('0.9.0') } } }, { json: { data: { connector: conn('1.0.0') } } }] },
      { match: { op: 'connectors' }, respond: { json: { data: { connectors: [] } } } },
      { match: { op: 'importConnector' }, respond: { json: { data: { importConnector: { id: 'C0', name: 'FirstEpss', head: { id: 'C0-1.0.0', version: '1.0.0', published: '2026-01-01' } } } } } },
      { match: { op: 'connectorExport' }, respond: { json: { data: { connectorExport: { export: fs.readFileSync(path.join(ROOT, file), 'utf8') } } } } },
    ];
    const r = runScript('skills/deployment/scripts/deploy.mjs', ['import', file, '--as-is', '--allow-existing', '--yes'], { rules, stateDir });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.equal(r.json.ledger, null);
    assert.ok(Object.values(readLedger({ SOPHOS_FUSION_STATE_DIR: stateDir }).runs).every((run) => run.objects.length === 0));
  });
});

describe('the response gate must skip the action in a dry run', () => {
  const example = fs.readFileSync(path.join(ROOT, 'examples/playbooks/case-ip-threat-feed-block/template.yaml'), 'utf8');
  const gate = '"!settings.variables.dry_run && size(plan.variables.planned) > 0';
  const withCondition = (c) => example.replace(gate, `"${c} && size(plan.variables.planned) > 0`);
  const gateErrors = (text) => validateText(text).findings.filter((x) => x.rule === 'response.gate');

  test('the example passes as written', () => {
    assert.ok(example.includes(gate));
    assert.equal(gateErrors(example).length, 0);
  });

  test('a condition that only mentions dry_run is an error', () => {
    for (const c of ['settings.variables.dry_run', 'settings.variables.dry_run || true', "inputs.?configuration.dry_run.orValue(true) != false"]) {
      assert.equal(gateErrors(withCondition(c)).length, 1, c);
    }
  });

  test('the ways of writing "dry run is off" all count', () => {
    for (const c of ['!settings.variables.dry_run', '!(settings.variables.dry_run)', 'settings.variables.dry_run == false', 'false == settings.variables.dry_run', 'settings.variables.dry_run != true', '!inputs.?configuration.dry_run.orValue(true)', '!bool(settings.variables.dry_run)']) {
      assert.equal(skipsInDryRun(`${c} && x > 0`), true, c);
      assert.equal(gateErrors(withCondition(c)).length, 0, c);
    }
    assert.equal(skipsInDryRun(undefined), false);
    assert.equal(skipsInDryRun('not ( valid'), false);
  });
});

describe('diff honors --prefix', () => {
  test('a copy made with another prefix matches its source', () => {
    const text = fs.readFileSync(path.join(ROOT, 'examples/playbooks/case-reference-lookup/template.yaml'), 'utf8');
    const copy = makeTestCopy(text, { prefix: 'ZZDemo_' });
    assert.deepEqual(diffValues(normalizeForDiff(loadYaml(text).value, { prefix: 'ZZDemo_' }), normalizeForDiff(loadYaml(copy.text).value, { prefix: 'ZZDemo_' })), []);
  });

  test('deploy.mjs diff passes the prefix through', () => {
    const file = 'examples/playbooks/case-reference-lookup/template.yaml';
    const copy = makeTestCopy(fs.readFileSync(path.join(ROOT, file), 'utf8'), { prefix: 'ZZDemo_' });
    const rules = [...authRules(), { match: { op: 'playbookExport' }, respond: { json: { data: { playbookExport: { export: copy.text } } } } }];
    const r = runScript('skills/deployment/scripts/deploy.mjs', ['diff', file, '--prefix', 'ZZDemo_'], { rules });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.equal(r.json.name, 'ZZDemo_CaseReferenceLookup');
    assert.equal(r.json.matches, true, JSON.stringify(r.json.differences));
  });
});

describe('whole-number options', () => {
  test('a bad --first or --limit is a usage error, with no request', () => {
    for (const [script, args] of [
      ['skills/execution/scripts/run.mjs', ['list', '--first', 'abc']],
      ['skills/authoring/scripts/catalog.mjs', ['connectors', '--search', 'x', '--limit', 'ten']],
    ]) {
      const r = runScript(script, args, { rules: authRules() });
      assert.equal(r.status, 2, `${args.join(' ')}: ${r.stdout}`);
      assert.equal(r.json.error.code, 'usage');
      assert.equal(r.calls.length, 0);
    }
  });
});
