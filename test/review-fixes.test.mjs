import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { requireWrite } from '../lib/cli.mjs';
import { GateError, MutationUnconfirmedError, SfsError } from '../lib/errors.mjs';
import { sendWithRetry, setSleep } from '../lib/retry.mjs';
import { Session } from '../lib/session.mjs';
import { redactText, clearSecrets } from '../lib/redact.mjs';
import { readLedger, record, startRun } from '../lib/ledger.mjs';
import { setQuiet } from '../lib/log.mjs';
import { installFetch } from './helpers/mock-fetch.mjs';
import { authRules, runScript, tempDir, FAKE, ROOT } from './helpers/scenario.mjs';

setQuiet(true);
setSleep(async () => {});
const EX1 = 'examples/playbooks/case-reference-lookup/template.yaml';
const pb = (id, name, version) => ({ id, name, isGlobal: false, tags: [], head: { id: `${id}-v`, version, title: 't', published: '2026-01-01' }, versions: [{ id: `${id}-v`, version, published: '2026-01-01' }] });

describe('gate and tenant target', () => {
  const partner = { name: 'mssp', kind: 'test', tenantId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee' };
  test('--tenant other than the profile tenant needs --production, and the message names that tenant', () => {
    const other = '99999999-bbbb-4ccc-8ddd-eeeeeeeeeeee';
    assert.throws(() => requireWrite({ yes: true, tenant: other }, partner, 'x'), (e) => e instanceof GateError && e.message.includes(other) && e.details.target === other);
    assert.doesNotThrow(() => requireWrite({ yes: true, production: true, tenant: other }, partner, 'x'));
    assert.doesNotThrow(() => requireWrite({ yes: true, tenant: partner.tenantId }, partner, 'x'));
  });

  test('a tenant credential whose profile names another tenant is refused', async () => {
    const mock = installFetch(authRules());
    try {
      const s = new Session({ name: 'p', clientId: FAKE.clientId, clientSecret: FAKE.clientSecret, kind: 'test', tenantId: '99999999-2222-4333-8444-555555555555' });
      await assert.rejects(() => s.target(), (e) => e instanceof SfsError && e.code === 'tenant_mismatch');
    } finally {
      mock.restore();
    }
  });
});

describe('answers that break off', () => {
  let mock;
  afterEach(() => mock?.restore());
  test('a write whose answer body drops is unconfirmed, and sent once', async () => {
    mock = installFetch([{ match: {}, bodyError: true }]);
    await assert.rejects(() => sendWithRetry('https://api.taegis.sophos.com/graphql', { method: 'POST' }, { write: true }), (e) => e instanceof MutationUnconfirmedError && e.failure === 'connection');
    assert.equal(mock.calls.length, 1);
  });
  test('a write whose answer body stalls times out as unconfirmed', async () => {
    mock = installFetch([{ match: {}, bodyStall: true }]);
    await assert.rejects(() => sendWithRetry('https://api.taegis.sophos.com/graphql', { method: 'POST' }, { write: true, timeoutMs: 50 }), (e) => e instanceof MutationUnconfirmedError && e.failure === 'timeout');
  });
  test('a read whose body drops is retried', async () => {
    mock = installFetch([{ match: {}, responses: [{ bodyError: true }, { status: 200, json: { ok: 1 } }] }]);
    const r = await sendWithRetry('https://api.taegis.sophos.com/graphql', { method: 'POST' }, { write: false });
    assert.equal(r.status, 200);
    assert.equal(mock.calls.length, 2);
  });
});

describe('redaction of values the leak check flags', () => {
  test('JSON secret pairs, webhook URLs, signed URLs, cloud keys and private keys', () => {
    clearSecrets();
    const out = redactText('{"access_token":"abcdefgh1234","note":"ok"} https://hooks.slack.com/services/T0/B0/xyzxyzxyz https://x.blob.core.windows.net/c?sv=1&sig=abcdefghijk AKIAABCDEFGHIJKLMNOP -----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----');
    assert.ok(!/abcdefgh1234|xyzxyzxyz|abcdefghijk|AKIAABCDEFGHIJKLMNOP|MIIabc/.test(out), out);
    assert.match(out, /"note":"ok"/);
  });
});

describe('deploy safety fixes', () => {
  test('importing over an existing template the scripts did not create is refused, with no write', () => {
    const rules = [...authRules(), { match: { op: 'playbooks' }, respond: { json: { data: { playbooks: [pb('P0', 'CaseReferenceLookup', '0.9.0')] } } } }];
    const r = runScript('skills/deployment/scripts/deploy.mjs', ['import', EX1, '--as-is', '--yes'], { rules });
    assert.equal(r.status, 2, r.stdout);
    assert.match(r.json.error.message, /did not create it/);
    assert.equal(r.calls.filter((c) => c.mutation).length, 0);
  });

  test('with --allow-existing the version is added, but the template is never put in the ledger', () => {
    const stateDir = tempDir();
    const rules = [
      ...authRules(),
      { match: { op: 'playbooks' }, responses: [{ json: { data: { playbooks: [pb('P0', 'CaseReferenceLookup', '0.9.0')] } } }, { json: { data: { playbooks: [pb('P0', 'CaseReferenceLookup', '0.9.0')] } } }] },
      { match: { op: 'importPlaybookV2' }, respond: { json: { data: { importPlaybookV2: { id: 'P0', name: 'CaseReferenceLookup', head: { id: 'v1', version: '1.0.0', published: '2026-01-01' } } } } } },
      { match: { op: 'playbook' }, respond: { json: { data: { playbook: { ...pb('P0', 'CaseReferenceLookup', '1.0.0'), instances: [] } } } } },
      { match: { op: 'playbookExport' }, respond: { json: { data: { playbookExport: { export: fs.readFileSync(path.join(ROOT, EX1), 'utf8') } } } } },
    ];
    const r = runScript('skills/deployment/scripts/deploy.mjs', ['import', EX1, '--as-is', '--allow-existing', '--yes'], { rules, stateDir });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.equal(r.json.ledger, null);
    assert.match(r.json.note, /rollback will not remove it/);
    const ledger = readLedger({ SOPHOS_FUSION_STATE_DIR: stateDir });
    assert.ok(Object.values(ledger.runs).every((run) => run.objects.length === 0));
  });

  test('an unconfirmed create never adopts an object that was already there', () => {
    const stateDir = tempDir();
    const rules = [
      ...authRules(),
      { match: { op: 'connector' }, respond: { json: { data: { connector: { id: 'C1', name: 'X', isGlobal: false, head: { authTypes: ['None'] }, versions: [], connections: [] } } } } },
      { match: { op: 'connections' }, respond: { json: { data: { connections: [{ id: 'OLD', name: 'ZZ Test conn', connector: { name: 'X' } }] } } } },
      { match: { op: 'createConnection' }, respond: { status: 502, json: { message: 'bad gateway' } } },
    ];
    const r = runScript('skills/deployment/scripts/deploy.mjs', ['connection-create', '--connector', 'X', '--name', 'ZZ Test other', '--auth-type', 'None', '--yes'], { rules, stateDir, env: { SOPHOS_FUSION_READBACK_MS: '300' } });
    assert.equal(r.json.error.code, 'write_unconfirmed');
    assert.equal(r.calls.filter((c) => c.op === 'createConnection').length, 1);
    assert.ok(Object.values(readLedger({ SOPHOS_FUSION_STATE_DIR: stateDir }).runs).every((run) => run.objects.length === 0));
  });

  test('an unconfirmed create that did land is found by name and recorded', () => {
    const stateDir = tempDir();
    const rules = [
      ...authRules(),
      { match: { op: 'connector' }, respond: { json: { data: { connector: { id: 'C1', name: 'X', isGlobal: false, head: { authTypes: ['None'] }, versions: [], connections: [] } } } } },
      { match: { op: 'connections' }, responses: [{ json: { data: { connections: [] } } }, { json: { data: { connections: [] } } }, { json: { data: { connections: [{ id: 'NEW', name: 'ZZ Test new', connector: { name: 'X' } }] } } }] },
      { match: { op: 'createConnection' }, respond: { status: 504 } },
      { match: { op: 'connection' }, respond: { json: { data: { connection: { id: 'NEW', name: 'ZZ Test new' } } } } },
    ];
    const r = runScript('skills/deployment/scripts/deploy.mjs', ['connection-create', '--connector', 'X', '--name', 'ZZ Test new', '--auth-type', 'None', '--yes'], { rules, stateDir, env: { SOPHOS_FUSION_READBACK_MS: '2000' } });
    assert.equal(r.status, 0, r.stdout);
    const objs = Object.values(readLedger({ SOPHOS_FUSION_STATE_DIR: stateDir }).runs).flatMap((run) => run.objects);
    assert.deepEqual(objs.map((o) => o.id), ['NEW']);
  });

  test('an empty or odd test prefix is refused', () => {
    for (const prefix of ['', 'Prod_', 'ZZ']) {
      const r = runScript('skills/deployment/scripts/deploy.mjs', ['import', EX1, '--prefix', prefix, '--yes'], { rules: authRules() });
      assert.equal(r.status, 2, prefix);
      assert.equal(r.calls.filter((c) => c.mutation).length, 0);
    }
  });

  test('secret-looking instance inputs are refused before anything is sent', () => {
    const rules = [...authRules(), { match: { op: 'playbooks' }, respond: { json: { data: { playbooks: [pb('P1', 'ZZTest_X', '1.0.0')] } } } }, { match: { op: 'playbookInstances' }, respond: { json: { data: { playbookInstances: [] } } } }, { match: { op: 'playbookExport' }, respond: { json: { data: { playbookExport: { export: 'kind: Playbook\nname: ZZTest_X\n' } } } } }, { match: { op: 'connections' }, respond: { json: { data: { connections: [] } } } }, { match: { op: 'playbookTriggerTypesV2' }, respond: { json: { data: { playbookTriggerTypesV2: [{ id: 'g', name: 'generic' }] } } } }];
    const r = runScript('skills/deployment/scripts/deploy.mjs', ['instance-create', '--template', 'ZZTest_X', '--name', 'ZZ Test x', '--trigger', 'generic', '--inputs', '{"url":"https://hooks.slack.com/services/T0/B0/abcdefgh"}', '--yes'], { rules });
    assert.equal(r.status, 2, r.stdout);
    assert.equal(r.calls.filter((c) => c.mutation).length, 0);
  });
});

describe('run and connector fixes', () => {
  test('a bad --timeout is a usage error', () => {
    const r = runScript('skills/execution/scripts/run.mjs', ['watch', '--execution', 'x', '--timeout', '5m'], { rules: authRules() });
    assert.equal(r.status, 2);
  });

  test('verify refuses secret-looking inputs before calling the vendor', () => {
    const rules = [...authRules(), { match: { op: 'connection' }, respond: { json: { data: { connection: { id: 'CN', name: 'ZZ Test c', authType: 'None', connector: { id: 'C1', name: 'ZZTest_FirstEpss' } } } } } }, { match: { op: 'connector' }, respond: { json: { data: { connector: null }, errors: [{ message: 'C5: unable to get connector from database' }] } } }];
    const r = runScript('skills/connectors/scripts/connector.mjs', ['verify', 'examples/connectors/first-epss/connector.yaml', '--connection', 'CN', '--action', 'getScores', '--inputs', '{"cves":["CVE-2021-44228"],"api_key":"abcdefgh12345"}', '--yes'], { rules });
    assert.equal(r.status, 2, r.stdout);
    assert.equal(r.calls.filter((c) => c.mutation).length, 0);
  });
});

describe('ledger lock', () => {
  test('parallel writers keep every entry', async () => {
    const stateDir = tempDir();
    startRun({ env: { SOPHOS_FUSION_STATE_DIR: stateDir } });
    const script = `import { record } from ${JSON.stringify(pathToFileURL(path.join(ROOT, 'lib/ledger.mjs')).href)};\nfor (let i = 0; i < 15; i++) record({ kind: 'connection', id: process.argv[2] + '-' + i, name: 'n', tenantId: 't', profile: 'p' }, { env: { SOPHOS_FUSION_STATE_DIR: ${JSON.stringify(stateDir)} } });`;
    const file = path.join(stateDir, 'writer.mjs');
    fs.writeFileSync(file, script);
    await Promise.all(['a', 'b', 'c', 'd'].map((w) => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [file, w]);
      child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`writer ${w} exited ${code}`))));
    })));
    const objs = Object.values(readLedger({ SOPHOS_FUSION_STATE_DIR: stateDir }).runs).flatMap((r) => r.objects);
    assert.equal(objs.length, 60);
    assert.equal(new Set(objs.map((o) => o.seq)).size, 60);
    assert.ok(!fs.existsSync(path.join(stateDir, 'ledger.lock')));
  });

  void record;
});
