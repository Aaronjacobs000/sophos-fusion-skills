import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { requireWrite, runCli } from '../lib/cli.mjs';
import { GateError } from '../lib/errors.mjs';
import { record, readLedger, rollbackOrder, startRun, resolveRun, markObject, liveObjects, isRecorded } from '../lib/ledger.mjs';
import { setQuiet } from '../lib/log.mjs';
import { authRules, runScript, tempDir, FAKE } from './helpers/scenario.mjs';

setQuiet(true);

describe('the write gate', () => {
  const test_ = { name: 'lab', kind: 'test', tenantId: null };
  const prod = { name: 'live', kind: 'production', tenantId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', label: null };

  test('a write without --yes is refused', () => {
    assert.throws(() => requireWrite({}, test_, 'importing x'), (e) => e instanceof GateError && e.exitCode === 3 && /--yes/.test(e.message));
  });

  test('a test profile needs only --yes', () => {
    assert.doesNotThrow(() => requireWrite({ yes: true }, test_, 'importing x'));
  });

  test('a production profile also needs --production, and names the tenant', () => {
    assert.throws(() => requireWrite({ yes: true }, prod, 'importing x'), (e) => e instanceof GateError && /production/.test(e.message) && e.message.includes(prod.tenantId) && e.details.needs.includes('--production'));
    assert.throws(() => requireWrite({ production: true }, prod, 'importing x'), GateError);
    assert.doesNotThrow(() => requireWrite({ yes: true, production: true }, prod, 'importing x'));
  });

  test('runCli checks the gate before the command runs', async () => {
    let ran = false;
    const spec = { name: 't.mjs', summary: 's', subcommands: { go: { summary: 'a write', write: true, run: async () => { ran = true; return {}; } } } };
    const out = [];
    const write = process.stdout.write;
    process.stdout.write = (s) => out.push(s) && true;
    try {
      const code = await runCli(spec, ['go'], { SOPHOS_FUSION_CLIENT_ID: 'a', SOPHOS_FUSION_CLIENT_SECRET: 'b', SOPHOS_FUSION_PROFILE_KIND: 'test' });
      assert.equal(code, 3);
      assert.equal(ran, false);
      assert.equal(JSON.parse(out.join('')).error.code, 'write_not_confirmed');
      const code2 = await runCli(spec, ['go', '--yes'], { SOPHOS_FUSION_CLIENT_ID: 'a', SOPHOS_FUSION_CLIENT_SECRET: 'b', SOPHOS_FUSION_PROFILE_KIND: 'test' });
      assert.equal(code2, 0);
      assert.equal(ran, true);
    } finally {
      process.stdout.write = write;
    }
  });
});

describe('the gate in the real scripts sends nothing', () => {
  const writes = [
    ['skills/deployment/scripts/deploy.mjs', ['import', 'examples/playbooks/case-reference-lookup/template.yaml']],
    ['skills/deployment/scripts/deploy.mjs', ['connection-create', '--connector', 'X', '--name', 'ZZ Test x', '--auth-type', 'None']],
    ['skills/deployment/scripts/deploy.mjs', ['instance-create', '--template', 'X', '--name', 'ZZ Test x', '--trigger', 'generic']],
    ['skills/deployment/scripts/deploy.mjs', ['enable', '--instance', 'abc']],
    ['skills/deployment/scripts/deploy.mjs', ['delete', '--kind', 'playbook', '--id', 'abc']],
    ['skills/deployment/scripts/deploy.mjs', ['schedule-create', '--instance', 'abc', '--name', 'ZZ Test s', '--cron', '0 7 * * 1']],
    ['skills/deployment/scripts/ledger.mjs', ['rollback']],
    ['skills/execution/scripts/run.mjs', ['execute', '--instance', 'abc']],
    ['skills/execution/scripts/run.mjs', ['cancel', '--execution', 'abc']],
    ['skills/connectors/scripts/connector.mjs', ['test-action', '--connection', 'abc', '--action', 'validate']],
    ['skills/validation/scripts/validate.mjs', ['connection', '--connector', 'X']],
  ];

  for (const [script, args] of writes) {
    test(`${path.basename(script)} ${args[0]} without --yes: exit 3, no request`, () => {
      const r = runScript(script, args, { rules: authRules() });
      assert.equal(r.status, 3, r.stderr);
      assert.equal(r.json.error.code, 'write_not_confirmed');
      assert.equal(r.calls.length, 0);
    });
  }

  test('a production profile with --yes alone is refused, with no request', () => {
    const r = runScript('skills/deployment/scripts/deploy.mjs', ['enable', '--instance', 'abc', '--yes'], { rules: authRules(), kind: 'production' });
    assert.equal(r.status, 3);
    assert.deepEqual(r.json.error.details.needs, ['--yes', '--production']);
    assert.equal(r.calls.length, 0);
  });

  test('changing an object the scripts did not create needs --allow-existing', () => {
    const r = runScript('skills/deployment/scripts/deploy.mjs', ['enable', '--instance', 'not-in-ledger', '--yes'], { rules: authRules() });
    assert.equal(r.status, 2);
    assert.match(r.json.error.message, /not in the ledger/);
    assert.equal(r.calls.length, 0);
  });
});

describe('the ledger', () => {
  const env = () => ({ SOPHOS_FUSION_STATE_DIR: tempDir() });

  test('records objects in order under the current run', () => {
    const e = env();
    const run = startRun({ label: 't', env: e });
    record({ kind: 'playbook', id: 'p1', name: 'ZZTest_A', tenantId: 't', profile: 'lab' }, { env: e });
    record({ kind: 'instance', id: 'i1', name: 'ZZ Test a', tenantId: 't', profile: 'lab', parentId: 'p1' }, { env: e });
    const objs = readLedger(e).runs[run.id].objects;
    assert.deepEqual(objs.map((o) => [o.seq, o.kind, o.status]), [[1, 'playbook', 'live'], [2, 'instance', 'live']]);
    assert.equal(isRecorded('instance', 'i1', e), true);
    assert.equal(isRecorded('instance', 'other', e), false);
  });

  test('resolveRun starts a run when there is none, and keeps named runs', () => {
    const e = env();
    const id = resolveRun(null, e);
    assert.match(id, /^run-\d{8}-\d{6}-[0-9a-f]{4}$/);
    assert.equal(resolveRun(null, e), id);
    assert.equal(resolveRun('named-run', e), 'named-run');
  });

  test('rollback order is newest first', () => {
    const objs = [
      { seq: 1, kind: 'connector', id: 'c', status: 'live' },
      { seq: 2, kind: 'connection', id: 'cn', parentId: 'c', status: 'live' },
      { seq: 3, kind: 'playbook', id: 'p', status: 'live' },
      { seq: 4, kind: 'instance', id: 'i', parentId: 'p', status: 'live' },
      { seq: 5, kind: 'schedule', id: 's', parentId: 'i', status: 'live' },
      { seq: 6, kind: 'playbook', id: 'gone', status: 'deleted' },
    ];
    assert.deepEqual(rollbackOrder(objs).map((o) => o.id), ['s', 'i', 'p', 'cn', 'c']);
  });

  test('children go before their parent even when recorded out of order', () => {
    const objs = [
      { seq: 1, kind: 'instance', id: 'i', parentId: 'p', status: 'live' },
      { seq: 2, kind: 'playbook', id: 'p', status: 'live' },
      { seq: 3, kind: 'schedule', id: 's', parentId: 'i', status: 'delete_failed' },
    ];
    const order = rollbackOrder(objs).map((o) => o.id);
    assert.ok(order.indexOf('s') < order.indexOf('i'));
    assert.ok(order.indexOf('i') < order.indexOf('p'));
  });

  test('marking objects changes what is live', () => {
    const e = env();
    const run = startRun({ env: e });
    const a = record({ kind: 'playbook', id: 'p1', name: 'n', tenantId: 't', profile: 'x' }, { env: e });
    record({ kind: 'playbook', id: 'p2', name: 'm', tenantId: 't', profile: 'x' }, { env: e });
    markObject(run.id, a.seq, 'deleted', null, e);
    assert.deepEqual(liveObjects(e).map((o) => o.id), ['p2']);
  });
});

describe('rollback through the real script', () => {
  function seedLedger(stateDir) {
    const e = { SOPHOS_FUSION_STATE_DIR: stateDir };
    const run = startRun({ label: 'seed', env: e });
    record({ kind: 'connector', id: 'C1', name: 'ZZTest_Conn', tenantId: FAKE.tenantId, profile: 'env' }, { env: e });
    record({ kind: 'connection', id: 'CN1', name: 'ZZ Test conn', tenantId: FAKE.tenantId, profile: 'env', parentId: 'C1' }, { env: e });
    record({ kind: 'playbook', id: 'P1', name: 'ZZTest_Play', tenantId: FAKE.tenantId, profile: 'env' }, { env: e });
    record({ kind: 'instance', id: 'I1', name: 'ZZ Test play', tenantId: FAKE.tenantId, profile: 'env', parentId: 'P1' }, { env: e });
    return run.id;
  }

  test('deletes newest first, reads each delete back, and empties the run', () => {
    const stateDir = tempDir();
    const runId = seedLedger(stateDir);
    const rules = [
      ...authRules(),
      { match: { op: 'playbookInstance' }, responses: [{ json: { data: { playbookInstance: { id: 'I1', name: 'ZZ Test play' } } } }, { json: { data: { playbookInstance: null } } }] },
      { match: { op: 'deletePlaybookInstance' }, respond: { json: { data: { deletePlaybookInstance: { id: 'I1', name: 'ZZ Test play' } } } } },
      { match: { op: 'playbook' }, responses: [{ json: { data: { playbook: { id: 'P1', name: 'ZZTest_Play', head: {}, versions: [], instances: [] } } } }, { json: { data: { playbook: null }, errors: [{ message: 'PB21: record not found' }] } }] },
      { match: { op: 'deletePlaybook' }, respond: { json: { data: { deletePlaybook: { id: 'P1', name: 'ZZTest_Play' } } } } },
      { match: { op: 'connection' }, responses: [{ json: { data: { connection: { id: 'CN1', name: 'ZZ Test conn' } } } }, { json: { data: { connection: null } } }] },
      { match: { op: 'deleteConnection' }, respond: { json: { data: { deleteConnection: { id: 'CN1', name: 'ZZ Test conn' } } } } },
      { match: { op: 'connector' }, responses: [{ json: { data: { connector: { id: 'C1', name: 'ZZTest_Conn', head: {}, versions: [], connections: [] } } } }, { json: { data: { connector: null }, errors: [{ message: 'C5: unable to get connector from database' }] } }] },
      { match: { op: 'deleteConnector' }, respond: { json: { data: { deleteConnector: { id: 'C1', name: 'ZZTest_Conn' } } } } },
    ];
    const r = runScript('skills/deployment/scripts/ledger.mjs', ['rollback', '--yes'], { rules, stateDir });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.deepEqual(r.json.results.map((x) => [x.kind, x.result]), [['instance', 'deleted'], ['playbook', 'deleted'], ['connection', 'deleted'], ['connector', 'deleted']]);
    const deletes = r.calls.filter((c) => c.mutation).map((c) => c.op);
    assert.deepEqual(deletes, ['deletePlaybookInstance', 'deletePlaybook', 'deleteConnection', 'deleteConnector']);
    const ledger = readLedger({ SOPHOS_FUSION_STATE_DIR: stateDir });
    assert.ok(ledger.runs[runId].objects.every((o) => o.status === 'deleted'));
  });

  test('a delete that does not take shows as still there, and the run stays live', () => {
    const stateDir = tempDir();
    const e = { SOPHOS_FUSION_STATE_DIR: stateDir };
    startRun({ env: e });
    record({ kind: 'connection', id: 'CN1', name: 'ZZ Test conn', tenantId: FAKE.tenantId, profile: 'env' }, { env: e });
    const rules = [
      ...authRules(),
      { match: { op: 'connection' }, respond: { json: { data: { connection: { id: 'CN1', name: 'ZZ Test conn' } } } } },
      { match: { op: 'deleteConnection' }, respond: { json: { data: { deleteConnection: { id: 'CN1' } } } } },
    ];
    const r = runScript('skills/deployment/scripts/ledger.mjs', ['rollback', '--yes'], { rules, stateDir, env: { SOPHOS_FUSION_READBACK_MS: '300' } });
    assert.equal(r.status, 1);
    assert.equal(r.json.results[0].result, 'still there');
    assert.equal(liveObjects(e).length, 1);
  });

  test('an object renamed since it was recorded is skipped, not deleted', () => {
    const stateDir = tempDir();
    const e = { SOPHOS_FUSION_STATE_DIR: stateDir };
    startRun({ env: e });
    record({ kind: 'connection', id: 'CN1', name: 'ZZ Test conn', tenantId: FAKE.tenantId, profile: 'env' }, { env: e });
    const rules = [...authRules(), { match: { op: 'connection' }, respond: { json: { data: { connection: { id: 'CN1', name: 'Production webhook' } } } } }];
    const r = runScript('skills/deployment/scripts/ledger.mjs', ['rollback', '--yes'], { rules, stateDir });
    assert.equal(r.json.results[0].result, 'skipped');
    assert.equal(r.calls.filter((c) => c.mutation).length, 0);
  });

  test('a run made on another tenant is refused', () => {
    const stateDir = tempDir();
    const e = { SOPHOS_FUSION_STATE_DIR: stateDir };
    startRun({ env: e });
    record({ kind: 'connection', id: 'CN1', name: 'ZZ Test conn', tenantId: 'another-tenant', profile: 'other' }, { env: e });
    const r = runScript('skills/deployment/scripts/ledger.mjs', ['rollback', '--yes'], { rules: authRules(), stateDir });
    assert.equal(r.json.error.code, 'wrong_tenant');
    assert.equal(r.calls.filter((c) => c.mutation).length, 0);
  });

  test('plan lists the order without calling Sophos', () => {
    const stateDir = tempDir();
    seedLedger(stateDir);
    const r = runScript('skills/deployment/scripts/ledger.mjs', ['plan'], { stateDir });
    assert.deepEqual(r.json.order.map((o) => o.id), ['I1', 'P1', 'CN1', 'C1']);
    assert.equal(r.calls.length, 0);
    assert.ok(fs.existsSync(path.join(stateDir, 'ledger.json')));
  });
});
