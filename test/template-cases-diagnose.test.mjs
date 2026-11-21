import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { makeTestCopy, extractDsl, normalizeForDiff, diffValues, dependencyList, testName } from '../lib/template.mjs';
import { loadYaml } from '../lib/yamlx.mjs';
import { toCelLiteral, withBindings, loadCases, offlineCheck, runCases, truthTable } from '../lib/cel-cases.mjs';
import { parseCel } from '../lib/cel.mjs';
import { diagnose, templateMarkers, logTask } from '../lib/diagnose.mjs';
import { scaffoldPlaybook, scaffoldConnector } from '../lib/scaffold.mjs';
import { validateText } from '../lib/rules.mjs';
import { authRules, FAKE, ROOT, runScript } from './helpers/scenario.mjs';

const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

describe('test copies', () => {
  test('rename the template and title, drop tenantId, map connectors in the list and in actions', () => {
    const text = read('examples/playbooks/closed-case-detection-note/template.yaml').replace('kind: Playbook\n', 'kind: Playbook\ntenantId: "999"\n');
    const copy = makeTestCopy(text, { connectorMap: { 'Taegis.Case': 'ZZTest_Case' } });
    const v = loadYaml(copy.text).value;
    assert.equal(v.name, 'ZZTest_ClosedCaseDetectionNote');
    assert.equal(v.title, 'ZZ Test Closed case detection note');
    assert.equal(v.tenantId, undefined);
    assert.deepEqual(v.connectors, ['ZZTest_Case:1.0.5']);
    assert.ok(v.dsl.tasks.filter((t) => t.action).every((t) => t.action.startsWith('ZZTest_Case.')));
    assert.ok(copy.changes.some((c) => c.field === 'tenantId'));
  });

  test('keeps quote styles, so single-quoted literals stay literals', () => {
    const copy = makeTestCopy(read('examples/playbooks/case-reference-lookup/template.yaml'));
    assert.match(copy.text, /source: 'Fusion case reference data'/);
  });

  test('does not prefix twice', () => {
    assert.equal(testName('ZZTest_X'), 'ZZTest_X');
    assert.equal(makeTestCopy(makeTestCopy(read('examples/connectors/first-epss/connector.yaml')).text).name, 'ZZTest_FirstEpss');
  });

  test('dependency lists split name and version', () => {
    assert.deepEqual(dependencyList({ connectors: ['Taegis.Case:1.0.5'] }, 'connectors'), [{ name: 'Taegis.Case', version: '1.0.5', entry: 'Taegis.Case:1.0.5' }]);
  });
});

describe('dsl extraction for the tenant check', () => {
  test('cuts the dsl block out unchanged and maps lines back', () => {
    const text = read('examples/playbooks/case-reference-lookup/template.yaml');
    const { yaml, lineOffset } = extractDsl(text);
    const dsl = loadYaml(yaml).value;
    assert.equal(dsl.name, 'CaseReferenceLookup');
    const firstTaskLine = yaml.split('\n').findIndex((l) => l.includes('name: get_types')) + 1;
    assert.match(text.split('\n')[firstTaskLine + lineOffset - 1], /name: get_types/);
    assert.match(yaml, /source: 'Fusion case reference data'/);
  });
});

describe('export and diff', () => {
  test('ignores tenant fields and the test prefix', () => {
    const local = loadYaml(read('examples/playbooks/case-reference-lookup/template.yaml')).value;
    const remote = { ...JSON.parse(JSON.stringify(local)), name: 'ZZTest_CaseReferenceLookup', title: 'ZZ Test Case reference lookup', tenantId: '5000', icon: 'abc', isCentralTenantVisible: false };
    assert.deepEqual(diffValues(normalizeForDiff(local), normalizeForDiff(remote)), []);
  });

  test('reports real differences with their path', () => {
    const a = { dsl: { tasks: [{ name: 'x', let: { v: 'a.b' } }] } };
    const b = { dsl: { tasks: [{ name: 'x', let: { v: 'a.c' } }] } };
    assert.deepEqual(diffValues(normalizeForDiff(a), normalizeForDiff(b)).map((d) => d.path), ['$.dsl.tasks[0].let.v']);
  });
});

describe('CEL cases', () => {
  test('JSON values become CEL literals that parse', () => {
    const lit = toCelLiteral({ s: "it's", n: 3, f: 0.5, b: true, z: null, l: [1, 'a'], nested: { k: 'line\nbreak' } });
    assert.equal(parseCel(lit).ok, true, lit);
    assert.equal(toCelLiteral(2), '2');
    assert.equal(toCelLiteral(0.6), '0.6');
  });

  test('bindings wrap CEL in cel.bind, and wrap each part of a template', () => {
    assert.equal(withBindings('t.outputs.x + 1', { t: { outputs: { x: 1 } } }), "cel.bind(t, {'outputs': {'x': 1}}, t.outputs.x + 1)");
    assert.equal(withBindings('n=${t.v} m=${u}', { t: { v: 2 } }), "n=${cel.bind(t, {'v': 2}, t.v)} m=${cel.bind(t, {'v': 2}, u)}");
    assert.equal(withBindings('a', null), 'a');
  });

  test('every example cases file loads, resolves its "from" paths, and parses', () => {
    for (const dir of ['case-reference-lookup', 'closed-case-detection-note', 'case-ip-threat-feed-block']) {
      const cases = loadCases(path.join(ROOT, 'examples/playbooks', dir, 'cel-cases.json'));
      assert.ok(cases.cases.length >= 10, dir);
      assert.ok(offlineCheck(cases).every((r) => r.ok), dir);
    }
  });

  test('a "from" that points at a single-quoted literal is refused', () => {
    const dir = fs.mkdtempSync(path.join(ROOT, 'test', '.tmp-'));
    try {
      fs.copyFileSync(path.join(ROOT, 'examples/playbooks/case-reference-lookup/template.yaml'), path.join(dir, 'template.yaml'));
      fs.writeFileSync(path.join(dir, 'c.json'), JSON.stringify({ template: 'template.yaml', cases: [{ name: 'x', from: 'dsl.outputs.source', expect: 1 }] }));
      assert.throws(() => loadCases(path.join(dir, 'c.json')), /single-quoted literal/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('runCases builds a truth table from Fusion answers', async () => {
    const cases = { cases: [{ name: 'a', expression: 'inputs.x', inputs: { x: 1 }, expect: 1 }, { name: 'b', expression: 'inputs.x', inputs: { x: 2 }, expect: 1 }, { name: 'c', expression: '1/0', expectError: true }] };
    const answers = [{ output: 1, errorMessage: '' }, { output: 2, errorMessage: '' }, { output: null, errorMessage: 'division by zero' }];
    const client = { request: async () => ({ data: { evaluateExpr: answers.shift() }, warnings: [] }) };
    const rows = await runCases(client, cases);
    assert.deepEqual(rows.map((r) => r.result), ['PASS', 'FAIL', 'PASS']);
    assert.match(truthTable(rows), /case +\| expect +\| got +\| result/);
  });
});

describe('diagnosis', () => {
  test('a Completed run with outcome UNKNOWN is called out', () => {
    const f = diagnose({ state: 'Completed', outcomeStatus: 'UNKNOWN' }, []);
    assert.ok(f.some((x) => x.kind === 'silent_outcome'));
  });

  test('task errors are read from the log', () => {
    const logs = [{ taskID: 1, message: { task: 'add_note', status: { Completion: 'Failure', Error: 'no such key: outputs' } } }];
    const f = diagnose({ state: 'Failed', outcomeStatus: 'FAIL', outcomeMessage: 'x' }, logs);
    const kinds = f.map((x) => x.kind);
    assert.ok(kinds.includes('failed_tasks') && kinds.includes('no_such_key') && kinds.includes('outcome_fail'));
    assert.equal(logTask(logs[0]).name, 'add_note');
  });

  test('words in response data are not mistaken for errors', () => {
    const logs = [{ taskID: 1, message: { task: 'get_types', status: { Completion: 'Success', Error: '' }, outputs: { description: 'stolen credentials, 401 attempts' } } }];
    assert.deepEqual(diagnose({ state: 'Completed', outcomeStatus: 'SUCCESS' }, logs).map((x) => x.kind), ['ok']);
  });

  test('connection failures and REAUTH are explained', () => {
    const f = diagnose({ state: 'Failed', outputs: 'connection not found for connector Taegis.Case; REAUTH_REQUIRED' }, []);
    assert.ok(f.some((x) => x.kind === 'connection'));
    assert.ok(f.some((x) => x.kind === 'reauth'));
  });

  test('secrets in a log are flagged', () => {
    const logs = [{ taskID: 1, message: { task: 'post', status: { Completion: 'Success' }, request: { url: 'https://hooks.slack.com/services/T0/B0/abcdefgh' } } }];
    assert.ok(diagnose({ state: 'Completed', outcomeStatus: 'SUCCESS' }, logs).some((x) => x.kind === 'secret_in_log'));
  });

  test('the client ID in a case event is an identifier, not a secret, in logs and diagnose', () => {
    // A close event made by the API credential: Fusion records its client ID as the creator, updater, and closer
    const actor = FAKE.clientId;
    const logs = [
      { id: 'L0', taskID: 0, parentID: null, message: { inputs: { case: { createdById: actor, updatedById: actor, contributorIds: [actor], delta: { changes: { closed_by_id: { before: null, after: actor } } } } } }, createdAt: '2026-01-01T00:00:00Z' },
      { id: 'L1', taskID: 1, parentID: null, message: { task: 'add_note', taskType: 'action', status: { Completion: 'Success' } }, createdAt: '2026-01-01T00:00:01Z' },
    ];
    const execution = { id: 'E1', state: 'Completed', outcomeStatus: 'SUCCESS', outcomeMessage: 'noted', inputs: {}, outputs: {}, summary: null, events: [] };
    const rules = [
      ...authRules(),
      { match: { op: 'playbookExecutionLogs' }, respond: { json: { data: { playbookExecutionLogs: logs } } } },
      { match: { op: 'playbookExecution' }, respond: { json: { data: { playbookExecution: execution } } } },
    ];
    const l = runScript('skills/execution/scripts/run.mjs', ['logs', '--execution', 'E1', '--raw'], { rules });
    assert.equal(l.status, 0, l.stdout);
    assert.deepEqual(l.json.secretLooking, []);
    assert.equal(l.json.identifiers.length, 4);
    assert.ok(l.json.identifiers.every((i) => i.identifier === 'client ID'));
    assert.ok(!l.stdout.includes(actor), 'the client ID is not printed');
    assert.equal(l.json.logs[0].message.inputs.case.createdById, '[client ID]');
    const d = runScript('skills/execution/scripts/run.mjs', ['diagnose', '--execution', 'E1'], { rules });
    assert.equal(d.status, 0, d.stdout);
    assert.deepEqual(d.json.findings.map((f) => f.kind), ['ok', 'identifier_in_log']);
    assert.match(d.json.findings[1].message, /client ID in 4 place\(s\).*not a secret/);
  });

  test('a run whose record is gone is diagnosed from its log', () => {
    const logs = [
      { taskID: 0, message: {} },
      { taskID: 1, message: { task: 'post', status: { Completion: 'Failure', Error: 'no such key: outputs' }, request: { url: 'https://hooks.slack.com/services/T0/B0/abcdefgh' } } },
    ];
    const kinds = diagnose(null, logs).map((x) => x.kind);
    assert.deepEqual(kinds, ['record_gone', 'failed_tasks', 'no_such_key', 'secret_in_log']);
    assert.deepEqual(diagnose(null, []).map((x) => x.kind), ['not_found']);
    // run.mjs diagnose reads the log even when Fusion answers PB21 for the run itself
    const rules = [
      ...authRules(),
      { match: { op: 'playbookExecutionLogs' }, respond: { json: { data: { playbookExecutionLogs: logs } } } },
      { match: { op: 'playbookExecution' }, respond: { json: { data: { playbookExecution: null }, errors: [{ message: 'PB21: Unable to get playbook execution: record not found', path: ['playbookExecution'] }] } } },
    ];
    // diagnose waits up to 15 s for a run that has just finished to show, so this test takes that long
    const r = runScript('skills/execution/scripts/run.mjs', ['diagnose', '--execution', 'E1'], { rules });
    assert.equal(r.status, 0, r.stdout);
    assert.equal(r.json.execution, null);
    assert.deepEqual(r.json.findings.map((x) => x.kind), ['record_gone', 'failed_tasks', 'no_such_key', 'secret_in_log']);
    assert.deepEqual(r.json.failedTasks, [{ name: 'post', state: 'Failure', reason: 'no such key: outputs' }]);
  });

  test('an unknown run is not_found even if the log read answers not found too', () => {
    const notFound = (op) => ({ match: { op }, respond: { json: { data: { [op]: null }, errors: [{ message: 'PB21: record not found', path: [op] }] } } });
    // diagnose waits up to 15 s for a run that has just finished to show, so this test takes that long
    const r = runScript('skills/execution/scripts/run.mjs', ['diagnose', '--execution', 'nope'], { rules: [...authRules(), notFound('playbookExecutionLogs'), notFound('playbookExecution')] });
    assert.equal(r.status, 0, r.stdout);
    assert.deepEqual(r.json.findings.map((x) => x.kind), ['not_found']);
  });

  test('the client secret in a log is still a secret', () => {
    const logs = [{ id: 'L0', taskID: 0, parentID: null, message: { inputs: { case: { createdById: FAKE.clientId, note: `oops ${FAKE.clientSecret}` } } }, createdAt: '2026-01-01T00:00:00Z' }];
    const rules = [...authRules(), { match: { op: 'playbookExecutionLogs' }, respond: { json: { data: { playbookExecutionLogs: logs } } } }];
    const l = runScript('skills/execution/scripts/run.mjs', ['logs', '--execution', 'E1'], { rules });
    assert.equal(l.status, 0, l.stdout);
    assert.deepEqual(l.json.secretLooking.map((x) => [x.kind, x.path]), [['known_secret', '$[0].message.inputs.case.note']]);
    assert.deepEqual(l.json.identifiers.map((x) => x.path), ['$[0].message.inputs.case.createdById']);
    assert.ok(!l.stdout.includes(FAKE.clientSecret));
  });

  test('run parameters holding ${ are found before they reach Fusion', () => {
    assert.deepEqual(templateMarkers({ a: 'ok', b: ['x ${y}'], c: { d: '${z}' } }), ['$.b[0]', '$.c.d']);
  });
});

describe('scaffolds', () => {
  for (const tier of ['lookup', 'notify', 'response']) {
    for (const trigger of ['generic', 'platform', 'actions']) {
      test(`playbook ${tier}/${trigger} passes offline validation`, () => {
        const r = validateText(scaffoldPlaybook({ name: `S_${tier}_${trigger}`, title: 'Scaffold test', tier, trigger }));
        assert.equal(r.errors, 0, JSON.stringify(r.findings));
        assert.equal(r.warnings, 0, JSON.stringify(r.findings));
      });
    }
  }

  test('connector skeletons pass offline validation and declare their host', () => {
    for (const auth of ['None', 'APIKey', 'Basic']) {
      const text = scaffoldConnector({ name: 'Acme_Thing', title: 'Acme', baseUrl: 'https://api.acme.example/v1', auth });
      const r = validateText(text);
      assert.equal(r.errors, 0, JSON.stringify(r.findings));
      assert.match(text, /- api\.acme\.example/);
    }
    assert.throws(() => scaffoldConnector({ name: 'A', title: 'A', baseUrl: 'http://insecure.example' }), /https/);
  });
});

describe('every script', () => {
  const scripts = [
    'skills/setup/scripts/profile.mjs',
    'skills/authoring/scripts/catalog.mjs',
    'skills/authoring/scripts/scaffold.mjs',
    'skills/validation/scripts/validate.mjs',
    'skills/deployment/scripts/deploy.mjs',
    'skills/deployment/scripts/ledger.mjs',
    'skills/execution/scripts/run.mjs',
    'skills/connectors/scripts/connector.mjs',
  ];
  for (const s of scripts) {
    test(`${s} has --help for itself and each command`, () => {
      const top = spawnSync(process.execPath, [path.join(ROOT, s), '--help'], { encoding: 'utf8' });
      assert.equal(top.status, 0);
      assert.match(top.stdout, /Usage: node /);
      const commands = [...top.stdout.matchAll(/^ {2}([a-z][a-z-]+) {2,}/gm)].map((m) => m[1]);
      assert.ok(commands.length >= 1);
      for (const c of commands) {
        const sub = spawnSync(process.execPath, [path.join(ROOT, s), c, '--help'], { encoding: 'utf8' });
        assert.equal(sub.status, 0, `${s} ${c}`);
        assert.match(sub.stdout, /Options:/);
      }
    });

    test(`${s} answers an unknown command with JSON and exit 2`, () => {
      const r = spawnSync(process.execPath, [path.join(ROOT, s), 'no-such-command'], { encoding: 'utf8' });
      assert.equal(r.status, 2);
      assert.equal(JSON.parse(r.stdout).error.code, 'usage');
    });
  }

  test('offline validation runs with no credentials at all', () => {
    const empty = path.join(os.tmpdir(), 'sfs-no-home-does-not-exist');
    const env = { PATH: process.env.PATH, HOME: empty, USERPROFILE: empty, SOPHOS_FUSION_CONFIG_DIR: path.join(empty, 'config'), SOPHOS_FUSION_STATE_DIR: path.join(empty, 'state') };
    const r = spawnSync(process.execPath, [path.join(ROOT, 'skills/validation/scripts/validate.mjs'), 'all', path.join(ROOT, 'examples')], { encoding: 'utf8', env });
    assert.equal(r.status, 0, r.stdout);
    assert.equal(JSON.parse(r.stdout).ok, true);
  });
});
