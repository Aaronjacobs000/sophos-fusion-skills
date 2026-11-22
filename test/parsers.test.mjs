import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import * as P from '../lib/parsers.mjs';
import { readLedger, record, startRun } from '../lib/ledger.mjs';
import { setQuiet } from '../lib/log.mjs';
import { enumNumbers, schemaInfo, typeKind } from '../lib/xsl.mjs';
import { fakeClient } from './helpers/fake-client.mjs';
import { authRules, FAKE, ROOT, runScript, tempDir } from './helpers/scenario.mjs';

setQuiet(true);

const EXAMPLE = path.join(ROOT, 'examples', 'parsers', 'opencanary');
const SCRIPT = 'skills/parsers/scripts/parser.mjs';
const folder = P.loadParserFolder(EXAMPLE);
const PARENT = folder.parsers.find((p) => p.role === 'parent');
const CHILD = folder.parsers.find((p) => p.role === 'child');
const TEMPLATE = '!CONFIRMWITH=PATTERN\n#!CONFIRMSTRING=<<your regex here>>\n';
const FAST = { SOPHOS_FUSION_READBACK_MS: '400' };

const parser = (id, name, { code = TEMPLATE, disabled = true, parentId = 0 } = {}) => ({ id, name, parentId, disabled, overrideGlobal: false, code });
const gql = (data) => ({ json: { data } });

/** A fake tenant engine: the vendored emulator, with enum names turned back into numbers as sampleParser answers. */
function engineAnswer(code, name, lines, { tweak = null, now = '2026-11-22T00:00:00Z' } = {}) {
  const res = P.emulate({ ...folder, parsers: [{ name, role: 'standalone', text: code, schema: 'x' }] }, lines, { now });
  return res.map((r) => {
    if (!r.extractor_path) return { message: r.sample, results: [{ schema: '(None)', extractors: 'Master', errors: null, fields: [], variables: [] }] };
    const schema = P.firstSchema(r.schema);
    const defs = schemaInfo(schema)?.fields || [];
    const rec = { ...(r.normalized || {}), ...(tweak ? tweak(r) : {}) };
    const fields = Object.entries(rec).map(([k, v]) => {
      const def = defs.find((d) => d.name === k);
      if (def && typeKind(def.type) === 'enum' && typeof v === 'string') {
        const num = Object.entries(enumNumbers(def.type)).find(([, n]) => n === v)?.[0];
        return { destination: k, value: num === undefined ? v : Number(num) };
      }
      return { destination: k, value: v };
    });
    fields.push({ destination: 'tenant_id', value: '1' }, { destination: 'ingest_time_usec', value: 1795309441000000 });
    return { message: r.sample, results: [{ schema, extractors: `Master -> ${r.extractor_path.split(' > ').pop()}`, errors: null, fields, variables: [] }] };
  });
}

function fakeTenant({ schemas = null, builtIn = null, tweak = null } = {}) {
  return fakeClient({
    parserSchemas: () => schemas || ['scwx.generic', 'scwx.thirdpartyalert', 'scwx.auth', 'xdr.findings.detectionfinding'],
    allParsers: () => [],
    validateParser: () => ({ ok: true, message: '' }),
    sampleParser: (v) => {
      if (!v.p) return v.m.map((m, i) => ({ message: m, results: [{ schema: builtIn && builtIn(m, i) ? 'scwx.thirdpartyalert' : '(None)', extractors: builtIn && builtIn(m, i) ? 'Master -> BUILTIN_HONEYPOT' : 'Master', errors: null, fields: [], variables: [] }] }));
      return engineAnswer(v.p.code, v.p.name, v.m, { tweak });
    },
  });
}

describe('the offline check', () => {
  test('the OpenCanary example: 0 errors and output equal to expected.json', () => {
    const r = P.checkFolder(folder);
    assert.equal(r.errors, 0, JSON.stringify(r.problems));
    assert.deepEqual(r.expected, { matches: true, differences: 0 });
    assert.equal(r.summary.lines, 48);
    assert.equal(r.lines[11].enums.severity, 'HIGH');
    assert.ok(!JSON.stringify(r.lines).includes('198.51.100.23'), 'field values are not in the per-line report');
  });

  test('a !SAMPLE line that is not in samples.log is an error', () => {
    const f = { ...folder, parsers: folder.parsers.map((p) => (p === PARENT ? { ...p, text: p.text.replace(/^!SAMPLE=.*$/m, '!SAMPLE=<12>an unmasked line') } : p)) };
    assert.ok(P.checkFolder(f).problems.some((p) => p.code === 'sample-directive'));
  });

  test('a test confirm that picks other lines than the child takes is an error', () => {
    const f = { ...folder, testConfirms: { [CHILD.name]: '"logtype"' } };
    const r = P.checkFolder(f);
    assert.ok(r.problems.some((p) => p.code === 'test-confirm' && p.level === 'error' && /also picks lines/.test(p.message)));
  });

  test('a child of a built-in parser is refused in v1', () => {
    const f = { ...folder, parsers: [{ ...CHILD, parent: 'SOPHOS_BUILTIN_PARENT' }] };
    assert.ok(P.checkFolder(f).problems.some((p) => p.code === 'builtin-parent'));
  });

  test('flattening puts the parent body before the child with a PATTERN confirm', () => {
    const flat = P.flattenChild(PARENT.text, CHILD.text, 'X');
    assert.match(flat, /^!CONFIRMWITH=PATTERN\n!CONFIRMSTRING=X\n!SCHEMA=scwx\.thirdpartyalert\n!TRIMALLOFF\n/);
    assert.ok(flat.indexOf('sensorType$ = "OpenCanary"') < flat.indexOf('# Parser Studio', flat.indexOf('sensorType$')));
    assert.ok(!/^!SAMPLE=/m.test(flat));
  });
});

describe('records', () => {
  test('engine fields map onto the schema with enum names', () => {
    const r = P.engineRecord({ schema: 'scwx.thirdpartyalert', extractors: 'Master -> X', fields: [{ destination: 'severity', value: 4 }, { destination: 'event_time_fidelity', value: 3 }, { destination: 'title', value: 't' }] });
    assert.deepEqual(r.record, { severity: 'HIGH', event_time_fidelity: 'MICRO', title: 't' });
    assert.deepEqual(r.path, ['Master', 'X']);
  });

  test('comparison skips platform fields and unset values, and names each difference', () => {
    const d = P.compareRecords({ title: 'a', severity: 'HIGH', summary: '' }, { title: 'b', severity: 'HIGH', tenant_id: '1', protocol: 0, log_type: '5' }, 'scwx.thirdpartyalert');
    assert.deepEqual(d.map((x) => `${x.path} ${x.kind}`), ['log_type engineOnly', 'title differ']);
  });
});

describe('tenant check (read-only)', () => {
  test('every line lands on the expected parser and schema, with no differences', async () => {
    const c = fakeTenant();
    const r = await P.tenantCheck(c, folder);
    assert.equal(r.ok, true, JSON.stringify(r.problems));
    assert.equal(r.lines.length, 48);
    assert.ok(r.lines.every((l) => l.routeOk));
    assert.deepEqual(r.differences, {});
    assert.ok(c.calls.every((x) => !x.mutation), 'the tenant check sends no mutation');
    assert.ok(r.problems.some((p) => p.code === 'schema-data' && p.level === 'warning'), 'a schema the tenant has and the vendored data lacks is a warning');
  });

  test('a schema the tenant lacks is an error', async () => {
    const r = await P.tenantCheck(fakeTenant({ schemas: ['scwx.generic'] }), folder);
    assert.equal(r.ok, false);
    assert.ok(r.problems.some((p) => p.code === 'schema' && p.level === 'error' && p.parser === CHILD.name));
  });

  test('built-in parsers that take the lines already are named', async () => {
    const r = await P.tenantCheck(fakeTenant({ builtIn: (m, i) => i < 3 }), folder);
    assert.equal(r.builtIn.lines, 3);
    assert.deepEqual(r.builtIn.byParser, { BUILTIN_HONEYPOT: 3 });
    assert.ok(r.problems.some((p) => p.code === 'builtin-claim'));
  });

  test('engine and emulator differences are listed per field', async () => {
    const r = await P.tenantCheck(fakeTenant({ tweak: (x) => (P.firstSchema(x.schema) === 'scwx.thirdpartyalert' ? { title: 'engine title' } : {}) }), folder);
    assert.equal(r.differences['title (differ)'], 46);
  });
});

function seedParsers(stateDir, { sha = P.sha256(PARENT.text) } = {}) {
  const e = { SOPHOS_FUSION_STATE_DIR: stateDir };
  startRun({ env: e });
  record({ kind: 'parser', id: 100, name: `ZZTest_${PARENT.name}`, tenantId: FAKE.tenantId, profile: 'env', detail: { dir: EXAMPLE, localName: PARENT.name, role: 'parent', sha256: sha } }, { env: e });
  record({ kind: 'parser', id: 101, name: `ZZTest_${CHILD.name}`, tenantId: FAKE.tenantId, profile: 'env', parentId: 100, detail: { dir: EXAMPLE, localName: CHILD.name, role: 'child', sha256: P.sha256(CHILD.text) } }, { env: e });
  return e;
}

describe('the write gate in parser.mjs', () => {
  for (const args of [['install', EXAMPLE], ['enable', '--id', '100'], ['disable', '--id', '100'], ['update-code', EXAMPLE, '--id', '100']]) {
    test(`${args[0]} without --yes: exit 3, no request`, () => {
      const r = runScript(SCRIPT, args, { rules: authRules() });
      assert.equal(r.status, 3, r.stdout);
      assert.equal(r.calls.length, 0);
    });
  }

  test('a production profile also needs --production', () => {
    const r = runScript(SCRIPT, ['install', EXAMPLE, '--yes'], { rules: authRules(), kind: 'production' });
    assert.equal(r.status, 3);
    assert.deepEqual(r.json.error.details.needs, ['--yes', '--production']);
    assert.equal(r.calls.length, 0);
  });
});

describe('install', () => {
  test('createParser stored the template: the code is sent with updateParser while disabled, read back equal, and recorded', () => {
    const stateDir = tempDir();
    const rules = [
      ...authRules(),
      { match: { op: 'allParsers' }, respond: gql({ allParsers: [parser(7, 'Existing parser', { disabled: false })] }) },
      { match: { op: 'createParser' }, responses: [gql({ createParser: parser(100, `ZZTest_${PARENT.name}`) }), gql({ createParser: parser(101, `ZZTest_${CHILD.name}`, { parentId: 100 }) })] },
      {
        match: { op: 'parser' },
        responses: [
          gql({ parser: parser(100, `ZZTest_${PARENT.name}`) }),
          gql({ parser: parser(100, `ZZTest_${PARENT.name}`, { code: PARENT.text }) }),
          gql({ parser: parser(101, `ZZTest_${CHILD.name}`, { parentId: 100 }) }),
          gql({ parser: parser(101, `ZZTest_${CHILD.name}`, { parentId: 100, code: CHILD.text }) }),
        ],
      },
      { match: { op: 'updateParser' }, respond: gql({ updateParser: parser(100, 'x') }) },
    ];
    const r = runScript(SCRIPT, ['install', EXAMPLE, '--yes', '--quiet'], { rules, stateDir, env: FAST });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.deepEqual(r.json.installed.map((x) => [x.id, x.name, x.readBack.code, x.readBack.disabled]), [[100, `ZZTest_${PARENT.name}`, true, true], [101, `ZZTest_${CHILD.name}`, true, true]]);
    const creates = r.calls.filter((c) => c.op === 'createParser').map((c) => JSON.parse(c.body).variables.p);
    assert.deepEqual(creates.map((p) => [p.type, p.format, p.schema, p.parentId, p.disabled, p.overrideGlobal]), [['PARENT', 'JSON', 'scwx.generic', 0, true, false], ['CHILD', 'JSON', 'scwx.thirdpartyalert', 100, true, false]]);
    const updates = r.calls.filter((c) => c.op === 'updateParser').map((c) => JSON.parse(c.body).variables.u);
    assert.deepEqual(updates.map((u) => Object.keys(u)), [['code'], ['code']]);
    const objs = Object.values(readLedger({ SOPHOS_FUSION_STATE_DIR: stateDir }).runs)[0].objects;
    assert.deepEqual(objs.map((o) => [o.kind, o.id, o.parentId, o.detail.sha256 === P.sha256(o.id === 100 ? PARENT.text : CHILD.text)]), [['parser', 100, null, true], ['parser', 101, 100, true]]);
  });

  test('code that still differs after the update: the parser is deleted and the command fails', () => {
    const stateDir = tempDir();
    const rules = [
      ...authRules(),
      { match: { op: 'allParsers' }, responses: [gql({ allParsers: [] }), gql({ allParsers: [parser(100, `ZZTest_${PARENT.name}`)] }), gql({ allParsers: [] })] },
      { match: { op: 'createParser' }, respond: gql({ createParser: parser(100, `ZZTest_${PARENT.name}`) }) },
      { match: { op: 'parser' }, respond: gql({ parser: parser(100, `ZZTest_${PARENT.name}`) }) },
      { match: { op: 'updateParser' }, respond: gql({ updateParser: parser(100, 'x') }) },
      { match: { op: 'deleteParser' }, respond: gql({ deleteParser: { id: 100, name: 'x' } }) },
    ];
    const r = runScript(SCRIPT, ['install', EXAMPLE, '--yes', '--quiet'], { rules, stateDir, env: FAST });
    assert.equal(r.status, 1, r.stdout);
    assert.equal(r.json.error.code, 'code_not_saved');
    assert.equal(r.calls.filter((c) => c.op === 'deleteParser').length, 1);
    assert.equal(r.calls.filter((c) => c.op === 'createParser').length, 1, 'the child is not attempted');
    const objs = Object.values(readLedger({ SOPHOS_FUSION_STATE_DIR: stateDir }).runs)[0].objects;
    assert.equal(objs[0].status, 'deleted');
  });

  test('a name clash with a parser the scripts did not create: nothing is written', () => {
    const rules = [...authRules(), { match: { op: 'allParsers' }, respond: gql({ allParsers: [parser(55, `ZZTest_${CHILD.name}`)] }) }];
    const r = runScript(SCRIPT, ['install', EXAMPLE, '--yes', '--quiet'], { rules });
    assert.equal(r.status, 1);
    assert.equal(r.json.error.code, 'duplicate');
    assert.equal(r.calls.filter((c) => c.mutation).length, 0);
  });
});

describe('enable', () => {
  const live = (code, disabled = true) => ({ match: { op: 'parser' }, respond: gql({ parser: parser(100, `ZZTest_${PARENT.name}`, { code, disabled }) }) });

  test('refuses live code that drifted from what was saved', () => {
    const stateDir = tempDir();
    seedParsers(stateDir);
    const r = runScript(SCRIPT, ['enable', '--id', '100', '--yes', '--quiet'], { rules: [...authRules(), live(`${PARENT.text}\n# edited in the console`)], stateDir });
    assert.equal(r.status, 2);
    assert.match(r.json.error.message, /not the code these scripts saved/);
    assert.equal(r.calls.filter((c) => c.mutation).length, 0);
  });

  test('refuses without a passing tenant check, and with a stale one', () => {
    const stateDir = tempDir();
    seedParsers(stateDir);
    const none = runScript(SCRIPT, ['enable', '--id', '100', '--yes', '--quiet'], { rules: [...authRules(), live(PARENT.text)], stateDir });
    assert.equal(none.status, 2);
    assert.match(none.json.error.message, /No passing tenant-check/);
    P.savePass('parsers', { tenantId: FAKE.tenantId, folder: EXAMPLE, scripts: { [PARENT.name]: P.sha256(PARENT.text) }, at: new Date(Date.now() - 2 * 86400e3).toISOString() }, { SOPHOS_FUSION_STATE_DIR: stateDir });
    const stale = runScript(SCRIPT, ['enable', '--id', '100', '--yes', '--quiet'], { rules: [...authRules(), live(PARENT.text)], stateDir });
    assert.equal(stale.status, 2);
    assert.equal(stale.calls.filter((c) => c.mutation).length, 0);
  });

  test('with a fresh pass on the same code it turns the parser on and reads it back', () => {
    const stateDir = tempDir();
    seedParsers(stateDir);
    P.savePass('parsers', { tenantId: FAKE.tenantId, folder: EXAMPLE, scripts: { [PARENT.name]: P.sha256(PARENT.text) } }, { SOPHOS_FUSION_STATE_DIR: stateDir });
    const rules = [...authRules(), { match: { op: 'parser' }, responses: [gql({ parser: parser(100, `ZZTest_${PARENT.name}`, { code: PARENT.text }) }), gql({ parser: parser(100, `ZZTest_${PARENT.name}`, { code: PARENT.text, disabled: false }) })] }, { match: { op: 'updateParser' }, respond: gql({ updateParser: parser(100, 'x') }) }];
    const r = runScript(SCRIPT, ['enable', '--id', '100', '--yes', '--quiet'], { rules, stateDir, env: FAST });
    assert.equal(r.status, 0, r.stdout);
    assert.equal(r.json.enabled, true);
    assert.deepEqual(JSON.parse(r.calls.find((c) => c.op === 'updateParser').body).variables.u, { disabled: false });
  });
});

describe('rollback of parsers', () => {
  test('child disabled and deleted before the parent; gone only when a clean list lacks it', () => {
    const stateDir = tempDir();
    seedParsers(stateDir);
    const both = [parser(100, `ZZTest_${PARENT.name}`, { disabled: false }), parser(101, `ZZTest_${CHILD.name}`, { disabled: false, parentId: 100 })];
    const rules = [
      ...authRules(),
      {
        match: { op: 'allParsers' },
        responses: [
          gql({ allParsers: both }), // rollback reads the child
          gql({ allParsers: both }), // removeParser: is it on?
          gql({ allParsers: [both[0], { ...both[1], disabled: true }] }), // off now
          { status: 500, text: 'Internal server error' }, // a failed list read is not "gone"
          gql({ allParsers: [both[0]] }), // the child is gone
          gql({ allParsers: [both[0]] }), // rollback reads the parent
          gql({ allParsers: [both[0]] }),
          gql({ allParsers: [{ ...both[0], disabled: true }] }),
          gql({ allParsers: [] }),
        ],
      },
      { match: { op: 'updateParser' }, respond: gql({ updateParser: parser(1, 'x') }) },
      { match: { op: 'deleteParser' }, respond: gql({ deleteParser: { id: 1, name: 'x' } }) },
    ];
    const r = runScript('skills/deployment/scripts/ledger.mjs', ['rollback', '--yes', '--quiet'], { rules, stateDir, env: { SOPHOS_FUSION_READBACK_MS: '3000' } });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.deepEqual(r.json.results.map((x) => [x.name, x.result]), [[`ZZTest_${CHILD.name}`, 'deleted'], [`ZZTest_${PARENT.name}`, 'deleted']]);
    const writes = r.calls.filter((c) => c.mutation).map((c) => `${c.op} ${JSON.parse(c.body).variables.id}`);
    assert.deepEqual(writes, ['updateParser 101', 'deleteParser 101', 'updateParser 100', 'deleteParser 100']);
  });

  test('a by-ID "Internal server error" is not read as gone', () => {
    const stateDir = tempDir();
    const e = { SOPHOS_FUSION_STATE_DIR: stateDir };
    startRun({ env: e });
    record({ kind: 'parser', id: 100, name: `ZZTest_${PARENT.name}`, tenantId: FAKE.tenantId, profile: 'env' }, { env: e });
    const rules = [
      ...authRules(),
      { match: { op: 'parser' }, respond: { json: { data: null, errors: [{ message: 'Internal server error' }] } } },
      { match: { op: 'allParsers' }, respond: gql({ allParsers: [parser(100, `ZZTest_${PARENT.name}`)] }) },
      { match: { op: 'deleteParser' }, respond: gql({ deleteParser: { id: 100, name: 'x' } }) },
    ];
    const r = runScript('skills/deployment/scripts/ledger.mjs', ['rollback', '--yes', '--quiet'], { rules, stateDir, env: FAST });
    assert.equal(r.status, 1);
    assert.equal(r.json.results[0].result, 'still there');
    assert.equal(r.calls.filter((c) => c.op === 'parser').length, 0, 'rollback never reads a parser by ID');
  });
});

describe('verify-ingest', () => {
  function rows({ tweak = null } = {}) {
    return P.emulate(folder).filter((r) => r.extractor_path).map((r) => ({
      ...r.normalized,
      ...(tweak ? tweak(r) : {}),
      original_data: r.sample,
      normalizer_revision: ['Master', ...r.extractor_path.split(' > ').map((n) => `ZZTest_${n}`)].join(' -> '),
      schema_type: P.firstSchema(r.schema) === 'scwx.thirdpartyalert' ? 'thirdparty' : 'generic',
      ingest_time_usec: Date.parse(folder.meta.reference_time) * 1000,
      tenant_id: '1',
    }));
  }
  const scenario = (values) => [
    ...authRules(),
    { match: { op: 'createSearch' }, respond: gql({ createSearch: { urn: 'u', status: 'COMPLETE', errors: [], outcome: { success: 'ALL', errors: [] }, expireTime: '2999-01-01T00:00:00Z' } }) },
    { match: { op: 'searchResults' }, responses: values.map((v) => gql({ searchResults: { values: v, totals: { total: { value: v.length } }, nextCursor: null } })) },
  ];

  const bySchema = (all) => [all.filter((r) => r.schema_type === 'generic'), all.filter((r) => r.schema_type === 'thirdparty')];

  test('polls until every schema-writing parser has records, filters on normalizer_revision, and prints no values', () => {
    // Each round searches generic, then thirdparty. The first round finds nothing.
    const r = runScript(SCRIPT, ['verify-ingest', EXAMPLE, '--wait', '30m', '--interval', '1', '--quiet'], { rules: scenario([[], [], ...bySchema(rows())]) });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.equal(r.json.ok, true);
    assert.equal(r.calls.filter((c) => c.op === 'createSearch').length, 4);
    assert.deepEqual(r.json.queries.map((q) => q.split(' where ')[0]), ['from generic', 'from thirdparty'], 'one search per schema');
    assert.match(r.json.queries[1], /normalizer_revision contains 'ZZTest_OPENCANARY_JSON_PARENT' or normalizer_revision contains 'ZZTest_OPENCANARY_JSON_CHILD_THIRDPARTYALERT'/);
    assert.equal(r.json.byParser[`ZZTest_${CHILD.name}`], 46);
    assert.deepEqual(r.json.differences, {});
    assert.ok(!r.stdout.includes('198.51.100.23'));
  });

  test('a field that differs is counted, with values only under --show-values', () => {
    const tweak = (x) => (P.firstSchema(x.schema) === 'scwx.thirdpartyalert' ? { title: 'Real title' } : {});
    const plain = runScript(SCRIPT, ['verify-ingest', EXAMPLE, '--wait', '0', '--quiet'], { rules: scenario(bySchema(rows({ tweak }))) });
    assert.equal(plain.json.ok, false);
    assert.equal(plain.json.differences['title (differ)'].count, 46);
    assert.equal(plain.json.differences['title (differ)'].example, undefined);
    const shown = runScript(SCRIPT, ['verify-ingest', EXAMPLE, '--wait', '0', '--show-values', '--quiet'], { rules: scenario(bySchema(rows({ tweak }))) });
    assert.equal(shown.json.differences['title (differ)'].example.real, 'Real title');
  });

  test('what Sophos Fusion adds to a record after parsing is not a difference', () => {
    const tweak = () => ({ alerts_data: { aggregated: { total: 2 } }, origin: 'x', enrichSummary: 'y' });
    const r = runScript(SCRIPT, ['verify-ingest', EXAMPLE, '--wait', '0', '--quiet'], { rules: scenario(bySchema(rows({ tweak }))) });
    assert.equal(r.json.ok, true, JSON.stringify(r.json.differences));
  });
});

describe('scaffold', () => {
  test('writes the library layout from masked samples and refuses raw.log', () => {
    const dir = tempDir();
    const samples = path.join(dir, 'masked.log');
    fs.copyFileSync(path.join(ROOT, 'test', 'fixtures', 'parsers', 'acme-raw.log'), samples);
    const out = path.join(dir, 'acme');
    const r = runScript(SCRIPT, ['scaffold', '--samples', samples, '--vendor', 'Acme', '--product', 'EdgeWall', '--out', out, '--quiet']);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    for (const f of ['meta.json', 'samples.log', 'expected.json', 'ACME_EDGEWALL_CEF_PARENT.parser.txt']) assert.ok(fs.existsSync(path.join(out, f)), f);
    const meta = JSON.parse(fs.readFileSync(path.join(out, 'meta.json'), 'utf8'));
    assert.ok(meta.parsers.filter((p) => p.role === 'child').every((p) => p.parent === 'ACME_EDGEWALL_CEF_PARENT'));
    const check = runScript(SCRIPT, ['check', out, '--quiet']);
    assert.equal(check.json.errors, 0, JSON.stringify(check.json.problems));
    fs.copyFileSync(samples, path.join(dir, 'raw.log'));
    const raw = runScript(SCRIPT, ['scaffold', '--samples', path.join(dir, 'raw.log'), '--vendor', 'Acme', '--product', 'X', '--out', path.join(dir, 'x'), '--quiet']);
    assert.equal(raw.status, 2);
  });
});
