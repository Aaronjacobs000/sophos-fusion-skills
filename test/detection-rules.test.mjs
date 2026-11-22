import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { emulate, firstSchema, loadParserFolder } from '../lib/parsers.mjs';
import { matches, parseQuery } from '../lib/xsl.mjs';
import { loadRuleFolder, parsedRules, validateRuleEntry } from '../lib/detection-rules-check.mjs';
import * as R from '../lib/detection-rules.mjs';
import { readLedger, record, startRun } from '../lib/ledger.mjs';
import { setQuiet } from '../lib/log.mjs';
import { fakeClient, gqlError } from './helpers/fake-client.mjs';
import { authRules, FAKE, ROOT, runScript, tempDir } from './helpers/scenario.mjs';

setQuiet(true);

const PARSER_DIR = path.join(ROOT, 'examples', 'parsers', 'opencanary');
const RULES_DIR = path.join(ROOT, 'examples', 'rules', 'opencanary-honeypot-activity');
const SCRIPT = 'skills/detection-rules/scripts/rules.mjs';
const parser = loadParserFolder(PARSER_DIR);
const example = loadRuleFolder(RULES_DIR);
const rules = parsedRules(example);
const gql = (data) => ({ json: { data } });

/** A copy of the example rule set with another rules.yaml (and tests.json, when given). */
function variant(fixture, tests = null) {
  const dir = tempDir();
  fs.copyFileSync(path.join(RULES_DIR, 'meta.json'), path.join(dir, 'meta.json'));
  fs.copyFileSync(path.join(ROOT, 'test', 'fixtures', 'rules', fixture), path.join(dir, 'rules.yaml'));
  fs.writeFileSync(path.join(dir, 'tests.json'), JSON.stringify(tests || { triggers: {}, quiet: [1] }));
  return loadRuleFolder(dir);
}
const codes = (r) => r.problems.filter((p) => p.level === 'error').map((p) => p.code);

describe('the offline check', () => {
  test('the OpenCanary rule set passes, and tests.json holds', () => {
    const r = validateRuleEntry(example, { parser });
    assert.equal(r.ok, true, JSON.stringify(r.problems));
    assert.deepEqual(r.hits[11], ['OpenCanary login with a planted credential']);
    assert.equal(validateRuleEntry(example, { parser, library: true }).ok, true);
  });

  test('an IOC-only query is refused', () => assert.ok(codes(validateRuleEntry(variant('ioc.yaml'), { parser })).includes('ioc')));
  test('a query that does not pin the sensor type is refused', () => assert.ok(codes(validateRuleEntry(variant('no-pin.yaml'), { parser })).includes('sensor')));
  test('an enum compared with a number is refused', () => assert.ok(codes(validateRuleEntry(variant('enum-number.yaml'), { parser })).includes('enum')));
  test('a backreference is refused', () => assert.ok(codes(validateRuleEntry(variant('backreference.yaml'), { parser })).includes('regex')));
  test('testShould is refused, with the lab reason', () => {
    const r = validateRuleEntry(variant('test-should.yaml'), { parser });
    assert.ok(r.problems.some((p) => p.level === 'error' && /hyperscan container/.test(p.message)));
  });

  test('a line that triggers two rules is refused', () => {
    const logins = [4, 6, 11, 12, 13, 21, 23, 25, 26, 27, 30, 32, 33, 46];
    const r = validateRuleEntry(variant('overlap.yaml', { triggers: { 'Any login attempt': logins, 'SSH login attempt': [12] }, quiet: [1] }), { parser });
    assert.ok(r.problems.some((p) => p.code === 'tests' && /triggers 2 rules/.test(p.message)));
  });

  test('a sensor type the custom parser does not write is refused', () => {
    const e = loadRuleFolder(RULES_DIR);
    e.meta = { ...e.meta, sensor_types: ['OpenCanary', 'THIRD_PARTY_ALERTS'] };
    assert.ok(validateRuleEntry(e, { parser }).problems.some((p) => p.code === 'sensor' && /custom parser/.test(p.message)));
  });
});

describe('tenant check (read-only)', () => {
  const sophos = (extra = []) => [
    { id: 'a', eventType: 'thirdpartyalert', ruleSource: 'DETECTOR', attackCategories: ['T1110.001'], filters: [], qlFilter: null },
    { id: 'b', eventType: 'thirdpartyalert', ruleSource: 'WATCHLIST', attackCategories: ['T1046'], filters: [{ key: 'scwx.thirdpartyalert.sensor_type', pattern: '^Nozomi$' }], qlFilter: null },
    ...extra,
  ];

  test('a validateQLFilter refusal maps to its rule', async () => {
    const c = fakeClient({
      validateQLFilter: (v) => {
        if (/log_type = '5000'/.test(v.f.query)) throw gqlError('ql filter validation failed: this query does not apply to any event type');
        return { eventType: 'thirdpartyalert', originalQuery: v.f.query, expandedQuery: v.f.query, errors: [] };
      },
    });
    const results = await Promise.all(rules.map((r) => R.validateQuery(c, r.query, 'scwx.thirdpartyalert')));
    assert.deepEqual(results.map((x) => x.ok), [true, true, false, true]);
    assert.match(results[2].errors[0], /does not apply to any event type/);
    assert.deepEqual(c.calls[0].variables.t, 'thirdpartyalert');
  });

  test('coverage: a shared technique is a warning, a named sensor type an error', () => {
    const cov = R.coverageOf(sophos([{ id: 'c', attackCategories: [], filters: [], qlFilter: { query: "from thirdparty where sensor_type = 'OpenCanary'" } }]));
    assert.deepEqual(cov.anySensorTechniques, ['T1110.001']);
    const p = R.coverageProblems(example.meta, rules, cov);
    assert.ok(p.some((x) => x.level === 'warning' && x.code === 'technique' && x.rule === 'OpenCanary login attempt'));
    assert.ok(p.some((x) => x.level === 'error' && x.code === 'sensor' && /OpenCanary/.test(x.message)));
    assert.equal(R.coverageProblems(example.meta, rules, R.coverageOf(sophos())).filter((x) => x.level === 'error').length, 0);
  });

  test('searchRules pages from 1 and stops at the last page', async () => {
    const pages = [];
    const c = fakeClient({ searchRules: (v) => (pages.push(v.p), { pageInfo: { totalPages: 2 }, rules: [{ id: `r${v.p}`, filters: [], attackCategories: [] }] }) });
    const all = await R.sophosRules(c, 'scwx.thirdpartyalert');
    assert.deepEqual(pages, [1, 2]);
    assert.equal(all.length, 2);
    assert.match(c.calls[0].variables.q.query, /event_type = 'thirdpartyalert'/);
  });
});

describe('search test', () => {
  const rowsFor = (pred) => emulate(parser).filter((r) => r.normalized && pred(r)).map((r) => ({ ...r.normalized, resource_id: `res-${r.line}`, original_data: r.sample }));

  test('agreement, disagreement and the volume limit', async () => {
    const all = rowsFor((r) => firstSchema(r.schema) === 'scwx.thirdpartyalert');
    const by = (name) => all.filter((row) => matches(parseQuery(rules.find((x) => x.name === name).query).where, row));
    const answers = new Map([[R.ruleQueries(example.meta, rules).universe, all], ...R.ruleQueries(example.meta, rules).rules.map((q) => [q.text, by(q.name)])]);
    const client = (drop = null) => fakeClient({
      createSearch: (v) => ({ urn: v.input.text, status: 'COMPLETE', errors: [], outcome: { success: 'ALL', errors: [] }, expireTime: '2999-01-01T00:00:00Z' }),
      searchResults: (v) => {
        let rows = answers.get(v.urn) || [];
        if (drop && v.urn.includes(drop)) rows = rows.slice(1);
        return { values: rows, totals: { total: { value: rows.length } }, nextCursor: null };
      },
    });
    const ok = await R.searchTest(client(), example.meta, rules);
    assert.equal(ok.agree, true);
    assert.equal(ok.records, 46);
    assert.deepEqual(ok.rules.map((r) => r.search), [1, 13, 1, 4]);
    const bad = await R.searchTest(client("log_type = '5000'"), example.meta, rules);
    assert.equal(bad.agree, false);
    assert.equal(bad.rules[2].onlyOffline, 1);
    assert.equal(R.overVolume({ capped: false, volume: { busiestDay: 1001 } }), true);
    assert.equal(R.overVolume({ capped: true, volume: { busiestDay: 5 } }), true);
    assert.equal(R.overVolume(ok.rules[1]), false);
  });

  test('enable refuses a rule whose search-test found over 1,000 a day, unless --allow-volume', () => {
    const stateDir = tempDir();
    const e = { SOPHOS_FUSION_STATE_DIR: stateDir };
    startRun({ env: e });
    record({ kind: 'detectionRule', id: 'r1', name: 'ZZ Test OpenCanary login attempt', tenantId: FAKE.tenantId, profile: 'env' }, { env: e });
    R.saveSearchPass({ tenantId: FAKE.tenantId, rule: 'OpenCanary login attempt', query: rules[1].query, busiestDay: 4000, meanPerDay: 3000, capped: false, records: 20000 }, e);
    const live = { id: 'r1', name: 'ZZ Test OpenCanary login attempt', enabled: false, deleted: false, severity: 0.6, createAlert: true, qlFilter: { query: rules[1].query } };
    const base = [...authRules(), { match: { op: 'rule' }, responses: [gql({ rule: live }), gql({ rule: { ...live, enabled: true } })] }, { match: { op: 'enableRule' }, respond: gql({ enableRule: { id: 'r1', enabled: true } }) }];
    const refused = runScript(SCRIPT, ['enable', '--id', 'r1', '--yes', '--quiet'], { rules: base, stateDir });
    assert.equal(refused.status, 2);
    assert.match(refused.json.error.message, /over 1000/);
    assert.equal(refused.calls.filter((c) => c.mutation).length, 0);
    const allowed = runScript(SCRIPT, ['enable', '--id', 'r1', '--yes', '--allow-volume', '--quiet'], { rules: base, stateDir, env: { SOPHOS_FUSION_READBACK_MS: '400' } });
    assert.equal(allowed.status, 0, allowed.stdout);
    assert.equal(allowed.json.enabled, true);
  });
});

describe('install', () => {
  test('without --yes: exit 3, no request', () => {
    for (const args of [['install', RULES_DIR, '--parser', PARSER_DIR], ['enable', '--id', 'x'], ['disable', '--id', 'x']]) {
      const r = runScript(SCRIPT, args, { rules: authRules() });
      assert.equal(r.status, 3);
      assert.equal(r.calls.length, 0);
    }
  });

  test('createCustomQLRule goes with enabled false, createAlert true and no test fields; each is read back and recorded', () => {
    const stateDir = tempDir();
    let n = 0;
    const made = rules.map((r) => ({ id: `rule-${++n}`, name: `ZZ Test ${r.name}`, enabled: false, deleted: false, severity: R.SEVERITY_SCORE[r.severity], createAlert: true, qlFilter: { query: r.query } }));
    const scenario = [
      ...authRules(),
      { match: { op: 'rules' }, respond: gql({ rules: [{ id: 'old', name: 'Someone else', deleted: false }] }) },
      { match: { op: 'validateQLFilter' }, respond: gql({ validateQLFilter: { eventType: 'thirdpartyalert', originalQuery: 'q', expandedQuery: 'q', errors: [] } }) },
      { match: { op: 'createCustomQLRule' }, responses: made.map((m) => gql({ createCustomQLRule: m })) },
      // The API stores each query with its whitespace collapsed.
      { match: { op: 'rule' }, responses: made.map((m) => gql({ rule: { ...m, qlFilter: { query: m.qlFilter.query.replace(/\s+/g, ' ').trim() } } })) },
    ];
    const r = runScript(SCRIPT, ['install', RULES_DIR, '--parser', PARSER_DIR, '--yes', '--quiet'], { rules: scenario, stateDir });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.ok(r.json.installed.every((x) => x.ok && x.readBack.enabled === false && x.readBack.createAlert === true && x.readBack.queryEqual));
    const sent = r.calls.filter((c) => c.op === 'createCustomQLRule').map((c) => JSON.parse(c.body).variables);
    assert.deepEqual(sent.map((v) => [v.i.name, v.i.enabled, v.i.createAlert, v.i.eventType, v.i.severity, v.i.confidence]), rules.map((x) => [`ZZ Test ${x.name}`, false, true, 'thirdpartyalert', R.SEVERITY_SCORE[x.severity], 0.5]));
    assert.ok(sent.every((v) => Object.keys(v.f).join() === 'query'));
    assert.deepEqual(sent[0].i.attackCategories, ['T1078']);
    const objs = Object.values(readLedger({ SOPHOS_FUSION_STATE_DIR: stateDir }).runs)[0].objects;
    assert.deepEqual(objs.map((o) => [o.kind, o.id]), made.map((m) => ['detectionRule', m.id]));
  });

  test('a name already on the tenant: nothing is written', () => {
    const scenario = [...authRules(), { match: { op: 'rules' }, respond: gql({ rules: [{ id: 'x', name: `ZZ Test ${rules[0].name}`, deleted: false }] }) }];
    const r = runScript(SCRIPT, ['install', RULES_DIR, '--parser', PARSER_DIR, '--yes', '--quiet'], { rules: scenario });
    assert.equal(r.json.error.code, 'duplicate');
    assert.equal(r.calls.filter((c) => c.mutation).length, 0);
  });
});

