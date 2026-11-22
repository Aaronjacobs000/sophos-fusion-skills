import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import * as C from '../lib/case-rules.mjs';
import { loadRuleFolder, parsedRules, validateRuleEntry } from '../lib/detection-rules-check.mjs';
import { readLedger, record, startRun } from '../lib/ledger.mjs';
import { setQuiet } from '../lib/log.mjs';
import { authRules, FAKE, ROOT, runScript, tempDir } from './helpers/scenario.mjs';

setQuiet(true);

const CASE_DIR = path.join(ROOT, 'examples', 'rules', 'opencanary-one-case-per-source-ip');
const RULES_DIR = path.join(ROOT, 'examples', 'rules', 'opencanary-honeypot-activity');
const SCRIPT = 'skills/detection-rules/scripts/case-rule.mjs';
const detection = { label: 'opencanary-honeypot-activity', rules: parsedRules(loadRuleFolder(RULES_DIR)) };
const YAML_TEXT = fs.readFileSync(path.join(CASE_DIR, 'case-rule.yaml'), 'utf8');
const gql = (data) => ({ json: { data } });
const FAST = { SOPHOS_FUSION_READBACK_MS: '400' };

function variant(edit) {
  const dir = tempDir();
  fs.copyFileSync(path.join(CASE_DIR, 'meta.json'), path.join(dir, 'meta.json'));
  fs.writeFileSync(path.join(dir, 'case-rule.yaml'), edit(YAML_TEXT));
  return validateRuleEntry(loadRuleFolder(dir), { detection });
}

describe('the case rule check', () => {
  test('the OpenCanary case rule passes', () => {
    const r = validateRuleEntry(loadRuleFolder(CASE_DIR), { detection });
    assert.equal(r.ok, true, JSON.stringify(r.problems));
    assert.equal(r.caseRule.titles.length, 4);
  });

  test('a filter that could reach another detector is refused', () => {
    const r = variant((t) => t.replace("metadata.creator.detector.detector_id = 'app:event-filter-ql' and ", ''));
    assert.ok(r.problems.some((p) => p.code === 'filter' && /only custom detections/.test(p.message)));
  });

  test('a Low rule in the filter is refused', () => {
    const low = { ...detection, rules: detection.rules.map((x) => (x.name === 'OpenCanary Nmap scan' ? { ...x, severity: 'low' } : x)) };
    const dir = tempDir();
    fs.copyFileSync(path.join(CASE_DIR, 'meta.json'), path.join(dir, 'meta.json'));
    fs.writeFileSync(path.join(dir, 'case-rule.yaml'), YAML_TEXT);
    const r = validateRuleEntry(loadRuleFolder(dir), { detection: low });
    assert.ok(r.problems.some((p) => p.code === 'filter' && /Medium and higher/.test(p.message)));
  });

  test('group_by without the rule name is refused, and so are is_global and an assignee', () => {
    const unsalted = variant((t) => t.replace(" + ' opencanary_one_case_per_source_ip'", ''));
    assert.ok(unsalted.problems.some((p) => p.code === 'group'));
    const global = variant((t) => t.replace('is_global: false', 'is_global: true'));
    assert.ok(global.problems.some((p) => /is_global must be false/.test(p.message)));
    const assignee = variant((t) => t.replace('    status: OPEN', '    status: OPEN\n    assignee: someone'));
    assert.ok(assignee.problems.some((p) => /assignee/.test(p.message)));
  });

  test('the test copy renames the rule, template, titles in the filter, and the group_by salt', () => {
    const t = C.makeTestCopy(YAML_TEXT);
    assert.equal(t.rule.name, 'ZZTest_opencanary_one_case_per_source_ip');
    assert.equal(t.template.name, 'ZZTest_opencanary_honeypot_unofficial');
    assert.equal(t.rule.template_name, t.template.name);
    assert.match(t.rule.filter, /detector_id = 'app:event-filter-ql' and title in \('ZZ Test OpenCanary login with a planted credential', /);
    assert.ok(t.rule.group_by.every((g) => g.includes('ZZTest_opencanary_one_case_per_source_ip')));
  });
});

describe('install', () => {
  const before = [{ id: 'cr-1', name: 'Existing one', title: 'x', order: 1, state: 'ENABLED', updatedAt: 't1', template: { id: 't-1', name: 'x' } }, { id: 'cr-2', name: 'Existing two', title: 'y', order: 2, state: 'TEST', updatedAt: 't2', template: { id: 't-2', name: 'y' } }];
  const newRule = (extra = {}) => ({ id: 'cr-new', name: 'ZZTest_opencanary_one_case_per_source_ip', title: 'ZZ Test OpenCanary', order: 3, state: 'TEST', filter: 'f', appendFilter: '', groupBy: ['g'], groupCount: 1, skipDetectionPrioritization: true, isGlobal: false, tags: [], updatedAt: 't3', template: { id: 'tpl-new', name: 'ZZTest_opencanary_honeypot_unofficial' }, ...extra });

  test('without --yes: exit 3, no request', () => {
    for (const args of [['install', CASE_DIR], ['enable', '--id', 'x'], ['test-state', '--id', 'x']]) {
      const r = runScript(SCRIPT, args, { rules: authRules() });
      assert.equal(r.status, 3);
      assert.equal(r.calls.length, 0);
    }
  });

  test('import, then one more save without the order; nothing else moved; both recorded, the rule under its template', () => {
    const stateDir = tempDir();
    const scenario = [
      ...authRules(),
      { match: { op: 'caseRules' }, responses: [gql({ caseRules: { totalCount: 2, rules: before } }), gql({ caseRules: { totalCount: 3, rules: [...before, newRule()] } })] },
      { match: { op: 'caseTemplate' }, respond: gql({ caseTemplate: null }) },
      { match: { op: 'importInvestigationResources' }, respond: gql({ importInvestigationResources: [{ __typename: 'InvestigationTemplate', id: 'tpl-new', name: 'ZZTest_opencanary_honeypot_unofficial', title: 't' }, { __typename: 'InvestigationRule', id: 'cr-new', name: 'ZZTest_opencanary_one_case_per_source_ip', order: 3, state: 'TEST' }] }) },
      { match: { op: 'caseRule' }, respond: gql({ caseRule: newRule() }) },
      { match: { op: 'updateCaseRule' }, respond: gql({ updateCaseRule: newRule() }) },
    ];
    const r = runScript(SCRIPT, ['install', CASE_DIR, '--yes', '--quiet'], { rules: scenario, stateDir, env: FAST });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.deepEqual(r.json.movedOtherRules, []);
    assert.equal(r.json.caseRule.state, 'TEST');
    const update = JSON.parse(r.calls.find((c) => c.op === 'updateCaseRule').body).variables.i;
    assert.equal(update.id, 'cr-new');
    assert.equal('order' in update, false);
    assert.equal(update.templateId, 'tpl-new');
    const objs = Object.values(readLedger({ SOPHOS_FUSION_STATE_DIR: stateDir }).runs)[0].objects;
    assert.deepEqual(objs.map((o) => [o.kind, o.id, o.parentId]), [['caseTemplate', 'tpl-new', null], ['caseRule', 'cr-new', 'tpl-new']]);
  });

  test('--method create imports the template alone and creates the rule after the last one', () => {
    const stateDir = tempDir();
    const scenario = [
      ...authRules(),
      { match: { op: 'caseRules' }, responses: [gql({ caseRules: { totalCount: 2, rules: before } }), gql({ caseRules: { totalCount: 3, rules: [...before, newRule()] } })] },
      { match: { op: 'caseTemplate' }, responses: [gql({ caseTemplate: null }), gql({ caseTemplate: { id: 'tpl-new', name: 'ZZTest_opencanary_honeypot_unofficial', title: 't' } })] },
      { match: { op: 'importInvestigationResources' }, respond: gql({ importInvestigationResources: [{ __typename: 'InvestigationTemplate', id: 'tpl-new', name: 'ZZTest_opencanary_honeypot_unofficial', title: 't' }] }) },
      { match: { op: 'createCaseRule' }, respond: gql({ createCaseRule: newRule() }) },
      { match: { op: 'caseRule' }, respond: gql({ caseRule: newRule() }) },
    ];
    const r = runScript(SCRIPT, ['install', CASE_DIR, '--method', 'create', '--yes', '--quiet'], { rules: scenario, stateDir, env: FAST });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    const create = JSON.parse(r.calls.find((c) => c.op === 'createCaseRule').body).variables.i;
    assert.equal(create.order, 3);
    assert.equal(create.state, 'TEST');
    assert.equal(create.templateId, 'tpl-new');
    assert.equal(create.isGlobal, false);
  });

  test('another case rule moving during the install is reported', () => {
    const scenario = [
      ...authRules(),
      { match: { op: 'caseRules' }, responses: [gql({ caseRules: { totalCount: 2, rules: before } }), gql({ caseRules: { totalCount: 3, rules: [before[0], { ...before[1], order: 3 }, newRule({ order: 2 })] } })] },
      { match: { op: 'caseTemplate' }, respond: gql({ caseTemplate: null }) },
      { match: { op: 'importInvestigationResources' }, respond: gql({ importInvestigationResources: [] }) },
      { match: { op: 'caseRule' }, respond: gql({ caseRule: newRule({ order: 2 }) }) },
      { match: { op: 'updateCaseRule' }, respond: gql({ updateCaseRule: newRule({ order: 2 }) }) },
    ];
    const r = runScript(SCRIPT, ['install', CASE_DIR, '--yes', '--quiet'], { rules: scenario, env: FAST });
    assert.equal(r.json.ok, false);
    assert.deepEqual(r.json.movedOtherRules, ['Existing two']);
  });

  test('a case rule or template name already on the tenant: nothing is written', () => {
    const rule = runScript(SCRIPT, ['install', CASE_DIR, '--yes', '--quiet'], { rules: [...authRules(), { match: { op: 'caseRules' }, respond: gql({ caseRules: { totalCount: 1, rules: [newRule()] } }) }] });
    assert.equal(rule.json.error.code, 'duplicate');
    const tpl = runScript(SCRIPT, ['install', CASE_DIR, '--yes', '--quiet'], { rules: [...authRules(), { match: { op: 'caseRules' }, respond: gql({ caseRules: { totalCount: 0, rules: [] } }) }, { match: { op: 'caseTemplate' }, respond: gql({ caseTemplate: { id: 'x', name: 'ZZTest_opencanary_honeypot_unofficial' } }) }] });
    assert.equal(tpl.json.error.code, 'duplicate');
    assert.equal(rule.calls.filter((c) => c.mutation).length + tpl.calls.filter((c) => c.mutation).length, 0);
  });
});

describe('rollback order', () => {
  test('case rule, then template, then each detection rule (disabled, then hard deleted), each read back', () => {
    const stateDir = tempDir();
    const e = { SOPHOS_FUSION_STATE_DIR: stateDir };
    startRun({ env: e });
    record({ kind: 'detectionRule', id: 'd1', name: 'ZZ Test One', tenantId: FAKE.tenantId, profile: 'env' }, { env: e });
    record({ kind: 'detectionRule', id: 'd2', name: 'ZZ Test Two', tenantId: FAKE.tenantId, profile: 'env' }, { env: e });
    record({ kind: 'caseTemplate', id: 't1', name: 'ZZTest_tpl', tenantId: FAKE.tenantId, profile: 'env' }, { env: e });
    record({ kind: 'caseRule', id: 'c1', name: 'ZZTest_rule', tenantId: FAKE.tenantId, profile: 'env', parentId: 't1' }, { env: e });
    const rule = (id, name, enabled) => gql({ rule: { id, name, enabled, deleted: false, qlFilter: { query: 'q' } } });
    const scenario = [
      ...authRules(),
      { match: { op: 'caseRule' }, responses: [gql({ caseRule: { id: 'c1', name: 'ZZTest_rule' } }), gql({ caseRule: null })] },
      { match: { op: 'deleteCaseRule' }, respond: gql({ deleteCaseRule: { id: 'c1', name: 'ZZTest_rule' } }) },
      { match: { op: 'caseTemplate' }, responses: [gql({ caseTemplate: { id: 't1', name: 'ZZTest_tpl' } }), gql({ caseTemplate: null })] },
      { match: { op: 'deleteCaseTemplate' }, respond: gql({ deleteCaseTemplate: { id: 't1', name: 'ZZTest_tpl' } }) },
      {
        match: { op: 'rule' },
        responses: [
          rule('d2', 'ZZ Test Two', true), rule('d2', 'ZZ Test Two', true), rule('d2', 'ZZ Test Two', false), { json: { data: { rule: { id: 'd2', name: 'ZZ Test Two', enabled: false, deleted: true } } } },
          rule('d1', 'ZZ Test One', false), rule('d1', 'ZZ Test One', false), { json: { data: { rule: null }, errors: [{ message: 'rule not found' }] } },
        ],
      },
      { match: { op: 'disableRule' }, respond: gql({ disableRule: { id: 'd2', enabled: false } }) },
      { match: { op: 'deleteRule' }, respond: gql({ deleteRule: { id: 'd', deleted: true, enabled: false } }) },
    ];
    const r = runScript('skills/deployment/scripts/ledger.mjs', ['rollback', '--yes', '--quiet'], { rules: scenario, stateDir, env: FAST });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.deepEqual(r.json.results.map((x) => [x.kind, x.result]), [['caseRule', 'deleted'], ['caseTemplate', 'deleted'], ['detectionRule', 'deleted'], ['detectionRule', 'deleted']]);
    const writes = r.calls.filter((c) => c.mutation).map((c) => c.op);
    assert.deepEqual(writes, ['deleteCaseRule', 'deleteCaseTemplate', 'disableRule', 'deleteRule', 'deleteRule']);
    assert.ok(r.calls.filter((c) => c.op === 'deleteRule').every((c) => JSON.parse(c.body).variables.h === true));
  });
});
