// Automatic case rules and case templates through the documented Cases GraphQL API, plus the
// undocumented YAML import (importInvestigationResources) and Rule Logs (getAllRuleLogs). A port of
// the library's tools/case-rule-install.mjs and tools/lib/fusion-cases.mjs onto FusionClient.
//
// Measured in a lab tenant (20/11 to 22/11/2026): the import takes the YAML that Automatic Cases
// exports, creates the template and the rule linked by name, keeps the file's state, and puts the
// rule after the tenant's own rules whatever order the file has. An imported rule opened no case
// until it was saved once more with updateCaseRule and no change. createCaseRule inserts at the
// order it is given and moves the tenant's rules from there down one, so a create goes after the
// last rule.

import * as YAML from '../vendor/yaml/index.js';
import { GraphQLError, SfsError } from './errors.mjs';
import { pollUntil } from './fusion.mjs';
import { CUSTOM_DETECTOR, CASE_SEVERITIES } from './xsl.mjs';
import { qlString } from './search.mjs';
import { readCaseRuleYaml } from './detection-rules-check.mjs';

export const TEST_NAME_PREFIX = 'ZZTest_';
export const TEST_TITLE_PREFIX = 'ZZ Test ';

const RULE_FIELDS = 'id name title description tags type order state filter appendFilter appendComment groupBy groupCount groupDuration groupExtendOnAppend searchQueries searchWindow tenantFilter skipDetectionPrioritization isGlobal updatedAt template { id name title }';
// The fields updateCaseRule takes back unchanged. The order is left out: a rule keeps its place
// when the update doesn't name one.
export const UPDATE_KEYS = ['title', 'description', 'tags', 'state', 'filter', 'appendFilter', 'appendComment', 'groupBy', 'groupCount', 'groupDuration', 'groupExtendOnAppend', 'searchQueries', 'searchWindow', 'tenantFilter', 'skipDetectionPrioritization', 'isGlobal'];

// group_by for each choice, with the rule's name added so only this rule adds to its cases.
export const GROUP_BY = {
  'source-ip': (name) => `\${alertSourceIPs(inputs).map(ip, ip + ' ${name}')}`,
  host: (name) => `\${alertHostnames(inputs).map(h, h + ' ${name}')}`,
  user: (name) => `\${alertUsernames(inputs).map(u, u + ' ${name}')}`,
};

async function readArg(client, op, fields, args) {
  try {
    const { data } = await client.request(`query($a: ${op === 'caseRule' ? 'CaseRuleArguments' : 'CaseTemplateArguments'}!) { ${op}(arguments: $a) { ${fields} } }`, { a: args }, { operation: op });
    return data[op] ?? null;
  } catch (error) {
    if (error instanceof GraphQLError && error.notFound) return null;
    throw error;
  }
}

export const getCaseRule = (client, args) => readArg(client, 'caseRule', RULE_FIELDS, args);
export const getCaseTemplate = (client, args) => readArg(client, 'caseTemplate', 'id name title updatedAt', args);

export async function listCaseRules(client) {
  const out = [];
  for (let page = 1; page < 50; page++) {
    const { data } = await client.request('query($a: CaseRulesArguments!) { caseRules(arguments: $a) { totalCount rules { id name title order state updatedAt template { id name } } } }', { a: { page, perPage: 100 } }, { operation: 'caseRules' });
    const d = data.caseRules;
    out.push(...(d.rules || []));
    if (out.length >= d.totalCount || !(d.rules || []).length) break;
  }
  return out;
}

export async function listCaseTemplates(client) {
  const out = [];
  for (let page = 1; page < 50; page++) {
    const { data } = await client.request('query($a: CaseTemplatesArguments!) { caseTemplates(arguments: $a) { totalCount templates { id name title updatedAt } } }', { a: { page, perPage: 100 } }, { operation: 'caseTemplates' });
    const d = data.caseTemplates;
    out.push(...(d.templates || []));
    if (out.length >= d.totalCount || !(d.templates || []).length) break;
  }
  return out;
}

const IMPORT_DOCUMENT = 'mutation($input: ImportInvestigationResourcesInput!) { importInvestigationResources(input: $input) { __typename ... on InvestigationRule { id name title order state template { id name } } ... on InvestigationTemplate { id name title } } }';

/** Sends YAML to importInvestigationResources as a multipart upload. Returns the resources it made. */
export async function importYaml(client, yamlText, filename = 'case-rule.yaml') {
  const { data } = await client.upload(IMPORT_DOCUMENT, { filename, content: yamlText }, { operation: 'importInvestigationResources' });
  return data.importInvestigationResources || [];
}

export async function updateCaseRule(client, input) {
  const { data } = await client.request(`mutation($i: UpdateCaseRuleInput!) { updateCaseRule(input: $i) { ${RULE_FIELDS} } }`, { i: input }, { operation: 'updateCaseRule' });
  return data.updateCaseRule;
}

export async function createCaseRule(client, input) {
  const { data } = await client.request(`mutation($i: CreateCaseRuleInput!) { createCaseRule(input: $i) { ${RULE_FIELDS} } }`, { i: input }, { operation: 'createCaseRule' });
  return data.createCaseRule;
}

export async function deleteCaseRule(client, id) {
  const { data } = await client.request('mutation($i: DeleteCaseRuleInput!) { deleteCaseRule(input: $i) { id name } }', { i: { id } }, { operation: 'deleteCaseRule' });
  return data.deleteCaseRule;
}

export async function deleteCaseTemplate(client, id) {
  const { data } = await client.request('mutation($i: DeleteCaseTemplateInput!) { deleteCaseTemplate(input: $i) { id name } }', { i: { id } }, { operation: 'deleteCaseTemplate' });
  return data.deleteCaseTemplate;
}

export async function ruleLogs(client, ruleId, { since = null, perPage = 100 } = {}) {
  const { data } = await client.request(
    'query($a: RuleLogQueryInput, $p: Pagination) { getAllRuleLogs(args: $a, pagination: $p) { totalCount entries { id rule template investigation alert level event message created_at } } }',
    { a: { rule: ruleId, ...(since ? { createdAtFrom: since } : {}) }, p: { page: 1, perPage } },
    { operation: 'getAllRuleLogs' },
  );
  return data.getAllRuleLogs || { totalCount: 0, entries: [] };
}

/** The createCaseRule input for the rule document of a case-rule.yaml, at the given order. */
export function createInput(rule, templateId, order) {
  return {
    name: rule.name,
    title: rule.title,
    ...(rule.description ? { description: rule.description } : {}),
    tags: rule.tags || [],
    type: rule.type || 'STATIC',
    order,
    state: rule.state,
    filter: rule.filter,
    appendFilter: rule.append_filter || '',
    groupBy: rule.group_by,
    groupCount: rule.group_count,
    skipDetectionPrioritization: rule.skip_alert_prioritization === true,
    isGlobal: false,
    templateId,
  };
}

/** The updateCaseRule input that saves a rule again with every value it holds, and no order. */
export function resaveInput(current, changes = {}) {
  const out = { id: current.id };
  for (const k of UPDATE_KEYS) if (current[k] !== null && current[k] !== undefined) out[k] = current[k];
  out.templateId = current.template?.id;
  return { ...out, ...changes };
}

/** The template document of a case-rule.yaml on its own, for --method create. */
export function templateText(yaml) {
  const parts = String(yaml).replace(/\r\n?/g, '\n').split(/^---\s*$/m);
  return parts[parts.length - 1].replace(/^\n/, '');
}

const docText = (rule, template) => `${YAML.stringify(rule, { lineWidth: 0 })}---\n${YAML.stringify(template, { lineWidth: 0 })}`;

/**
 * The test copy of a case-rule.yaml: ZZTest_ names, ZZ Test titles, the filter's rule titles
 * renamed to the ZZ Test copies of the detection rules, and group_by carrying the new name.
 */
export function makeTestCopy(yamlText, { ruleTitlePrefix = TEST_TITLE_PREFIX } = {}) {
  const doc = readCaseRuleYaml(yamlText);
  if (!doc) throw new SfsError('case-rule.yaml does not read as a rule and its template. Run case-rule.mjs check.', { code: 'bad_case_rule' });
  const rule = { ...doc.rule };
  const template = { ...doc.template };
  const oldName = rule.name;
  rule.name = `${TEST_NAME_PREFIX}${rule.name}`;
  rule.title = `${TEST_TITLE_PREFIX}${rule.title}`;
  template.name = `${TEST_NAME_PREFIX}${template.name}`;
  template.title = `${TEST_TITLE_PREFIX}${template.title}`;
  rule.template_name = template.name;
  rule.group_by = (rule.group_by || []).map((g) => g.split(oldName).join(rule.name));
  rule.filter = String(rule.filter).replace(/'((?:[^'\\]|\\.)*)'/g, (m, v) => {
    if (v === CUSTOM_DETECTOR) return m;
    return qlString(`${ruleTitlePrefix}${v.replace(/\\(.)/g, '$1')}`);
  });
  if ([rule.name, rule.title, template.name, template.title].some((n) => /claude/i.test(n))) throw new SfsError('Keep assistant names out of tenant object names.', { code: 'usage' });
  return { text: docText(rule, template), rule, template };
}

/** A case-rule.yaml for a detection rule set: its Medium and higher rules, grouped by one entity. */
export function scaffoldCaseRule({ name, title, rules, groupBy, templateName, templateTitle }) {
  const titles = rules.filter((r) => CASE_SEVERITIES.has(r.severity)).map((r) => r.name);
  if (!titles.length) throw new SfsError('None of the rules is Medium or higher, and case rules act only on those.', { code: 'no_rules' });
  const rule = {
    apiVersion: 'v0.0.1',
    kind: 'rule',
    name,
    title,
    tags: [],
    type: 'STATIC',
    order: 1,
    state: 'TEST',
    filter: `from detection where metadata.creator.detector.detector_id = '${CUSTOM_DETECTOR}' and title in (${titles.map(qlString).join(', ')})`,
    append_filter: '',
    group_by: [GROUP_BY[groupBy](name)],
    group_count: 1,
    skip_alert_prioritization: true,
    is_global: false,
    template_name: templateName,
  };
  const template = {
    apiVersion: 'v0.0.1',
    kind: 'template',
    name: templateName,
    title: templateTitle,
    description: `Case for the ${title} custom detections.`,
    tags: [],
    investigation: { tags: [], type: 'SECURITY_INVESTIGATION', title, status: 'OPEN', priority: '3', generate_key_findings: false, usages: ['AUTO_INVESTIGATION'] },
  };
  return { text: docText(rule, template), titles };
}

const same = (a, b) => a.order === b.order && a.state === b.state && a.updatedAt === b.updatedAt;

/** The case rules whose order, state or save time changed between two lists. */
export function movedRules(before, after) {
  return before.filter((b) => {
    const a = after.find((x) => x.id === b.id);
    return !a || !same(a, b);
  }).map((b) => b.name);
}

/** Read until a read passes ok, since reads lag writes. A read that errors counts as not yet. */
export async function readUntil(read, ok) {
  return pollUntil(async () => {
    try {
      const v = await read();
      return ok(v) ? v : null;
    } catch {
      return null;
    }
  });
}
