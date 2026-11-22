// Offline checks for detection rule sets and automatic case rules, in the library's rule entry
// layout. A port of the checks a single entry needs from the library's tools/lib/rules.mjs (which
// sits outside its studio/core, so it isn't vendored), reading YAML with vendor/yaml.
//
//   <dir>/meta.json        kind (detection or case), title, vendor, product, schema, sensor_types, volume, ...
//   <dir>/rules.yaml       a detection set: name, description, severity, mitre, query, enabled_by_default
//   <dir>/tests.json       the parser's sample lines each rule must trigger, and quiet lines
//   <dir>/case-rule.yaml   a case rule and its template, as Automatic Cases exports them
//
// Two modes. Local (the default) checks what the skill needs to test and install a rule. Library
// (contribute) adds the library's metadata rules: author, license, docs, the MDR note, the About text,
// and a parser that is a library entry.

import fs from 'node:fs';
import path from 'node:path';
import * as YAML from '../vendor/yaml/index.js';
import {
  aboutProblems,
  CASE_SEVERITIES,
  compareTests,
  compileRules,
  conditions,
  CUSTOM_DETECTOR,
  gitleaksProblems,
  LICENSES,
  parseQuery,
  PARSER_PATH,
  pinnedSensorTypes,
  QlError,
  RULE_KINDS,
  RULE_PATH,
  ruleHits,
  ruleQueryProblems,
  scanText,
  SCHEMA_IDS,
  SEVERITIES,
  slug,
  topConjuncts,
} from './xsl.mjs';
import { emulate, firstSchema } from './parsers.mjs';

export const RULE_FILES = { detection: ['meta.json', 'rules.yaml', 'tests.json', 'README.md'], case: ['meta.json', 'case-rule.yaml', 'README.md'] };
const REQUIRED = { detection: ['meta.json', 'rules.yaml', 'tests.json'], case: ['meta.json', 'case-rule.yaml'] };
export const LIMITS = { rules: 20, name: 100, description: 1000, query: 4000 };
export const RULE_KEYS = ['name', 'description', 'severity', 'mitre', 'query', 'enabled_by_default'];
// Keys people reach for that v1 refuses, with the reason.
const REFUSED_KEYS = {
  testShould: 'Any test value made the rule save fail in a lab tenant ("hyperscan container has not been built", 20/11/2026). Keep tests in tests.json.',
  testShouldNot: 'Any test value made the rule save fail in a lab tenant ("hyperscan container has not been built", 20/11/2026). Keep tests in tests.json.',
  suppress: 'Suppression rules can silence Sophos detections before playbooks see them, so these skills make none.',
  suppression: 'Suppression rules can silence Sophos detections before playbooks see them, so these skills make none.',
  action: 'Suppression rules can silence Sophos detections before playbooks see them, so these skills make none.',
  threshold: "The rule builder takes one query on one schema, with no count or window, so there are no threshold rules.",
  window: "The rule builder takes one query on one schema, with no count or window, so there are no threshold rules.",
  count: "The rule builder takes one query on one schema, with no count or window, so there are no threshold rules.",
};
const META_KEYS = {
  detection: ['kind', 'title', 'vendor', 'product', 'parser', 'schema', 'sensor_types', 'volume', 'mdr_note', 'tested', 'author', 'license', 'docs', 'summary', 'notes', 'links'],
  case: ['kind', 'title', 'vendor', 'product', 'parser', 'mdr_note', 'tested', 'author', 'license', 'docs', 'summary', 'notes', 'links'],
};
const CASE_RULE_KEYS = ['apiVersion', 'kind', 'name', 'title', 'description', 'tags', 'type', 'order', 'state', 'filter', 'append_filter', 'group_by', 'group_count', 'skip_alert_prioritization', 'is_global', 'template_name'];
const TEMPLATE_KEYS = ['apiVersion', 'kind', 'name', 'title', 'description', 'tags', 'investigation'];
const INVESTIGATION_KEYS = ['tags', 'type', 'title', 'status', 'priority', 'assignee', 'generate_key_findings', 'usages'];

const HANDLE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const MITRE = /^T\d{4}(?:\.\d{3})?$/;
export const CASE_NAME = /^[A-Za-z][A-Za-z0-9_]*$/;
const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
const PLAYBOOK_PATH = /^playbooks\/[a-z0-9]+(?:-[a-z0-9]+)*\/[a-z0-9]+(?:-[a-z0-9]+)*$/;
const MDR_DENY = /\b(premier|roadmap|internal|confidential|nda|eap|beta|coming soon|planned|not yet released|under nda)\b/i;
const IOC = { ip: /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$|^[0-9a-f:]+:[0-9a-f:]*(\/\d{1,3})?$/i, hash: /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i, domain: /^(\*\.)?([a-z0-9-]+\.)+[a-z]{2,}$/i };

class Report {
  constructor() {
    this.problems = [];
  }

  add(level, code, message, file = null, line = null) {
    this.problems.push({ level, code, message, file, line });
  }

  error(code, message, file, line) {
    this.add('error', code, message, file, line);
  }

  warn(code, message, file, line) {
    this.add('warning', code, message, file, line);
  }

  review(message, file = null) {
    this.add('warning', 'review', `Review: ${message}`, file, null);
  }
}

const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const text = (v, max) => typeof v === 'string' && v.trim() && v.length <= max;
const lineOf = (s, index) => s.slice(0, index).split('\n').length;

// ---------------------------------------------------------------- reading the files

function yamlDocs(content) {
  const lc = new YAML.LineCounter();
  const docs = YAML.parseAllDocuments(content, { lineCounter: lc, uniqueKeys: true, strict: true });
  const list = Array.isArray(docs) ? docs : [docs];
  const at = (offset) => (typeof offset === 'number' ? lc.linePos(offset).line : null);
  const line = (node) => at(node?.range?.[0]);
  const errors = list.flatMap((d) => (d.errors || []).map((e) => ({ message: e.message.split('\n')[0], line: at(e.pos?.[0]) })));
  return { list, line, errors };
}

/** rules.yaml as [{...rule, line, isMap}], or null with the problem reported. */
export function readRulesYaml(content, r = new Report()) {
  const { list, line, errors } = yamlDocs(content);
  const bad = errors[0];
  if (bad) {
    r.error('yaml', `rules.yaml is not YAML this check can read: ${bad.message}`, 'rules.yaml', bad.line);
    return null;
  }
  if (list.length !== 1) {
    r.error('yaml', 'rules.yaml must hold one YAML document', 'rules.yaml', 1);
    return null;
  }
  const root = list[0].contents;
  if (!YAML.isMap(root) || !root.items.some((p) => p.key?.value === 'rules')) {
    r.error('yaml', 'rules.yaml must be a mapping with one key, "rules", holding a list of rules', 'rules.yaml', line(root));
    return null;
  }
  for (const p of root.items) if (p.key?.value !== 'rules') r.error('yaml', `rules.yaml: "${p.key?.value}" is not a key (only "rules")`, 'rules.yaml', line(p.key));
  const seq = root.items.find((p) => p.key?.value === 'rules').value;
  if (!YAML.isSeq(seq)) {
    r.error('yaml', 'rules must be a list', 'rules.yaml', line(seq));
    return null;
  }
  return seq.items.map((n) => ({ ...(YAML.isMap(n) ? n.toJSON() : {}), line: line(n), isMap: YAML.isMap(n) }));
}

/** case-rule.yaml as {rule, template, lines, templateLine, docs}, or null. */
export function readCaseRuleYaml(content, r = new Report()) {
  const { list, line, errors } = yamlDocs(content);
  const bad = errors[0];
  if (bad) {
    r.error('yaml', `case-rule.yaml is not YAML this check can read: ${bad.message}`, 'case-rule.yaml', bad.line);
    return null;
  }
  const [a, b] = list.map((d) => d.contents);
  const kindOf = (n) => (YAML.isMap(n) ? n.items.find((p) => p.key?.value === 'kind')?.value?.value : null);
  if (list.length !== 2 || !YAML.isMap(a) || !YAML.isMap(b) || kindOf(a) !== 'rule' || kindOf(b) !== 'template') {
    r.error('yaml', 'case-rule.yaml must hold two documents, as Automatic Cases exports a rule with its template: kind: rule, then --- and kind: template', 'case-rule.yaml', 1);
    return null;
  }
  const lines = {};
  for (const p of a.items) lines[p.key?.value] = line(p.key);
  return { rule: a.toJSON(), template: b.toJSON(), lines, templateLine: line(b) };
}

/** Reads a rule entry folder as {id, dir, files, meta, loadProblems}. */
export function loadRuleFolder(dir) {
  const abs = path.resolve(dir);
  if (!fs.existsSync(abs) || !fs.statSync(abs).isDirectory()) throw new Error(`${dir} is not a folder`);
  const files = [];
  const loadProblems = [];
  for (const d of fs.readdirSync(abs, { withFileTypes: true })) {
    if (!d.isFile()) {
      loadProblems.push({ level: 'error', code: 'files', message: `${d.name} is not a regular file. Entries hold plain files only.`, file: d.name });
      continue;
    }
    files.push({ path: d.name, content: fs.readFileSync(path.join(abs, d.name), 'utf8').replace(/\r\n?/g, '\n') });
  }
  let meta = null;
  const m = files.find((f) => f.path === 'meta.json');
  if (m) {
    try {
      meta = JSON.parse(m.content);
    } catch (e) {
      loadProblems.push({ level: 'error', code: 'json', message: `meta.json is not valid JSON: ${e.message}`, file: 'meta.json' });
    }
  }
  const id = meta && typeof meta.vendor === 'string' && typeof meta.title === 'string' ? `${slug(meta.vendor)}/${slug(meta.title)}` : path.basename(abs);
  return { id, dir: abs, files, meta, loadProblems };
}

/** The rules of a detection folder without checks: [{name, severity, query, ...}] or null. */
export function parsedRules(entry) {
  const f = (entry.files || []).find((x) => x.path === 'rules.yaml');
  if (!f) return null;
  const list = readRulesYaml(f.content);
  return list ? list.filter((x) => x.isMap).map(({ line, isMap, ...rest }) => rest) : null;
}

export function readTests(entry) {
  const f = (entry.files || []).find((x) => x.path === 'tests.json');
  if (!f) return null;
  try {
    return JSON.parse(f.content);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- the parser's records

/** The sensor types a parser folder's records carry in a schema, from the emulator on its samples. */
export function folderSensorTypes(parserFolder, schemaId, results = null) {
  const out = new Set();
  for (const r of results || emulate(parserFolder)) {
    const recs = [[firstSchema(r.schema), r.normalized], ...(r.also || []).map((a) => [a.schema, a.normalized])];
    for (const [s, n] of recs) if (s === schemaId && n && typeof n.sensor_type === 'string') out.add(n.sensor_type);
  }
  return out;
}

// ---------------------------------------------------------------- meta.json

function checkMeta(r, entry, ctx) {
  const m = entry.meta;
  const err = (msg) => r.error('meta', msg, 'meta.json');
  if (!isObj(m)) {
    err('meta.json must be a JSON object');
    return false;
  }
  if (!RULE_KINDS.includes(m.kind)) {
    err(`kind must be ${RULE_KINDS.join(' or ')}`);
    return false;
  }
  for (const k of ['title', 'vendor', 'product']) if (!text(m[k], 80)) err(`${k} is required (text up to 80 characters)`);
  for (const k of Object.keys(m)) if (!META_KEYS[m.kind].includes(k)) err(`"${k}" is not a ${m.kind} entry meta.json field`);
  if (m.kind === 'detection') {
    if (!SCHEMA_IDS.includes(m.schema)) err(`schema must be the schema the rules read, one of ${SCHEMA_IDS.join(', ')}`);
    if (!Array.isArray(m.sensor_types) || !m.sensor_types.length || m.sensor_types.some((s) => !text(s, 80))) err('sensor_types must list the sensor types the parser writes that the rules match');
    if (!text(m.volume, 600)) err('volume is required: how many detections a day to expect, and when there are more (up to 600 characters)');
  }
  if (!ctx.library) return true;
  // The library's own rules, for a contribution
  if (typeof m.vendor === 'string' && typeof m.title === 'string' && ctx.id) {
    const want = `${slug(m.vendor)}/${slug(m.title)}`;
    if (want !== ctx.id) r.error('folder', `the entry would be rules/${ctx.id}, but vendor and title make it rules/${want}`, 'meta.json');
  }
  if (typeof m.author !== 'string' || !HANDLE.test(m.author)) err('author must be a GitHub handle, without the @');
  if (!LICENSES.includes(m.license)) err(`license must be one of ${LICENSES.join(', ')}`);
  if (!Array.isArray(m.docs) || !m.docs.length || m.docs.some((u) => typeof u !== 'string' || !/^https:\/\//.test(u))) err('docs must list the https pages of the public docs the entry follows');
  for (const p of aboutProblems(m, { kind: 'rule' })) r.add(p.level, 'about', p.message, 'meta.json');
  if (!text(m.mdr_note, 800)) err("mdr_note is required: in public words, that the detections and cases are the customer's to work, and Sophos MDR doesn't work them (up to 800 characters)");
  else if (MDR_DENY.test(m.mdr_note)) err(`mdr_note: "${MDR_DENY.exec(m.mdr_note)[0]}" reads as an internal tier, plan or date. Use the public wording only.`);
  const t = m.tested;
  if (!isObj(t)) err('tested must be an object like {"search": null, "tenant": null}');
  else {
    for (const k of Object.keys(t)) if (!['search', 'tenant'].includes(k)) err(`tested.${k} is not a field (search, tenant)`);
    if (t.search !== null && !(typeof t.search === 'string' && DATE.test(t.search))) err('tested.search must be null or the date (YYYY-MM-DD) each query returned its sample lines, and only them, in Data Lake Search');
    if (m.kind === 'case' && t.search) err('tested.search is for detection rules: a case rule has no search to run, so leave it null');
    if (t.tenant !== null && !(isObj(t.tenant) && DATE.test(t.tenant.date || '') && /^[a-z]{2}\d{2}$/.test(t.tenant.region || ''))) err('tested.tenant must be null or {"date": "YYYY-MM-DD", "region": "eu01"}, recorded only after the rules ran live in a real tenant');
  }
  if (typeof m.parser !== 'string' || !PARSER_PATH.test(m.parser)) err('parser must be the library path of the parser entry the rules need, such as "parsers/thinkst/opencanary". A new source contributes its parser first, in its own pull request.');
  const links = m.links === undefined ? {} : m.links;
  if (!isObj(links)) err('links must be an object');
  else if (m.kind === 'detection') {
    for (const k of Object.keys(links)) if (!['case_rule', 'playbooks'].includes(k)) err(`links.${k} is not a field (case_rule, playbooks)`);
    if (links.case_rule !== undefined && links.case_rule !== null && (typeof links.case_rule !== 'string' || !RULE_PATH.test(links.case_rule))) err('links.case_rule must be the path of a case entry, such as "rules/acme/acme-one-case-per-host"');
    if (links.playbooks !== undefined && (!Array.isArray(links.playbooks) || links.playbooks.some((p) => typeof p !== 'string' || !PLAYBOOK_PATH.test(p)))) err('links.playbooks must list playbook paths, such as "playbooks/microsoft/teams-case-chat-sync"');
  } else {
    for (const k of Object.keys(links)) if (k !== 'detection_rules') err(`links.${k} is not a field (detection_rules)`);
    if (typeof links.detection_rules !== 'string' || !RULE_PATH.test(links.detection_rules)) err('links.detection_rules must be the path of the detection rule entry the case rule collects');
  }
  return true;
}

// ---------------------------------------------------------------- detection entries

// True when every condition beyond the sensor type compares a field with IPs, domains or hashes.
function iocOnly(parsed) {
  const leaves = conditions(parsed.where).filter((c) => c.field !== 'sensor_type');
  if (!leaves.length) return false;
  return leaves.every((c) => ['=', 'in'].includes(c.op) && (c.values || [c.value]).every((l) => l && l.kind === 'string' && Object.values(IOC).some((re) => re.test(l.value))));
}

function checkRules(r, entry, ctx) {
  const m = entry.meta;
  const f = (entry.files || []).find((x) => x.path === 'rules.yaml');
  if (!f) return null;
  const list = readRulesYaml(f.content, r);
  if (!list) return null;
  if (!list.length) r.error('rules', 'rules.yaml lists no rules', 'rules.yaml');
  if (list.length > LIMITS.rules) r.error('rules', `at most ${LIMITS.rules} rules per entry`, 'rules.yaml');
  // Sensor types must come from the custom parser: rules on Sophos products and built-in integrations are refused.
  if (ctx.parser) {
    const produced = folderSensorTypes(ctx.parser, m.schema, ctx.parserResults);
    for (const st of Array.isArray(m.sensor_types) ? m.sensor_types : []) {
      if (typeof st === 'string' && !produced.has(st)) r.error('sensor', `sensor_types: ${st} isn't a sensor type the parser writes to ${m.schema} (its records have ${[...produced].join(', ') || 'none'}). Rules here are only for sources that reach Sophos NG-SIEM through a custom parser.`, 'meta.json');
    }
  }
  const names = new Set();
  for (const rule of list) {
    const at = rule.line;
    const where = `rule ${JSON.stringify(rule.name || '?')}`;
    if (!rule.isMap) {
      r.error('rules', 'each rule is a mapping of name, description, severity, mitre, query and enabled_by_default', 'rules.yaml', at);
      continue;
    }
    for (const k of Object.keys(rule)) {
      if (['line', 'isMap'].includes(k) || RULE_KEYS.includes(k)) continue;
      r.error('rules', `${where}: "${k}" is not a field.${REFUSED_KEYS[k] ? ` ${REFUSED_KEYS[k]}` : ''} rules.yaml holds the Create Rule form's fields only: ${RULE_KEYS.join(', ')}.`, 'rules.yaml', at);
    }
    if (!text(rule.name, LIMITS.name)) r.error('rules', `a rule needs a name (up to ${LIMITS.name} characters), which becomes its detections' title`, 'rules.yaml', at);
    else {
      if (names.has(rule.name.toLowerCase())) r.error('rules', `${where} is in rules.yaml twice`, 'rules.yaml', at);
      names.add(rule.name.toLowerCase());
      if (/claude/i.test(rule.name)) r.error('rules', `${where}: keep assistant names out of rule names, which become tenant objects`, 'rules.yaml', at);
    }
    if (!text(rule.description, LIMITS.description)) r.error('rules', `${where} needs a description (up to ${LIMITS.description} characters)`, 'rules.yaml', at);
    if (!SEVERITIES.includes(rule.severity)) r.error('rules', `${where}: severity must be one of ${SEVERITIES.join(', ')}`, 'rules.yaml', at);
    if (typeof rule.enabled_by_default !== 'boolean') r.error('rules', `${where}: enabled_by_default must be true or false`, 'rules.yaml', at);
    else if ((rule.severity === 'low' || rule.severity === 'informational') && rule.enabled_by_default) r.error('rules', `${where} is ${rule.severity}, so it ships off: set enabled_by_default to false`, 'rules.yaml', at);
    if (!Array.isArray(rule.mitre) || rule.mitre.some((t) => typeof t !== 'string' || !MITRE.test(t))) r.error('rules', `${where}: mitre must list MITRE ATT&CK technique IDs, such as T1110 or T1078.003, or be []`, 'rules.yaml', at);
    else if (!rule.mitre.length) r.warn('rules', `${where} has no MITRE technique`, 'rules.yaml', at);
    if (typeof rule.query !== 'string' || !rule.query.trim() || rule.query.length > LIMITS.query) {
      r.error('ql', `${where} needs a query (up to ${LIMITS.query} characters)`, 'rules.yaml', at);
      continue;
    }
    let parsed;
    try {
      parsed = parseQuery(rule.query);
    } catch (e) {
      if (!(e instanceof QlError)) throw e;
      r.error('ql', `${where}: the query doesn't parse: ${e.message}`, 'rules.yaml', at);
      continue;
    }
    for (const p of ruleQueryProblems(parsed, { schemaId: SCHEMA_IDS.includes(m.schema) ? m.schema : null })) r.add(p.level, p.code, `${where}: ${p.message}`, 'rules.yaml', at);
    const pins = pinnedSensorTypes(parsed);
    if (!pins.length) r.error('sensor', `${where}: the query must pin the sensor type with a top-level sensor_type = '...', so it matches only the custom parser's records`, 'rules.yaml', at);
    for (const p of pins) if (Array.isArray(m.sensor_types) && !m.sensor_types.includes(p)) r.error('sensor', `${where}: the query matches sensor type ${p}, which isn't in sensor_types`, 'rules.yaml', at);
    const beyond = conditions(parsed.where).filter((c) => c.field !== 'sensor_type');
    if (!beyond.length) r.error('rules', `${where} matches every event of the sensor type. Each rule needs a condition beyond sensor_type.`, 'rules.yaml', at);
    else if (iocOnly(parsed)) r.error('ioc', `${where} only matches literal IP addresses, domains or hashes. Sophos's IP and Domain Watchlists do that, so these skills make no IOC rules.`, 'rules.yaml', at);
    if (conditions(parsed.where).some((c) => c.op === 'matches_regex')) r.review(`${where} uses MATCHES_REGEX. Rules and Data Lake Search use different regex engines, so run it as a live rule as well as a search.`, 'rules.yaml');
  }
  return list;
}

/** Runs the parser on its samples, then the rules on the records, and holds tests.json to it. */
function checkTests(r, entry, ctx, list) {
  const f = (entry.files || []).find((x) => x.path === 'tests.json');
  if (!f || !list || !ctx.parser) return null;
  let tests;
  try {
    tests = JSON.parse(f.content);
  } catch (e) {
    r.error('json', `tests.json is not valid JSON: ${e.message}`, 'tests.json');
    return null;
  }
  const results = ctx.parserResults || emulate(ctx.parser);
  const compiled = compileRules(list.filter((x) => typeof x.query === 'string'));
  const hits = ruleHits(compiled, results);
  for (const msg of compareTests(tests, hits, compiled.map((x) => x.name))) r.error('tests', msg, 'tests.json');
  return { hits, results, compiled };
}

// ---------------------------------------------------------------- case entries

function checkCaseRule(r, entry, ctx) {
  const f = (entry.files || []).find((x) => x.path === 'case-rule.yaml');
  if (!f) return null;
  const doc = readCaseRuleYaml(f.content, r);
  if (!doc) return null;
  const { rule, template, lines } = doc;
  const file = 'case-rule.yaml';
  const e = (code, msg, key) => r.error(code, msg, file, lines[key] || null);
  for (const k of Object.keys(rule)) if (!CASE_RULE_KEYS.includes(k)) r.warn('case', `case-rule.yaml: "${k}" isn't a field these checks know in an Automatic Cases rule`, file, lines[k]);
  if (rule.apiVersion !== 'v0.0.1') e('case', 'apiVersion must be v0.0.1, as Automatic Cases exports it', 'apiVersion');
  if (typeof rule.name !== 'string' || !CASE_NAME.test(rule.name)) e('case', 'name must be letters, digits and underscores, starting with a letter', 'name');
  if (!text(rule.title, 120)) e('case', 'title is required', 'title');
  if (rule.type !== 'STATIC') e('case', 'type must be STATIC', 'type');
  if (rule.state !== 'TEST') e('case', 'state must be TEST: the case rule installs in Test state, and you turn it on after reading its Rule Logs', 'state');
  if (rule.is_global !== false) e('case', 'is_global must be false: partner-level case rules reach every customer tenant', 'is_global');
  if (rule.template_name !== template.name) e('case', `template_name must be the template in the same file, ${template.name}`, 'template_name');
  if (rule.append_filter !== undefined && rule.append_filter !== null && rule.append_filter !== '') r.review(`append_filter adds detections to an open case beyond the filter: check it can't reach Sophos's detections: ${String(rule.append_filter).slice(0, 200)}`, file);
  if (!Number.isInteger(rule.group_count) || rule.group_count < 1) e('case', 'group_count must be a whole number, 1 or more', 'group_count');
  const want = ctx.detection ? ctx.detection.rules : null;
  let titles = [];
  if (typeof rule.filter !== 'string' || !rule.filter.trim()) e('filter', 'filter is required', 'filter');
  else {
    let parsed = null;
    try {
      parsed = parseQuery(rule.filter);
    } catch (x) {
      if (!(x instanceof QlError)) throw x;
      e('filter', `the filter doesn't parse: ${x.message}`, 'filter');
    }
    if (parsed) {
      if (parsed.schemas.length !== 1 || parsed.schemas[0].toLowerCase() !== 'detection') e('filter', 'the filter must read from detection', 'filter');
      if (parsed.pipeline !== null || parsed.time.length) e('filter', "the filter can't have a pipeline, EARLIEST or LATEST", 'filter');
      const top = topConjuncts(parsed.where).filter((c) => c.type === 'cmp');
      const detector = top.find((c) => c.field === 'metadata.creator.detector.detector_id' && c.op === '=' && c.value.kind === 'string' && c.value.value === CUSTOM_DETECTOR);
      if (!detector) e('filter', `the filter must take only custom detections: a top-level metadata.creator.detector.detector_id = '${CUSTOM_DETECTOR}'. Otherwise it can reach other detectors, Sophos's included.`, 'filter');
      const title = top.find((c) => c.field === 'title' && (c.op === '=' || c.op === 'in'));
      if (!title) e('filter', "the filter must name the rules it collects: a top-level title = '...' or title in (...), with the detection rules' names", 'filter');
      else titles = (title.values || [title.value]).map((l) => String(l.value));
      if (want) {
        for (const t of titles) {
          const hit = want.find((x) => x.name === t);
          if (!hit) e('filter', `the filter names "${t}", which isn't a rule in ${ctx.detection.label}. It could take another rule's detections.`, 'filter');
          else if (!CASE_SEVERITIES.has(hit.severity)) e('filter', `the filter names "${t}", a ${hit.severity} rule. Case rules act only on Medium and higher detections.`, 'filter');
        }
      } else r.warn('filter', 'No detection rule set to check the filter titles against. Give the rules folder.', file);
    }
  }
  if (!Array.isArray(rule.group_by) || !rule.group_by.length || rule.group_by.some((g) => typeof g !== 'string')) e('group', 'group_by must list the expressions that group detections into a case', 'group_by');
  else if (typeof rule.name === 'string' && rule.group_by.some((g) => !g.includes(rule.name))) e('group', `each group_by expression must carry the rule's name, ${rule.name}, so only this rule adds to its cases: grouping isn't tied to a rule`, 'group_by');
  const tl = doc.templateLine;
  for (const k of Object.keys(template)) if (!TEMPLATE_KEYS.includes(k)) r.warn('case', `the template's "${k}" isn't a field these checks know`, file, tl);
  if (template.apiVersion !== 'v0.0.1') r.error('case', "the template's apiVersion must be v0.0.1", file, tl);
  if (typeof template.name !== 'string' || !CASE_NAME.test(template.name)) r.error('case', "the template's name must be letters, digits and underscores, starting with a letter", file, tl);
  if (!text(template.title, 120)) r.error('case', 'the template needs a title', file, tl);
  const inv = template.investigation;
  if (!isObj(inv)) r.error('case', 'the template needs an investigation block: the case it opens', file, tl);
  else {
    for (const k of Object.keys(inv)) if (!INVESTIGATION_KEYS.includes(k)) r.warn('case', `investigation.${k} isn't a field these checks know`, file, tl);
    if (inv.type !== 'SECURITY_INVESTIGATION') r.error('case', 'investigation.type must be SECURITY_INVESTIGATION, the Security Case type, which you manage', file, tl);
    if (inv.status !== 'OPEN') r.error('case', 'investigation.status must be OPEN', file, tl);
    if (inv.assignee !== undefined && inv.assignee !== null && inv.assignee !== '') r.error('case', 'leave out the assignee: user IDs differ in every tenant, so you set it after import', file, tl);
    if (!Array.isArray(inv.usages) || !inv.usages.includes('AUTO_INVESTIGATION')) r.error('case', 'investigation.usages must include AUTO_INVESTIGATION, so the case rule can use the template', file, tl);
  }
  for (const n of [rule.name, rule.title, template.name, template.title]) if (typeof n === 'string' && /claude/i.test(n)) r.error('case', 'keep assistant names out of case rule and template names, which become tenant objects', file, null);
  return { rule, template, titles };
}

// ---------------------------------------------------------------- files and scans

function scanFile(r, entry, f) {
  for (const s of gitleaksProblems(f.content, `rules/${entry.id}/${f.path}`, { source: f.path })) r.error(s.code, s.message, f.path, s.line);
  let content = f.content;
  if (f.path === 'meta.json') {
    try {
      content = JSON.stringify({ ...JSON.parse(f.content), docs: undefined }, null, 2);
    } catch {
      // scanned as is
    }
  }
  for (const s of scanText(content, { source: f.path })) r.add(s.level, s.code, s.message, f.path, s.line);
  for (const m of f.content.matchAll(UUID)) r.error('id', `${m[0]} looks like a tenant, user or object ID. Rule entries hold none.`, f.path, lineOf(f.content, m.index));
}

/**
 * Checks one rule entry. opts: {parser: a loaded parser folder (detection), detection: {label, rules}
 * (case), library: true for the library's contribution rules, id: the library folder id}.
 * Returns {ok, problems, rules, hits, results, caseRule}.
 */
export function validateRuleEntry(entry, opts = {}) {
  const r = new Report();
  for (const p of entry.loadProblems || []) r.add(p.level, p.code, p.message, p.file || null, p.line || null);
  const ctx = { parser: opts.parser || null, parserResults: opts.parser ? emulate(opts.parser) : null, detection: opts.detection || null, library: Boolean(opts.library), id: opts.id || entry.id };
  const ok = checkMeta(r, entry, ctx);
  const kind = ok && entry.meta ? entry.meta.kind : null;
  const names = (entry.files || []).map((f) => f.path);
  if (kind) {
    for (const f of names) if (!RULE_FILES[kind].includes(f)) (ctx.library ? r.error : r.warn).call(r, 'files', `${f} is not allowed in a ${kind} entry (allowed: ${RULE_FILES[kind].join(', ')})`, f);
    for (const f of REQUIRED[kind]) if (!names.includes(f)) r.error('files', `${f} is missing`, f);
  }
  if (ctx.library) for (const f of entry.files || []) scanFile(r, entry, f);
  let list = null;
  let tested = null;
  let caseRule = null;
  if (kind === 'detection') {
    if (!ctx.parser) r.error('parser', 'Give the parser folder whose records the rules read (--parser).', null);
    list = checkRules(r, entry, ctx);
    tested = checkTests(r, entry, ctx, list);
  } else if (kind === 'case') {
    caseRule = checkCaseRule(r, entry, ctx);
  }
  return { ok: !r.problems.some((p) => p.level === 'error'), problems: r.problems, rules: list ? list.filter((x) => x.isMap).map(({ line, isMap, ...rest }) => rest) : null, hits: tested ? tested.hits : null, results: tested ? tested.results : null, caseRule };
}

/** The sensor type patterns Sophos rules name, as exact names and other patterns (from tools/lib/rules.mjs). */
export function coveragePatterns(namedSensorTypes) {
  const exact = new Map();
  const patterns = [];
  for (const p of namedSensorTypes || []) {
    const names = literalNames(p);
    if (names) for (const n of names) exact.set(n.toLowerCase(), n);
    else {
      try {
        patterns.push({ re: new RegExp(p, 'i'), pattern: p });
      } catch {
        // left out
      }
    }
  }
  return { exact, patterns };
}

// X, ^X$, and ^(A|B)$ or ^(A|B)_SUFFIX$ stand for names; an alternation without anchors stays a pattern.
function literalNames(p) {
  const raw = String(p);
  const anchored = raw.startsWith('^') && raw.endsWith('$');
  const s = raw.replace(/^\^/, '').replace(/\$$/, '');
  const alt = /^\(([^()]+)\)([A-Za-z0-9_ ]*)$/.exec(s);
  if (alt) return anchored && alt[1].split('|').every((x) => /^[A-Za-z0-9_ ]+$/.test(x)) ? alt[1].split('|').map((x) => x + alt[2]) : null;
  return /^[A-Za-z0-9_ ]+$/.test(s) ? [s] : null;
}

/** MITRE techniques a rule shares with Sophos rules that match every sensor type. T1078 and T1078.004 share T1078. */
export function sharedTechniques(anySensorTechniques, mitre) {
  if (!Array.isArray(anySensorTechniques) || !Array.isArray(mitre)) return [];
  const base = (t) => String(t).split('.')[0];
  const theirs = new Set(anySensorTechniques.map(base));
  return [...new Set(mitre.filter((t) => theirs.has(base(t))))];
}
