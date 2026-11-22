// Custom detection rules: the rule API (undocumented), Sophos's own rule coverage read live, the
// Data Lake search test (a port of the library's tools/lib/ql-rules.mjs onto lib/search.mjs), and
// detections. Every write is reached only through a script that passed the write gate.

import { GraphQLError, SfsError } from './errors.mjs';
import { pollUntil } from './fusion.mjs';
import { matches, parseQuery, qlName, schemaFromQlName } from './xsl.mjs';
import { qlString, qlTime, rowDay, searchRows, ROW_CAP } from './search.mjs';
import { readChecks, savePass } from './parsers.mjs';
import { coveragePatterns, sharedTechniques } from './detection-rules-check.mjs';

// Each severity's floor in the docs' bands; 0.4 and 0.6 behaved as Medium and High in the lab.
export const SEVERITY_SCORE = { critical: 0.8, high: 0.6, medium: 0.4, low: 0.2, informational: 0.1 };
export const CONFIDENCE = 0.5;
// Sophos turns a rule off above these.
export const SOPHOS_LIMITS = { perHour: 5000, perDay: 100_000 };
export const VOLUME_LIMIT = 1000;
export const SEARCH_MAX_AGE_MS = 7 * 86400e3;

/** A query as the rule API stores it: runs of whitespace, line breaks included, become one space (lab, 22/11/2026). */
export function normalizeQuery(q) {
  return String(q ?? '').replace(/\s+/g, ' ').trim();
}

/** The rule API's event type for a schema: RuleEventType, not the QL name (thirdpartyalert, not thirdparty). */
export function eventTypeOf(schemaId) {
  const name = String(schemaId).replace(/^scwx\./, '');
  return name === 'managementevent' ? 'management_event' : name;
}

const RULE_FIELDS = 'id name description enabled deleted severity confidence eventType ruleSource ruleType createAlert tags attackCategories createdAt updatedAt qlFilter { query }';

export async function getRule(client, id) {
  try {
    const { data } = await client.request(`query($id: ID!) { rule(id: $id) { ${RULE_FIELDS} } }`, { id: String(id) }, { operation: 'rule' });
    return data.rule ?? null;
  } catch (error) {
    if (error instanceof GraphQLError && error.notFound) return null;
    throw error;
  }
}

/** The tenant's custom QL rules (the list includes deleted ones, flagged). */
export async function listRules(client) {
  const out = [];
  for (let page = 0; page < 50; page++) {
    const { data } = await client.request(`query($p: Int, $c: Int) { rules(page: $p, count: $c, ruleType: QL) { ${RULE_FIELDS} } }`, { p: page, c: 100 }, { operation: 'rules' });
    const rows = data.rules || [];
    out.push(...rows.filter((r) => !out.some((x) => x.id === r.id)));
    if (rows.length < 100) break;
  }
  return out;
}

export async function rulesCount(client) {
  const { data } = await client.request('query { detailedRulesCount { custom { enabled disabled deleted } suppression { enabled disabled deleted } } }', {}, { operation: 'detailedRulesCount' });
  return data.detailedRulesCount;
}

/** validateQLFilter: { ok, errors: [text] }. Some refusals come back as GraphQL errors, others in the answer. */
export async function validateQuery(client, query, schemaId) {
  try {
    const { data } = await client.request(
      'query($f: RuleQLFilterInput!, $t: RuleEventType) { validateQLFilter(qlFilter: $f, optionalEventType: $t) { eventType originalQuery expandedQuery errors { description startLine startColumn } } }',
      { f: { query }, t: eventTypeOf(schemaId) },
      { operation: 'validateQLFilter' },
    );
    const v = data.validateQLFilter;
    const errors = (v?.errors || []).map((e) => `${e.description}${e.startLine || e.startColumn ? ` (line ${e.startLine}, column ${e.startColumn})` : ''}`);
    return { ok: errors.length === 0 && Boolean(v?.eventType), eventType: v?.eventType ?? null, errors: errors.length || v?.eventType ? errors : ['validateQLFilter returned no event type'] };
  } catch (error) {
    if (!(error instanceof GraphQLError)) throw error;
    return { ok: false, eventType: null, errors: error.errors.map((e) => String(e.message).replace(/^ql filter validation failed:\s*/, '').replace(/\s+/g, ' ').trim()) };
  }
}

export function ruleInput(rule, { name, schemaId }) {
  return {
    name,
    description: rule.description,
    severity: SEVERITY_SCORE[rule.severity],
    confidence: CONFIDENCE,
    eventType: eventTypeOf(schemaId),
    enabled: false,
    // The API saved false when this was left out (lab, 20/11/2026).
    createAlert: true,
    attackCategories: rule.mitre || [],
  };
}

/** Creates a rule, off. The query goes alone: any testShould or testShouldNot made the save fail in the lab. */
export async function createRule(client, input, query) {
  const { data } = await client.request(`mutation($i: RuleInput!, $f: RuleQLFilterInput!) { createCustomQLRule(input: $i, qlFilter: $f) { ${RULE_FIELDS} } }`, { i: input, f: { query } }, { operation: 'createCustomQLRule' });
  return data.createCustomQLRule;
}

export async function setRuleEnabled(client, id, enabled) {
  const op = enabled ? 'enableRule' : 'disableRule';
  const { data } = await client.request(`mutation($id: ID!) { ${op}(id: $id) { id enabled } }`, { id: String(id) }, { operation: op });
  return data[op];
}

export async function deleteRule(client, id, { hard = true } = {}) {
  const { data } = await client.request('mutation($id: ID!, $h: Boolean) { deleteRule(ruleID: $id, hard: $h) { id deleted enabled } }', { id: String(id), h: hard }, { operation: 'deleteRule' });
  return data.deleteRule;
}

/** A rule counts as gone when it no longer reads, or reads as deleted. */
export async function readLiveRule(client, id) {
  const r = await getRule(client, id);
  return r && !r.deleted ? r : null;
}

/** Disable (if on), hard delete, falling back to a soft delete, and read back until gone. */
export async function removeRule(client, id) {
  const live = await readLiveRule(client, id);
  if (!live) return { ok: true, waitedMs: 0, hard: null };
  if (live.enabled) {
    await setRuleEnabled(client, id, false);
    const off = await pollUntil(async () => (await getRule(client, id))?.enabled === false);
    if (!off.ok) throw new SfsError(`Rule ${id} did not read back disabled, so it was not deleted.`, { code: 'readback_failed' });
  }
  let hard = true;
  try {
    await deleteRule(client, id, { hard: true });
  } catch (error) {
    if (!(error instanceof GraphQLError)) throw error;
    hard = false;
    await deleteRule(client, id, { hard: false });
  }
  const gone = await pollUntil(async () => !(await readLiveRule(client, id)));
  return { ...gone, hard };
}

// ---------------------------------------------------------------- Sophos's own rules

/** Every global Sophos rule on a schema, through searchRules (pages start at 1). */
export async function sophosRules(client, schemaId) {
  const out = new Map();
  for (let page = 1; page <= 50; page++) {
    const { data } = await client.request(
      'query($q: SearchRulesInput!, $p: Int, $c: Int) { searchRules(query: $q, page: $p, count: $c) { pageInfo { totalPages } rules { id eventType ruleSource attackCategories filters { key pattern } qlFilter { query } } } }',
      { q: { query: `WHERE event_type = ${qlString(eventTypeOf(schemaId))}`, global: true, ruleSources: 'WATCHLIST, DETECTOR, DWL' }, p: page, c: 100 },
      { operation: 'searchRules' },
    );
    const r = data.searchRules || {};
    for (const x of r.rules || []) out.set(x.id, x);
    if (!(r.rules || []).length || page >= (r.pageInfo?.totalPages ?? 1)) break;
  }
  return [...out.values()];
}

/** Coverage in the library's terms: the sensor types Sophos rules name, and the techniques of rules that name none. */
export function coverageOf(rules) {
  const named = new Set();
  const anyTechniques = new Set();
  let anySensorRules = 0;
  for (const r of rules) {
    const pats = (r.filters || []).filter((f) => String(f.key).endsWith('.sensor_type')).map((f) => f.pattern);
    const q = r.qlFilter?.query || '';
    const inQuery = [...q.matchAll(/sensor_type\s*(?:=|in|matches_regex|matches)\s*\(?\s*'([^']+)'/gi)].map((m) => m[1]);
    if (pats.length || inQuery.length) for (const p of [...pats, ...inQuery]) named.add(p);
    else {
      anySensorRules++;
      for (const t of r.attackCategories || []) anyTechniques.add(t);
    }
  }
  return { rules: rules.length, anySensorRules, anySensorTechniques: [...anyTechniques].sort(), namedSensorTypes: [...named].sort() };
}

/** Problems of a rule set against Sophos's coverage: a named sensor type is an error, a shared technique a warning. */
export function coverageProblems(meta, rules, coverage) {
  const out = [];
  const { exact, patterns } = coveragePatterns(coverage.namedSensorTypes);
  for (const st of meta.sensor_types || []) {
    if (exact.has(String(st).toLowerCase())) out.push({ level: 'error', code: 'sensor', message: `Sensor type ${st} is one Sophos's own rules name, so it comes from a Sophos product or built-in integration. These skills make rules only for custom-parser sources.` });
    for (const p of patterns.filter((x) => x.re.test(st))) out.push({ level: 'warning', code: 'sensor', message: `Sophos rules on ${meta.schema} match sensor types like /${p.pattern}/, which ${st} fits. Check Sophos doesn't already detect this.` });
  }
  for (const r of rules) {
    const shared = sharedTechniques(coverage.anySensorTechniques, r.mitre);
    if (shared.length) out.push({ level: 'warning', code: 'technique', rule: r.name, message: `"${r.name}" shares ${shared.join(', ')} with Sophos rules on ${meta.schema} that match every sensor type. Check in Detector Explorer that Sophos doesn't already detect it.` });
  }
  return out;
}

// ---------------------------------------------------------------- search test

/** The searches: one for every record of the sensor types, and one per rule, all over the same window. */
export function ruleQueries(meta, rules, { earliest = '-7d', latest = null } = {}) {
  const time = qlTime({ earliest, latest });
  const universe = `from ${qlName(meta.schema)} where sensor_type in (${(meta.sensor_types || []).map(qlString).join(', ')})${time}`;
  return {
    universe,
    rules: rules.map((r) => {
      const p = parseQuery(r.query);
      return { name: r.name, text: `from ${p.schemas[0]} where (${p.whereText})${time}` };
    }),
  };
}

export const rowKey = (row) => (row && row.resource_id ? `id:${row.resource_id}` : JSON.stringify([row && row.original_data, row && row.event_time_usec]));

/** Per rule: what its search returned against what the rules match offline on the universe rows. */
export function compareRuleSearches(rules, universeRows, ruleRows) {
  return rules.map((r) => {
    const parsed = parseQuery(r.query);
    const offline = new Set(universeRows.filter((row) => matches(parsed.where, row)).map(rowKey));
    const rows = ruleRows.get(r.name) || [];
    const found = new Set(rows.map(rowKey));
    const perDay = {};
    for (const row of rows) perDay[rowDay(row)] = (perDay[rowDay(row)] || 0) + 1;
    return {
      name: r.name,
      search: found.size,
      offline: offline.size,
      onlySearch: [...found].filter((k) => !offline.has(k)).length,
      onlyOffline: [...offline].filter((k) => !found.has(k)).length,
      perDay,
    };
  });
}

/** Matches a day for a rule over the window: the busiest day, and the mean. */
export function volumeOf(perDay, windowDays) {
  const counts = Object.values(perDay);
  const total = counts.reduce((a, b) => a + b, 0);
  return { total, busiestDay: counts.length ? Math.max(...counts) : 0, meanPerDay: windowDays > 0 ? Math.round((total / windowDays) * 10) / 10 : total };
}

export async function searchTest(client, meta, rules, { earliest = '-7d', windowDays = 7 } = {}) {
  const q = ruleQueries(meta, rules, { earliest });
  const universe = await searchRows(client, q.universe, { max: ROW_CAP });
  const ruleRows = new Map();
  const capped = { universe: universe.capped };
  const partial = { universe: universe.partial };
  for (const r of q.rules) {
    const res = await searchRows(client, r.text, { max: ROW_CAP });
    ruleRows.set(r.name, res.rows);
    capped[r.name] = res.capped;
    partial[r.name] = res.partial;
  }
  const report = compareRuleSearches(rules, universe.rows, ruleRows).map((r) => ({ ...r, volume: volumeOf(r.perDay, windowDays), capped: capped[r.name], partial: partial[r.name] }));
  return { queries: q, records: universe.rows.length, universeCapped: universe.capped, universePartial: universe.partial, rules: report, agree: report.every((r) => r.onlySearch === 0 && r.onlyOffline === 0) };
}

/** True when a rule's search-test says it stays under the volume limit. A capped search counts as over. */
export function overVolume(r, limit = VOLUME_LIMIT) {
  return r.capped || r.volume.busiestDay > limit;
}

export function saveSearchPass(rec, env = process.env) {
  savePass('rules', { ...rec, query: normalizeQuery(rec.query) }, env);
}

/** The newest search-test of this tenant that ran this query (whitespace aside), within maxAgeMs. */
export function findSearchPass(tenantId, query, { env = process.env, now = Date.now(), maxAgeMs = SEARCH_MAX_AGE_MS } = {}) {
  const q = normalizeQuery(query);
  return readChecks(env).rules.filter((r) => r.tenantId === tenantId && normalizeQuery(r.query) === q && now - Date.parse(r.at) <= maxAgeMs).pop() ?? null;
}

// ---------------------------------------------------------------- detections

const DET_FIELDS = 'id tags status metadata { title severity created_at { seconds } creator { detector { detector_id } rule { rule_id } } } investigation_ids { id }';

export async function detectionsOf(client, ruleId, { earliest = '-1h', limit = 100 } = {}) {
  const { data } = await client.request(
    `query($in: SearchRequestInput!) { detectionSearch(in: $in) { status reason alerts { total_results list { ${DET_FIELDS} } } } }`,
    { in: { cql_query: `FROM detection WHERE metadata.creator.rule.rule_id = ${qlString(ruleId)} EARLIEST=${earliest}`, limit, offset: 0 } },
    { operation: 'detectionSearch' },
  );
  const a = data.detectionSearch?.alerts || {};
  return { total: a.total_results ?? 0, list: a.list || [], status: data.detectionSearch?.status ?? null, reason: data.detectionSearch?.reason ?? null };
}

export { schemaFromQlName };
