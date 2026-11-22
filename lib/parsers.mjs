// Custom parsers for Sophos NG-SIEM: the local parser folder (the library's layout), the offline
// checks on the vendored emulator, the read-only checks in the tenant's own engine, and the parser
// API calls. The parser API is undocumented: references/api.md in the parsers skill dates each fact.
//
// A parser folder holds meta.json, one <NAME>.parser.txt per parser, samples.log (masked lines),
// expected.json (the emulator's output), and test-confirms.json (local only: the PATTERN confirm
// each child gets when it is tested flattened with its parent, since the tenant's test call takes
// one unsaved parser).

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { SfsError, UsageError } from './errors.mjs';
import { stateDir, withLock } from './ledger.mjs';
import { pollUntil } from './fusion.mjs';
import {
  compareExpected,
  compileGo,
  enumNumbers,
  expectedFrom,
  GENERIC,
  lintParsers,
  messageType,
  parseScript,
  runParsers,
  schemaInfo,
  SCHEMA_IDS,
  typeKind,
} from './xsl.mjs';
import { sampleLines } from './samples.mjs';

export const PARSER_FILE = /^([A-Z0-9_]+)\.parser\.txt$/;
export const API_FORMATS = { json: 'JSON', cef: 'CEF', leef: 'LEEF' };
export const API_TYPES = { parent: 'PARENT', child: 'CHILD', standalone: 'STANDALONE' };
// Fields the platform sets after parsing, which a parser can't set and the comparison skips.
export const PLATFORM_FIELDS = new Set(['resource_id', 'tenant_id', 'sensor_tenant', 'visibility', 'normalizer', 'normalizer_version', 'normalizer_revision', 'original_data', 'ingest_time_usec', 'ingest', 'schema_type', 'enrichSummary', 'enrich_summary']);
// Fields the engine fills when the parser leaves them unset.
export const ENGINE_DEFAULTS = new Set(['sensor_id', 'sensor_type', 'event_time_usec', 'event_time_fidelity']);
export const PASS_MAX_AGE_MS = 24 * 3600 * 1000;

export const sha256 = (text) => crypto.createHash('sha256').update(String(text)).digest('hex');

// ---------------------------------------------------------------- the local folder

function readJson(file, label, fallback) {
  if (!fs.existsSync(file)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    throw new UsageError(`${label} is not valid JSON: ${error.message}`);
  }
}

/** Reads a parser folder. Parsers come from meta.json when it lists them, else from the .parser.txt files. */
export function loadParserFolder(dir) {
  const abs = path.resolve(dir);
  if (!fs.existsSync(abs) || !fs.statSync(abs).isDirectory()) throw new UsageError(`${dir} is not a folder.`);
  const meta = readJson(path.join(abs, 'meta.json'), 'meta.json', null);
  if (!meta || typeof meta !== 'object') throw new UsageError(`${dir} has no meta.json. Make the folder with "parser.mjs scaffold".`);
  const texts = {};
  for (const f of fs.readdirSync(abs)) {
    const m = PARSER_FILE.exec(f);
    if (m) texts[m[1]] = fs.readFileSync(path.join(abs, f), 'utf8').replace(/\r\n?/g, '\n');
  }
  const listed = Array.isArray(meta.parsers) && meta.parsers.length ? meta.parsers : Object.keys(texts).map((name) => ({ name, file: `${name}.parser.txt`, role: 'standalone' }));
  const parsers = listed.map((p) => {
    if (texts[p.name] === undefined) throw new UsageError(`meta.json lists ${p.name}, but ${p.name}.parser.txt is not in ${dir}.`);
    const script = parseScript(texts[p.name]);
    return { name: p.name, role: p.role || 'standalone', parent: p.parent || null, schema: script.directives.SCHEMA || p.schema || GENERIC, text: texts[p.name] };
  });
  const samplesFile = path.join(abs, 'samples.log');
  return {
    dir: abs,
    meta,
    parsers,
    texts,
    samples: fs.existsSync(samplesFile) ? sampleLines(fs.readFileSync(samplesFile, 'utf8')) : [],
    expected: readJson(path.join(abs, 'expected.json'), 'expected.json', null),
    testConfirms: readJson(path.join(abs, 'test-confirms.json'), 'test-confirms.json', {}),
  };
}

export const engineParsers = (folder) => folder.parsers.map((p) => ({ name: p.name, text: p.text, parent: p.parent || undefined, role: p.role }));

export function emulate(folder, lines = folder.samples, { now } = {}) {
  return runParsers(engineParsers(folder), lines, { now: now || folder.meta.reference_time || undefined });
}

export const firstSchema = (s) => String(s || GENERIC).split(',')[0].trim();
export const lastParser = (p) => String(p || '').split(/\s*(?:->|>)\s*/).filter(Boolean).pop() || null;

// ---------------------------------------------------------------- records

function fieldDefs(schemaId) {
  return schemaInfo(schemaId)?.fields || [];
}

/** A record as path -> value: objects join with dots, key-value lists become path[key]. */
export function flatten(value, prefix = '', out = new Map()) {
  if (Array.isArray(value)) {
    if (value.length && value.every((x) => x && typeof x === 'object' && !Array.isArray(x) && typeof x.key === 'string')) {
      for (const item of value) {
        const rest = { ...item };
        delete rest.key;
        const p = `${prefix}[${item.key}]`;
        if (Object.keys(rest).length === 1 && 'value' in rest) out.set(p, rest.value);
        else flatten(rest, p, out);
      }
    } else if (value.length && value.every((x) => x && typeof x === 'object' && !Array.isArray(x))) {
      value.forEach((item, i) => flatten(item, `${prefix}[${i}]`, out));
    } else if (prefix) out.set(prefix, value);
    return out;
  }
  if (value && typeof value === 'object') {
    const keys = Object.keys(value);
    if (!keys.length && prefix) out.set(prefix, value);
    for (const k of keys) flatten(value[k], prefix ? `${prefix}.${k}` : k, out);
    return out;
  }
  if (prefix) out.set(prefix, value);
  return out;
}

function zeroEnum(type) {
  const n = enumNumbers(type);
  return n ? n['0'] ?? null : null;
}

/** The schema definition of a flattened path, walking into message types, or null. */
export function defAt(schemaId, p) {
  let defs = fieldDefs(schemaId);
  let def = null;
  for (const seg of p.split('.')) {
    const name = seg.replace(/\[.*$/, '');
    def = (defs || []).find((f) => f.name === name) || null;
    if (!def) return null;
    if (/\[[^\]\d][^\]]*\]$/.test(seg)) return { name: p, type: 'string' };
    defs = messageType(def.type);
  }
  return def;
}

/** True for a value a record holds when nothing set it: empty, 0, false, or an enum's zero member. */
export function isUnset(v, def = null) {
  if (v === null || v === undefined || v === '' || v === false || v === 0) return true;
  if (Array.isArray(v)) return v.length === 0;
  if (typeof v === 'object') return Object.keys(v).length === 0;
  if (typeof v === 'string' && def && typeKind(def.type) === 'enum') return v === zeroEnum(def.type);
  return false;
}

function enumName(def, v) {
  if (typeof v !== 'number' && !(typeof v === 'string' && /^\d+$/.test(v))) return v;
  return enumNumbers(def.type)?.[String(v)] ?? v;
}

/** Engine values with enum numbers turned into member names, nested messages included. */
function namedValue(def, v) {
  if (!def) return v;
  const kind = typeKind(def.type);
  if (Array.isArray(v)) return v.map((x) => namedValue({ ...def, repeated: false }, x));
  if (kind === 'enum') return enumName(def, v);
  if (kind === 'message' && v && typeof v === 'object') {
    const subs = messageType(def.type) || [];
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, namedValue(subs.find((s) => s.name === k), x)]));
  }
  return v;
}

/** sampleParser's fields [{destination, value}] as a record in the emulator's form (enum names). */
export function engineRecord(result) {
  const schemaId = firstSchema(result?.schema);
  const defs = fieldDefs(schemaId);
  const record = {};
  for (const f of result?.fields || []) {
    if (!f || typeof f.destination !== 'string') continue;
    record[f.destination] = namedValue(defs.find((d) => d.name === f.destination), f.value);
  }
  return { schema: schemaId, path: String(result?.extractors || '').split(/\s*->\s*/).filter(Boolean), errors: result?.errors || null, record };
}

function sameValue(a, b) {
  if (Array.isArray(a) || Array.isArray(b)) {
    const x = Array.isArray(a) ? a : [a];
    const y = Array.isArray(b) ? b : [b];
    return x.length === y.length && x.every((v, i) => sameValue(v, y[i]));
  }
  if (typeof a === 'number' || typeof b === 'number') return a !== '' && b !== '' && Number(a) === Number(b);
  if (a && typeof a === 'object' && b && typeof b === 'object') return JSON.stringify(a) === JSON.stringify(b);
  return a === b;
}

/**
 * Field-by-field differences between the emulator's record and the engine's, in one schema:
 * [{path, kind: 'differ'|'emulatorOnly'|'engineOnly', emulator, engine}]. Values stay in the result
 * for --show-values; callers print paths unless asked.
 */
export function compareRecords(emulator, engine, schemaId, { emulatorNowUsec = null, engineIngestUsec = null, schemaFieldsOnly = false } = {}) {
  const e = flatten(emulator || {});
  const g = flatten(engine || {});
  const out = [];
  const top = (p) => p.replace(/[.[].*$/, '');
  for (const p of new Set([...e.keys(), ...g.keys()])) {
    if (PLATFORM_FIELDS.has(top(p))) continue;
    const def = defAt(schemaId, p);
    const ev = e.get(p);
    const gv = g.get(p);
    const eUnset = isUnset(ev, def);
    const gUnset = isUnset(gv, def);
    if (eUnset && gUnset) continue;
    // A line with no time of its own gets each side's own ingest time.
    if (p === 'event_time_usec' && Number(ev) === emulatorNowUsec && Number(gv) === engineIngestUsec) continue;
    if (eUnset && ENGINE_DEFAULTS.has(p)) continue;
    // A Data Lake record carries what Sophos Fusion adds after parsing (alerts_data, enrichments, origin);
    // a path the schema doesn't list is one of those, not a parser difference.
    if (eUnset && schemaFieldsOnly && !def) continue;
    if (eUnset) out.push({ path: p, kind: 'engineOnly', emulator: ev ?? null, engine: gv });
    else if (gUnset) out.push({ path: p, kind: 'emulatorOnly', emulator: ev, engine: gv ?? null });
    else if (!sameValue(ev, gv)) out.push({ path: p, kind: 'differ', emulator: ev, engine: gv });
  }
  return out.sort((a, b) => a.path.localeCompare(b.path));
}

/** The field paths a record sets, and the enum members it holds, without other values. */
export function recordSummary(record, schemaId) {
  const fields = [];
  const enums = {};
  for (const [p, v] of flatten(record || {})) {
    const def = defAt(schemaId, p);
    if (isUnset(v, def)) continue;
    fields.push(p);
    if (def && typeKind(def.type) === 'enum') enums[p] = v;
  }
  return { fields: fields.sort(), enums };
}

// ---------------------------------------------------------------- offline checks

/** The lines of samples.log a !SAMPLE directive must come from, and the ones that don't. */
function sampleDirectiveProblems(folder) {
  const lines = new Set(folder.samples);
  const out = [];
  for (const p of folder.parsers) {
    p.text.split('\n').forEach((l, i) => {
      if (l.startsWith('!SAMPLE=') && !lines.has(l.slice('!SAMPLE='.length))) {
        out.push({ level: 'error', code: 'sample-directive', parser: p.name, line: i + 1, message: `${p.name} line ${i + 1}: the !SAMPLE line is not a line of samples.log. Copy one from samples.log, so no unmasked line reaches the tenant's parser code.` });
      }
    });
  }
  return out;
}

/** Flatten a child into one script with its parent: what the tenant's test call can run. */
export function flattenChild(parentText, childText, confirm) {
  const split = (t) => {
    const d = [];
    const b = [];
    for (const l of String(t).split('\n')) (l.startsWith('!') ? d : b).push(l);
    return [d, b];
  };
  const [pd, pb] = split(parentText);
  const [cd, cb] = split(childText);
  const schema = cd.find((x) => x.startsWith('!SCHEMA=')) || '!SCHEMA=scwx.generic';
  const flags = [...new Set([...cd, ...pd].filter((x) => x === '!TRIMALLOFF' || x === '!SANITIZEALLOFF'))].sort();
  return `${['!CONFIRMWITH=PATTERN', `!CONFIRMSTRING=${confirm}`, schema, ...flags, '', ...pb, '', ...cb].join('\n').replace(/\n+$/, '')}\n`;
}

/** Each child's test-confirms.json pattern must take the lines the child takes in the emulator. */
export function confirmProblems(folder, results) {
  const out = [];
  const children = folder.parsers.filter((p) => p.role === 'child' && folder.parsers.some((x) => x.name === p.parent));
  for (const c of children) {
    const pattern = folder.testConfirms?.[c.name];
    if (typeof pattern !== 'string' || !pattern) {
      out.push({ level: 'warning', code: 'test-confirm', parser: c.name, message: `test-confirms.json has no PATTERN confirm for ${c.name}, so tenant-check can't run it flattened with ${c.parent}. Add a regex that matches exactly the lines ${c.name} takes.` });
      continue;
    }
    let re;
    try {
      re = compileGo(pattern);
    } catch (error) {
      out.push({ level: 'error', code: 'test-confirm', parser: c.name, message: `test-confirms.json: the pattern for ${c.name} doesn't compile as RE2: ${error.message}` });
      continue;
    }
    const takes = results.filter((r) => lastParser(r.extractor_path) === c.name).map((r) => r.line);
    const picks = results.filter((r) => re.test(r.sample)).map((r) => r.line);
    const extra = picks.filter((l) => !takes.includes(l));
    const missing = takes.filter((l) => !picks.includes(l));
    if (extra.length || missing.length) {
      out.push({ level: 'error', code: 'test-confirm', parser: c.name, message: `test-confirms.json: the pattern for ${c.name} picks other lines than its confirm does in the emulator${missing.length ? `; it misses lines ${missing.join(', ')}` : ''}${extra.length ? `; it also picks lines ${extra.join(', ')}` : ''}.` });
    }
  }
  return out;
}

/**
 * The offline check: lint, the emulator on samples.log, expected.json, !SAMPLE lines and the test
 * confirms. Field names and enum members per line; no other values.
 */
export function checkFolder(folder, { strict = false } = {}) {
  const problems = [];
  if (!folder.samples.length) problems.push({ level: 'error', code: 'samples', message: 'samples.log has no lines.' });
  for (const p of folder.parsers) {
    if (p.role === 'child' && !folder.parsers.some((x) => x.name === p.parent)) problems.push({ level: 'error', code: 'builtin-parent', parser: p.name, message: `${p.name} is a child of ${p.parent}, which isn't in this folder. Children under built-in parsers come in a later version.` });
    if (/^!PARENT=/m.test(p.text)) problems.push({ level: 'error', code: 'builtin-parent', parser: p.name, message: `${p.name} has a !PARENT line. These skills make new parsers only, not children of built-in parsers.` });
    if (!SCHEMA_IDS.includes(p.schema)) problems.push({ level: 'error', code: 'schema', parser: p.name, message: `${p.name}: ${p.schema} is not a schema custom parsers can use.` });
  }
  const lint = lintParsers(engineParsers(folder), { samples: folder.samples, now: folder.meta.reference_time || undefined });
  for (const p of lint.problems) {
    if (p.level === 'info' || p.code === 'unmatched') continue;
    problems.push({ level: p.level === 'inferred' ? 'info' : p.level, code: `lint:${p.code}`, parser: p.parser || null, line: p.line || null, message: `${p.parser ? `${p.parser}${p.line ? ` line ${p.line}` : ''}: ` : ''}${p.message}` });
  }
  const results = lint.results?.length === folder.samples.length ? lint.results : emulate(folder);
  problems.push(...sampleDirectiveProblems(folder));
  problems.push(...confirmProblems(folder, results));
  let expected = null;
  if (Array.isArray(folder.expected)) {
    const diffs = compareExpected(results, folder.expected);
    expected = { matches: diffs.length === 0, differences: diffs.length };
    for (const d of diffs.slice(0, 50)) problems.push({ level: 'error', code: 'expected', message: `expected.json: ${d.replace(/ gives .*$| has .*$/, ' differs')}` });
  }
  const lines = results.map((r) => {
    const schema = firstSchema(r.schema);
    const s = r.normalized ? recordSummary(r.normalized, schema) : { fields: [], enums: {} };
    return { line: r.line, parser: lastParser(r.extractor_path), path: r.extractor_path, schema, error: r.error ? true : undefined, fields: s.fields, enums: s.enums };
  });
  const errors = problems.filter((p) => p.level === 'error').length;
  const warnings = problems.filter((p) => p.level === 'warning').length;
  const bySchema = {};
  for (const l of lines) bySchema[l.schema] = (bySchema[l.schema] || 0) + 1;
  return { ok: errors === 0 && (!strict || warnings === 0), errors, warnings, problems, lines, summary: { lines: lines.length, bySchema, errorLines: lines.filter((l) => l.error).length }, expected, results };
}

// ---------------------------------------------------------------- the parser API (undocumented)

const P_FIELDS = 'id name parentId disabled overrideGlobal code';

export async function listParsers(client) {
  const { data } = await client.request('query { allParsers { id name parentId disabled overrideGlobal } }', {}, { operation: 'allParsers' });
  if (!Array.isArray(data.allParsers)) throw new SfsError('allParsers answered without a list.', { code: 'bad_response' });
  return data.allParsers;
}

/** One parser by ID. A deleted parser reads as an error, the same as a failed read, so this throws then. */
export async function getParser(client, id) {
  const { data } = await client.request(`query($f: ParserFilterInput!) { parser(filter: $f) { ${P_FIELDS} } }`, { f: { id: Number(id) } }, { operation: 'parser' });
  return data.parser ?? null;
}

/** A parser by ID from the list of every parser: null only when a list read without error lacks it. */
export async function findParser(client, id) {
  const all = await listParsers(client);
  return all.find((p) => Number(p.id) === Number(id)) ?? null;
}

export async function parserSchemas(client) {
  const { data } = await client.request('query { parserSchemas }', {}, { operation: 'parserSchemas' });
  return data.parserSchemas || [];
}

export async function validateParser(client, { code, parentId = 0, name }) {
  const { data } = await client.request('query($u: UnvalidatedParserInput!) { validateParser(unvalidatedParser: $u) { ok message } }', { u: { code, parentId, ...(name ? { name } : {}) } }, { operation: 'validateParser' });
  return data.validateParser;
}

/** Runs the tenant's engine on lines. Saves nothing. With no parser, only the tenant's own parsers run. */
export async function sampleParser(client, lines, parser = null) {
  const { data } = await client.request(
    'query($m: [String!]!, $p: UnvalidatedParserInput) { sampleParser(messages: $m, parser: $p) { message results { schema extractors errors fields } } }',
    { m: lines, p: parser ? { code: parser.code, parentId: parser.parentId ?? 0, name: parser.name } : null },
    { operation: 'sampleParser', timeoutMs: 120_000 },
  );
  return data.sampleParser || [];
}

export async function createParser(client, input) {
  const { data } = await client.request(`mutation($p: ParserInput!) { createParser(parser: $p) { ${P_FIELDS} } }`, { p: input }, { operation: 'createParser' });
  return data.createParser;
}

export async function updateParser(client, id, update) {
  const { data } = await client.request(`mutation($id: Int!, $u: UpdatedParserInput!) { updateParser(id: $id, updatedParser: $u) { ${P_FIELDS} } }`, { id: Number(id), u: update }, { operation: 'updateParser' });
  return data.updateParser;
}

export async function deleteParser(client, id) {
  const { data } = await client.request('mutation($id: Int!) { deleteParser(id: $id) { id name } }', { id: Number(id) }, { operation: 'deleteParser' });
  return data.deleteParser;
}

/** Reads a parser until it matches, since reads lag writes. A read that errors counts as not yet. */
export async function readParserUntil(client, id, ok) {
  return pollUntil(async () => {
    try {
      const p = await getParser(client, id);
      return p && ok(p) ? p : null;
    } catch {
      return null;
    }
  });
}

/**
 * Disable (if on), delete, and wait for a clean parser list to lack it. Only list reads are used:
 * reading a parser by ID can answer "Internal server error" whether it is there or not.
 */
export async function removeParser(client, id) {
  const listed = async () => {
    try {
      return { ok: true, parser: await findParser(client, id) };
    } catch {
      return { ok: false, parser: null };
    }
  };
  const first = await pollUntil(async () => {
    const r = await listed();
    return r.ok ? r : null;
  });
  if (!first.ok) throw new SfsError(`The parser list could not be read, so parser ${id} was left as it is.`, { code: 'read_failed' });
  if (!first.value.parser) return { ok: true, waitedMs: 0, already: true };
  if (!first.value.parser.disabled) {
    await updateParser(client, id, { disabled: true });
    const off = await pollUntil(async () => (await listed()).parser?.disabled === true);
    if (!off.ok) throw new SfsError(`Parser ${id} did not read back disabled, so it was not deleted.`, { code: 'readback_failed' });
  }
  await deleteParser(client, id);
  return pollUntil(async () => {
    const r = await listed();
    return r.ok && r.parser === null;
  });
}

export function installedName(name, { asIs = false, prefix = 'ZZTest_' } = {}) {
  const out = asIs ? name : `${prefix}${name}`;
  if (/claude/i.test(out)) throw new UsageError('Keep assistant names out of tenant object names.');
  return out;
}

export function apiFormat(meta) {
  return API_FORMATS[String(meta?.format || '').toLowerCase()] || 'UNSTRUCTURED';
}

// ---------------------------------------------------------------- tenant check

/** The unsaved scripts tenant-check runs: standalone parsers and parents as they are, each child flattened. */
export function testScripts(folder) {
  const out = [];
  for (const p of folder.parsers) {
    if (p.role === 'child') {
      const parent = folder.parsers.find((x) => x.name === p.parent);
      const confirm = folder.testConfirms?.[p.name];
      if (!parent) continue;
      out.push({ name: p.name, code: confirm ? flattenChild(parent.text, p.text, confirm) : null, flattened: true, parent: parent.name, missingConfirm: !confirm });
    } else {
      out.push({ name: p.name, code: p.text, flattened: false });
    }
  }
  return out;
}

const chunk = (arr, n) => Array.from({ length: Math.ceil(arr.length / n) }, (_, i) => arr.slice(i * n, i * n + n));

/** Built-in parsers that take the lines already: sampleParser with no parser of ours. */
export async function builtInClaims(client, lines) {
  const out = [];
  for (const [ci, part] of chunk(lines, 50).entries()) {
    const res = await sampleParser(client, part, null);
    res.forEach((r, i) => {
      for (const x of r.results || []) {
        const p = lastParser(x.extractors);
        if (p && p !== 'Master') out.push({ line: ci * 50 + i + 1, parser: p, schema: firstSchema(x.schema) });
      }
    });
  }
  const byParser = {};
  for (const c of out) byParser[c.parser] = (byParser[c.parser] || 0) + 1;
  return { lines: [...new Set(out.map((c) => c.line))].length, byParser };
}

/** Library entries (from a local clone) whose parsers claim any of the lines in the emulator. */
export function libraryClaims(libraryDir, lines) {
  const base = path.join(libraryDir, 'parsers');
  if (!fs.existsSync(base)) throw new UsageError(`${libraryDir} has no parsers folder. Give a clone of the library.`);
  const out = [];
  for (const v of fs.readdirSync(base, { withFileTypes: true }).filter((d) => d.isDirectory())) {
    for (const p of fs.readdirSync(path.join(base, v.name), { withFileTypes: true }).filter((d) => d.isDirectory())) {
      let entry;
      try {
        entry = loadParserFolder(path.join(base, v.name, p.name));
      } catch {
        continue;
      }
      const res = emulate(entry, lines);
      const taken = res.filter((r) => r.extractor_path).length;
      if (taken) out.push({ entry: `parsers/${v.name}/${p.name}`, lines: taken });
    }
  }
  return out.sort((a, b) => b.lines - a.lines);
}

/**
 * The read-only tenant check. Returns the full report; the caller prints it. retries: how many more
 * times a line runs when the engine gave it to another parser.
 */
export async function tenantCheck(client, folder, { retries = 3, library = null } = {}) {
  const problems = [];
  const offline = checkFolder(folder);
  if (offline.errors) problems.push({ level: 'error', code: 'offline', message: `The offline check has ${offline.errors} errors. Fix them first (parser.mjs check).` });

  // Schemas the tenant takes
  const tenantSchemas = await parserSchemas(client);
  for (const p of folder.parsers) if (!tenantSchemas.includes(p.schema)) problems.push({ level: 'error', code: 'schema', parser: p.name, message: `The tenant doesn't list ${p.schema} (parserSchemas), so ${p.name} can't be saved.` });
  const newOnTenant = tenantSchemas.filter((s) => !SCHEMA_IDS.includes(s));
  for (const s of newOnTenant) problems.push({ level: 'warning', code: 'schema-data', message: `The tenant has schema ${s}, which the vendored schema data lacks. Checks on its fields are skipped.` });

  // Parsers already there
  const existing = await listParsers(client);
  const clashes = folder.parsers.flatMap((p) => existing.filter((x) => x.name === p.name || x.name === `ZZTest_${p.name}`).map((x) => ({ parser: p.name, existing: x.name, id: x.id, disabled: x.disabled })));

  // Syntax in the real engine
  const validate = [];
  for (const s of testScripts(folder)) {
    const own = folder.parsers.find((p) => p.name === s.name);
    const alone = await validateParser(client, { code: own.text, parentId: 0, name: s.name });
    validate.push({ script: s.name, flattened: false, ok: alone.ok, message: alone.ok ? null : alone.message });
    if (s.flattened && s.code) {
      const flat = await validateParser(client, { code: s.code, parentId: 0, name: s.name });
      validate.push({ script: s.name, flattened: true, ok: flat.ok, message: flat.ok ? null : flat.message });
    }
  }
  for (const v of validate.filter((x) => !x.ok)) problems.push({ level: 'error', code: 'validate', parser: v.script, message: `validateParser refused ${v.script}${v.flattened ? ' (flattened with its parent)' : ''}: ${String(v.message).slice(0, 400)}` });

  // Built-in parsers and library entries that take the lines already
  const builtIn = await builtInClaims(client, folder.samples);
  if (builtIn.lines) {
    const own = new Set(folder.parsers.flatMap((p) => [p.name, `ZZTest_${p.name}`]));
    const claimers = Object.keys(builtIn.byParser);
    const message = claimers.every((n) => own.has(n))
      ? `This folder's own installed parsers (${claimers.join(', ')}) already take ${builtIn.lines} of ${folder.samples.length} lines, and they compete with the test runs. For a clean tenant check, disable them first.`
      : `Parsers already on the tenant take ${builtIn.lines} of ${folder.samples.length} lines (${claimers.join(', ')}). Ask the user whether they want a parser anyway before going on.`;
    problems.push({ level: 'warning', code: 'builtin-claim', message });
  }
  const libraryHits = library ? libraryClaims(library, folder.samples) : null;
  if (libraryHits?.length) problems.push({ level: 'warning', code: 'library-claim', message: `Library entries claim these lines in the emulator: ${libraryHits.map((h) => `${h.entry} (${h.lines})`).join(', ')}. One may already do the job.` });

  // Every line through the engine, routed to the script the emulator says takes it
  const emu = emulate(folder);
  const scripts = testScripts(folder);
  const scriptFor = (r) => {
    const last = lastParser(r.extractor_path);
    return scripts.find((s) => s.name === last) || null;
  };
  for (const s of scripts.filter((x) => x.missingConfirm)) problems.push({ level: 'error', code: 'test-confirm', parser: s.name, message: `${s.name} has no PATTERN in test-confirms.json, so its lines can't run in the tenant's engine.` });
  const lines = [];
  const routed = new Map();
  emu.forEach((r, i) => {
    const s = scriptFor(r);
    const key = s ? s.name : '(none)';
    if (!routed.has(key)) routed.set(key, []);
    routed.get(key).push(i);
  });
  const emulatorNowUsec = Date.parse(folder.meta.reference_time || '') * 1000 || null;
  for (const [name, idxs] of routed) {
    const s = scripts.find((x) => x.name === name);
    if (s && !s.code) {
      for (const i of idxs) lines.push({ line: i + 1, expectedParser: name, expectedSchema: firstSchema(emu[i].schema), engineParser: null, engineSchema: null, skipped: 'no test confirm' });
      continue;
    }
    // Lines no parser of ours takes in the emulator run through every top-level script, and must stay with none of them.
    const runs = s ? [s] : scripts.filter((x) => !x.flattened);
    const got = new Map();
    for (const run of runs) {
      for (const part of chunk(idxs, 50)) {
        const res = await sampleParser(client, part.map((i) => folder.samples[i]), { code: run.code, parentId: 0, name: run.name });
        part.forEach((i, k) => {
          const rec = engineRecord((res[k]?.results || [])[0]);
          const took = lastParser(rec.path.join(' -> ')) === run.name;
          if (!got.has(i) || took) got.set(i, { ...rec, script: run.name, took, attempts: 1 });
        });
      }
    }
    // A line the engine gave to another parser runs again, as the library's lab harness does.
    if (s) {
      for (const i of idxs) {
        let g = got.get(i);
        for (let a = 0; a < retries && g && !g.took; a++) {
          const [again] = await sampleParser(client, [folder.samples[i]], { code: s.code, parentId: 0, name: s.name });
          const rec = engineRecord((again?.results || [])[0]);
          g = { ...rec, script: s.name, took: lastParser(rec.path.join(' -> ')) === s.name, attempts: g.attempts + 1 };
          got.set(i, g);
        }
      }
    }
    for (const i of idxs) {
      const g = got.get(i);
      const r = emu[i];
      const expectedSchema = firstSchema(r.schema);
      const engineParser = g ? lastParser(g.path.join(' -> ')) : null;
      const engineSchema = g && g.took ? g.schema : GENERIC;
      const expectedParser = s ? s.name : null;
      const routeOk = s ? Boolean(g?.took) && engineSchema === expectedSchema && !g.errors?.length : !runs.some((run) => engineParser === run.name);
      const ingestUsec = Number(g?.record?.ingest_time_usec) || null;
      const differences = s && g?.took ? compareRecords(r.normalized, g.record, expectedSchema, { emulatorNowUsec, engineIngestUsec: ingestUsec }) : [];
      lines.push({
        line: i + 1,
        expectedParser,
        expectedSchema: s ? expectedSchema : '(stays generic)',
        engineParser: engineParser === 'Master' ? null : engineParser,
        engineSchema: s ? engineSchema : g?.took ? g.schema : '(stays generic)',
        routeOk,
        attempts: g?.attempts ?? 0,
        engineErrors: g?.errors?.length ? g.errors.length : 0,
        differences,
      });
    }
  }
  lines.sort((a, b) => a.line - b.line);
  for (const l of lines.filter((x) => x.routeOk === false)) {
    problems.push({ level: 'error', code: 'route', line: l.line, message: `Line ${l.line}: the emulator gives it to ${l.expectedParser || 'no parser'} in ${l.expectedSchema}; the engine gave it to ${l.engineParser || 'no parser'} in ${l.engineSchema}${l.engineErrors ? ` with ${l.engineErrors} engine errors` : ''}.` });
  }
  const differences = {};
  for (const l of lines) for (const d of l.differences || []) {
    const k = `${d.path} (${d.kind})`;
    differences[k] = (differences[k] || 0) + 1;
  }
  const errors = problems.filter((p) => p.level === 'error').length;
  return {
    ok: errors === 0,
    errors,
    warnings: problems.filter((p) => p.level === 'warning').length,
    problems,
    schemas: { tenant: tenantSchemas.length, missingFromVendoredData: newOnTenant },
    existingParsers: existing.length,
    clashes,
    validate,
    builtIn,
    library: libraryHits,
    lines,
    differences,
  };
}

// ---------------------------------------------------------------- pass records

export function checksPath(env = process.env) {
  return path.join(stateDir(env), 'checks.json');
}

export function readChecks(env = process.env) {
  const file = checksPath(env);
  if (!fs.existsSync(file)) return { parsers: [], rules: [] };
  try {
    const d = JSON.parse(fs.readFileSync(file, 'utf8'));
    return { parsers: Array.isArray(d.parsers) ? d.parsers : [], rules: Array.isArray(d.rules) ? d.rules : [] };
  } catch {
    return { parsers: [], rules: [] };
  }
}

/** Adds a pass record under kind ("parsers" or "rules"), keeping the newest 100. */
export function savePass(kind, rec, env = process.env) {
  withLock(env, () => {
    const d = readChecks(env);
    d[kind] = [...d[kind], { ...rec, at: rec.at || new Date().toISOString() }].slice(-100);
    const file = checksPath(env);
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, `${JSON.stringify(d, null, 2)}\n`, { mode: 0o600 });
  });
}

/** The newest passing tenant check for this tenant that ran this exact code, within maxAgeMs. */
export function findParserPass(tenantId, codeSha, { env = process.env, now = Date.now(), maxAgeMs = PASS_MAX_AGE_MS } = {}) {
  return readChecks(env).parsers
    .filter((r) => r.tenantId === tenantId && Object.values(r.scripts || {}).includes(codeSha) && now - Date.parse(r.at) <= maxAgeMs)
    .pop() ?? null;
}
