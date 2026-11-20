// Template and connector file helpers: test copies, the dsl block for the
// tenant check, dependency lists, and export-and-diff.

import { YAML, getNode, loadYaml } from './yamlx.mjs';
import { walkDsl } from './dsl.mjs';
import { TENANT_FIELDS, TEST_DISPLAY_PREFIX, TEST_PREFIX } from './constants.mjs';
import { SfsError } from './errors.mjs';

export function parseOrThrow(text, file = 'the file') {
  const loaded = loadYaml(text);
  if (!loaded.ok) {
    const e = loaded.errors[0];
    throw new SfsError(`${file} does not parse as YAML${e?.line ? ` (line ${e.line})` : ''}: ${e?.message}. Run the offline validator first.`, { code: 'yaml_parse' });
  }
  if (!['Playbook', 'Connector'].includes(loaded.value?.kind)) {
    throw new SfsError(`${file} is not a Fusion playbook template or connector (kind must be Playbook or Connector).`, { code: 'bad_kind' });
  }
  return loaded;
}

/** Split "Name:1.2.3" lists from a template into { name, version } pairs. */
export function dependencyList(value, key) {
  return (Array.isArray(value?.[key]) ? value[key] : []).map((entry) => {
    const i = String(entry).lastIndexOf(':');
    return i > 0 ? { name: String(entry).slice(0, i), version: String(entry).slice(i + 1), entry: String(entry) } : { name: String(entry), version: null, entry: String(entry) };
  });
}

/**
 * The dsl block as its own YAML text, cut from the source so its lines and
 * quote styles are unchanged. lineOffset maps a line in it back to the file.
 */
export function extractDsl(text) {
  const loaded = parseOrThrow(text);
  const node = getNode(loaded.doc.contents, 'dsl');
  if (!YAML.isMap(node) || !node.range) throw new SfsError('The template has no dsl map.', { code: 'no_dsl' });
  const start = text.lastIndexOf('\n', node.range[0] - 1) + 1;
  let end = text.indexOf('\n', node.range[1] - 1);
  if (end === -1) end = text.length;
  const lines = text.slice(start, end).split('\n');
  const indent = Math.min(...lines.filter((l) => l.trim() !== '').map((l) => l.match(/^ */)[0].length));
  const dedented = lines.map((l) => l.slice(Math.min(indent, l.match(/^ */)[0].length))).join('\n');
  const lineOffset = text.slice(0, start).split('\n').length - 1;
  return { yaml: `${dedented.replace(/\s+$/, '')}\n`, lineOffset };
}

export function testName(name, prefix = TEST_PREFIX) {
  return String(name).startsWith(prefix) ? String(name) : `${prefix}${name}`;
}

export function testTitle(title) {
  const t = String(title ?? '');
  return t.startsWith(TEST_DISPLAY_PREFIX) ? t : `${TEST_DISPLAY_PREFIX}${t}`;
}

/**
 * A test copy of a template or connector: the name gets the test prefix, the
 * title gets "ZZ Test ", tenantId is dropped, and connectors named in
 * connectorMap ({ Original: ZZTest_Original }) are swapped in the connectors
 * list and in every action reference.
 */
export function makeTestCopy(text, { prefix = TEST_PREFIX, connectorMap = {} } = {}) {
  const loaded = parseOrThrow(text);
  const doc = loaded.doc;
  const v = loaded.value;
  const changes = [];
  const newName = testName(v.name, prefix);
  if (newName !== v.name) {
    doc.set('name', newName);
    changes.push({ field: 'name', from: v.name, to: newName });
  }
  if (v.title !== undefined) {
    const t = testTitle(v.title);
    if (t !== v.title) {
      doc.set('title', t);
      changes.push({ field: 'title', from: v.title, to: t });
    }
  }
  if (doc.has('tenantId')) {
    doc.delete('tenantId');
    changes.push({ field: 'tenantId', from: '(tenant ID)', to: null });
  }
  if (v.kind === 'Playbook' && Object.keys(connectorMap).length) {
    const seq = getNode(doc.contents, 'connectors');
    if (YAML.isSeq(seq)) {
      seq.items.forEach((item, i) => {
        const [name, version] = String(item.value ?? item).split(':');
        if (connectorMap[name]) {
          seq.set(i, `${connectorMap[name]}:${version}`);
          changes.push({ field: `connectors[${i}]`, from: `${name}:${version}`, to: `${connectorMap[name]}:${version}` });
        }
      });
    }
    const dslNode = getNode(doc.contents, 'dsl');
    const model = walkDsl(dslNode, () => null);
    for (const t of model.tasks) {
      if (!t.action) continue;
      const i = String(t.action).lastIndexOf('.');
      const conn = String(t.action).slice(0, i);
      if (connectorMap[conn]) {
        const next = `${connectorMap[conn]}${String(t.action).slice(i)}`;
        t.node.set('action', next);
        changes.push({ field: `${t.path}.action`, from: t.action, to: next });
      }
    }
  }
  return { text: doc.toString({ lineWidth: 0 }), name: newName, originalName: v.name, changes };
}

function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const out = {};
    for (const k of Object.keys(value).sort()) out[k] = sortKeys(value[k]);
    return out;
  }
  return value;
}

/** A template or connector reduced to what should survive an import, for diffing. */
export function normalizeForDiff(value, { prefix = TEST_PREFIX } = {}) {
  const v = JSON.parse(JSON.stringify(value ?? {}));
  for (const f of TENANT_FIELDS) delete v[f];
  if (typeof v.name === 'string' && v.name.startsWith(prefix)) v.name = v.name.slice(prefix.length);
  if (typeof v.title === 'string' && v.title.startsWith(TEST_DISPLAY_PREFIX)) v.title = v.title.slice(TEST_DISPLAY_PREFIX.length);
  if (Array.isArray(v.connectors)) v.connectors = v.connectors.map((c) => String(c).replace(new RegExp(`^${prefix}`), ''));
  if (v.dsl?.tasks) {
    const strip = (tasks) => {
      for (const t of tasks || []) {
        if (typeof t.action === 'string') t.action = t.action.replace(new RegExp(`^${prefix}`), '');
        for (const k of ['for', 'do', 'then', 'else']) strip(t[k]);
        if (t.case && typeof t.case === 'object') for (const list of Object.values(t.case)) strip(list);
      }
    };
    strip(v.dsl.tasks);
  }
  return sortKeys(v);
}

/** Paths where two values differ. Empty when they match. */
export function diffValues(a, b, path = '$', out = []) {
  if (out.length >= 200) return out;
  if (Object.is(a, b)) return out;
  const ta = Array.isArray(a) ? 'array' : a === null ? 'null' : typeof a;
  const tb = Array.isArray(b) ? 'array' : b === null ? 'null' : typeof b;
  if (ta !== tb) {
    out.push({ path, local: summarizeValue(a), tenant: summarizeValue(b) });
    return out;
  }
  if (ta === 'array') {
    const n = Math.max(a.length, b.length);
    for (let i = 0; i < n; i++) diffValues(a[i], b[i], `${path}[${i}]`, out);
    return out;
  }
  if (ta === 'object') {
    for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) diffValues(a[k], b[k], `${path}.${k}`, out);
    return out;
  }
  // Exports write some scalars differently (numbers as strings); compare as text
  if (String(a).trim() !== String(b).trim()) out.push({ path, local: summarizeValue(a), tenant: summarizeValue(b) });
  return out;
}

function summarizeValue(v) {
  if (v === undefined) return '(absent)';
  const s = typeof v === 'string' ? v : JSON.stringify(v);
  return s.length > 120 ? `${s.slice(0, 117)}...` : s;
}
