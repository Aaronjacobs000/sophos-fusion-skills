// YAML loading with line numbers and quote styles kept, on the vendored
// yaml 2.9.1 parser.

import fs from 'node:fs';
import * as YAML from '../vendor/yaml/index.js';

export { YAML };

/**
 * Parse YAML text. Returns { ok, doc, value, lines, errors }.
 * lines(node) gives the 1-based line a node starts on.
 */
export function loadYaml(text) {
  const lineCounter = new YAML.LineCounter();
  const docs = YAML.parseAllDocuments(text, { lineCounter, prettyErrors: false, uniqueKeys: true, strict: true });
  const list = Array.isArray(docs) ? docs : [docs];
  const lineOf = (node) => {
    const off = node?.range?.[0];
    return typeof off === 'number' ? lineCounter.linePos(off).line : null;
  };
  const errors = [];
  if (list.length === 0) errors.push({ message: 'the file is empty', line: 1 });
  if (list.length > 1) errors.push({ message: `the file holds ${list.length} YAML documents; Fusion imports one`, line: lineOf(list[1].contents) ?? 1 });
  const doc = list[0];
  for (const e of doc?.errors || []) {
    const off = e.pos?.[0];
    errors.push({ message: e.message.split('\n')[0], line: typeof off === 'number' ? lineCounter.linePos(off).line : null });
  }
  if (errors.length) return { ok: false, errors, doc, value: null, lineOf };
  const value = doc.toJS({ maxAliasCount: 50 });
  return { ok: true, errors: [], doc, value, lineOf };
}

export function loadYamlFile(file) {
  const text = fs.readFileSync(file, 'utf8');
  return { text, ...loadYaml(text) };
}

/** The node at a key of a YAML map node, or undefined. */
export function getNode(mapNode, key) {
  if (!YAML.isMap(mapNode)) return undefined;
  const pair = mapNode.items.find((p) => (YAML.isScalar(p.key) ? p.key.value : p.key) === key);
  return pair ? pair.value : undefined;
}

export function getPair(mapNode, key) {
  if (!YAML.isMap(mapNode)) return undefined;
  return mapNode.items.find((p) => (YAML.isScalar(p.key) ? p.key.value : p.key) === key);
}

export function keysOf(mapNode) {
  if (!YAML.isMap(mapNode)) return [];
  return mapNode.items.map((p) => (YAML.isScalar(p.key) ? p.key.value : String(p.key)));
}

/** True for a scalar written in single quotes, which Fusion reads as a literal string. */
export function isSingleQuoted(node) {
  return YAML.isScalar(node) && node.type === 'QUOTE_SINGLE';
}

export function stringify(value) {
  return YAML.stringify(value, { lineWidth: 0, defaultStringType: 'PLAIN', defaultKeyType: 'PLAIN' });
}
