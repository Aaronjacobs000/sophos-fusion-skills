// CEL cases files: named expressions with sample inputs and the result each
// should give. Offline, every expression is parsed. Against a tenant, each
// case runs in Fusion's own engine (evaluateExpr) and the results print as a
// truth table.
//
// File shape (JSON):
// {
//   "template": "template.yaml",            // optional, for "from" lookups
//   "cases": [
//     { "name": "...",
//       "from": "triggerHints[0].config.filter" | "task:<name>.<field>[.<key>]" | "dsl.outcomeMessage",
//       "expression": "...",                // instead of "from"
//       "inputs": { ... } | "inputsFile": "sample.json",
//       "bindings": { "<task name>": { "outputs": { ... } } },
//       "expect": <value> | "expectError": true }
//   ]
// }

import fs from 'node:fs';
import path from 'node:path';
import { SfsError } from './errors.mjs';
import { checkField, splitTemplate } from './cel.mjs';
import { loadYaml, getNode, YAML } from './yamlx.mjs';
import { walkDsl } from './dsl.mjs';
import { evaluate } from './fusion.mjs';

export function loadCases(file) {
  let data;
  try {
    data = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (error) {
    throw new SfsError(`${file} is not valid JSON: ${error.message}`, { code: 'bad_cases' });
  }
  if (!Array.isArray(data?.cases) || data.cases.length === 0) throw new SfsError(`${file} needs a non-empty "cases" list.`, { code: 'bad_cases' });
  const dir = path.dirname(file);
  let template = null;
  if (data.template) {
    const tfile = path.resolve(dir, data.template);
    const loaded = loadYaml(fs.readFileSync(tfile, 'utf8'));
    if (!loaded.ok) throw new SfsError(`${data.template} does not parse as YAML.`, { code: 'bad_cases' });
    template = { file: tfile, loaded };
  }
  const cases = data.cases.map((c, i) => {
    if (!c?.name) throw new SfsError(`Case ${i + 1} needs a name.`, { code: 'bad_cases' });
    const expression = c.expression ?? resolveFrom(c.from, template, c.name);
    let inputs = c.inputs;
    if (c.inputsFile) inputs = JSON.parse(fs.readFileSync(path.resolve(dir, c.inputsFile), 'utf8'));
    if (!('expect' in c) && !c.expectError) throw new SfsError(`Case "${c.name}" needs "expect" or "expectError".`, { code: 'bad_cases' });
    return { name: c.name, from: c.from ?? null, expression, inputs, bindings: c.bindings ?? null, expect: c.expect, expectError: Boolean(c.expectError) };
  });
  return { file, template: template?.file ?? null, cases };
}

/** Find the expression a case points at inside the template. */
export function resolveFrom(from, template, caseName) {
  if (!from) throw new SfsError(`Case "${caseName}" needs "expression" or "from".`, { code: 'bad_cases' });
  if (!template) throw new SfsError(`Case "${caseName}" uses "from", so the cases file needs "template".`, { code: 'bad_cases' });
  const { loaded } = template;
  let node;
  if (from.startsWith('task:')) {
    const [taskName, ...rest] = from.slice(5).split('.');
    const model = walkDsl(getNode(loaded.doc.contents, 'dsl'), loaded.lineOf);
    const task = model.tasks.find((t) => t.name === taskName);
    if (!task) throw new SfsError(`Case "${caseName}": no task named ${taskName} in the template.`, { code: 'bad_cases' });
    node = task.node;
    for (const key of rest) node = getNode(node, key);
  } else {
    node = loaded.doc.contents;
    for (const part of from.match(/[^.[\]]+/g) || []) {
      node = /^\d+$/.test(part) ? (YAML.isSeq(node) ? node.items[Number(part)] : undefined) : getNode(node, part);
    }
  }
  if (!YAML.isScalar(node) || typeof node.value !== 'string') throw new SfsError(`Case "${caseName}": "${from}" does not point at an expression string.`, { code: 'bad_cases' });
  if (node.type === 'QUOTE_SINGLE') throw new SfsError(`Case "${caseName}": "${from}" is a single-quoted literal, which Fusion does not evaluate.`, { code: 'bad_cases' });
  return node.value;
}

/** A JSON value written as a CEL literal. */
export function toCelLiteral(value) {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new SfsError('Bindings cannot hold NaN or Infinity.', { code: 'bad_cases' });
    return Number.isInteger(value) ? String(value) : String(value).includes('e') ? value.toExponential() : String(value);
  }
  if (typeof value === 'string') return `'${value.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t')}'`;
  if (Array.isArray(value)) return `[${value.map(toCelLiteral).join(', ')}]`;
  return `{${Object.entries(value).map(([k, v]) => `${toCelLiteral(k)}: ${toCelLiteral(v)}`).join(', ')}}`;
}

/**
 * evaluateExpr binds only `inputs`. Task results are supplied by wrapping the
 * expression in cel.bind(name, <value>, ...), once per binding. Templates get
 * the wrap inside each ${...}.
 */
export function withBindings(expression, bindings) {
  if (!bindings || Object.keys(bindings).length === 0) return expression;
  const wrap = (expr) => Object.entries(bindings).reduceRight((inner, [name, val]) => `cel.bind(${name}, ${toCelLiteral(val)}, ${inner})`, expr);
  if (expression.includes('${')) {
    const split = splitTemplate(expression);
    if (!split.ok) return expression;
    return split.parts.map((p) => (p.kind === 'expr' ? `\${${wrap(p.text)}}` : p.text)).join('');
  }
  return wrap(expression);
}

export function offlineCheck(cases) {
  return cases.cases.map((c) => {
    const r = checkField(c.expression);
    return { name: c.name, ok: r.ok, ...(r.ok ? {} : { error: r.error.message }) };
  });
}

function sameValue(a, b) {
  return JSON.stringify(normalize(a)) === JSON.stringify(normalize(b));
}

function normalize(v) {
  if (Array.isArray(v)) return v.map(normalize);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = normalize(v[k]);
    return out;
  }
  return v;
}

/** Run every case in Fusion. Returns rows for the truth table. */
export async function runCases(client, cases) {
  const rows = [];
  for (const c of cases.cases) {
    const expression = withBindings(c.expression, c.bindings);
    let got;
    let error = null;
    try {
      const r = await evaluate(client, expression, c.inputs);
      if (r.errorMessage) error = r.errorMessage;
      else got = r.output;
    } catch (e) {
      error = e.message;
    }
    let result;
    if (c.expectError) result = error ? 'PASS' : 'FAIL';
    else if (error) result = 'ERROR';
    else result = sameValue(got, c.expect) ? 'PASS' : 'FAIL';
    rows.push({ name: c.name, expect: c.expectError ? '(an error)' : c.expect, got: error ? `error: ${error.split('\n')[0].slice(0, 200)}` : got, result });
  }
  return rows;
}

export function truthTable(rows) {
  const cell = (v) => {
    const s = typeof v === 'string' ? v : JSON.stringify(v);
    return s.length > 48 ? `${s.slice(0, 45)}...` : s;
  };
  const header = ['case', 'expect', 'got', 'result'];
  const data = rows.map((r) => [r.name, cell(r.expect), cell(r.got), r.result]);
  const widths = header.map((h, i) => Math.max(h.length, ...data.map((d) => String(d[i]).length)));
  const line = (cols) => cols.map((c, i) => String(c).padEnd(widths[i])).join(' | ');
  return [line(header), widths.map((w) => '-'.repeat(w)).join('-|-'), ...data.map(line)].join('\n');
}
