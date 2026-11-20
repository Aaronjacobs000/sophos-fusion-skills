// A model of a playbook's dsl block: every task, where it sits, and every
// field Fusion evaluates. The validator and the CEL cases runner both use it.
//
// How Fusion reads a playbook field (measured with playbookValidateDSLV2 on
// 21/11/2026): a string is one CEL expression, unless it holds "${", which
// makes it a template. A scalar written in YAML single quotes is a literal
// string and is not evaluated. Numbers, booleans and null are literals.
// Strings nested in maps and lists under let, variables and inputs are
// evaluated the same way.

import { YAML, getNode, keysOf, isSingleQuoted } from './yamlx.mjs';

// Keys a task may carry. Fusion warns "unexpected task dsl statement" on others.
export const TASK_KEYS = new Set([
  'name', 'description', 'condition', 'optional', 'retry', 'nolog', 'sleep', 'timeout',
  'let', 'variables', 'action', 'call', 'exec', 'inputs',
  'range', 'for', 'value', 'key', 'index', 'while', 'do', 'if', 'then', 'else', 'switch', 'case',
]);

// Fields holding one expression, and fields holding a map or tree of them.
const EXPR_FIELDS = ['condition', 'range', 'while', 'if', 'switch'];
const EXPR_TREES = ['let', 'variables', 'inputs'];
const BLOCKS = ['for', 'do', 'then', 'else'];

/**
 * Walk dsl.tasks. Returns { tasks, dslFields }. Each task is
 * { name, line, path, parent, block, siblings, index, node, keys, fields, kind,
 *   action, call, exec, condition, optional, nolog, valueName, keyName }.
 * Each field is { task, key, path, line, node, text, literal }.
 */
export function walkDsl(dslNode, lineOf) {
  const tasks = [];
  const dslFields = [];

  function fieldsFrom(node, path, key, task, out) {
    if (node === undefined || node === null) return;
    if (YAML.isScalar(node)) {
      const literal = isSingleQuoted(node) || typeof node.value !== 'string';
      out.push({ task, key, path, line: lineOf(node), node, text: typeof node.value === 'string' ? node.value : node.value, literal });
      return;
    }
    if (YAML.isMap(node)) {
      for (const pair of node.items) {
        const k = YAML.isScalar(pair.key) ? pair.key.value : String(pair.key);
        fieldsFrom(pair.value, `${path}.${k}`, key, task, out);
      }
      return;
    }
    if (YAML.isSeq(node)) {
      node.items.forEach((item, i) => fieldsFrom(item, `${path}[${i}]`, key, task, out));
    }
  }

  function walkList(seqNode, path, parent, block) {
    if (!YAML.isSeq(seqNode)) return [];
    const list = [];
    seqNode.items.forEach((item, index) => {
      const tpath = `${path}[${index}]`;
      const nameNode = getNode(item, 'name');
      const scalar = (k) => {
        const n = getNode(item, k);
        return YAML.isScalar(n) ? n.value : undefined;
      };
      const task = {
        name: YAML.isScalar(nameNode) ? String(nameNode.value) : null,
        line: lineOf(item),
        path: tpath,
        parent,
        block,
        index,
        node: item,
        keys: keysOf(item),
        fields: [],
        children: [],
        action: scalar('action'),
        call: scalar('call'),
        exec: scalar('exec'),
        sleep: scalar('sleep'),
        optional: scalar('optional') === true,
        nolog: scalar('nolog') === true,
        condition: scalar('condition'),
        valueName: scalar('value') ?? 'value',
        keyName: scalar('key') ?? 'key',
        isMap: YAML.isMap(item),
      };
      task.kind = task.action ? 'action' : task.call ? 'call' : task.exec ? 'exec' : getNode(item, 'range') !== undefined ? 'loop' : getNode(item, 'while') !== undefined ? 'while' : getNode(item, 'if') !== undefined ? 'if' : getNode(item, 'switch') !== undefined ? 'switch' : getNode(item, 'let') !== undefined ? 'let' : task.sleep !== undefined ? 'sleep' : 'other';
      tasks.push(task);
      list.push(task);
      for (const k of EXPR_FIELDS) {
        const n = getNode(item, k);
        if (n !== undefined) fieldsFrom(n, `${tpath}.${k}`, k, task, task.fields);
      }
      // sleep is a duration literal such as 30s, or an expression that gives one
      const sleepNode = getNode(item, 'sleep');
      if (YAML.isScalar(sleepNode) && typeof sleepNode.value === 'string' && !/^\d+(ms|s|m|h)$/.test(sleepNode.value)) {
        fieldsFrom(sleepNode, `${tpath}.sleep`, 'sleep', task, task.fields);
      }
      for (const k of EXPR_TREES) {
        const n = getNode(item, k);
        if (n !== undefined) fieldsFrom(n, `${tpath}.${k}`, k, task, task.fields);
      }
      for (const b of BLOCKS) {
        const n = getNode(item, b);
        if (n !== undefined) task.children.push(...walkList(n, `${tpath}.${b}`, task, b));
      }
      const cases = getNode(item, 'case');
      if (YAML.isMap(cases)) {
        for (const pair of cases.items) {
          const label = YAML.isScalar(pair.key) ? pair.key.value : String(pair.key);
          task.children.push(...walkList(pair.value, `${tpath}.case.${label}`, task, `case:${label}`));
        }
      }
    });
    // siblings in order, for scope checks
    for (const t of list) t.siblings = list;
    return list;
  }

  const tasksNode = getNode(dslNode, 'tasks');
  const top = walkList(tasksNode, 'dsl.tasks', null, null);
  for (const k of ['outputs', 'summary', 'outcomeStatus', 'outcomeMessage']) {
    const n = getNode(dslNode, k);
    if (n !== undefined) fieldsFrom(n, `dsl.${k}`, k, null, dslFields);
  }
  return { tasks, top, dslFields, tasksNode };
}

/** Tasks in the order Fusion runs them, depth first. */
export function executionOrder(top) {
  const out = [];
  const visit = (list) => {
    for (const t of list) {
      out.push(t);
      visit(t.children);
    }
  };
  visit(top);
  return out;
}

/**
 * Task names visible to a field of `task` (null means the dsl outputs and
 * outcome, which see the top-level tasks). Visible: earlier siblings, the
 * enclosing block tasks, and their earlier siblings, all the way up.
 */
export function visibleTasks(task, top) {
  const names = new Map();
  if (task === null) {
    for (const t of top) if (t.name) names.set(t.name, t);
    return names;
  }
  let cur = task;
  while (cur) {
    for (const s of cur.siblings || []) {
      if (s.index < cur.index && s.name) names.set(s.name, s);
    }
    if (cur.parent?.name) names.set(cur.parent.name, cur.parent);
    cur = cur.parent;
  }
  return names;
}

/** The chain of enclosing block tasks, innermost first. */
export function ancestors(task) {
  const out = [];
  let cur = task?.parent;
  while (cur) {
    out.push(cur);
    cur = cur.parent;
  }
  return out;
}
