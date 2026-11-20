// Offline validation for Sophos Fusion playbook templates and connectors.
// No credentials, no network. Every finding carries a rule ID, a level
// (error or warning), a message, the YAML path and, where known, the line.

import fs from 'node:fs';
import { YAML, getNode, keysOf, loadYaml } from './yamlx.mjs';
import { TASK_KEYS, walkDsl, executionOrder, visibleTasks, ancestors } from './dsl.mjs';
import { checkField, references, splitTemplate, parseCel } from './cel.mjs';
import { findLeaks } from './redact.mjs';
import {
  ACTION_CATEGORIES, ACTION_CONTEXTS, AUTH_TYPES, CEL_RESERVED_WORDS, CONNECTOR_CATEGORIES, CEL_TYPE_IDENTS, CONNECTOR_METHODS, CONNECTOR_ROOTS, GENERIC_USAGE, IMPLICIT_CONNECTORS,
  PARTNER_ONLY_EVENTS, PLATFORM_SOURCES, SOPHOS_ONLY_FIELDS, PLAYBOOK_ROOTS, RESERVED_TASK_NAMES, SEMVER, TASK_NAME, TEMPLATE_NAME, TEMPLATE_TYPES, TRIGGER_TYPES,
} from './fusion-facts.mjs';

// Words that mark a value as secret-bearing when they appear in a key or a reference path.
const SECRET_WORDS = /(password|passwd|secret|token|api_?key|apikey|webhook|credential|signature|private_?key|bearer)/i;

// Action names that change something outside Fusion: containment, blocking,
// account changes, message removal.
const RESPONSE_ACTION = /(isolate|contain|disable|enableuser|block|quarantine|resetpassword|resetmfa|reset_password|forcepassword|changepassword|setpassword|lock|revoke|kill|wipe|terminate|suspend|ban|threatfeedindicator|clawback|purge|deletemessage|deleteemail|confirm\w*compromised|scan)/i;

const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
const EXAMPLE_DOMAIN = /@(example\.(com|org|net)|[a-z0-9.-]+\.example|[a-z0-9.-]+\.(test|invalid|localhost))$/i;

const DURATION = /^\d+(ms|s|m|h)$/;
const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];

class Findings {
  constructor(file) {
    this.file = file;
    this.items = [];
  }

  add(level, rule, message, { path = null, line = null } = {}) {
    this.items.push({ level, rule, message, path, line, file: this.file });
  }

  error(rule, message, where) {
    this.add('error', rule, message, where);
  }

  warn(rule, message, where) {
    this.add('warning', rule, message, where);
  }
}

/** Validate a file on disk. */
export function validateFile(file) {
  const text = fs.readFileSync(file, 'utf8');
  return validateText(text, file);
}

/** Validate YAML text. Returns { file, kind, name, ok, errors, warnings, findings }. */
export function validateText(text, file = '<input>') {
  const f = new Findings(file);
  const loaded = loadYaml(text);
  if (!loaded.ok) {
    for (const e of loaded.errors) f.error('yaml.parse', `YAML does not parse: ${e.message}`, { line: e.line });
    return summarize(f, null, null);
  }
  const root = loaded.doc.contents;
  const value = loaded.value;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    f.error('yaml.shape', 'The file must be a YAML map with a kind field.', { line: 1 });
    return summarize(f, null, null);
  }
  const kind = value.kind;
  if (kind === 'Playbook') checkPlaybook(f, root, value, loaded.lineOf);
  else if (kind === 'Connector') checkConnector(f, root, value, loaded.lineOf);
  else f.error('kind.unknown', `kind must be Playbook or Connector, found ${JSON.stringify(kind ?? null)}.`, { path: 'kind', line: loaded.lineOf(getNode(root, 'kind')) ?? 1 });
  checkData(f, root, loaded.lineOf, kind);
  return summarize(f, kind ?? null, value.name ?? null);
}

function summarize(f, kind, name) {
  const errors = f.items.filter((i) => i.level === 'error').length;
  const warnings = f.items.length - errors;
  return { file: f.file, kind, name, ok: errors === 0, errors, warnings, findings: f.items };
}

function where(root, key, lineOf) {
  const n = getNode(root, key);
  return { path: key, line: n !== undefined ? lineOf(n) : null };
}

// ---------------------------------------------------------------- playbooks

function checkPlaybook(f, root, v, lineOf) {
  for (const key of ['apiVersion', 'name', 'version', 'title', 'description', 'dsl']) {
    if (v[key] === undefined || v[key] === null || v[key] === '') f.error('field.required', `A playbook template needs ${key}.`, { path: key, line: 1 });
  }
  for (const key of ['documentation', 'triggerHints']) {
    if (v[key] === undefined) f.warn('field.recommended', `Add ${key}: ${key === 'triggerHints' ? 'without it the console suggests no trigger for this template' : 'it is what people read in the console'}.`, { path: key, line: 1 });
  }
  if (typeof v.name === 'string' && !TEMPLATE_NAME.test(v.name)) {
    f.error('name.template', `Template name "${v.name}" must be letters, digits and underscores, in dot-separated parts (for example Acme.CaseNotes).`, where(root, 'name', lineOf));
  }
  if (v.name !== undefined && typeof v.name === 'string' && v.name.length > 100) f.error('name.template', 'Template name is longer than 100 characters.', where(root, 'name', lineOf));
  if (v.version !== undefined && !SEMVER.test(String(v.version))) f.error('version.semver', `version "${v.version}" is not semantic versioning (major.minor.patch).`, where(root, 'version', lineOf));
  if (v.type !== undefined && !TEMPLATE_TYPES.includes(v.type)) f.error('field.type', `type must be one of ${TEMPLATE_TYPES.join(', ')}.`, where(root, 'type', lineOf));

  checkCategories(f, root, v, 'connectorCategories', lineOf);
  for (const k of SOPHOS_ONLY_FIELDS) {
    if (v[k] === true) f.error('field.sophos-only', `${k}: true can only be set by Sophos. A customer import fails. Remove it.`, where(root, k, lineOf));
  }
  const deps = {};
  for (const key of ['connectors', 'playbooks', 'interfaces']) {
    deps[key] = new Map();
    const list = v[key];
    if (list === undefined || list === null) continue;
    if (!Array.isArray(list)) {
      f.error('deps.format', `${key} must be a list of "Name:version" entries.`, where(root, key, lineOf));
      continue;
    }
    const seq = getNode(root, key);
    list.forEach((entry, i) => {
      const line = YAML.isSeq(seq) ? lineOf(seq.items[i]) : null;
      const m = /^([A-Za-z][A-Za-z0-9_.]*):(.+)$/.exec(String(entry));
      if (!m || !SEMVER.test(m[2])) {
        f.error('deps.format', `${key}[${i}] "${entry}" must be "Name:major.minor.patch".`, { path: `${key}[${i}]`, line });
        return;
      }
      if (deps[key].has(m[1])) f.warn('deps.duplicate', `${m[1]} is listed twice in ${key}.`, { path: `${key}[${i}]`, line });
      deps[key].set(m[1], { version: m[2], line, used: false });
    });
  }

  checkTriggerHints(f, root, v, lineOf);

  const dslNode = getNode(root, 'dsl');
  if (!YAML.isMap(dslNode)) {
    if (v.dsl !== undefined) f.error('dsl.shape', 'dsl must be a map with name and tasks.', where(root, 'dsl', lineOf));
    return;
  }
  if (!v.dsl.name) f.warn('field.recommended', 'Give dsl a name: Fusion shows it in execution logs.', { path: 'dsl.name', line: lineOf(dslNode) });
  const tasksNode = getNode(dslNode, 'tasks');
  if (!YAML.isSeq(tasksNode) || tasksNode.items.length === 0) {
    f.error('dsl.tasks', 'dsl.tasks must be a list with at least one task (Fusion: "dsl must contain at least one task").', { path: 'dsl.tasks', line: lineOf(dslNode) });
    return;
  }
  for (const k of keysOf(dslNode)) {
    if (!['name', 'description', 'tasks', 'outputs', 'summary', 'outcomeStatus', 'outcomeMessage'].includes(k)) {
      f.warn('dsl.keys', `Unknown dsl key "${k}".`, { path: `dsl.${k}`, line: lineOf(getNode(dslNode, k)) });
    }
  }

  const model = walkDsl(dslNode, lineOf);
  checkTasks(f, model, deps);
  checkReferences(f, model);
  checkSecretsNolog(f, model, deps);
  checkResponseTier(f, root, v, model, lineOf);

  for (const [key, map] of Object.entries(deps)) {
    for (const [name, d] of map) {
      if (!d.used) f.warn('deps.unused', `${name} is declared in ${key} but no task uses it.`, { path: key, line: d.line });
    }
  }
}

function checkCategories(f, root, v, key, lineOf) {
  if (v[key] === undefined) return;
  const list = Array.isArray(v[key]) ? v[key] : [v[key]];
  for (const c of list) {
    if (!CONNECTOR_CATEGORIES.includes(c)) {
      f.error('field.category', `${key} "${c}" is not a category Fusion knows (it lists ${CONNECTOR_CATEGORIES.join(', ')}). The import fails with "Invalid Connector Categories".`, where(root, key, lineOf));
    }
  }
}

function checkTriggerHints(f, root, v, lineOf) {
  const hints = v.triggerHints;
  if (hints === undefined) return;
  if (!Array.isArray(hints)) {
    f.error('trigger.shape', 'triggerHints must be a list.', where(root, 'triggerHints', lineOf));
    return;
  }
  const seq = getNode(root, 'triggerHints');
  hints.forEach((h, i) => {
    const node = YAML.isSeq(seq) ? seq.items[i] : null;
    const at = { path: `triggerHints[${i}]`, line: node ? lineOf(node) : null };
    if (!h || typeof h !== 'object') {
      f.error('trigger.shape', 'Each trigger hint is a map with type and config.', at);
      return;
    }
    if (h.isProactiveResponse === true) {
      f.error('trigger.proactive', 'isProactiveResponse: true can only be set by Sophos. A customer import fails ("can only be set by tenant 5000"). Use false.', at);
    }
    if (!TRIGGER_TYPES.includes(h.type)) {
      f.error('trigger.type', `Trigger hint type "${h.type}" must be one of ${TRIGGER_TYPES.join(', ')} (User Initiated is "actions").`, at);
      return;
    }
    const c = h.config || {};
    if (h.type === 'platform') {
      const events = PLATFORM_SOURCES[c.source];
      if (!events) f.error('trigger.source', `Platform source "${c.source}" is not one Fusion lists: ${Object.keys(PLATFORM_SOURCES).join(', ')}.`, at);
      else if (!Array.isArray(c.events) || c.events.length === 0) f.error('trigger.events', `A platform trigger hint needs events for source ${c.source}.`, at);
      else {
        const allowed = [...events, ...(PARTNER_ONLY_EVENTS[c.source] || [])];
        for (const e of c.events) {
          if (!allowed.some((x) => x.toLowerCase() === String(e).toLowerCase())) f.error('trigger.events', `Event "${e}" is not an event of source ${c.source}: ${events.join(', ')}.`, at);
        }
        if (c.source === 'identityFindings' && c.events.some((e) => String(e).toLowerCase() === 'updated')) {
          f.warn('trigger.events', 'Identity Findings "updated" fires on posture re-checks, often several times a day for the same finding. Prefer "created" for anything that acts.', at);
        }
      }
      if (c.filter !== undefined) checkExpressionText(f, String(c.filter), `triggerHints[${i}].config.filter`, at.line, 'trigger filter');
      else f.warn('trigger.filter', 'A platform trigger hint without a filter runs for every event of that source. Add an "Only when" filter.', at);
    }
    if (h.type === 'actions') {
      if (!ACTION_CATEGORIES.includes(c.category)) f.error('trigger.category', `User Initiated category must be lookup or response, found "${c.category}".`, at);
      if (c.context !== undefined && !ACTION_CONTEXTS.some((x) => x.toLowerCase() === String(c.context).toLowerCase())) {
        f.warn('trigger.context', `Context "${c.context}" is not one Fusion lists. Check it with catalog.mjs triggers.`, at);
      }
      if (!c.name) f.error('trigger.name', 'A User Initiated trigger hint needs the action name people see in the console.', at);
    }
    if (h.type === 'generic' && !GENERIC_USAGE.includes(c.usage)) {
      f.error('trigger.usage', `Generic trigger usage must be one of ${GENERIC_USAGE.join(', ')}.`, at);
    }
    for (const [j, ch] of (h.celHints || []).entries()) {
      if (ch?.expr !== undefined) checkExpressionText(f, String(ch.expr), `triggerHints[${i}].celHints[${j}].expr`, at.line, 'CEL hint');
    }
  });
}

function checkExpressionText(f, text, path, line, label) {
  const r = checkField(text);
  if (!r.ok) {
    const rel = r.error.line && r.error.line > 1 ? ` (expression line ${r.error.line})` : '';
    f.error('cel.syntax', `${label} does not parse: ${r.error.message} at character ${r.error.offset + 1}${rel}.`, { path, line });
  }
  return r;
}

function checkTasks(f, model, deps) {
  const seen = new Map();
  for (const t of model.tasks) {
    const at = { path: t.path, line: t.line };
    if (!t.isMap) {
      f.error('task.shape', 'Each task must be a map.', at);
      continue;
    }
    if (!t.name) {
      if (t.parent === null) f.error('task.name', 'Top-level tasks need a name so later tasks and outputs can read them.', at);
      else f.warn('task.name', 'This task has no name, so nothing can read its results.', at);
    } else {
      if (!TASK_NAME.test(t.name)) f.error('task.name', `Task name "${t.name}" must be lower case letters, digits and underscores, starting with a letter (Fusion's naming rule).`, at);
      if (RESERVED_TASK_NAMES.includes(t.name)) f.error('task.name', `Task name "${t.name}" collides with a CEL name. Fusion then fails every expression in the playbook with "overlapping identifier".`, at);
      if (CEL_RESERVED_WORDS.includes(t.name)) f.error('task.name', `Task name "${t.name}" is a CEL reserved word, so no expression can read it (Fusion: "reserved identifier"). Rename it, for example each_${t.name}.`, at);
      if (seen.has(t.name)) f.error('task.name', `Task name "${t.name}" is used twice (first on line ${seen.get(t.name)}). Fusion needs unique names.`, at);
      else seen.set(t.name, t.line);
    }
    for (const k of t.keys) {
      if (!TASK_KEYS.has(k)) f.warn('task.keys', `Unknown task key "${k}". Fusion ignores it with a warning ("unexpected task dsl statement").`, { path: `${t.path}.${k}`, line: t.line });
    }
    const kinds = ['action', 'call', 'exec'].filter((k) => t[k] !== undefined);
    if (kinds.length > 1) f.error('task.kind', `A task can run one of action, call or exec, not ${kinds.join(' and ')}.`, at);
    if (t.action !== undefined) {
      const m = /^([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*)\.([A-Za-z][A-Za-z0-9_]*)$/.exec(String(t.action));
      if (!m) f.error('task.action', `action "${t.action}" must be Connector.actionName, for example Taegis.Case.addComment.`, at);
      else {
        const dep = deps.connectors.get(m[1]);
        if (!dep && IMPLICIT_CONNECTORS.includes(m[1])) {
          // provided by the platform without a connectors entry
        } else if (!dep) f.error('deps.connector-undeclared', `Task uses connector ${m[1]} but the template's connectors list does not declare it. Add "${m[1]}:<version>".`, at);
        else dep.used = true;
      }
    }
    if (t.exec !== undefined) {
      const dep = deps.playbooks.get(String(t.exec));
      if (!dep) f.error('deps.playbook-undeclared', `Task runs playbook ${t.exec} but the playbooks list does not declare it.`, at);
      else dep.used = true;
    }
    if (t.call !== undefined) {
      const dep = deps.interfaces.get(String(t.call));
      if (!dep) f.error('deps.interface-undeclared', `Task calls interface ${t.call} but the interfaces list does not declare it (Fusion: "missing from required interfaces").`, at);
      else dep.used = true;
    }
    if (t.keys.includes('retry') && !t.action) f.warn('task.retry', 'retry only works on action tasks. Fusion warns "retry can only be used with a function task" and ignores it.', at);
    if (t.sleep !== undefined && !DURATION.test(String(t.sleep))) {
      const r = typeof t.sleep === 'string' ? parseCel(t.sleep) : { ok: false };
      if (!r.ok) f.error('task.sleep', `sleep "${t.sleep}" must be a duration such as 30s or 5m, or an expression that gives one.`, at);
    }
    if (getNode(t.node, 'range') !== undefined && getNode(t.node, 'for') === undefined) f.error('task.loop', 'A task with range needs a for list of tasks to run per item.', at);
    if (getNode(t.node, 'for') !== undefined && getNode(t.node, 'range') === undefined) f.error('task.loop', 'A for block needs a range expression.', at);
    if (getNode(t.node, 'while') !== undefined && getNode(t.node, 'do') === undefined) f.error('task.loop', 'A while task needs a do list.', at);
    if (getNode(t.node, 'if') !== undefined && getNode(t.node, 'then') === undefined) f.error('task.branch', 'An if task needs a then list.', at);
    if (getNode(t.node, 'switch') !== undefined && getNode(t.node, 'case') === undefined) f.error('task.branch', 'A switch task needs a case map.', at);
    const isBlock = ['loop', 'while', 'if', 'switch'].includes(t.kind);
    const isBody = t.kind === 'let' && t.parent !== null;
    if (!isBlock && !isBody && t.kind === 'other' && !t.keys.includes('variables')) {
      f.warn('task.kind', 'This task does nothing: it has no let, action, call, exec, loop or branch.', at);
    }
    for (const field of t.fields) checkFieldSyntax(f, field);
  }
  for (const field of model.dslFields) checkFieldSyntax(f, field);
}

function checkFieldSyntax(f, field) {
  if (field.literal || typeof field.text !== 'string') return;
  const r = checkField(field.text);
  field.check = r;
  if (!r.ok) {
    const inner = r.error.line && r.error.line > 1 ? `, expression line ${r.error.line}` : '';
    f.error('cel.syntax', `${field.key} does not parse as ${r.kind === 'template' ? 'a template' : 'CEL'}: ${r.error.message} (character ${r.error.offset + 1}${inner}). For a literal string, write it in YAML single quotes or as a CEL string such as "'text'".`, { path: field.path, line: field.line });
  }
}

function checkReferences(f, model) {
  const order = executionOrder(model.top);
  const position = new Map(order.map((t, i) => [t, i]));
  const byName = new Map(model.tasks.filter((t) => t.name).map((t) => [t.name, t]));

  const readers = [...model.tasks.map((t) => ({ task: t, fields: t.fields })), { task: null, fields: model.dslFields }];
  for (const { task, fields } of readers) {
    const visible = visibleTasks(task, model.top);
    const encl = ancestors(task);
    // guards from the reading task's own condition apply to all its fields
    const conditionGuards = new Set();
    const conditions = new Set();
    for (const t of [task, ...encl].filter(Boolean)) {
      if (typeof t.condition === 'string') conditions.add(t.condition.trim());
      for (const fl of t.fields) {
        if (fl.key === 'condition' && fl.check?.ok) {
          for (const e of fl.check.expressions) {
            const r = references(e.ast);
            for (const g of r.guards) conditionGuards.add(g);
            for (const ref of r.refs) if (ref.optional) conditionGuards.add(ref.root);
          }
        }
      }
    }
    for (const fl of fields) {
      if (!fl.check?.ok) continue;
      for (const e of fl.check.expressions) {
        const { refs, guards } = references(e.ast);
        // A has() check or an optional read of a task anywhere in the expression
        // counts as a guard for every read of that task in it (a ? b : c pattern).
        const guardedRoots = new Set(guards);
        for (const ref of refs) if (ref.optional) guardedRoots.add(ref.root);
        for (const ref of refs) {
          const at = { path: fl.path, line: fl.line };
          if (PLAYBOOK_ROOTS.includes(ref.root)) continue;
          const target = byName.get(ref.root);
          if (!target && CEL_TYPE_IDENTS.includes(ref.root) && ref.path.length === 0) continue;
          if (!target) {
            f.error('ref.undeclared', `${fl.key} reads "${ref.root}", which is not a task, inputs, TDR or tenant. Fusion only warns about this, then the run fails with "undeclared reference".`, at);
            continue;
          }
          if (task && target === task) {
            // A while condition re-reads its own variables each pass; anything else has no results yet.
            const ownVariables = fl.key === 'let' && task.keys.includes('variables') && ref.path[0] === 'variables';
            if (fl.key !== 'while' && !ownVariables) f.error('ref.self', `${fl.key} of task ${task.name} reads its own results before it has any.`, at);
            continue;
          }
          if (!visible.has(ref.root)) {
            const tp = position.get(target);
            const rp = task ? position.get(task) : order.length;
            const scopedInside = target.parent !== null && !encl.includes(target.parent) && target.parent !== task;
            if (scopedInside) {
              f.error('ref.nested', `${fl.key} reads task ${ref.root}, which sits inside the ${target.block} block of ${target.parent?.name ?? 'another task'}. Tasks in a loop or branch are not visible outside it: the run fails with "undeclared reference". Copy the value into the block task's variables instead.`, at);
            } else if (tp > rp) {
              f.error('ref.forward', `${fl.key} reads task ${ref.root}, which runs later. Fusion's validator lets this through, but the value does not exist yet when this runs.`, at);
            } else {
              f.error('ref.scope', `${fl.key} reads task ${ref.root}, which is not in scope here.`, at);
            }
            continue;
          }
          // Inside a loop, its item is <loop>.value (or the name set with value:).
          const isEnclosing = encl.includes(target) || (task && target === task);
          if (!isEnclosing && ref.path[0] && [target.valueName, target.keyName].includes(ref.path[0]) && ['loop'].includes(target.kind)) {
            f.error('ref.loop-item', `${fl.key} reads ${ref.root}.${ref.path[0]} outside the loop, where there is no current item.`, at);
            continue;
          }
          if (isEnclosing) continue;
          // Guarded: optional selection, a has() on the task in this expression or in
          // the reader's (or an enclosing block's) condition, or the same condition as
          // the task being read, so both run or neither does.
          const sameCondition = typeof target.condition === 'string' && conditions.has(target.condition.trim());
          const guarded = guardedRoots.has(ref.root) || conditionGuards.has(ref.root) || (sameCondition && !target.optional);
          if (!guarded && (target.condition !== undefined || target.optional)) {
            const how = target.condition !== undefined ? 'has a condition, so it can be skipped' : 'is optional, so it can fail and leave no outputs';
            const readsResults = ref.path.length === 0 || ['outputs', 'variables'].includes(ref.path[0]);
            if (readsResults) {
              f.error('ref.skipped', `${fl.key} reads ${[ref.root, ...ref.path].join('.')} without a guard, and task ${ref.root} ${how}. Fusion only warns; the run then fails with "no such key". Guard it with has(${ref.root}, '${ref.path.join('.') || 'outputs'}') or ${ref.root}.?${ref.path.join('.?') || 'outputs'}.orValue(...).`, at);
            }
          }
        }
      }
    }
  }
}

function fieldMentionsSecret(field) {
  if (SECRET_WORDS.test(field.path.split('.').slice(-1)[0] || '')) return true;
  if (!field.check?.ok) return false;
  for (const e of field.check.expressions) {
    for (const ref of references(e.ast).refs) {
      if (ref.path.some((p) => SECRET_WORDS.test(p))) return true;
    }
  }
  return false;
}

function checkSecretsNolog(f, model) {
  for (const t of model.tasks) {
    if (t.nolog) continue;
    const reasons = [];
    if (t.action && /(webhook|password|secret|token|credential|apikey|sendworkflowmessage)/i.test(t.action)) reasons.push(`action ${t.action}`);
    const names = t.fields.filter((fl) => fieldMentionsSecret(fl)).map((fl) => fl.path.replace(`${t.path}.`, ''));
    if (names.length) reasons.push(`${names.slice(0, 3).join(', ')}${names.length > 3 ? ', ...' : ''}`);
    if (reasons.length) {
      f.error('secret.nolog', `Task ${t.name ?? t.path} handles a secret (${reasons.join('; ')}) without nolog: true. Fusion keeps every successful step's URL, body and response in the execution log, permanently. Add nolog: true.`, { path: t.path, line: t.line });
    }
  }
}

/** Property names declared anywhere in a JSON schema, with their schema. */
function schemaProperties(schema, path = 'inputs', out = []) {
  if (!schema || typeof schema !== 'object') return out;
  for (const [k, s] of Object.entries(schema.properties || {})) {
    out.push({ name: k, schema: s, path: `${path}.properties.${k}` });
    schemaProperties(s, `${path}.properties.${k}`, out);
  }
  return out;
}

export function responseTasks(model) {
  return model.tasks.filter((t) => t.action && RESPONSE_ACTION.test(String(t.action).split('.').pop()));
}

export function isResponseTier(v, model) {
  const hints = Array.isArray(v.triggerHints) ? v.triggerHints : [];
  if (hints.some((h) => h?.type === 'actions' && h?.config?.category === 'response')) return true;
  if ((v.tags || []).some((t) => String(t).toLowerCase() === 'type:response')) return true;
  if (v.type === 'ResponseAction') return true;
  return responseTasks(model).length > 0;
}

function checkResponseTier(f, root, v, model, lineOf) {
  if (!isResponseTier(v, model)) return;
  const props = schemaProperties(v.inputs);
  const at = where(root, 'inputs', lineOf);
  const dry = props.find((p) => p.name === 'dry_run');
  if (!dry) f.error('response.dry-run', 'This is a response playbook, so it needs a boolean input named dry_run with default: true. Fusion has no platform dry run.', { ...at, path: at.path || 'inputs' });
  else if (dry.schema?.type !== 'boolean' || dry.schema?.default !== true) f.error('response.dry-run', 'Input dry_run must be type: boolean with default: true, so a new instance changes nothing until someone turns it off.', { path: dry.path, line: at.line });
  const cap = props.find((p) => /^max_/.test(p.name) && p.schema?.type === 'integer');
  if (!cap) f.error('response.cap', 'This is a response playbook, so it needs an integer input starting max_ (for example max_targets) that caps how many things one run can change.', { ...at, path: at.path || 'inputs' });
  else {
    if (!(Number.isInteger(cap.schema.default) && cap.schema.default >= 1)) f.error('response.cap', `Input ${cap.name} needs an integer default of at least 1.`, { path: cap.path, line: at.line });
    const used = model.tasks.some((t) => t.fields.some((fl) => typeof fl.text === 'string' && fl.text.includes(cap.name)));
    if (!used) f.error('response.cap', `Input ${cap.name} is declared but no task reads it, so nothing enforces the cap.`, { path: cap.path, line: at.line });
  }
  for (const t of responseTasks(model)) {
    const gated = [t, ...ancestors(t)].some((x) => skipsInDryRun(x.condition));
    if (!gated) f.error('response.gate', `Task ${t.name ?? t.path} runs ${t.action} without a condition that skips it in a dry run. Make its condition !...dry_run && ... (a condition that only mentions dry_run, such as dry_run && ..., or dry_run || ..., does not gate it).`, { path: t.path, line: t.line });
  }
}

/** A read of a dry_run value: x.dry_run, x.?dry_run, dry_run, or one of those with .orValue(...) or .value(). */
function isDryRunRead(n) {
  if (!n) return false;
  if (n.type === 'ident') return n.name === 'dry_run';
  if (n.type === 'select') return n.field === 'dry_run';
  if (n.type === 'call' && n.target && ['orValue', 'value'].includes(n.fn)) return isDryRunRead(n.target);
  if (n.type === 'call' && !n.target && n.fn === 'bool' && n.args.length === 1) return isDryRunRead(n.args[0]);
  return false;
}

/** !dry_run, dry_run == false, or dry_run != true. */
function isDryRunOff(n) {
  if (n?.type === 'unary' && n.op === '!') return isDryRunRead(n.operand);
  if (n?.type === 'binary' && (n.op === '==' || n.op === '!=')) {
    const want = n.op === '!=';
    const isBool = (x) => x?.type === 'literal' && x.kind === 'bool' && x.value === want;
    return (isDryRunRead(n.left) && isBool(n.right)) || (isDryRunRead(n.right) && isBool(n.left));
  }
  return false;
}

function conjuncts(n) {
  return n?.type === 'binary' && n.op === '&&' ? [...conjuncts(n.left), ...conjuncts(n.right)] : [n];
}

/** True when a task condition is false whenever dry_run is on: one of its && terms turns dry_run off. */
export function skipsInDryRun(condition) {
  if (typeof condition !== 'string') return false;
  const r = parseCel(condition);
  return r.ok && conjuncts(r.ast).some(isDryRunOff);
}

// ---------------------------------------------------------------- connectors

function checkConnector(f, root, v, lineOf) {
  for (const key of ['apiVersion', 'name', 'version', 'title', 'description', 'method', 'actions', 'authTypes']) {
    if (v[key] === undefined || v[key] === null || v[key] === '') f.error('field.required', `A connector needs ${key}.`, { path: key, line: 1 });
  }
  if (v.documentation === undefined) f.warn('field.recommended', 'Add documentation: it is what people read in the console, and it is where the hosts the connector calls are declared.', { path: 'documentation', line: 1 });
  if (typeof v.name === 'string' && !TEMPLATE_NAME.test(v.name)) f.error('name.connector', `Connector name "${v.name}" must be letters, digits and underscores, in dot-separated parts.`, where(root, 'name', lineOf));
  if (v.version !== undefined && !SEMVER.test(String(v.version))) f.error('version.semver', `version "${v.version}" is not semantic versioning.`, where(root, 'version', lineOf));
  if (v.method !== undefined && !CONNECTOR_METHODS.includes(v.method)) f.error('connector.method', `method must be one of ${CONNECTOR_METHODS.join(', ')}. Custom connectors use http.`, where(root, 'method', lineOf));
  if (v.authTypes !== undefined) {
    if (!Array.isArray(v.authTypes) || v.authTypes.length === 0) f.error('connector.auth', 'authTypes must be a non-empty list.', where(root, 'authTypes', lineOf));
    else for (const a of v.authTypes) if (!AUTH_TYPES.includes(a)) f.error('connector.auth', `Unknown auth type "${a}". Fusion accepts: ${AUTH_TYPES.join(', ')}.`, where(root, 'authTypes', lineOf));
  }
  checkCategories(f, root, v, 'categories', lineOf);
  const params = new Set(Object.keys(v.parameters?.properties || {}));
  const actionsNode = getNode(root, 'actions');
  if (!Array.isArray(v.actions)) {
    if (v.actions !== undefined) f.error('connector.actions', 'actions must be a list.', where(root, 'actions', lineOf));
    return;
  }
  if (!v.actions.some((a) => a?.name === 'validate')) {
    f.warn('connector.validate', 'Add a validate action. Fusion runs it to test a connection (validateConnection) and shows the result.', where(root, 'actions', lineOf));
  }
  const hosts = new Map();
  const names = new Set();
  v.actions.forEach((a, i) => {
    const node = YAML.isSeq(actionsNode) ? actionsNode.items[i] : null;
    const at = { path: `actions[${i}]`, line: node ? lineOf(node) : null };
    if (!a || typeof a !== 'object') {
      f.error('connector.actions', 'Each action is a map.', at);
      return;
    }
    if (!a.name || !/^[A-Za-z][A-Za-z0-9_]*$/.test(a.name)) f.error('connector.action-name', `Action name "${a.name}" must be letters, digits and underscores.`, at);
    else if (names.has(a.name)) f.error('connector.action-name', `Action name "${a.name}" is used twice.`, at);
    else names.add(a.name);
    if (!a.description) f.warn('connector.action-doc', `Action ${a.name} has no description.`, at);
    const c = a.config;
    if (!c || typeof c !== 'object') {
      if (v.method === 'http') f.error('connector.config', `Action ${a.name} needs a config block.`, at);
      return;
    }
    if (v.method === 'http') {
      if (!c.url) f.error('connector.url', `Action ${a.name} needs config.url.`, at);
      if (!c.method || !HTTP_METHODS.includes(String(c.method).toUpperCase())) f.error('connector.http-method', `Action ${a.name} needs config.method (${HTTP_METHODS.join(', ')}).`, at);
      if (c.outputs === undefined) f.warn('connector.outputs', `Action ${a.name} maps no outputs, so playbooks get nothing back from it.`, at);
      if (typeof c.url === 'string') checkUrl(f, c.url, a.name, params, hosts, at);
    }
    walkTemplates(c, `actions[${i}].config`, (text, path) => {
      const split = splitTemplate(text);
      if (!split.ok) {
        f.error('cel.syntax', `${path} has an unclosed "\${".`, { path, line: at.line });
        return;
      }
      for (const part of split.parts.filter((p) => p.kind === 'expr')) {
        const r = parseCel(part.text);
        if (!r.ok) {
          f.error('cel.syntax', `${path} template does not parse: ${r.error.message} (character ${part.offset + r.error.offset + 1}).`, { path, line: at.line });
          continue;
        }
        for (const ref of references(r.ast).refs) {
          if (!CONNECTOR_ROOTS.includes(ref.root) && !(CEL_TYPE_IDENTS.includes(ref.root) && ref.path.length === 0)) f.warn('ref.connector', `${path} reads "${ref.root}". Connector templates read ${CONNECTOR_ROOTS.join(', ')}.`, { path, line: at.line });
          if (ref.root === 'config' && ref.path[0] && params.size && !params.has(ref.path[0])) f.error('ref.connector', `${path} reads config.${ref.path[0]}, which is not in the connector's parameters.`, { path, line: at.line });
        }
      }
    });
    for (const h of Array.isArray(c.headers) ? c.headers : []) {
      if (h && /^(authorization|x-api-key|api-key|apikey|x-auth-token)$/i.test(String(h.name)) && typeof h.value === 'string' && !h.value.includes('${')) {
        f.error('data.hardcoded-secret', `Action ${a.name} sets the ${h.name} header to a fixed value. Put credentials in the connection (authTypes), never in the connector.`, at);
      }
    }
  });
  const doc = String(v.documentation || '');
  for (const [host, actions] of hosts) {
    if (!doc.toLowerCase().includes(host.toLowerCase())) {
      f.error('connector.hosts', `Actions ${actions.join(', ')} call ${host}, but the documentation does not declare it. List every host the connector calls in a "Hosts" section of documentation.`, where(root, 'documentation', lineOf));
    }
  }
}

function checkUrl(f, url, action, params, hosts, at) {
  const u = url.trim();
  if (/^http:\/\//i.test(u)) {
    f.error('connector.url', `Action ${action} calls ${u.split('/').slice(0, 3).join('/')} over plain http. Use https.`, at);
    return;
  }
  const literal = /^https:\/\/([A-Za-z0-9.-]+)(?::\d+)?(?:[/?#]|$)/.exec(u);
  if (literal) {
    const list = hosts.get(literal[1]) || [];
    list.push(action);
    hosts.set(literal[1], list);
    return;
  }
  const checkParams = (text) => {
    for (const m of text.matchAll(/\$\{\s*config\.\??([A-Za-z_][A-Za-z0-9_]*)/g)) {
      if (params.size && !params.has(m[1])) f.error('connector.url', `Action ${action} builds its URL from config.${m[1]}, which is not a declared parameter.`, at);
    }
  };
  // A host the connection supplies: https://${config.host}/..., or a URL that starts with ${config.url}
  if (/^https:\/\/[A-Za-z0-9.-]*\$\{\s*config\.[A-Za-z_][A-Za-z0-9_]*\s*\}/.test(u) || /^\$\{\s*config\.[A-Za-z_][A-Za-z0-9_]*\s*\}/.test(u)) {
    checkParams(u);
    return;
  }
  // Platform hosts
  if (/^\$\{\s*TDR\.API\s*\}/.test(u) || /^https:\/\/[A-Za-z0-9.-]*\$\{\s*sophos\./.test(u)) return;
  checkParams(u);
  f.warn('connector.url', `Action ${action} computes its URL with an expression. Prefer https:// with a fixed host, or a URL that starts with a connection parameter, so it is clear what the connector calls.`, at);
}

function walkTemplates(value, path, fn) {
  if (typeof value === 'string') {
    if (value.includes('${')) fn(value, path);
    return;
  }
  if (Array.isArray(value)) value.forEach((v, i) => walkTemplates(v, `${path}[${i}]`, fn));
  else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) walkTemplates(v, `${path}.${k}`, fn);
}

// ---------------------------------------------------------------- data hygiene

function checkData(f, root, lineOf, kind) {
  const tenantNode = getNode(root, 'tenantId');
  if (tenantNode !== undefined) {
    f.error('data.tenant-id', 'Remove tenantId: it names the tenant this file was exported from, and Fusion sets it on import.', { path: 'tenantId', line: lineOf(tenantNode) });
  }
  const visit = (node, path) => {
    if (YAML.isScalar(node)) {
      if (typeof node.value !== 'string') return;
      const s = node.value;
      if (path === 'icon' || path === 'tenantId') return;
      const prose = /^(documentation|description|changeNotes|changeNotesMarkdown|title)$/.test(path) || /\.(description|documentation|title)$/.test(path);
      const report = prose ? f.warn.bind(f) : f.error.bind(f);
      for (const leak of findLeaks(s)) {
        if (leak.kind === 'known_secret') continue;
        report('data.hardcoded-secret', `${path} looks like it holds a secret (${leak.kind}). Secrets belong in the connection, never in the file.`, { path, line: lineOf(node) });
      }
      for (const m of s.matchAll(EMAIL)) {
        if (!EXAMPLE_DOMAIN.test(m[0])) report('data.personal', `${path} holds an email address (${m[0].replace(/^(.).*@/, '$1...@')}). Use a playbook input, or an example.com address in documentation.`, { path, line: lineOf(node) });
      }
      if (/(^|\.)(tenant_?id|tenantId)$/i.test(path) && kind === 'Playbook') {
        const r = parseCel(s);
        if (r.ok && r.ast.type === 'literal') f.error('data.tenant-id', `${path} is a fixed tenant ID. Read it from the event or TDR.tenant instead.`, { path, line: lineOf(node) });
      }
      return;
    }
    if (YAML.isMap(node)) {
      for (const p of node.items) {
        const k = YAML.isScalar(p.key) ? p.key.value : String(p.key);
        if (path === '' && k === 'tenantId') continue;
        if (YAML.isScalar(p.value) && /(^|_)(tenant_?id|tenantId)$/i.test(k) && kind === 'Playbook' && /^\d{3,}$/.test(String(p.value.value))) {
          f.error('data.tenant-id', `${path ? `${path}.` : ''}${k} is a fixed tenant ID.`, { path: `${path ? `${path}.` : ''}${k}`, line: lineOf(p.value) });
        }
        visit(p.value, path ? `${path}.${k}` : k);
      }
    } else if (YAML.isSeq(node)) {
      node.items.forEach((item, i) => visit(item, `${path}[${i}]`));
    }
  };
  visit(root, '');
}
