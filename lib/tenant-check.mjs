// Tenant-side validation of a template: Fusion's own DSL check
// (playbookValidateDSLV2) plus checks Fusion skips. Read-only.
//
// Fusion reports CEL syntax errors and undeclared references only as
// warnings, and lets unknown action names through. Those fail the run, so
// this check promotes them to errors and looks up every action itself.

import * as F from './fusion.mjs';
import { dependencyList, extractDsl, parseOrThrow } from './template.mjs';
import { walkDsl } from './dsl.mjs';
import { getNode } from './yamlx.mjs';

// Warning texts that mean the run will fail.
const FATAL_WARNINGS = [
  /Syntax error/i,
  /undeclared reference/i,
  /overlapping identifier/i,
  /is not unique/i,
  /found no matching overload/i,
  /unexpected task dsl statement/i,
];

export function classifyWarning(message) {
  return FATAL_WARNINGS.some((re) => re.test(message)) ? 'error' : 'warning';
}

/**
 * Resolve a template's connectors, playbooks and interfaces on the tenant.
 * Returns { connectorIds, playbookIds, interfaceIds, versions, findings }.
 */
export async function resolveDependencies(client, value) {
  const findings = [];
  const connectors = dependencyList(value, 'connectors');
  const playbooks = dependencyList(value, 'playbooks');
  const ifaces = dependencyList(value, 'interfaces');
  const versions = connectors.length ? await F.connectorVersions(client, connectors.map((c) => c.entry)) : [];
  const connectorIds = [];
  for (const c of connectors) {
    const hit = versions.find((x) => x.connector?.name === c.name && x.version === c.version);
    if (hit) connectorIds.push(hit.id);
    else {
      const head = await F.getConnector(client, { name: c.name });
      findings.push({
        level: 'error',
        rule: 'tenant.connector',
        message: head
          ? `Connector ${c.name} is on the tenant, but not at version ${c.version} (head is ${head.head?.version}). Use a version the tenant has.`
          : `Connector ${c.name} is not on this tenant. Import it first, or use a connector the tenant has.`,
        path: 'connectors',
      });
    }
  }
  const playbookIds = [];
  for (const p of playbooks) {
    const hit = await F.playbookVersionByName(client, p.entry);
    if (hit) playbookIds.push(hit.id);
    else findings.push({ level: 'error', rule: 'tenant.playbook', message: `Playbook ${p.entry} is not on this tenant.`, path: 'playbooks' });
  }
  const interfaceIds = [];
  if (ifaces.length) {
    for (const i of await F.interfaceVersions(client, ifaces.map((x) => x.entry))) {
      if (i.id) interfaceIds.push(i.id);
      else findings.push({ level: 'error', rule: 'tenant.interface', message: `Interface ${i.name} is not on this tenant at that version.`, path: 'interfaces' });
    }
  }
  return { connectorIds, playbookIds, interfaceIds, versions, findings };
}

/** Check each action task against the connector version's actions and input schema. */
export function checkActions(model, versions) {
  const findings = [];
  for (const t of model.tasks) {
    if (!t.action) continue;
    const i = String(t.action).lastIndexOf('.');
    const conn = String(t.action).slice(0, i);
    const action = String(t.action).slice(i + 1);
    const version = versions.find((v) => v.connector?.name === conn);
    if (!version) continue; // the platform's implicit connectors and missing ones are reported elsewhere
    const def = version.actions.find((a) => a.name === action);
    if (!def) {
      const near = version.actions.map((a) => a.name).filter((n) => n.toLowerCase().includes(action.toLowerCase().slice(0, 4))).slice(0, 5);
      findings.push({ level: 'error', rule: 'tenant.action', message: `${conn} ${version.version} has no action "${action}". Fusion's validator lets this through and the run fails.${near.length ? ` Close matches: ${near.join(', ')}.` : ''}`, path: t.path, line: t.line });
      continue;
    }
    // Inputs the action declares, plus any its config reads (platform actions
    // read some, such as tenant_id, without declaring them).
    const declared = def.inputs?.properties ? Object.keys(def.inputs.properties) : null;
    const readByConfig = [...JSON.stringify(def.config ?? {}).matchAll(/inputs\.\??([A-Za-z_][A-Za-z0-9_]*)/g)].map((m) => m[1]);
    const props = declared ? [...new Set([...declared, ...readByConfig])] : null;
    const required = Array.isArray(def.inputs?.required) ? def.inputs.required : [];
    const inputsNode = getNode(t.node, 'inputs');
    const given = inputsNode?.items ? inputsNode.items.map((p) => String(p.key?.value ?? p.key)) : [];
    const inputsIsExpression = inputsNode && !inputsNode.items;
    if (props && !inputsIsExpression) {
      for (const g of given) {
        if (!props.includes(g)) findings.push({ level: 'warning', rule: 'tenant.action-input', message: `${t.action} neither declares nor reads an input "${g}" (it takes ${props.join(', ') || 'none'}). Check the name.`, path: `${t.path}.inputs.${g}`, line: t.line });
      }
      for (const r of required) {
        if (!given.includes(r)) findings.push({ level: 'error', rule: 'tenant.action-input', message: `${t.action} requires input "${r}".`, path: `${t.path}.inputs`, line: t.line });
      }
    }
  }
  return findings;
}

/** Full tenant check of one template's text. */
export async function tenantValidate(client, text) {
  const loaded = parseOrThrow(text);
  const value = loaded.value;
  if (value.kind !== 'Playbook') {
    return { ok: false, findings: [{ level: 'error', rule: 'tenant.kind', message: 'The tenant DSL check is for playbook templates. Connectors are checked live with the connectors skill.' }] };
  }
  const deps = await resolveDependencies(client, value);
  const { yaml, lineOffset } = extractDsl(text);
  const result = await F.validateDsl(client, {
    yaml,
    connectors: deps.connectorIds,
    playbooks: deps.playbookIds,
    interfaces: deps.interfaceIds,
    inputs: value.inputs,
  });
  const findings = [...deps.findings];
  // Template metadata the DSL check does not look at, but the import does.
  const known = (await F.connectorCategories(client)).map((c) => c.name);
  for (const c of Array.isArray(value.connectorCategories) ? value.connectorCategories : []) {
    if (!known.includes(c)) findings.push({ level: 'error', rule: 'tenant.category', message: `connectorCategories "${c}" is not on this tenant (it has ${known.join(', ') || 'none'}). The import would fail.`, path: 'connectorCategories' });
  }
  for (const e of result.errors || []) findings.push({ level: 'error', rule: 'fusion.error', message: e.message.trim(), line: e.lineno ? e.lineno + lineOffset : null });
  for (const w of result.warnings || []) findings.push({ level: classifyWarning(w.message), rule: 'fusion.warning', message: w.message.trim(), line: w.lineno ? w.lineno + lineOffset : null });
  const model = walkDsl(getNode(loaded.doc.contents, 'dsl'), loaded.lineOf);
  findings.push(...checkActions(model, deps.versions));
  const errors = findings.filter((f) => f.level === 'error').length;
  return {
    ok: errors === 0,
    errors,
    warnings: findings.length - errors,
    fusion: { errors: (result.errors || []).length, warnings: (result.warnings || []).length },
    resolved: { connectors: deps.connectorIds.length, playbooks: deps.playbookIds.length, interfaces: deps.interfaceIds.length },
    findings,
  };
}
