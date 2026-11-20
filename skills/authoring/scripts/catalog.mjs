#!/usr/bin/env node
// Read-only discovery on the tenant: connectors and their actions, trigger
// types and event shapes, interfaces, CEL functions, and Sophos's own
// templates to learn from. Nothing here writes.

import fs from 'node:fs';
import { intArg, main } from '../../../lib/cli.mjs';
import { UsageError } from '../../../lib/errors.mjs';
import * as F from '../../../lib/fusion.mjs';
import { loadYaml } from '../../../lib/yamlx.mjs';

// Where each platform event lands in the playbook's inputs, and the schema
// definition that describes it.
const EVENT_SHAPES = {
  case: { inputsKey: 'case', definition: 'CaseEvent' },
  investigationNotification: { inputsKey: 'investigation', definition: 'InvestigationNotification' },
  investigation: { inputsKey: 'investigation', definition: 'Investigation' },
  health: { inputsKey: 'health', definition: 'Health' },
  alert2: { inputsKey: 'alert2', definition: 'Alert2' },
  tenant: { inputsKey: 'tenant', definition: 'TenantV4' },
  tenantlabel: { inputsKey: 'tenantlabel', definition: 'TenantLabel' },
  'auto-investigation': { inputsKey: 'autoInvestigation', definition: 'AutoInvestigation' },
  execution: { inputsKey: 'execution', definition: 'Execution' },
  identityFindings: { inputsKey: 'identityFindings', definition: 'IdentityFindings' },
  playbookAction: { inputsKey: 'playbookAction', definition: 'PlaybookActionEvent' },
};

/** Resolve $ref and type-name references a few levels deep so the shape is readable. */
function expand(schema, defs, depth = 0) {
  if (!schema || typeof schema !== 'object') return schema;
  if (depth > 3) return { type: schema.type || 'object', note: 'nested further' };
  const ref = schema.$ref?.replace('#/$defs/', '') || (typeof schema.type === 'string' && defs[schema.type] && schema.type !== 'object' ? schema.type : null);
  if (ref && defs[ref]) return expand({ ...defs[ref], ...(schema.description ? { description: schema.description } : {}) }, defs, depth + 1);
  const out = {};
  if (schema.type) out.type = defs[schema.type] ? 'object' : schema.type;
  if (schema.description) out.description = schema.description;
  if (schema.properties) {
    out.properties = {};
    for (const [k, v] of Object.entries(schema.properties)) out.properties[k] = expand(v, defs, depth + 1);
  }
  if (schema.items) out.items = expand(schema.items, defs, depth + 1);
  if (schema.enum) out.enum = schema.enum;
  return out;
}

/** A skeleton value for a schema: what a synthetic test event can start from. */
function skeleton(schema, depth = 0) {
  if (!schema || depth > 4) return null;
  if (schema.properties) {
    const o = {};
    for (const [k, v] of Object.entries(schema.properties)) o[k] = skeleton(v, depth + 1);
    return o;
  }
  switch (schema.type) {
    case 'array':
      return schema.items?.properties ? [skeleton(schema.items, depth + 1)] : [];
    case 'string':
      return '';
    case 'number':
    case 'integer':
      return 0;
    case 'boolean':
      return false;
    default:
      return null;
  }
}

function compactSchema(s) {
  if (!s?.properties) return s ?? null;
  const req = new Set(s.required || []);
  const out = {};
  for (const [k, v] of Object.entries(s.properties)) out[k] = `${v.type || 'any'}${req.has(k) ? ' (required)' : ''}${v.description ? ` - ${String(v.description).slice(0, 120)}` : ''}`;
  return out;
}

const spec = {
  name: 'catalog.mjs',
  summary: 'Look up what the tenant offers for playbook authoring. Read-only.',
  subcommands: {
    connectors: {
      summary: 'List connectors, or search them by meaning with --search',
      options: {
        search: { type: 'string', help: 'Plain-language search, for example "threat intelligence lookup"' },
        custom: { type: 'boolean', help: 'Only connectors made on this tenant' },
        limit: { type: 'string', help: 'Most results to return (default 15 for search)' },
      },
      run: async (ctx, args) => {
        if (args.search) {
          const r = await F.searchConnectors(ctx.client, args.search, intArg(args.limit ?? 15, '--limit'));
          return { search: args.search, results: r.results.map((x) => ({ name: x.connector.name, score: Number(x.score.toFixed(3)), version: x.connector.head?.version, title: x.connector.head?.title, vendor: x.connector.head?.vendorName, custom: !x.connector.isGlobal })) };
        }
        let list = await F.listConnectors(ctx.client);
        if (args.custom) list = list.filter((c) => !c.isGlobal);
        return { count: list.length, connectors: list.map((c) => ({ name: c.name, version: c.head?.version, title: c.head?.title, vendor: c.head?.vendorName, authTypes: c.head?.authTypes, custom: !c.isGlobal, connections: (c.connections || []).map((x) => ({ id: x.id, name: x.name })) })) };
      },
    },
    connector: {
      summary: 'Show one connector: versions, auth types, actions with their inputs and outputs',
      options: {
        name: { type: 'string', required: true, help: 'Connector name, for example Taegis.Case' },
        version: { type: 'string', help: 'Version (default: the head version)' },
        action: { type: 'string', help: 'Only this action, with full input and output schemas' },
        export: { type: 'string', help: 'Write the connector YAML to this file, to study it. Do not commit Sophos files' },
      },
      run: async (ctx, args) => {
        const c = await F.getConnector(ctx.client, { name: args.name });
        if (!c) throw new UsageError(`No connector named ${args.name} on this tenant. Search with: catalog.mjs connectors --search "<what it does>"`);
        const version = args.version || c.head?.version;
        const [v] = await F.connectorVersions(ctx.client, [`${c.name}:${version}`]);
        if (!v) throw new UsageError(`${c.name} has no version ${version}. Versions: ${c.versions.map((x) => x.version).join(', ')}`);
        let actions = v.actions;
        if (args.action) {
          actions = actions.filter((a) => a.name === args.action);
          if (!actions.length) throw new UsageError(`${c.name} ${version} has no action ${args.action}. Actions: ${v.actions.map((a) => a.name).join(', ')}`);
        }
        if (args.export) {
          fs.writeFileSync(args.export, await F.exportConnector(ctx.client, { name: c.name, version }));
        }
        return {
          name: c.name,
          version,
          versions: c.versions.map((x) => x.version),
          custom: !c.isGlobal,
          authTypes: v.authTypes,
          parameters: compactSchema(v.parameters),
          connections: (c.connections || []).map((x) => ({ id: x.id, name: x.name })),
          dependencyEntry: `${c.name}:${version}`,
          actions: actions.map((a) => (args.action ? { name: a.name, description: a.description, inputs: a.inputs, outputs: a.outputs, call: `${c.name}.${a.name}` } : { name: a.name, description: a.description, inputs: compactSchema(a.inputs), outputs: compactSchema(a.outputs), call: `${c.name}.${a.name}` })),
          ...(args.export ? { exportedTo: args.export } : {}),
        };
      },
    },
    triggers: {
      summary: 'Trigger types, platform event sources and events, and User Initiated contexts',
      run: async (ctx) => {
        const types = await F.triggerTypes(ctx.client);
        const out = {};
        for (const t of types) {
          if (t.name === 'platform') {
            out.platform = { title: t.title, sources: t.properties.source.oneOf.map((s) => ({ source: s.value, title: s.title, events: s.properties?.events?.items?.enum || [] })) };
          } else if (t.name === 'actions') {
            out.actions = { title: t.title, categories: t.properties.category.oneOf.map((c) => ({ category: c.value, title: c.title, contexts: (c.properties?.context?.oneOf || []).map((x) => x.value) })) };
          } else if (t.name === 'generic') {
            out.generic = { title: t.title, usage: (t.properties?.usage?.oneOf || []).map((u) => u.const ?? u.value) };
          }
        }
        out.ids = Object.fromEntries(types.map((t) => [t.name, t.id]));
        return out;
      },
    },
    'event-shape': {
      summary: 'The event a platform source passes to a playbook, with a skeleton for test events',
      options: {
        source: { type: 'string', help: `Platform source: ${Object.keys(EVENT_SHAPES).join(', ')}` },
        definition: { type: 'string', help: 'Or any schema definition by name, for example CaseEvent' },
        list: { type: 'boolean', help: 'List every definition name' },
      },
      run: async (ctx, args) => {
        const types = await F.triggerTypes(ctx.client);
        const defs = types.find((t) => t.name === 'platform')?.definitions || {};
        if (args.list) return { definitions: Object.keys(defs).sort() };
        const shape = args.source ? EVENT_SHAPES[args.source] : null;
        if (args.source && !shape) throw new UsageError(`Unknown source ${args.source}. Sources: ${Object.keys(EVENT_SHAPES).join(', ')}`);
        const name = args.definition || shape?.definition;
        if (!name) throw new UsageError('Give --source or --definition (or --list).');
        if (!defs[name]) throw new UsageError(`No definition named ${name}. List them with --list.`);
        const schema = expand(defs[name], defs);
        const sample = { event: shape ? 'Update' : undefined, [shape?.inputsKey || 'value']: skeleton(schema) };
        return {
          source: args.source ?? null,
          inputsKey: shape?.inputsKey ?? null,
          definition: name,
          note: shape ? `The event arrives as inputs.${shape.inputsKey}, with the event name in inputs.event. Fusion's macros (for example caseId(inputs)) read from there.` : undefined,
          schema,
          sampleInputs: sample,
        };
      },
    },
    actions: {
      summary: 'User Initiated actions configured on the tenant (what people can run from the console)',
      options: { search: { type: 'string', help: 'Only actions whose name contains this text' } },
      run: async (ctx, args) => {
        const all = [];
        for (let page = 1; page <= 20; page++) {
          const r = await F.actionsCatalog(ctx.client, { page, perPage: 100 });
          all.push(...r.actions);
          if (all.length >= r.totalCount || r.actions.length === 0) break;
        }
        const list = args.search ? all.filter((a) => a.name.toLowerCase().includes(args.search.toLowerCase())) : all;
        return { count: list.length, actions: list.map((a) => ({ name: a.name, category: a.category?.name, context: a.context?.name, enabled: a.isEnabled, responseMode: a.responseMode })) };
      },
    },
    interfaces: {
      summary: 'Playbook interfaces (call: targets that fan out to implementations)',
      options: { search: { type: 'string', help: 'Only interfaces whose name contains this text' } },
      run: async (ctx, args) => {
        let list = await F.interfaces(ctx.client);
        if (args.search) list = list.filter((i) => i.name.toLowerCase().includes(args.search.toLowerCase()));
        return { count: list.length, interfaces: list.map((i) => ({ name: i.name, id: i.id, version: i.head?.version, versionId: i.head?.id, dependencyEntry: `${i.name}:${i.head?.version}`, title: i.head?.title, inputs: compactSchema(i.head?.inputs), outputs: compactSchema(i.head?.outputs) })) };
      },
    },
    functions: {
      summary: "Fusion's CEL functions (macros), with descriptions and examples",
      options: { search: { type: 'string', help: 'Name prefix to search, for example case or detection' } },
      run: async (ctx, args) => {
        const list = await F.celFunctions(ctx.client, args.search || '');
        return { count: list.length, functions: list.map((m) => ({ name: m.name, description: m.description, returns: m.returnType?.join('|'), examples: (m.usage || []).slice(0, 2).map((u) => `${u.expression} => ${u.result}`) })) };
      },
    },
    templates: {
      summary: "List playbook templates: Sophos's own (good starting points) and the tenant's",
      options: {
        search: { type: 'string', help: 'Only templates whose name or title contains this text' },
        custom: { type: 'boolean', help: 'Only templates made on this tenant' },
      },
      run: async (ctx, args) => {
        let list = await F.listPlaybooks(ctx.client);
        if (args.custom) list = list.filter((p) => !p.isGlobal);
        if (args.search) {
          const q = args.search.toLowerCase();
          list = list.filter((p) => p.name.toLowerCase().includes(q) || String(p.head?.title || '').toLowerCase().includes(q));
        }
        return { count: list.length, templates: list.map((p) => ({ name: p.name, version: p.head?.version, title: p.head?.title, custom: !p.isGlobal, tags: p.tags })) };
      },
    },
    template: {
      summary: 'Show or export one template, to learn its structure. Do not commit Sophos files',
      options: {
        name: { type: 'string', required: true, help: 'Template name' },
        version: { type: 'string', help: 'Version (default head)' },
        export: { type: 'string', help: 'Write the template YAML to this file' },
      },
      run: async (ctx, args) => {
        const text = await F.exportPlaybook(ctx.client, { name: args.name, version: args.version });
        if (args.export) fs.writeFileSync(args.export, text);
        const loaded = loadYaml(text);
        const v = loaded.value || {};
        return {
          name: v.name,
          version: v.version,
          title: v.title,
          type: v.type,
          triggerHints: v.triggerHints,
          connectors: v.connectors || [],
          playbooks: v.playbooks || [],
          interfaces: v.interfaces || [],
          inputs: compactSchema(v.inputs),
          tasks: (v.dsl?.tasks || []).map((t) => ({ name: t.name, uses: t.action || t.call || t.exec || (t.range ? 'loop' : t.let ? 'let' : t.if ? 'if' : t.switch ? 'switch' : t.while ? 'while' : 'other'), condition: t.condition })),
          ...(args.export ? { exportedTo: args.export } : {}),
        };
      },
    },
  },
};

main(spec);
