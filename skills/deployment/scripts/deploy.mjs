#!/usr/bin/env node
// Deployment: duplicate and version checks, imports (a test copy by
// default), export-and-diff, connections, disabled instances, trigger
// filters, schedules, enable and publish, list and export, and delete.
//
// Every write needs --yes (and --production on a production profile), is
// recorded in the ledger the moment Fusion returns an ID, and is read back.

import fs from 'node:fs';
import path from 'node:path';
import { main, splitList } from '../../../lib/cli.mjs';
import { MutationUnconfirmedError, SfsError, UsageError } from '../../../lib/errors.mjs';
import * as F from '../../../lib/fusion.mjs';
import { record, isRecorded, readLedger, markObject } from '../../../lib/ledger.mjs';
import { validateText } from '../../../lib/rules.mjs';
import { dependencyList, diffValues, makeTestCopy, normalizeForDiff, parseOrThrow, testName } from '../../../lib/template.mjs';
import { loadYaml } from '../../../lib/yamlx.mjs';
import { checkField } from '../../../lib/cel.mjs';
import { TENANT_FIELDS, TEST_DISPLAY_PREFIX, TEST_PREFIX } from '../../../lib/constants.mjs';
import { log } from '../../../lib/log.mjs';
import { addSecret, findLeaks } from '../../../lib/redact.mjs';

/** Instance and schedule inputs end up in execution logs: refuse secret-looking values. */
function checkedInputs(value, label) {
  const leaks = findLeaks(value);
  if (leaks.length) throw new UsageError(`${label} holds secret-looking values (${leaks.map((l) => l.path).join(', ')}). Keep secrets in connections; Fusion logs inputs.`);
  return value;
}

const SEMVER = /^(\d+)\.(\d+)\.(\d+)/;

function compareSemver(a, b) {
  const pa = SEMVER.exec(String(a));
  const pb = SEMVER.exec(String(b));
  if (!pa || !pb) return 0;
  for (let i = 1; i <= 3; i++) {
    const d = Number(pa[i]) - Number(pb[i]);
    if (d) return Math.sign(d);
  }
  return 0;
}

function readJsonArg(value, label) {
  if (value === undefined) return undefined;
  const text = value.startsWith('@') ? fs.readFileSync(value.slice(1), 'utf8') : value;
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new UsageError(`${label} is not valid JSON: ${error.message}`);
  }
}

function parseMap(values) {
  const out = {};
  for (const pair of splitList(values)) {
    const [from, to] = pair.split('=');
    if (!from || !to) throw new UsageError(`--connector-map ${pair}: write Original=Replacement.`);
    out[from] = to;
  }
  return out;
}

/** Display names for instances, connections and schedules in test mode. */
function requireTestDisplayName(name, args, what) {
  if (args['as-is']) return name;
  if (!name.startsWith(TEST_DISPLAY_PREFIX)) {
    throw new UsageError(`${what} names start with "${TEST_DISPLAY_PREFIX}" so test objects are easy to find and remove. Use --name "${TEST_DISPLAY_PREFIX}${name}", or --as-is for a named deployment.`);
  }
  if (/claude/i.test(name)) throw new UsageError('Keep assistant names out of tenant object names.');
  return name;
}

/** Writes that change objects already on the tenant need the object in the ledger, or --allow-existing. */
function requireOwned(kind, id, args, env) {
  if (isRecorded(kind, id, env)) return;
  if (!args['allow-existing']) {
    throw new UsageError(`That ${kind} was not created by these scripts (it is not in the ledger). To change an object that already existed, the user must ask for it by name; then add --allow-existing.`);
  }
}

async function recordCreated(ctx, kind, obj, parentId = null) {
  const target = await ctx.session.target();
  return record({ kind, id: obj.id, name: obj.name, tenantId: target.tenantId, profile: ctx.profile.name, parentId }, { runId: ctx.args['run-id'], env: ctx.env });
}

/** Objects of a kind with this name, as they are now. */
async function findByName(ctx, kind, name) {
  switch (kind) {
    case 'playbook':
      return (await F.listPlaybooks(ctx.client)).filter((p) => p.name === name);
    case 'connector':
      return (await F.listConnectors(ctx.client)).filter((c) => c.name === name);
    case 'connection':
      return (await F.listConnections(ctx.client)).filter((c) => c.name === name);
    case 'instance':
      return (await F.listInstances(ctx.client)).filter((i) => i.name === name);
    case 'schedule':
      return (await F.listSchedules(ctx.client)).filter((x) => x.name === name);
    default:
      return [];
  }
}

/**
 * After a create that may or may not have happened, look for an object with
 * the name that was not there before the create. An object that already
 * existed is never adopted into the ledger.
 */
async function findAfterUnconfirmed(ctx, kind, name, before) {
  const r = await F.pollUntil(async () => (await findByName(ctx, kind, name)).find((o) => !before.has(o.id)) ?? null);
  return r.ok ? r.value : null;
}

async function createWithLedger(ctx, kind, name, create, parentId = null) {
  const before = new Set((await findByName(ctx, kind, name)).map((o) => o.id));
  let obj;
  try {
    obj = await create();
  } catch (error) {
    if (!(error instanceof MutationUnconfirmedError)) throw error;
    log(`The create may or may not have happened (${error.failure}). Looking for a new ${kind} named ${name}.`);
    const found = await findAfterUnconfirmed(ctx, kind, name, before);
    if (!found) throw error;
    const entry = await recordCreated(ctx, kind, found, parentId);
    return { obj: found, entry, note: 'The create answered with an error, but the object exists, so it was recorded in the ledger.' };
  }
  if (!obj?.id) throw new SfsError(`Fusion answered the ${kind} create without an ID. Nothing was recorded; check the tenant by name (${name}).`, { code: 'no_id' });
  if (before.has(obj.id)) {
    // The create landed on an object that was already there (an import that added a version)
    const known = isRecorded(kind, obj.id, ctx.env);
    return { obj, entry: null, note: `That ${kind} already existed, so no new ledger entry was made${known ? ' (it is already in the ledger)' : ', and rollback will not remove it'}.` };
  }
  const entry = await recordCreated(ctx, kind, obj, parentId);
  return { obj, entry };
}

async function readBack(ctx, kind, id, expect = () => true) {
  const r = await F.pollUntil(async () => {
    const o = await F.readObject(ctx.client, kind, id);
    return o && expect(o) ? o : null;
  });
  return r;
}

async function exportAndDiff(ctx, kind, name, localText) {
  const exported = kind === 'playbook' ? await F.exportPlaybook(ctx.client, { name }) : await F.exportConnector(ctx.client, { name });
  const remote = loadYaml(exported).value;
  const local = loadYaml(localText).value;
  const differences = diffValues(normalizeForDiff(local), normalizeForDiff(remote));
  return { matches: differences.length === 0, ignored: TENANT_FIELDS, differences };
}

function triggerTypeId(types, name) {
  const t = types.find((x) => x.name === name);
  if (!t) throw new SfsError(`The tenant has no ${name} trigger type.`, { code: 'no_trigger_type' });
  return t.id;
}

function buildTriggerConfig(args) {
  const filter = args.filter ?? 'true';
  if (args.filter) {
    const r = checkField(args.filter);
    if (!r.ok) throw new UsageError(`--filter does not parse as CEL: ${r.error.message}`);
  }
  switch (args.trigger) {
    case 'generic':
      return { usage: { value: args.usage || 'other' } };
    case 'platform': {
      if (!args.source || !args.events) throw new UsageError('A platform trigger needs --source and --events.');
      const source = { value: args.source, events: splitList(args.events) };
      if (args.source === 'alert2') source.include_suppressed_alerts = Boolean(args['include-suppressed']);
      return { source, filter: { value: filter } };
    }
    case 'actions': {
      if (!args.category || !args.context || !args['action-name']) throw new UsageError('A User Initiated trigger needs --category, --context and --action-name.');
      return { category: { value: args.category, context: { value: args.context } }, filter: { value: filter }, name: args['action-name'] };
    }
    default:
      throw new UsageError('--trigger must be generic, platform or actions.');
  }
}

const OWN = { 'allow-existing': { type: 'boolean', help: 'Allow changing an object these scripts did not create (only when the user asked for that object by name)' } };

const spec = {
  name: 'deploy.mjs',
  summary: 'Deploy Sophos Fusion templates and connectors safely: test copies, disabled instances, ledger, read-back.',
  subcommands: {
    list: {
      summary: 'List objects on the tenant: templates, connectors, connections, instances or schedules',
      options: {
        kind: { type: 'string', default: 'templates', help: 'templates, connectors, connections, instances or schedules' },
        custom: { type: 'boolean', help: 'Templates and connectors made on this tenant only' },
        search: { type: 'string', help: 'Only names containing this text' },
      },
      run: async (ctx, args) => {
        const q = args.search?.toLowerCase();
        const keep = (n) => !q || String(n).toLowerCase().includes(q);
        switch (args.kind) {
          case 'templates': {
            const l = (await F.listPlaybooks(ctx.client)).filter((p) => (!args.custom || !p.isGlobal) && keep(p.name));
            return { kind: 'templates', count: l.length, items: l.map((p) => ({ id: p.id, name: p.name, version: p.head?.version, title: p.head?.title, custom: !p.isGlobal, versions: p.versions?.map((v) => v.version) })) };
          }
          case 'connectors': {
            const l = (await F.listConnectors(ctx.client)).filter((c) => (!args.custom || !c.isGlobal) && keep(c.name));
            return { kind: 'connectors', count: l.length, items: l.map((c) => ({ id: c.id, name: c.name, version: c.head?.version, custom: !c.isGlobal, connections: c.connections?.length ?? 0 })) };
          }
          case 'connections': {
            const l = (await F.listConnections(ctx.client)).filter((c) => keep(c.name));
            return { kind: 'connections', count: l.length, items: l.map((c) => ({ id: c.id, name: c.name, connector: c.connector?.name, version: c.version?.version, authType: c.authType, health: c.healthStatus })) };
          }
          case 'instances': {
            const l = (await F.listInstances(ctx.client)).filter((i) => keep(i.name));
            return { kind: 'instances', count: l.length, items: l.map((i) => ({ id: i.id, name: i.name, template: i.playbook?.name, version: i.version?.version, enabled: i.enabled, trigger: i.trigger?.type?.name })) };
          }
          case 'schedules': {
            const l = (await F.listSchedules(ctx.client)).filter((s) => keep(s.name));
            return { kind: 'schedules', count: l.length, items: l };
          }
          default:
            throw new UsageError('--kind must be templates, connectors, connections, instances or schedules.');
        }
      },
    },
    show: {
      summary: 'Show one object in full, for example an instance with its trigger and filter. Read-only',
      options: {
        kind: { type: 'string', required: true, help: 'playbook, connector, connection, instance or schedule' },
        id: { type: 'string', required: true, help: 'Object ID' },
      },
      run: async (ctx, args) => {
        if (!['playbook', 'connector', 'connection', 'instance', 'schedule'].includes(args.kind)) throw new UsageError('--kind must be playbook, connector, connection, instance or schedule.');
        const o = await F.readObject(ctx.client, args.kind, args.id);
        if (!o) throw new SfsError(`No ${args.kind} with that ID.`, { code: 'not_found' });
        return { kind: args.kind, inLedger: isRecorded(args.kind, args.id, ctx.env), object: o };
      },
    },
    counts: {
      summary: 'Count templates, connectors, connections, instances and schedules (before and after a test)',
      run: async (ctx) => ({ tenant: await ctx.tenantSummary(), counts: await F.counts(ctx.client) }),
    },
    export: {
      summary: 'Export a template or connector from the tenant to a file',
      options: {
        template: { type: 'string', help: 'Template name' },
        connector: { type: 'string', help: 'Connector name' },
        version: { type: 'string', help: 'Version (default head)' },
        out: { type: 'string', required: true, help: 'File to write' },
        clean: { type: 'boolean', help: 'Drop tenant fields (tenantId and platform flags) so the file can be shared' },
      },
      run: async (ctx, args) => {
        if (Boolean(args.template) === Boolean(args.connector)) throw new UsageError('Give --template or --connector.');
        let text = args.template ? await F.exportPlaybook(ctx.client, { name: args.template, version: args.version }) : await F.exportConnector(ctx.client, { name: args.connector, version: args.version });
        if (args.clean) {
          const loaded = loadYaml(text);
          for (const f of TENANT_FIELDS.filter((x) => x !== 'icon')) loaded.doc.delete(f);
          text = loaded.doc.toString({ lineWidth: 0 });
        }
        fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true });
        fs.writeFileSync(args.out, text);
        return { exported: args.template || args.connector, out: args.out, bytes: Buffer.byteLength(text), cleaned: Boolean(args.clean) };
      },
    },
    check: {
      summary: 'Duplicate and version check before an import. Read-only',
      args: '<file.yaml>',
      minPositionals: 1,
      options: {
        'as-is': { type: 'boolean', help: 'Check the real name instead of the test copy name' },
        prefix: { type: 'string', default: TEST_PREFIX, help: 'Test copy prefix' },
      },
      run: async (ctx, args, [file]) => {
        const text = fs.readFileSync(file, 'utf8');
        const { value } = parseOrThrow(text, file);
        const name = args['as-is'] ? value.name : testName(value.name, args.prefix);
        const kind = value.kind === 'Playbook' ? 'playbook' : 'connector';
        const existing = kind === 'playbook' ? await F.findPlaybookByName(ctx.client, name) : await F.getConnector(ctx.client, { name });
        const deps = kind === 'playbook' ? ['connectors', 'playbooks', 'interfaces'].flatMap((k) => dependencyList(value, k).map((d) => ({ list: k, ...d }))) : [];
        let verdict;
        if (!existing) verdict = 'new';
        else {
          const cmp = compareSemver(value.version, existing.head?.version);
          verdict = cmp > 0 ? 'newer_than_tenant' : cmp === 0 ? 'same_version_exists' : 'older_than_tenant';
        }
        const advice = {
          new: 'Nothing on the tenant has this name. Safe to import.',
          newer_than_tenant: 'The tenant has an older version under this name. Import adds the new version; existing instances keep their version strategy.',
          same_version_exists: 'The tenant already has this name at this version. Bump version in the file, or remove the old copy (ledger rollback) first.',
          older_than_tenant: 'The tenant has a newer version. Check you have the latest file before importing.',
        }[verdict];
        return { file, kind, name, version: value.version, onTenant: existing ? { id: existing.id, version: existing.head?.version, versions: existing.versions?.map((v) => v.version), custom: !existing.isGlobal, inLedger: isRecorded(kind, existing.id, ctx.env) } : null, verdict, advice, dependencies: deps };
      },
    },
    import: {
      summary: 'Import a template or connector. By default a test copy (ZZTest_ name, "ZZ Test " title)',
      write: true,
      args: '<file.yaml>',
      minPositionals: 1,
      options: {
        'as-is': { type: 'boolean', help: 'Import under the real name, not as a test copy' },
        prefix: { type: 'string', default: TEST_PREFIX, help: 'Test copy prefix' },
        'connector-map': { type: 'string', multiple: true, help: 'Original=Replacement connector name in a template (repeatable). Test copies map custom connectors to their ZZTest_ copies when those exist' },
        'save-copy': { type: 'string', help: 'Also write the exact text that was imported to this file' },
        ...OWN,
      },
      gateDescription: (args, [file]) => `importing ${file}${args['as-is'] ? ' under its real name' : ' as a test copy'}`,
      run: async (ctx, args, [file]) => {
        const text = fs.readFileSync(file, 'utf8');
        const offline = validateText(text, file);
        if (!offline.ok) {
          return { ok: false, error: { code: 'validation_failed', message: `${file} has ${offline.errors} offline validation errors. Fix them before importing.` }, findings: offline.findings.filter((f) => f.level === 'error') };
        }
        const { value } = parseOrThrow(text, file);
        const kind = value.kind === 'Playbook' ? 'playbook' : 'connector';
        let body = text;
        let name = value.name;
        let changes = [];
        if (!args['as-is'] && !/^ZZ[A-Za-z0-9]*_$/.test(args.prefix)) {
          throw new UsageError('--prefix must start with ZZ and end with an underscore (default ZZTest_), so test copies stay easy to find and remove. Use --as-is for a real-name import.');
        }
        if (!args['as-is']) {
          const map = parseMap(args['connector-map']);
          if (kind === 'playbook') {
            const custom = dependencyList(value, 'connectors').filter((d) => !d.name.startsWith('Taegis.') && !map[d.name]);
            for (const d of custom) {
              const copy = testName(d.name, args.prefix);
              if (await F.getConnector(ctx.client, { name: copy })) map[d.name] = copy;
            }
          }
          const copy = makeTestCopy(text, { prefix: args.prefix, connectorMap: map });
          body = copy.text;
          name = copy.name;
          changes = copy.changes;
        }
        const existing = kind === 'playbook' ? await F.findPlaybookByName(ctx.client, name) : await F.getConnector(ctx.client, { name });
        if (existing && compareSemver(value.version, existing.head?.version) <= 0) {
          throw new SfsError(`${name} is already on the tenant at version ${existing.head?.version}. Bump the version in the file, or remove the old copy first.`, { code: 'duplicate' });
        }
        // Adding a version to an object these scripts did not create changes it, and no rollback can take a published version back.
        if (existing && !isRecorded(kind, existing.id, ctx.env) && !args['allow-existing']) {
          throw new UsageError(`${name} already exists on the tenant (version ${existing.head?.version}) and these scripts did not create it. Importing adds version ${value.version} to it, which rollback cannot undo. Only with the user's approval for that object by name, add --allow-existing.`);
        }
        if (args['save-copy']) fs.writeFileSync(args['save-copy'], body);
        const created = await createWithLedger(ctx, kind, name, () => (kind === 'playbook' ? F.importPlaybook(ctx.client, body, path.basename(file)) : F.importConnector(ctx.client, body, path.basename(file))));
        const id = created.obj.id;
        const back = await readBack(ctx, kind, id, (o) => o.name === name && o.head?.version === String(value.version));
        const diff = back.ok ? await exportAndDiff(ctx, kind, name, body) : null;
        return {
          ok: back.ok,
          imported: { kind, id, name, version: created.obj.head?.version, headVersionId: created.obj.head?.id, published: Boolean(created.obj.head?.published) },
          testCopy: !args['as-is'],
          changes,
          ledger: created.entry ? { runId: created.entry.runId, seq: created.entry.seq } : null,
          readBack: back.ok ? { found: true, waitedMs: back.waitedMs } : { found: false, note: 'The import returned an ID but the object did not read back in time. Check again before retrying.' },
          diff,
          ...(created.note ? { note: created.note } : {}),
          next: kind === 'playbook' ? `Create a disabled instance: deploy.mjs instance-create --template ${name} --name "${TEST_DISPLAY_PREFIX}..." --trigger <type> --yes` : `Create a connection: deploy.mjs connection-create --connector ${name} --name "${TEST_DISPLAY_PREFIX}..." --auth-type <type> --yes`,
        };
      },
    },
    diff: {
      summary: 'Export a template or connector and compare it with a local file, ignoring tenant fields. Read-only',
      args: '<file.yaml>',
      minPositionals: 1,
      options: {
        name: { type: 'string', help: 'Name on the tenant (default: the test copy name)' },
        'as-is': { type: 'boolean', help: 'Compare with the real name' },
        prefix: { type: 'string', default: TEST_PREFIX, help: 'Test copy prefix' },
      },
      run: async (ctx, args, [file]) => {
        const text = fs.readFileSync(file, 'utf8');
        const { value } = parseOrThrow(text, file);
        const name = args.name || (args['as-is'] ? value.name : testName(value.name, args.prefix));
        const kind = value.kind === 'Playbook' ? 'playbook' : 'connector';
        return { file, name, ...(await exportAndDiff(ctx, kind, name, text)) };
      },
    },
    'connection-create': {
      summary: 'Create a connection for a connector. Credentials come from environment variables, never arguments',
      write: true,
      options: {
        connector: { type: 'string', required: true, help: 'Connector name' },
        name: { type: 'string', required: true, help: `Connection name (test mode: starts "${TEST_DISPLAY_PREFIX}")` },
        'auth-type': { type: 'string', required: true, help: 'None, APIKey, Basic, OAuthClientCreds, ...' },
        config: { type: 'string', help: 'Connection parameters as JSON, or @file.json' },
        'credentials-env': { type: 'string', multiple: true, help: 'key=ENV_VAR: a credential field read from an environment variable (repeatable)' },
        'auth-url': { type: 'string', help: 'Token URL, for OAuth auth types' },
        'as-is': { type: 'boolean', help: 'Allow a name without the test prefix' },
      },
      gateDescription: (args) => `creating connection "${args.name}" for ${args.connector}`,
      run: async (ctx, args) => {
        const name = requireTestDisplayName(args.name, args, 'Connection');
        const c = await F.getConnector(ctx.client, { name: args.connector });
        if (!c) throw new SfsError(`No connector named ${args.connector}.`, { code: 'not_found' });
        if (!(c.head?.authTypes || []).includes(args['auth-type'])) throw new UsageError(`${c.name} supports auth types ${c.head?.authTypes?.join(', ')}.`);
        if ((await F.listConnections(ctx.client)).some((x) => x.name === name)) throw new SfsError(`A connection named "${name}" already exists.`, { code: 'duplicate' });
        const credentials = {};
        for (const pair of splitList(args['credentials-env'])) {
          const [k, envName] = pair.split('=');
          if (!k || !envName || !ctx.env[envName]) throw new UsageError(`--credentials-env ${pair}: give key=ENV_VAR with the variable set.`);
          addSecret(ctx.env[envName]);
          credentials[k] = ctx.env[envName];
        }
        const input = {
          name,
          authType: args['auth-type'],
          versionStrategy: 'FollowMajorVersion',
          config: readJsonArg(args.config, '--config') || {},
          ...(Object.keys(credentials).length ? { credentials } : {}),
          ...(args['auth-url'] ? { authUrl: args['auth-url'] } : {}),
        };
        const created = await createWithLedger(ctx, 'connection', name, () => F.createConnection(ctx.client, c.id, input), c.id);
        const back = await readBack(ctx, 'connection', created.obj.id, (o) => o.name === name);
        return { ok: back.ok, connection: { id: created.obj.id, name, connector: c.name, authType: input.authType }, ledger: created.entry ? { runId: created.entry.runId, seq: created.entry.seq } : null, readBack: { found: back.ok, waitedMs: back.waitedMs } };
      },
    },
    'instance-create': {
      summary: 'Create a configured playbook (instance). Always created disabled',
      write: true,
      options: {
        template: { type: 'string', required: true, help: 'Template name on the tenant' },
        name: { type: 'string', required: true, help: `Instance name (test mode: starts "${TEST_DISPLAY_PREFIX}")` },
        trigger: { type: 'string', required: true, help: 'generic, platform or actions (User Initiated)' },
        usage: { type: 'string', help: 'Generic trigger usage: other, schedule or notification (default other)' },
        source: { type: 'string', help: 'Platform source, for example case' },
        events: { type: 'string', help: 'Platform events, comma separated, for example Update' },
        'include-suppressed': { type: 'boolean', help: 'alert2 source: include suppressed alerts' },
        filter: { type: 'string', help: 'CEL "Only when" filter (default true)' },
        category: { type: 'string', help: 'User Initiated: lookup or response' },
        context: { type: 'string', help: 'User Initiated context, for example case' },
        'action-name': { type: 'string', help: 'User Initiated: the name people see' },
        inputs: { type: 'string', help: 'Instance inputs as JSON, or @file.json' },
        connections: { type: 'string', help: 'Connection IDs, comma separated. Default: the only connection of each connector the template uses' },
        interfaces: { type: 'string', help: 'Interface bindings as JSON, or @file.json: [{interface, version, playbook, connections}]' },
        version: { type: 'string', help: 'Template version (default head), pinned with versionStrategy Fixed' },
        'as-is': { type: 'boolean', help: 'Allow a name without the test prefix' },
      },
      gateDescription: (args) => `creating disabled instance "${args.name}" of ${args.template}`,
      run: async (ctx, args) => {
        const name = requireTestDisplayName(args.name, args, 'Instance');
        const pb = await F.findPlaybookByName(ctx.client, args.template);
        if (!pb) throw new SfsError(`No template named ${args.template}.`, { code: 'not_found' });
        const version = args.version ? pb.versions.find((v) => v.version === args.version) : pb.head;
        if (!version) throw new UsageError(`${args.template} has no version ${args.version}.`);
        if ((await F.listInstances(ctx.client)).some((i) => i.name === name)) throw new SfsError(`An instance named "${name}" already exists.`, { code: 'duplicate' });
        const text = await F.exportPlaybook(ctx.client, { name: pb.name, version: version.version });
        const tv = loadYaml(text).value;
        let connections = splitList(args.connections);
        const picked = [];
        if (!args.connections) {
          const all = await F.listConnections(ctx.client);
          for (const d of dependencyList(tv, 'connectors')) {
            const mine = all.filter((c) => c.connector?.name === d.name);
            if (mine.length === 1) {
              connections.push(mine[0].id);
              picked.push({ connector: d.name, connection: mine[0].name, id: mine[0].id });
            } else if (mine.length === 0) {
              throw new SfsError(`The template uses ${d.name}, which has no connection on this tenant. Create one first (connection-create).`, { code: 'no_connection' });
            } else {
              throw new UsageError(`${d.name} has ${mine.length} connections (${mine.map((c) => c.name).join(', ')}). Pick with --connections.`);
            }
          }
        }
        connections = [...new Set(connections)];
        const types = await F.triggerTypes(ctx.client);
        const instance = {
          name,
          versionStrategy: 'Fixed',
          version: version.id,
          enabled: false,
          trigger: { name, typeId: triggerTypeId(types, args.trigger), config: buildTriggerConfig(args) },
          inputs: checkedInputs(readJsonArg(args.inputs, '--inputs') || {}, '--inputs'),
          connections,
          ...(args.interfaces ? { interfaces: readJsonArg(args.interfaces, '--interfaces') } : {}),
        };
        const created = await createWithLedger(ctx, 'instance', name, () => F.createInstance(ctx.client, pb.id, instance), pb.id);
        const back = await readBack(ctx, 'instance', created.obj.id, (o) => o.name === name);
        const readEnabled = back.value?.enabled;
        return {
          ok: back.ok && readEnabled === false,
          instance: { id: created.obj.id, name, template: pb.name, version: version.version, enabled: readEnabled, trigger: args.trigger, connections: picked.length ? picked : connections },
          ledger: created.entry ? { runId: created.entry.runId, seq: created.entry.seq } : null,
          readBack: { found: back.ok, enabled: readEnabled, waitedMs: back.waitedMs },
          next: args.trigger === 'generic' ? `Run it: run.mjs execute --instance ${created.obj.id} --yes` : 'Enable it only when the user approves: deploy.mjs enable --instance <id> --yes',
        };
      },
    },
    'set-filter': {
      summary: "Set an instance's CEL \"Only when\" filter",
      write: true,
      options: { instance: { type: 'string', required: true, help: 'Instance ID' }, filter: { type: 'string', required: true, help: 'CEL filter' }, ...OWN },
      gateDescription: (args) => `setting the trigger filter on instance ${args.instance}`,
      run: async (ctx, args) => {
        requireOwned('instance', args.instance, args, ctx.env);
        const r = checkField(args.filter);
        if (!r.ok) throw new UsageError(`--filter does not parse as CEL: ${r.error.message}`);
        const inst = await F.getInstance(ctx.client, args.instance);
        if (!inst) throw new SfsError('No such instance.', { code: 'not_found' });
        if (!inst.trigger?.type?.id) throw new SfsError('That instance has no trigger to filter.', { code: 'no_trigger' });
        if (inst.trigger.type.name === 'generic') throw new UsageError('Generic Trigger instances have no filter; they run when started.');
        const config = { ...(inst.trigger.config || {}), filter: { value: args.filter } };
        await F.updateInstance(ctx.client, { playbookInstanceId: inst.id, trigger: { name: inst.trigger.name, typeId: inst.trigger.type.id, config } });
        const back = await readBack(ctx, 'instance', inst.id, (o) => o.trigger?.config?.filter?.value === args.filter);
        return { ok: back.ok, instance: inst.id, filter: args.filter, readBack: { matches: back.ok, waitedMs: back.waitedMs } };
      },
    },
    'schedule-create': {
      summary: 'Create a schedule for a Generic Trigger instance. Created paused unless --start',
      write: true,
      options: {
        instance: { type: 'string', required: true, help: 'Instance ID' },
        name: { type: 'string', required: true, help: `Schedule name (test mode: starts "${TEST_DISPLAY_PREFIX}")` },
        cron: { type: 'string', required: true, help: 'Cron expression, for example "0 7 * * 1"' },
        'time-zone': { type: 'string', default: 'UTC', help: 'IANA time zone (default UTC)' },
        inputs: { type: 'string', help: 'Run inputs as JSON, or @file.json' },
        start: { type: 'boolean', help: 'Create it running instead of paused' },
        'as-is': { type: 'boolean', help: 'Allow a name without the test prefix' },
        ...OWN,
      },
      gateDescription: (args) => `creating schedule "${args.name}" (${args.cron}) on instance ${args.instance}${args.start ? ', running' : ', paused'}`,
      run: async (ctx, args) => {
        const name = requireTestDisplayName(args.name, args, 'Schedule');
        requireOwned('instance', args.instance, args, ctx.env);
        if (!/^\S+(\s+\S+){4,5}$/.test(args.cron.trim())) throw new UsageError('--cron needs five fields (minute hour day month weekday).');
        const inst = await F.getInstance(ctx.client, args.instance);
        if (!inst) throw new SfsError('No such instance.', { code: 'not_found' });
        if (inst.trigger?.type?.name !== 'generic') throw new UsageError('Schedules run Generic Trigger instances only.');
        if (!inst.enabled) {
          return { ok: false, error: { code: 'instance_disabled', message: `Fusion only schedules an enabled instance (PB12). Enable it first with deploy.mjs enable --instance ${inst.id} --yes (its own approval). The schedule is created paused, so it will not run until someone resumes it.` } };
        }
        if ((await F.listSchedules(ctx.client)).some((x) => x.name === name)) throw new SfsError(`A schedule named "${name}" already exists.`, { code: 'duplicate' });
        const input = { name, playbookInstance: args.instance, cron: args.cron.trim(), timeZone: args['time-zone'], paused: !args.start, inputs: checkedInputs(readJsonArg(args.inputs, '--inputs') || {}, '--inputs'), childType: 'NONE' };
        const created = await createWithLedger(ctx, 'schedule', name, () => F.createSchedule(ctx.client, input), args.instance);
        const back = await readBack(ctx, 'schedule', created.obj.id, (o) => o.paused === input.paused);
        return { ok: back.ok, schedule: { id: created.obj.id, name, cron: input.cron, timeZone: input.timeZone, paused: back.value?.paused ?? null, nextRun: back.value?.nextRun ?? null }, ledger: created.entry ? { runId: created.entry.runId, seq: created.entry.seq } : null, readBack: { matches: back.ok } };
      },
    },
    enable: {
      summary: 'Enable an instance. A separate, explicit step: an enabled instance runs on its trigger',
      write: true,
      options: { instance: { type: 'string', required: true, help: 'Instance ID' }, ...OWN },
      gateDescription: (args) => `ENABLING instance ${args.instance}, after which it runs whenever its trigger fires`,
      run: async (ctx, args) => {
        requireOwned('instance', args.instance, args, ctx.env);
        await F.updateInstance(ctx.client, { playbookInstanceId: args.instance, enabled: true });
        const back = await readBack(ctx, 'instance', args.instance, (o) => o.enabled === true);
        return { ok: back.ok, instance: args.instance, enabled: back.value?.enabled ?? null };
      },
    },
    disable: {
      summary: 'Disable an instance',
      write: true,
      options: { instance: { type: 'string', required: true, help: 'Instance ID' }, ...OWN },
      gateDescription: (args) => `disabling instance ${args.instance}`,
      run: async (ctx, args) => {
        requireOwned('instance', args.instance, args, ctx.env);
        await F.updateInstance(ctx.client, { playbookInstanceId: args.instance, enabled: false });
        const back = await readBack(ctx, 'instance', args.instance, (o) => o.enabled === false);
        return { ok: back.ok, instance: args.instance, enabled: back.value?.enabled ?? null };
      },
    },
    publish: {
      summary: 'Publish a draft template version (makes it immutable and the head)',
      write: true,
      options: { template: { type: 'string', required: true, help: 'Template name' }, version: { type: 'string', required: true, help: 'Draft version to publish' }, ...OWN },
      gateDescription: (args) => `publishing ${args.template} ${args.version}`,
      run: async (ctx, args) => {
        const pb = await F.findPlaybookByName(ctx.client, args.template);
        if (!pb) throw new SfsError(`No template named ${args.template}.`, { code: 'not_found' });
        requireOwned('playbook', pb.id, args, ctx.env);
        const v = pb.versions.find((x) => x.version === args.version);
        if (!v) throw new UsageError(`${args.template} has no version ${args.version}.`);
        if (v.published) return { template: pb.name, version: args.version, published: v.published, note: 'Already published. Imports publish the version they create.' };
        const r = await F.publishPlaybookVersion(ctx.client, v.id, args.version);
        const back = await F.pollUntil(async () => (await F.getPlaybook(ctx.client, pb.id))?.versions.find((x) => x.version === args.version)?.published);
        return { ok: back.ok, template: pb.name, version: args.version, published: back.value ?? r?.published ?? null };
      },
    },
    delete: {
      summary: 'Delete one object these scripts created, then read back that it is gone',
      write: true,
      options: { kind: { type: 'string', required: true, help: 'playbook, connector, connection, instance or schedule' }, id: { type: 'string', required: true, help: 'Object ID' }, ...OWN },
      gateDescription: (args) => `deleting ${args.kind} ${args.id}`,
      run: async (ctx, args) => {
        if (!['playbook', 'connector', 'connection', 'instance', 'schedule'].includes(args.kind)) throw new UsageError('--kind must be playbook, connector, connection, instance or schedule.');
        requireOwned(args.kind, args.id, args, ctx.env);
        const before = await F.readObject(ctx.client, args.kind, args.id);
        if (!before) return { kind: args.kind, id: args.id, deleted: false, note: 'Not on the tenant (already gone).' };
        await F.deleteObject(ctx.client, args.kind, args.id);
        const gone = await F.pollUntil(async () => !(await F.readObject(ctx.client, args.kind, args.id)));
        const ledger = readLedger(ctx.env);
        for (const run of Object.values(ledger.runs)) {
          const o = run.objects.find((x) => x.kind === args.kind && x.id === args.id);
          if (o && gone.ok) markObject(run.id, o.seq, 'deleted', null, ctx.env);
        }
        return { ok: gone.ok, kind: args.kind, id: args.id, name: before.name, deleted: gone.ok, readBack: { gone: gone.ok, waitedMs: gone.waitedMs } };
      },
    },
  },
};

main(spec);
