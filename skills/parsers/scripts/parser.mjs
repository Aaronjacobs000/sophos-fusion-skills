#!/usr/bin/env node
// Custom parsers for Sophos NG-SIEM: samples into a private, masked workspace, a first draft from
// the library's generator, offline checks on the vendored emulator, read-only checks in the
// tenant's own engine, then installs (disabled, ZZTest_ copies by default), enable as its own
// step, and a check on real ingest.
//
// Every write needs --yes (and --production on a production profile), is recorded in the ledger the
// moment Sophos returns an ID, and is read back. Rollback is "ledger.mjs rollback" in the
// deployment skill.

import fs from 'node:fs';
import path from 'node:path';
import { intArg, main } from '../../../lib/cli.mjs';
import { MutationUnconfirmedError, SfsError, UsageError } from '../../../lib/errors.mjs';
import { findRecorded, liveObjects, markObject, record, updateDetail } from '../../../lib/ledger.mjs';
import { log } from '../../../lib/log.mjs';
import { addToWorkspace, assertPrivatePath, maskText, readSampleFile, sampleLines } from '../../../lib/samples.mjs';
import { durationMs, qlString, qlTime, searchRows } from '../../../lib/search.mjs';
import { contributeParser } from '../../../lib/contribute.mjs';
import { pollUntil } from '../../../lib/fusion.mjs';
import * as P from '../../../lib/parsers.mjs';
import { analyse, buildPlan, expectedFrom, GENERIC, qlName, schemaFromQlName, SCHEMA_IDS, writeParsers } from '../../../lib/xsl.mjs';

const LIBRARY_FORMATS = new Set(['json', 'cef', 'leef', 'kv', 'syslog', 'csv', 'xml']);

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function parserReport(folder) {
  return folder.parsers.map((p) => ({ name: p.name, role: p.role, parent: p.parent, schema: p.schema }));
}

/** Install order: parents, then standalone parsers, then children. */
function installOrder(folder) {
  const rank = { parent: 0, standalone: 1, child: 2 };
  return folder.parsers.slice().sort((a, b) => rank[a.role] - rank[b.role]);
}

async function tenantOf(ctx) {
  return (await ctx.session.target()).tenantId;
}

/** A ledger-owned parser, read live. Refuses anything these scripts didn't create. */
async function ownedParser(ctx, id) {
  const entry = findRecorded('parser', Number(id), ctx.env);
  if (!entry || !['live', 'delete_failed'].includes(entry.status)) throw new UsageError(`Parser ${id} is not in the ledger as live. These scripts change only parsers they created.`);
  const live = await P.getParser(ctx.client, id);
  if (!live) throw new SfsError(`Parser ${id} does not read back.`, { code: 'not_found' });
  if (live.name !== entry.name) throw new UsageError(`Parser ${id} is now named "${live.name}", not "${entry.name}" as recorded. Check it by hand.`);
  return { entry, live };
}

const ENABLE_NOTE = 'Turning a parser on changes how matching lines are normalized, tenant-wide and at once. Generic events continue. Sophos detectors (IP and Domain Watchlist, DGA, and Sophos rules that match any sensor type on the schema) start running on the new records. On a tenant Sophos MDR monitors, the MDR team works those detections, so tell them first.';

/** Creates one parser disabled, records it, and makes the live code equal the local file. */
async function installOne(ctx, folder, p, { name, parentId, before }) {
  const target = await ctx.session.target();
  const input = { name, type: P.API_TYPES[p.role], format: P.apiFormat(folder.meta), schema: p.schema, code: p.text, parentId: parentId ?? 0, disabled: true, overrideGlobal: false };
  let created;
  try {
    created = await P.createParser(ctx.client, input);
  } catch (error) {
    if (!(error instanceof MutationUnconfirmedError)) throw error;
    log(`createParser may or may not have happened (${error.failure}). Looking for a new parser named ${name}.`);
    const found = await pollUntil(async () => (await P.listParsers(ctx.client)).find((x) => x.name === name && !before.has(x.id)) ?? null);
    if (!found.ok) throw error;
    created = found.value;
  }
  if (!created?.id) throw new SfsError(`createParser answered without an ID. Nothing was recorded; check the tenant for ${name}.`, { code: 'no_id' });
  const entry = record({ kind: 'parser', id: Number(created.id), name, tenantId: target.tenantId, profile: ctx.profile.name, parentId: parentId ? Number(parentId) : null, detail: { dir: folder.dir, localName: p.name, role: p.role, schema: p.schema, sha256: P.sha256(p.text) } }, { runId: ctx.args['run-id'], env: ctx.env });
  const steps = [`created ${created.id} disabled`];
  // Wait until it reads at all, then look at the code: a parser that reads with other code won't change on its own.
  let back = await P.readParserUntil(ctx.client, created.id, () => true);
  if (back.ok && back.value.code !== p.text) back = { ...back, ok: false };
  if (!back.ok) {
    // createParser stores the console's new-parser template instead of the code sent (lab 16/10, 20/11 and 22/11/2026).
    steps.push('createParser stored other code; sending it with updateParser while disabled');
    await P.updateParser(ctx.client, created.id, { code: p.text });
    back = await P.readParserUntil(ctx.client, created.id, (x) => x.code === p.text);
  }
  if (!back.ok) {
    steps.push('the code still differs; deleting the parser');
    const gone = await P.removeParser(ctx.client, created.id);
    markObject(entry.runId, entry.seq, gone.ok ? 'deleted' : 'delete_failed', gone.ok ? 'code did not save' : 'code did not save, and the delete did not read back', ctx.env);
    throw new SfsError(`${name}: the code did not save, so the parser was deleted${gone.ok ? '' : ' (the delete did not read back: check the parser list)'}.`, { code: 'code_not_saved', details: { steps } });
  }
  const live = back.value;
  const readBack = { name: live.name === name, parentId: Number(live.parentId) === Number(parentId ?? 0), disabled: live.disabled === true, code: live.code === p.text };
  return { id: Number(created.id), name, local: p.name, role: p.role, schema: p.schema, ledger: { runId: entry.runId, seq: entry.seq }, readBack, ok: Object.values(readBack).every(Boolean), steps };
}

const SHOW_VALUES = { 'show-values': { type: 'boolean', help: 'Also print field values. They can hold customer data, so only when the user asks' } };

const spec = {
  name: 'parser.mjs',
  summary: 'Build, check, install, and confirm custom parsers for Sophos NG-SIEM in Sophos Fusion.',
  subcommands: {
    samples: {
      summary: 'Sample lines: "samples add <file>", "samples mask <raw> --out <file>", "samples from-tenant --where <QL>"',
      args: 'add <file> | mask <file> | from-tenant',
      minPositionals: 1,
      options: {
        workspace: { type: 'string', help: 'add, from-tenant: the workspace folder (default: a new one under the state folder)' },
        label: { type: 'string', help: 'add, from-tenant: a short note saved with the workspace' },
        raw: { type: 'boolean', help: 'add: keep the lines unmasked (the user opts out of masking)' },
        out: { type: 'string', help: 'mask: the file to write' },
        where: { type: 'string', help: 'from-tenant: the QL condition for the source\'s records, such as "sensor_type = \'Acme\'"' },
        from: { type: 'string', default: 'generic', help: 'from-tenant: the schema to search (default generic)' },
        earliest: { type: 'string', default: '-24h', help: 'from-tenant: how far back (default -24h)' },
        max: { type: 'string', default: '200', help: 'from-tenant: most lines to keep (default 200)' },
      },
      notes: `
add copies the lines to a private workspace (folder 0700, files 0600) and writes a masked copy
beside them. Read only masked.log. Nothing prints a sample value.
mask masks a file on its own. from-tenant runs a Data Lake search (read-only) and saves each
record's original_data the same way.`,
      run: async (ctx, args, [action, file]) => {
        if (action === 'add') {
          if (!file) throw new UsageError('samples add needs the file of sample lines.');
          const added = addToWorkspace(readSampleFile(file), { workspace: args.workspace, env: ctx.env, label: args.label ?? null });
          if (args.raw) fs.copyFileSync(added.raw, added.masked);
          const lines = sampleLines(fs.readFileSync(added.masked, 'utf8'));
          return { ...added, format: analyse(lines).format, masked: args.raw ? false : true, ...(args.raw ? { maskedValues: {}, warning: 'Unmasked: masked.log is a copy of raw.log, as the user asked.' } : {}), next: `Read ${added.masked}, then: parser.mjs scaffold --samples ${added.masked} --vendor <v> --product <p> --out <dir>` };
        }
        if (action === 'mask') {
          if (!file || !args.out) throw new UsageError('samples mask needs the file and --out.');
          assertPrivatePath(path.dirname(path.resolve(args.out)), 'The output folder');
          const r = maskText(readSampleFile(file));
          fs.writeFileSync(args.out, r.text, { mode: 0o600 });
          return { out: args.out, lines: sampleLines(r.text).length, maskedValues: r.counts, warnings: r.warnings };
        }
        if (action === 'from-tenant') {
          if (!args.where) throw new UsageError('samples from-tenant needs --where with the QL condition for the source.');
          const max = intArg(args.max, '--max', { min: 1, max: 1000 });
          const schema = schemaFromQlName(args.from) || (SCHEMA_IDS.includes(args.from) ? args.from : null);
          if (!schema) throw new UsageError(`--from ${args.from} is not a schema.`);
          const text = `from ${qlName(schema)} where (${args.where})${qlTime({ earliest: args.earliest })}`;
          const res = await searchRows(ctx.client, text, { max });
          const lines = res.rows.map((r) => r.original_data).filter((x) => typeof x === 'string' && x.trim());
          if (!lines.length) return { ok: false, query: text, records: res.rows.length, error: { code: 'no_records', message: 'The search found no records with original_data. Check the condition and the time range.' } };
          const added = addToWorkspace(lines.join('\n'), { workspace: args.workspace, env: ctx.env, label: args.label ?? `from-tenant ${args.from}` });
          return { query: text, records: res.rows.length, partial: res.partial, ...added, format: analyse(sampleLines(fs.readFileSync(added.masked, 'utf8'))).format };
        }
        throw new UsageError('samples takes add, mask or from-tenant.');
      },
    },
    scaffold: {
      summary: "A first draft from masked samples, with the library's generator, in the library's folder layout",
      options: {
        samples: { type: 'string', required: true, help: 'The masked sample file (masked.log)' },
        vendor: { type: 'string', required: true, help: 'Vendor name, for example "Acme"' },
        product: { type: 'string', required: true, help: 'Product name, for example "Firewall"' },
        out: { type: 'string', required: true, help: 'The parser folder to write' },
        schema: { type: 'string', help: 'Schema for a standalone parser, for example scwx.auth (default: the generator picks)' },
      },
      run: async (ctx, args) => {
        if (path.basename(args.samples) === 'raw.log') throw new UsageError('Give the masked copy (masked.log), not raw.log.');
        if (args.schema && !SCHEMA_IDS.includes(args.schema)) throw new UsageError(`--schema must be one of ${SCHEMA_IDS.join(', ')}.`);
        const out = path.resolve(args.out);
        if (fs.existsSync(path.join(out, 'meta.json'))) throw new UsageError(`${args.out} already has a meta.json. Pick a new folder.`);
        assertPrivatePath(out, 'The parser folder (its samples.log holds your masked lines)');
        const lines = sampleLines(readSampleFile(args.samples));
        if (!lines.length) throw new UsageError(`${args.samples} has no lines.`);
        const analysis = analyse(lines);
        const plan = buildPlan(analysis, { vendor: args.vendor, product: args.product }, args.schema ? { __single: args.schema } : {});
        if (args.schema) for (const u of plan.units) if (!u.schema || u.schema === GENERIC) u.schema = args.schema;
        const parsers = writeParsers(plan, lines);
        const parentName = parsers.find((p) => p.role === 'parent')?.name;
        const meta = {
          vendor: args.vendor,
          product: args.product,
          versions: [],
          format: LIBRARY_FORMATS.has(analysis.format) ? analysis.format : 'other',
          ship_method: 'syslog',
          reference_time: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
          parsers: parsers.map((p) => ({ name: p.name, file: `${p.name}.parser.txt`, role: p.role, ...(p.role === 'child' ? { parent: parentName } : {}), schema: p.schema })),
        };
        fs.mkdirSync(out, { recursive: true, mode: 0o700 });
        writeJson(path.join(out, 'meta.json'), meta);
        for (const p of parsers) fs.writeFileSync(path.join(out, `${p.name}.parser.txt`), p.text);
        fs.writeFileSync(path.join(out, 'samples.log'), `${lines.join('\n')}\n`, { mode: 0o600 });
        const folder = P.loadParserFolder(out);
        const results = P.emulate(folder);
        writeJson(path.join(out, 'expected.json'), expectedFrom(results));
        const children = folder.parsers.filter((p) => p.role === 'child').map((p) => p.name);
        return {
          folder: out,
          format: meta.format,
          parsers: parserReport(folder),
          notes: analysis.notes || [],
          next: [
            `Edit the parsers with references/syntax.md, then: parser.mjs check ${args.out}`,
            ...(children.length ? [`Write test-confirms.json: a PATTERN regex for each child (${children.join(', ')}) that matches the lines it takes. check proves it.`] : []),
          ],
        };
      },
    },
    check: {
      summary: 'Offline: lint, run on samples.log, compare expected.json, and report schema, path and fields per line',
      args: '<folder>',
      minPositionals: 1,
      options: { strict: { type: 'boolean', help: 'Treat warnings as failures' } },
      run: async (ctx, args, [dir]) => {
        const folder = P.loadParserFolder(dir);
        const r = P.checkFolder(folder, { strict: args.strict });
        for (const p of r.problems.filter((x) => x.level === 'error' || x.level === 'warning')) log(`${p.level === 'error' ? 'ERROR' : 'warn '} ${p.message}`);
        return { ok: r.ok, folder: folder.dir, parsers: parserReport(folder), errors: r.errors, warnings: r.warnings, problems: r.problems, summary: r.summary, expected: r.expected, lines: r.lines };
      },
    },
    expected: {
      summary: "Write expected.json from the emulator's output (read the diff after)",
      args: '<folder>',
      minPositionals: 1,
      run: async (ctx, args, [dir]) => {
        const folder = P.loadParserFolder(dir);
        const results = P.emulate(folder);
        writeJson(path.join(folder.dir, 'expected.json'), expectedFrom(results));
        return { folder: folder.dir, lines: results.length, normalized: results.filter((r) => r.normalized).length, errors: results.filter((r) => r.error).length };
      },
    },
    'tenant-check': {
      summary: "Read-only, in the tenant's engine: schemas, name clashes, validateParser, built-in claims, and every line engine against emulator",
      args: '<folder>',
      minPositionals: 1,
      options: {
        ...SHOW_VALUES,
        library: { type: 'string', help: 'A local clone of the library, to name entries that already claim these lines' },
        retries: { type: 'string', default: '3', help: 'How many more times to run a line another parser took (default 3)' },
      },
      notes: 'Nothing is saved: validateParser and sampleParser are reads. A pass is recorded for enable, which needs one on the same code within 24 hours.',
      run: async (ctx, args, [dir]) => {
        const folder = P.loadParserFolder(dir);
        const r = await P.tenantCheck(ctx.client, folder, { retries: intArg(args.retries, '--retries', { min: 0, max: 10 }), library: args.library ?? null });
        const tenantId = await tenantOf(ctx);
        const scripts = Object.fromEntries(folder.parsers.map((p) => [p.name, P.sha256(p.text)]));
        if (r.ok) P.savePass('parsers', { tenantId, folder: folder.dir, scripts }, ctx.env);
        for (const p of r.problems) log(`${p.level === 'error' ? 'ERROR' : 'warn '} ${p.message}`);
        const lines = r.lines.map((l) => ({ ...l, differences: args['show-values'] ? l.differences : l.differences.map((d) => `${d.path} (${d.kind})`) }));
        return { ok: r.ok, tenant: await ctx.tenantSummary(), folder: folder.dir, errors: r.errors, warnings: r.warnings, problems: r.problems, schemas: r.schemas, existingParsers: r.existingParsers, clashes: r.clashes, validate: r.validate, builtIn: r.builtIn, library: r.library, differences: r.differences, lines, passRecorded: r.ok };
      },
    },
    list: {
      summary: 'List the tenant\'s custom parsers. Read-only',
      options: { search: { type: 'string', help: 'Only names containing this text' } },
      run: async (ctx, args) => {
        const q = args.search?.toLowerCase();
        const all = (await P.listParsers(ctx.client)).filter((p) => !q || p.name.toLowerCase().includes(q));
        return { count: all.length, items: all.map((p) => ({ id: p.id, name: p.name, parentId: p.parentId || null, disabled: p.disabled, overrideGlobal: p.overrideGlobal, inLedger: Boolean(findRecorded('parser', Number(p.id), ctx.env)) })) };
      },
    },
    show: {
      summary: 'Show one parser. Read-only',
      options: { id: { type: 'string', required: true, help: 'Parser ID' }, code: { type: 'boolean', help: 'Include its code' } },
      run: async (ctx, args) => {
        const p = await P.getParser(ctx.client, args.id).catch(() => null);
        if (!p) throw new SfsError(`No parser ${args.id} reads back. A deleted parser reads as an error, so check "parser.mjs list".`, { code: 'not_found' });
        return { parser: { id: p.id, name: p.name, parentId: p.parentId || null, disabled: p.disabled, overrideGlobal: p.overrideGlobal, codeSha256: P.sha256(p.code), ...(args.code ? { code: p.code } : {}) }, inLedger: Boolean(findRecorded('parser', Number(p.id), ctx.env)) };
      },
    },
    counts: {
      summary: 'Count custom parsers: all, enabled, ZZ test copies (before and after a test)',
      run: async (ctx) => {
        const all = await P.listParsers(ctx.client);
        return { tenant: await ctx.tenantSummary(), counts: { parsers: all.length, enabled: all.filter((p) => !p.disabled).length, testCopies: all.filter((p) => /^zz/i.test(p.name)).length } };
      },
    },
    install: {
      summary: 'Create each parser disabled, parent first, as a ZZTest_ copy, and make the live code equal the file',
      write: true,
      args: '<folder>',
      minPositionals: 1,
      options: { 'as-is': { type: 'boolean', help: 'Install under the real names, not as ZZTest_ copies' } },
      gateDescription: (args, [dir]) => `installing the parsers in ${dir}, disabled${args['as-is'] ? ', under their real names' : ', as ZZTest_ copies'}`,
      run: async (ctx, args, [dir]) => {
        const folder = P.loadParserFolder(dir);
        const offline = P.checkFolder(folder);
        if (offline.errors) return { ok: false, error: { code: 'check_failed', message: `${offline.errors} offline errors. Run parser.mjs check and fix them first.` }, problems: offline.problems.filter((p) => p.level === 'error') };
        const existing = await P.listParsers(ctx.client);
        const names = Object.fromEntries(folder.parsers.map((p) => [p.name, P.installedName(p.name, { asIs: args['as-is'] })]));
        for (const [local, name] of Object.entries(names)) {
          const clash = existing.find((x) => x.name === name);
          if (!clash) continue;
          const owned = findRecorded('parser', Number(clash.id), ctx.env);
          if (owned && owned.status === 'live') throw new UsageError(`${name} is already installed (parser ${clash.id}, in the ledger). Use update-code, or roll back first.`);
          throw new SfsError(`The tenant already has a parser named ${name} (${clash.id}) that these scripts did not create. Nothing was installed.`, { code: 'duplicate', details: { parser: local } });
        }
        const before = new Set(existing.map((x) => x.id));
        const ids = {};
        const installed = [];
        for (const p of installOrder(folder)) {
          const parentId = p.role === 'child' ? ids[p.parent] : 0;
          if (p.role === 'child' && !parentId) throw new SfsError(`${p.name}: its parent ${p.parent} was not installed.`, { code: 'no_parent' });
          try {
            const r = await installOne(ctx, folder, p, { name: names[p.name], parentId, before });
            ids[p.name] = r.id;
            installed.push(r);
          } catch (error) {
            return { ok: false, installed, error: { code: error.code || 'failed', message: error.message }, next: installed.length ? 'Roll back what was installed: ledger.mjs rollback --yes' : null };
          }
        }
        return { ok: installed.every((r) => r.ok), tenant: await ctx.tenantSummary(), installed, next: `Enable is its own step and approval: parser.mjs enable --id <id> --yes (parents first). ${ENABLE_NOTE}` };
      },
    },
    enable: {
      summary: 'Turn one parser on. Needs a passing tenant-check on the same code within 24 hours',
      write: true,
      options: { id: { type: 'string', required: true, help: 'Parser ID' } },
      gateDescription: (args) => `ENABLING parser ${args.id}. ${ENABLE_NOTE}`,
      run: async (ctx, args) => {
        const { entry, live } = await ownedParser(ctx, args.id);
        const liveSha = P.sha256(live.code);
        if (entry.detail?.sha256 && liveSha !== entry.detail.sha256) throw new UsageError(`Parser ${args.id}'s live code is not the code these scripts saved. Check it by hand.`);
        const localFile = entry.detail?.dir && entry.detail?.localName ? path.join(entry.detail.dir, `${entry.detail.localName}.parser.txt`) : null;
        if (localFile && fs.existsSync(localFile) && P.sha256(fs.readFileSync(localFile, 'utf8').replace(/\r\n?/g, '\n')) !== liveSha) {
          throw new UsageError(`The live code of parser ${args.id} differs from ${localFile}. Run tenant-check on the folder, then update-code, before enabling.`);
        }
        const pass = P.findParserPass(await tenantOf(ctx), liveSha, { env: ctx.env });
        if (!pass) throw new UsageError(`No passing tenant-check on this code in the last 24 hours. Run parser.mjs tenant-check ${entry.detail?.dir || '<folder>'} first.`);
        if (Number(live.parentId)) {
          const parent = await P.getParser(ctx.client, live.parentId).catch(() => null);
          if (!parent || parent.disabled) throw new UsageError(`Parser ${args.id} is a child of ${live.parentId}, which is ${parent ? 'disabled' : 'not readable'}. Enable the parent first.`);
        }
        if (!live.disabled) return { id: Number(args.id), name: live.name, enabled: true, note: 'Already enabled.' };
        await P.updateParser(ctx.client, args.id, { disabled: false });
        const back = await P.readParserUntil(ctx.client, args.id, (x) => x.disabled === false);
        updateDetail(entry.runId, entry.seq, { enabledAt: new Date().toISOString() }, ctx.env);
        return { ok: back.ok && back.value.code === live.code, id: Number(args.id), name: live.name, enabled: back.value?.disabled === false, codeUnchanged: back.value?.code === live.code, tenantCheckAt: pass.at, note: ENABLE_NOTE, next: `Confirm on real ingest: parser.mjs verify-ingest ${entry.detail?.dir || '<folder>'}` };
      },
    },
    disable: {
      summary: 'Turn one parser off. A parent goes off only after its children',
      write: true,
      options: { id: { type: 'string', required: true, help: 'Parser ID' } },
      gateDescription: (args) => `disabling parser ${args.id}`,
      run: async (ctx, args) => {
        const { live } = await ownedParser(ctx, args.id);
        const kids = (await P.listParsers(ctx.client)).filter((x) => Number(x.parentId) === Number(args.id) && !x.disabled);
        if (kids.length) throw new UsageError(`Parser ${args.id} has enabled children (${kids.map((k) => k.id).join(', ')}). Disable them first.`);
        if (live.disabled) return { id: Number(args.id), name: live.name, enabled: false, note: 'Already disabled.' };
        await P.updateParser(ctx.client, args.id, { disabled: true });
        const back = await P.readParserUntil(ctx.client, args.id, (x) => x.disabled === true);
        return { ok: back.ok, id: Number(args.id), name: live.name, enabled: back.value ? !back.value.disabled : null };
      },
    },
    'update-code': {
      summary: 'Send a parser\'s code from the folder again. Ledger-owned and disabled parsers only',
      write: true,
      args: '<folder>',
      minPositionals: 1,
      options: { id: { type: 'string', required: true, help: 'Parser ID' } },
      gateDescription: (args, [dir]) => `updating the code of parser ${args.id} from ${dir}`,
      run: async (ctx, args, [dir]) => {
        const { entry, live } = await ownedParser(ctx, args.id);
        if (!live.disabled) throw new UsageError(`Parser ${args.id} is enabled. Code changes take effect at once on an enabled parser, so disable it first.`);
        const folder = P.loadParserFolder(dir);
        const local = folder.parsers.find((p) => p.name === entry.detail?.localName) || folder.parsers.find((p) => P.installedName(p.name) === live.name || p.name === live.name);
        if (!local) throw new UsageError(`${dir} has no parser that matches ${live.name}.`);
        const offline = P.checkFolder(folder);
        if (offline.errors) return { ok: false, error: { code: 'check_failed', message: `${offline.errors} offline errors. Fix them first.` } };
        await P.updateParser(ctx.client, args.id, { code: local.text });
        const back = await P.readParserUntil(ctx.client, args.id, (x) => x.code === local.text);
        if (back.ok) updateDetail(entry.runId, entry.seq, { sha256: P.sha256(local.text), dir: folder.dir, localName: local.name }, ctx.env);
        return { ok: back.ok, id: Number(args.id), name: live.name, codeMatches: back.ok, disabled: back.value?.disabled ?? null, next: 'Run tenant-check on the folder again before enabling.' };
      },
    },
    'verify-ingest': {
      summary: "Data Lake: find real records the installed parsers made, rerun the folder's parsers on each raw line, compare fields",
      args: '<folder>',
      minPositionals: 1,
      options: {
        ...SHOW_VALUES,
        earliest: { type: 'string', default: '-1h', help: 'How far back to search (default -1h)' },
        wait: { type: 'string', default: '30m', help: 'How long to wait for records (default 30m; 0 for one search)' },
        max: { type: 'string', default: '1000', help: 'Most records to read (default 1000)' },
        'source-where': { type: 'string', help: "QL condition for the source's records, to count the ones still in generic" },
        'as-is': { type: 'boolean', help: 'The parsers were installed under their real names' },
        interval: { type: 'string', default: '60', help: 'Seconds between searches while waiting (default 60)' },
      },
      run: async (ctx, args, [dir]) => {
        const folder = P.loadParserFolder(dir);
        const max = intArg(args.max, '--max', { min: 1, max: 10_000 });
        const waitMs = args.wait === '0' ? 0 : durationMs(args.wait);
        if (waitMs === null) throw new UsageError('--wait takes a time such as 30m or 0.');
        const owned = liveObjects(ctx.env).filter((o) => o.kind === 'parser' && o.detail?.dir === folder.dir);
        const installed = Object.fromEntries(folder.parsers.map((p) => [p.name, owned.find((o) => o.detail.localName === p.name)?.name || P.installedName(p.name, { asIs: args['as-is'] })]));
        const localOf = Object.fromEntries(Object.entries(installed).map(([l, n]) => [n, l]));
        const schemas = [...new Set(folder.parsers.map((p) => p.schema))];
        // One search per schema: a search over several schemas returns only the columns they share (lab, 22/11/2026).
        const where = Object.values(installed).map((n) => `normalizer_revision contains ${qlString(n)}`).join(' or ');
        const queries = schemas.map((s) => `from ${qlName(s)} where ${where}${qlTime({ earliest: args.earliest })}`);
        const needs = folder.parsers.filter((p) => p.schema !== GENERIC).map((p) => installed[p.name]);
        const started = Date.now();
        let res;
        let made;
        for (;;) {
          const parts = [];
          for (const q of queries) parts.push(await searchRows(ctx.client, q, { max }));
          res = { rows: parts.flatMap((x) => x.rows), capped: parts.some((x) => x.capped), partial: parts.some((x) => x.partial) };
          made = {};
          for (const row of res.rows) {
            const last = P.lastParser(row.normalizer_revision);
            if (localOf[last]) made[last] = (made[last] || 0) + 1;
          }
          if (needs.every((n) => made[n]) || Date.now() - started >= waitMs) break;
          log(`Records so far: ${JSON.stringify(made)}. Searching again in ${args.interval} s.`);
          await new Promise((r) => setTimeout(r, intArg(args.interval, '--interval', { min: 1, max: 600 }) * 1000));
        }
        const fields = {};
        let compared = 0;
        let routeDiffer = 0;
        let notYetActive = 0;
        for (const row of res.rows) {
          if (typeof row.original_data !== 'string' || !row.original_data) continue;
          const realPath = String(row.normalizer_revision || '').split(/\s*->\s*/).map((n) => localOf[n]).filter(Boolean);
          const schema = schemaFromQlName(row.schema_type) || folder.parsers.find((p) => p.name === realPath[realPath.length - 1])?.schema || GENERIC;
          const usec = Number(row.ingest_time_usec);
          const now = usec > 0 ? new Date(Math.floor(usec / 1000)).toISOString() : undefined;
          const [emu] = P.emulate(folder, [row.original_data], { now });
          const emuPath = (emu.extractor_path || '').split(' > ').filter(Boolean);
          if (emuPath.join('>') !== realPath.join('>')) {
            // A child takes lines a few minutes after it goes on, so a record its parent made alone is not a difference.
            if (realPath.length < emuPath.length && realPath.every((n, i) => emuPath[i] === n)) notYetActive++;
            else routeDiffer++;
            continue;
          }
          const emuRecord = P.firstSchema(emu.schema) === schema ? emu.normalized : (emu.also || []).find((a) => a.schema === schema)?.normalized ?? null;
          compared++;
          for (const d of P.compareRecords(emuRecord, row, schema, { emulatorNowUsec: usec || null, engineIngestUsec: usec || null, schemaFieldsOnly: true })) {
            const k = `${d.path} (${d.kind})`;
            fields[k] ??= { count: 0, ...(args['show-values'] ? { example: { emulator: d.emulator, real: d.engine } } : {}) };
            fields[k].count++;
          }
        }
        let generic = null;
        if (args['source-where']) {
          const g = await searchRows(ctx.client, `from generic where (${args['source-where']})${qlTime({ earliest: args.earliest })}`, { max: 10_000 });
          generic = { stillGeneric: g.rows.length, capped: g.capped };
        }
        const missing = needs.filter((n) => !made[n]);
        const unexplained = Object.values(fields).reduce((n, f) => n + f.count, 0);
        return {
          ok: missing.length === 0 && unexplained === 0 && routeDiffer === 0,
          tenant: await ctx.tenantSummary(),
          queries,
          waitedMs: Date.now() - started,
          records: res.rows.length,
          capped: res.capped,
          partial: res.partial,
          byParser: made,
          missing,
          compared,
          parserPathDiffers: routeDiffer,
          madeBeforeChildActive: notYetActive,
          differences: fields,
          ...(generic ? { generic } : {}),
          ...(missing.length ? { note: `No records yet from ${missing.join(', ')}. Normalization starts a few minutes after enable, and only for lines the source sends after that.` } : {}),
        };
      },
    },
    contribute: {
      summary: 'Opt-in: build a library entry from new synthetic samples, with the bundle for the issue form and the upload link',
      args: '<folder>',
      minPositionals: 1,
      options: {
        samples: { type: 'string', required: true, help: "Synthetic sample lines written from the vendor's public log format docs" },
        out: { type: 'string', required: true, help: 'Folder to write the entry and bundle to, outside any repository' },
        workspace: { type: 'string', multiple: true, help: 'Another sample workspace to compare against (repeatable). Workspaces under the state folder are always compared' },
      },
      notes: "Set author, license, docs, sample_source, summary and notes in the folder's meta.json first; the library's checks say what is missing. Nothing is posted.",
      run: async (ctx, args, [dir]) => {
        const r = contributeParser(dir, { samplesFile: args.samples, out: args.out, env: ctx.env, workspaces: args.workspace || [] });
        for (const p of r.problems || []) if (p.level === 'error') log(`ERROR ${p.message}`);
        return r;
      },
    },
  },
};

main(spec);
