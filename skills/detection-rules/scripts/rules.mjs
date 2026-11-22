#!/usr/bin/env node
// Custom detection rules for a custom parser's records: scaffold, offline checks on the parser's own
// samples, read-only tenant checks (validateQLFilter and Sophos's own rule coverage), a Data Lake
// search test with a volume estimate, then installs (off, ZZ Test copies by default), enable as its
// own step, and the detections each rule made.
//
// Every write needs --yes (and --production on a production profile), is recorded in the ledger the
// moment Sophos returns an ID, and is read back. Rollback is "ledger.mjs rollback" in the deployment
// skill.

import fs from 'node:fs';
import path from 'node:path';
import { main } from '../../../lib/cli.mjs';
import { MutationUnconfirmedError, SfsError, UsageError } from '../../../lib/errors.mjs';
import { findRecorded, record } from '../../../lib/ledger.mjs';
import { log } from '../../../lib/log.mjs';
import { pollUntil } from '../../../lib/fusion.mjs';
import { TEST_DISPLAY_PREFIX } from '../../../lib/constants.mjs';
import { defAt, emulate, firstSchema, loadParserFolder, recordSummary } from '../../../lib/parsers.mjs';
import { durationMs } from '../../../lib/search.mjs';
import { folderSensorTypes, loadRuleFolder, parsedRules, validateRuleEntry } from '../../../lib/detection-rules-check.mjs';
import * as R from '../../../lib/detection-rules.mjs';
import { writeRuleEntry } from '../../../lib/contribute.mjs';
import { enumMembers, GENERIC, qlName, slug, typeKind } from '../../../lib/xsl.mjs';

const VOLUME_NOTE = `Sophos turns a rule off above ${R.SOPHOS_LIMITS.perHour.toLocaleString('en-US')} detections an hour or ${R.SOPHOS_LIMITS.perDay.toLocaleString('en-US')} a day.`;
const ENABLE_NOTE = `An enabled rule makes a detection for every matching event, and detections can't be deleted. Custom detections are yours to work: Sophos MDR doesn't work them. ${VOLUME_NOTE}`;

function loadDetection(dir) {
  const entry = loadRuleFolder(dir);
  if (!entry.meta || entry.meta.kind !== 'detection') throw new UsageError(`${dir} is not a detection rule set (meta.json kind detection). Case rules use case-rule.mjs.`);
  return entry;
}

function rulesOf(entry) {
  const rules = parsedRules(entry);
  if (!rules || !rules.length) throw new UsageError(`${entry.dir}/rules.yaml has no rules that read. Run rules.mjs check.`);
  return rules;
}

/** A ledger-owned rule, read live. Refuses anything these scripts didn't create. */
async function ownedRule(ctx, id) {
  const entry = findRecorded('detectionRule', String(id), ctx.env);
  if (!entry || !['live', 'delete_failed'].includes(entry.status)) throw new UsageError(`Rule ${id} is not in the ledger as live. These scripts change only rules they created.`);
  const live = await R.readLiveRule(ctx.client, id);
  if (!live) throw new SfsError(`Rule ${id} does not read back.`, { code: 'not_found' });
  if (live.name !== entry.name) throw new UsageError(`Rule ${id} is now named "${live.name}", not "${entry.name}" as recorded. Check it by hand.`);
  return { entry, live };
}

const spec = {
  name: 'rules.mjs',
  summary: "Build, check, search-test, install, and confirm custom detection rules on a custom parser's records.",
  subcommands: {
    scaffold: {
      summary: "Write a rule set folder for a parser folder: meta.json, rules.yaml and tests.json in the library's layout",
      options: {
        parser: { type: 'string', required: true, help: 'The parser folder whose records the rules read' },
        title: { type: 'string', required: true, help: 'The rule set title, for example "Acme firewall admin activity"' },
        out: { type: 'string', required: true, help: 'The folder to write' },
        schema: { type: 'string', help: 'The schema the rules read, when the parser writes more than one' },
      },
      run: async (ctx, args) => {
        const parser = loadParserFolder(args.parser);
        const results = emulate(parser);
        const schemas = [...new Set(results.map((r) => firstSchema(r.schema)).filter((s) => s !== GENERIC))];
        const schema = args.schema || (schemas.length === 1 ? schemas[0] : null);
        if (!schema) throw new UsageError(schemas.length ? `The parser writes ${schemas.join(', ')}. Pick one with --schema.` : 'No line reaches a schema other than generic in the emulator, so there is nothing for a rule to match.');
        const sensorTypes = [...folderSensorTypes(parser, schema, results)];
        const out = path.resolve(args.out);
        if (fs.existsSync(path.join(out, 'meta.json'))) throw new UsageError(`${args.out} already has a meta.json. Pick a new folder.`);
        fs.mkdirSync(out, { recursive: true });
        const meta = {
          kind: 'detection',
          title: args.title,
          vendor: parser.meta.vendor,
          product: parser.meta.product,
          parser: `parsers/${slug(parser.meta.vendor)}/${slug(parser.meta.product)}`,
          schema,
          sensor_types: sensorTypes,
          volume: '',
          tested: { search: null, tenant: null },
        };
        fs.writeFileSync(path.join(out, 'meta.json'), `${JSON.stringify(meta, null, 2)}\n`);
        fs.writeFileSync(path.join(out, 'rules.yaml'), `# ${args.title}: custom detection rules on ${schema} records with sensor type ${sensorTypes.join(' or ')}.\n# Each rule holds the Create Rule form's fields: name, description, severity, mitre, query and\n# enabled_by_default. The query pins the sensor type and adds a condition beyond it. See\n# references/ql.md, and "rules.mjs fields --parser ${args.parser}" for the fields the records set.\nrules: []\n`);
        fs.writeFileSync(path.join(out, 'tests.json'), `${JSON.stringify({ triggers: {}, quiet: parser.samples.map((_, i) => i + 1) }, null, 2)}\n`);
        return { folder: out, schema, sensorTypes, sampleLines: parser.samples.length, next: [`Fill in volume in meta.json and write the rules in rules.yaml, then: rules.mjs check ${args.out} --parser ${args.parser}`, 'In tests.json, move each line a rule must trigger from quiet to that rule under triggers.'] };
      },
    },
    fields: {
      summary: "The fields the parser's records set, with enum members, for writing queries. Read-only",
      options: { parser: { type: 'string', required: true, help: 'The parser folder' } },
      run: async (ctx, args) => {
        const parser = loadParserFolder(args.parser);
        const results = emulate(parser);
        const bySchema = {};
        for (const r of results) {
          const schema = firstSchema(r.schema);
          if (!r.normalized) continue;
          const s = (bySchema[schema] ??= { records: 0, sensorTypes: new Set(), fields: {} });
          s.records++;
          if (typeof r.normalized.sensor_type === 'string') s.sensorTypes.add(r.normalized.sensor_type);
          const sum = recordSummary(r.normalized, schema);
          for (const f of sum.fields) {
            const def = defAt(schema, f);
            const x = (s.fields[f] ??= { records: 0, type: def?.type ?? 'string', ...(def && typeKind(def.type) === 'enum' ? { enum: true, members: enumMembers(def.type), seen: new Set() } : {}) });
            x.records++;
            if (x.seen && sum.enums[f]) x.seen.add(sum.enums[f]);
          }
        }
        const out = Object.entries(bySchema).map(([schema, s]) => ({
          schema,
          qlName: qlName(schema),
          records: s.records,
          sensorTypes: [...s.sensorTypes],
          fields: Object.entries(s.fields).map(([field, x]) => ({ field, records: x.records, type: x.type, ...(x.enum ? { enum: true, members: x.members, seen: [...x.seen] } : {}) })),
        }));
        return { parser: parser.dir, schemas: out, note: "Compare an enum field with a member's name in quotes, such as severity = 'HIGH', never a number." };
      },
    },
    check: {
      summary: "Offline: parse each query, check fields, enums and regex, run the parser's samples through the rules, and hold tests.json",
      args: '<folder>',
      minPositionals: 1,
      options: { parser: { type: 'string', required: true, help: 'The parser folder whose records the rules read' } },
      run: async (ctx, args, [dir]) => {
        const entry = loadDetection(dir);
        const parser = loadParserFolder(args.parser);
        const r = validateRuleEntry(entry, { parser });
        for (const p of r.problems) log(`${p.level === 'error' ? 'ERROR' : 'warn '} ${p.file || ''}${p.line ? `:${p.line}` : ''} ${p.message}`);
        const hitLines = {};
        (r.hits || []).forEach((names, i) => names.forEach((n) => (hitLines[n] ??= []).push(i + 1)));
        return { ok: r.ok, folder: entry.dir, parser: parser.dir, errors: r.problems.filter((p) => p.level === 'error').length, warnings: r.problems.filter((p) => p.level === 'warning').length, problems: r.problems, rules: (r.rules || []).map((x) => ({ name: x.name, severity: x.severity, triggers: hitLines[x.name] || [] })) };
      },
    },
    'tenant-check': {
      summary: "Read-only: validateQLFilter on each query, and Sophos's own rules on the schema (named sensor types, shared techniques)",
      args: '<folder>',
      minPositionals: 1,
      run: async (ctx, args, [dir]) => {
        const entry = loadDetection(dir);
        const rules = rulesOf(entry);
        const problems = [];
        const validate = [];
        for (const r of rules) {
          const v = await R.validateQuery(ctx.client, r.query, entry.meta.schema);
          validate.push({ rule: r.name, ok: v.ok, eventType: v.eventType, errors: v.errors });
          for (const e of v.errors) problems.push({ level: 'error', code: 'validate', rule: r.name, message: `"${r.name}": validateQLFilter refused the query: ${e}` });
        }
        const coverage = R.coverageOf(await R.sophosRules(ctx.client, entry.meta.schema));
        problems.push(...R.coverageProblems(entry.meta, rules, coverage));
        for (const p of problems) log(`${p.level === 'error' ? 'ERROR' : 'warn '} ${p.message}`);
        const errors = problems.filter((p) => p.level === 'error').length;
        return { ok: errors === 0, tenant: await ctx.tenantSummary(), folder: entry.dir, errors, warnings: problems.length - errors, problems, validate, sophosCoverage: { schema: entry.meta.schema, rules: coverage.rules, anySensorRules: coverage.anySensorRules, anySensorTechniques: coverage.anySensorTechniques.length, namedSensorTypes: coverage.namedSensorTypes.length } };
      },
    },
    'search-test': {
      summary: 'Read-only: each query in Data Lake Search, against the rules run offline on every record of the sensor types; matches per day',
      args: '<folder>',
      minPositionals: 1,
      options: {
        earliest: { type: 'string', default: '-7d', help: 'How far back (default -7d)' },
        'show-values': { type: 'boolean', help: 'Also list the raw lines the search and the offline run disagree on. They can hold customer data' },
      },
      run: async (ctx, args, [dir]) => {
        const entry = loadDetection(dir);
        const rules = rulesOf(entry);
        const windowMs = durationMs(args.earliest);
        if (!windowMs) throw new UsageError('--earliest takes a relative time such as -7d or -24h.');
        const days = Math.max(1, Math.round(windowMs / 86400e3));
        const t = await R.searchTest(ctx.client, entry.meta, rules, { earliest: args.earliest, windowDays: days });
        const tenantId = (await ctx.session.target()).tenantId;
        const report = t.rules.map((r) => ({ name: r.name, search: r.search, offline: r.offline, onlySearch: r.onlySearch, onlyOffline: r.onlyOffline, perDay: r.perDay, busiestDay: r.volume.busiestDay, meanPerDay: r.volume.meanPerDay, overVolume: R.overVolume(r), capped: r.capped }));
        const nothing = t.records === 0;
        if (!nothing && t.agree) {
          for (const r of t.rules) R.saveSearchPass({ tenantId, rule: r.name, query: rules.find((x) => x.name === r.name).query, busiestDay: r.volume.busiestDay, meanPerDay: r.volume.meanPerDay, capped: r.capped, records: t.records }, ctx.env);
        } else if (nothing) {
          for (const r of rules) R.saveSearchPass({ tenantId, rule: r.name, query: r.query, busiestDay: 0, meanPerDay: 0, capped: false, records: 0 }, ctx.env);
        }
        const out = { ok: !nothing && t.agree, tenant: await ctx.tenantSummary(), folder: entry.dir, earliest: args.earliest, records: t.records, agree: t.agree, rules: report, universeCapped: t.universeCapped, queries: t.queries, limit: R.VOLUME_LIMIT, note: VOLUME_NOTE };
        if (nothing) out.error = { code: 'no_records', message: `No ${entry.meta.schema} records with sensor type ${entry.meta.sensor_types.join(' or ')} in ${args.earliest}, so there is nothing to test against. Get the parser on and ingesting first.` };
        else if (!t.agree) out.error = { code: 'disagree', message: 'Data Lake Search and the offline run differ for at least one rule. The engine is the authority: read the rule against references/ql.md.' };
        return out;
      },
    },
    install: {
      summary: 'Create each rule off, with createAlert on, as a "ZZ Test" copy, and read it back',
      write: true,
      args: '<folder>',
      minPositionals: 1,
      options: {
        parser: { type: 'string', required: true, help: 'The parser folder, for the offline check that runs first' },
        'as-is': { type: 'boolean', help: 'Install under the real names, not as ZZ Test copies' },
      },
      gateDescription: (args, [dir]) => `installing the detection rules in ${dir}, off${args['as-is'] ? ', under their real names' : ', as ZZ Test copies'}`,
      run: async (ctx, args, [dir]) => {
        const entry = loadDetection(dir);
        const check = validateRuleEntry(entry, { parser: loadParserFolder(args.parser) });
        if (!check.ok) return { ok: false, error: { code: 'check_failed', message: 'The offline check failed. Run rules.mjs check and fix it first.' }, problems: check.problems.filter((p) => p.level === 'error') };
        const rules = check.rules;
        const names = Object.fromEntries(rules.map((r) => [r.name, args['as-is'] ? r.name : `${TEST_DISPLAY_PREFIX}${r.name}`]));
        if (Object.values(names).some((n) => /claude/i.test(n))) throw new UsageError('Keep assistant names out of tenant object names.');
        const existing = (await R.listRules(ctx.client)).filter((r) => !r.deleted);
        for (const n of Object.values(names)) if (existing.some((x) => x.name === n)) throw new SfsError(`The tenant already has a rule named "${n}". Nothing was installed.`, { code: 'duplicate' });
        for (const r of rules) {
          const v = await R.validateQuery(ctx.client, r.query, entry.meta.schema);
          if (!v.ok) return { ok: false, error: { code: 'validate_failed', message: `validateQLFilter refused "${r.name}": ${v.errors.join('; ')}` } };
        }
        const target = await ctx.session.target();
        const before = new Set(existing.map((x) => x.id));
        const installed = [];
        for (const r of rules) {
          const name = names[r.name];
          let created;
          try {
            created = await R.createRule(ctx.client, R.ruleInput(r, { name, schemaId: entry.meta.schema }), r.query);
          } catch (error) {
            if (!(error instanceof MutationUnconfirmedError)) return { ok: false, installed, error: { code: error.code || 'failed', message: error.message }, next: installed.length ? 'Roll back what was installed: ledger.mjs rollback --yes' : null };
            log(`createCustomQLRule may or may not have happened (${error.failure}). Looking for a new rule named ${name}.`);
            const found = await pollUntil(async () => (await R.listRules(ctx.client)).find((x) => x.name === name && !x.deleted && !before.has(x.id)) ?? null);
            if (!found.ok) return { ok: false, installed, error: { code: 'write_unconfirmed', message: error.message } };
            created = found.value;
          }
          if (!created?.id) return { ok: false, installed, error: { code: 'no_id', message: `createCustomQLRule answered without an ID for "${name}". Check the tenant by name.` } };
          const led = record({ kind: 'detectionRule', id: String(created.id), name, tenantId: target.tenantId, profile: ctx.profile.name, detail: { dir: entry.dir, localName: r.name, query: r.query } }, { runId: ctx.args['run-id'], env: ctx.env });
          // The API stores the query with its whitespace collapsed, so the read-back compares it that way.
          const back = await pollUntil(async () => R.getRule(ctx.client, created.id));
          const v = back.value;
          const readBack = { found: back.ok, enabled: v?.enabled ?? null, createAlert: v?.createAlert ?? null, queryEqual: R.normalizeQuery(v?.qlFilter?.query) === R.normalizeQuery(r.query), severity: v ? Math.round(v.severity * 100) / 100 : null };
          installed.push({ id: String(created.id), name, local: r.name, severity: r.severity, ledger: { runId: led.runId, seq: led.seq }, readBack, ok: back.ok && v.enabled === false && v.createAlert === true && readBack.queryEqual });
        }
        return { ok: installed.every((x) => x.ok), tenant: await ctx.tenantSummary(), installed, next: `Each rule goes on separately: rules.mjs enable --id <id> --yes, after search-test. ${ENABLE_NOTE}` };
      },
    },
    enable: {
      summary: 'Turn one rule on. Needs a search-test of its query in the last 7 days under 1,000 matches a day',
      write: true,
      options: {
        id: { type: 'string', required: true, help: 'Rule ID' },
        'allow-volume': { type: 'boolean', help: 'Enable even when the search-test estimated more than 1,000 a day or found no records (the user accepts the volume)' },
      },
      gateDescription: (args) => `ENABLING detection rule ${args.id}. ${ENABLE_NOTE}`,
      run: async (ctx, args) => {
        const { live } = await ownedRule(ctx, args.id);
        const tenantId = (await ctx.session.target()).tenantId;
        const pass = R.findSearchPass(tenantId, live.qlFilter?.query, { env: ctx.env });
        if (!pass) throw new UsageError(`No search-test of this rule's query on this tenant in the last 7 days. Run rules.mjs search-test on its folder first.`);
        if (!args['allow-volume']) {
          if (!pass.records) throw new UsageError('The search-test found no records of the sensor type, so the volume is unknown. Add --allow-volume only if the user accepts that.');
          if (pass.capped || pass.busiestDay > R.VOLUME_LIMIT) throw new UsageError(`The search-test found up to ${pass.busiestDay}${pass.capped ? '+' : ''} matches a day, over ${R.VOLUME_LIMIT}. Tighten the query, or add --allow-volume if the user accepts it. ${VOLUME_NOTE}`);
        }
        if (live.enabled) return { id: String(args.id), name: live.name, enabled: true, note: 'Already enabled.' };
        await R.setRuleEnabled(ctx.client, args.id, true);
        const back = await pollUntil(async () => (await R.getRule(ctx.client, args.id))?.enabled === true);
        return { ok: back.ok, id: String(args.id), name: live.name, enabled: back.ok, searchTest: { at: pass.at, busiestDay: pass.busiestDay, records: pass.records }, note: ENABLE_NOTE, next: `See what it makes: rules.mjs detections --rule ${args.id}` };
      },
    },
    disable: {
      summary: 'Turn one rule off',
      write: true,
      options: { id: { type: 'string', required: true, help: 'Rule ID' } },
      gateDescription: (args) => `disabling detection rule ${args.id}`,
      run: async (ctx, args) => {
        const { live } = await ownedRule(ctx, args.id);
        if (!live.enabled) return { id: String(args.id), name: live.name, enabled: false, note: 'Already disabled.' };
        await R.setRuleEnabled(ctx.client, args.id, false);
        const back = await pollUntil(async () => (await R.getRule(ctx.client, args.id))?.enabled === false);
        return { ok: back.ok, id: String(args.id), name: live.name, enabled: !back.ok };
      },
    },
    detections: {
      summary: 'The detections a rule made (detection search). Read-only',
      options: {
        rule: { type: 'string', required: true, help: 'Rule ID' },
        earliest: { type: 'string', default: '-1h', help: 'How far back (default -1h)' },
      },
      run: async (ctx, args) => {
        const d = await R.detectionsOf(ctx.client, args.rule, { earliest: args.earliest });
        return {
          rule: String(args.rule),
          total: d.total,
          detections: d.list.map((x) => ({ id: x.id, title: x.metadata?.title, severity: x.metadata?.severity, createdAt: x.metadata?.created_at?.seconds ? new Date(Number(x.metadata.created_at.seconds) * 1000).toISOString() : null, detector: x.metadata?.creator?.detector?.detector_id, cases: (x.investigation_ids || []).map((i) => i.id) })),
        };
      },
    },
    list: {
      summary: "List the tenant's custom QL rules. Read-only",
      options: { search: { type: 'string', help: 'Only names containing this text' } },
      run: async (ctx, args) => {
        const q = args.search?.toLowerCase();
        const all = (await R.listRules(ctx.client)).filter((r) => !r.deleted && (!q || r.name.toLowerCase().includes(q)));
        return { count: all.length, items: all.map((r) => ({ id: r.id, name: r.name, enabled: r.enabled, eventType: r.eventType, severity: Math.round(r.severity * 100) / 100, createAlert: r.createAlert, inLedger: Boolean(findRecorded('detectionRule', String(r.id), ctx.env)) })) };
      },
    },
    show: {
      summary: 'Show one rule. Read-only',
      options: { id: { type: 'string', required: true, help: 'Rule ID' } },
      run: async (ctx, args) => {
        const r = await R.getRule(ctx.client, args.id);
        if (!r) throw new SfsError(`No rule ${args.id}.`, { code: 'not_found' });
        return { rule: { id: r.id, name: r.name, description: r.description, enabled: r.enabled, deleted: r.deleted, eventType: r.eventType, severity: r.severity, confidence: r.confidence, createAlert: r.createAlert, attackCategories: r.attackCategories, query: r.qlFilter?.query ?? null }, inLedger: Boolean(findRecorded('detectionRule', String(r.id), ctx.env)) };
      },
    },
    counts: {
      summary: 'Count custom rules (before and after a test). Read-only',
      run: async (ctx) => {
        const all = (await R.listRules(ctx.client)).filter((r) => !r.deleted);
        return { tenant: await ctx.tenantSummary(), counts: { rules: all.length, enabled: all.filter((r) => r.enabled).length, testCopies: all.filter((r) => /^zz/i.test(r.name)).length }, detailed: await R.rulesCount(ctx.client) };
      },
    },
    contribute: {
      summary: "Opt-in: build a library rule entry folder once the rules' parser is a library entry, and the upload link",
      args: '<folder>',
      minPositionals: 1,
      options: {
        'parser-entry': { type: 'string', required: true, help: "The library parser entry folder (from a library clone): tests.json lines point at its synthetic samples.log" },
        out: { type: 'string', required: true, help: 'Folder to write the entry to, outside any repository' },
      },
      notes: 'Rule entries have no issue form: upload the folder. The library labels every rule pull request "needs review" and never merges one on its own. Nothing is posted.',
      run: async (ctx, args, [dir]) => {
        const entry = loadDetection(dir);
        const parser = loadParserFolder(args['parser-entry']);
        if (!['synthetic', 'vendor-docs'].includes(parser.meta.sample_source)) throw new UsageError(`${args['parser-entry']} is not a library parser entry with synthetic samples (meta.sample_source). Contribute the parser first, in its own pull request.`);
        const want = `parsers/${slug(parser.meta.vendor)}/${slug(parser.meta.product)}`;
        if (entry.meta.parser !== want) throw new UsageError(`meta.json parser is ${entry.meta.parser}, but the parser entry is ${want}.`);
        const r = validateRuleEntry(entry, { parser, library: true });
        if (!r.ok) return { ok: false, problems: r.problems };
        const files = entry.files.filter((f) => ['meta.json', 'rules.yaml', 'tests.json', 'README.md'].includes(f.path));
        return { ok: true, problems: r.problems, ...writeRuleEntry(entry.id, files, args.out), note: 'Nothing was posted. The library reviews every rule entry by hand.' };
      },
    },
  },
};

main(spec);
