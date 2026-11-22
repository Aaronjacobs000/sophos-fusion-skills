#!/usr/bin/env node
// An automatic case rule for a detection rule set: scaffold, offline checks, install in Test state
// (import and one more save by default), Rule Logs, and Test or Enabled as their own steps.
//
// Every write needs --yes (and --production on a production profile), is recorded in the ledger the
// moment Sophos returns an ID, and is read back. Rollback is "ledger.mjs rollback" in the deployment
// skill: the case rule, then its template, then the detection rules.

import fs from 'node:fs';
import path from 'node:path';
import { main } from '../../../lib/cli.mjs';
import { SfsError, UsageError } from '../../../lib/errors.mjs';
import { findRecorded, record } from '../../../lib/ledger.mjs';
import { log } from '../../../lib/log.mjs';
import { loadRuleFolder, parsedRules, readCaseRuleYaml, validateRuleEntry } from '../../../lib/detection-rules-check.mjs';
import * as C from '../../../lib/case-rules.mjs';
import { writeRuleEntry } from '../../../lib/contribute.mjs';
import { RULE_PATH, slug } from '../../../lib/xsl.mjs';

const ENABLE_NOTE = 'A case rule turned on takes the detections that already fit it, not only new ones: in a lab run it opened two cases within 6 seconds from earlier detections. Cases it opens are Managed By Self, and Sophos MDR does not work them.';

function loadCase(dir) {
  const entry = loadRuleFolder(dir);
  if (!entry.meta || entry.meta.kind !== 'case') throw new UsageError(`${dir} is not a case rule folder (meta.json kind case).`);
  return entry;
}

/** The detection rule set a case rule collects: --rules, else links.detection_rules as a folder or a library path's sibling. */
function detectionFor(entry, rulesArg) {
  const candidates = [];
  if (rulesArg) candidates.push(path.resolve(rulesArg));
  const link = entry.meta?.links?.detection_rules;
  if (typeof link === 'string') {
    candidates.push(path.resolve(entry.dir, link));
    if (RULE_PATH.test(link)) candidates.push(path.join(path.dirname(entry.dir), link.split('/').pop()));
  }
  for (const c of candidates) {
    if (fs.existsSync(path.join(c, 'rules.yaml'))) {
      const d = loadRuleFolder(c);
      return { label: path.relative(process.cwd(), c) || c, dir: c, rules: parsedRules(d) || [] };
    }
  }
  if (rulesArg) throw new UsageError(`${rulesArg} has no rules.yaml.`);
  return null;
}

/** A ledger-owned case rule, read live. */
async function ownedCaseRule(ctx, id) {
  const entry = findRecorded('caseRule', String(id), ctx.env);
  if (!entry || !['live', 'delete_failed'].includes(entry.status)) throw new UsageError(`Case rule ${id} is not in the ledger as live. These scripts change only case rules they created.`);
  const live = await C.getCaseRule(ctx.client, { id: String(id) });
  if (!live) throw new SfsError(`Case rule ${id} does not read back.`, { code: 'not_found' });
  if (live.name !== entry.name) throw new UsageError(`Case rule ${id} is now named "${live.name}", not "${entry.name}" as recorded. Check it by hand.`);
  return { entry, live };
}

async function setState(ctx, id, state) {
  const { live } = await ownedCaseRule(ctx, id);
  if (live.state === state) return { id: String(id), name: live.name, state, note: `Already ${state}.` };
  await C.updateCaseRule(ctx.client, { id: String(id), state });
  const back = await C.readUntil(() => C.getCaseRule(ctx.client, { id: String(id) }), (v) => v && v.state === state);
  return { ok: back.ok, id: String(id), name: live.name, state: back.value?.state ?? null, order: back.value?.order ?? null };
}

const RULES_OPT = { rules: { type: 'string', help: 'The detection rule set folder (default: links.detection_rules in meta.json)' } };

const spec = {
  name: 'case-rule.mjs',
  summary: 'An automatic case rule for custom detections: scaffold, check, install in Test state, Rule Logs, then Enabled.',
  subcommands: {
    scaffold: {
      summary: "Write a case rule and its template for a rule set's Medium and higher rules, grouped by one entity",
      options: {
        rules: { type: 'string', required: true, help: 'The detection rule set folder' },
        'group-by': { type: 'string', required: true, help: 'source-ip, host or user' },
        out: { type: 'string', required: true, help: 'The folder to write' },
        name: { type: 'string', help: 'Case rule name: letters, digits and underscores (default from the rule set title)' },
      },
      run: async (ctx, args) => {
        if (!C.GROUP_BY[args['group-by']]) throw new UsageError('--group-by must be source-ip, host or user.');
        const det = loadRuleFolder(args.rules);
        if (det.meta?.kind !== 'detection') throw new UsageError(`${args.rules} is not a detection rule set.`);
        const rules = parsedRules(det) || [];
        const what = { 'source-ip': 'source IP', host: 'host', user: 'user' }[args['group-by']];
        const name = args.name || `${slug(det.meta.title).replace(/-/g, '_')}_one_case_per_${args['group-by'].replace('-', '_')}`;
        if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(name)) throw new UsageError('--name takes letters, digits and underscores, starting with a letter.');
        const s = C.scaffoldCaseRule({ name, title: `${det.meta.title}, one case per ${what}`, rules, groupBy: args['group-by'], templateName: `${name}_template`, templateTitle: det.meta.title });
        const out = path.resolve(args.out);
        if (fs.existsSync(path.join(out, 'meta.json'))) throw new UsageError(`${args.out} already has a meta.json. Pick a new folder.`);
        fs.mkdirSync(out, { recursive: true });
        fs.writeFileSync(path.join(out, 'case-rule.yaml'), s.text);
        const meta = { kind: 'case', title: `${det.meta.title}: one case per ${what}`, vendor: det.meta.vendor, product: det.meta.product, parser: det.meta.parser, tested: { search: null, tenant: null }, links: { detection_rules: path.relative(out, path.resolve(args.rules)).split(path.sep).join('/') } };
        fs.writeFileSync(path.join(out, 'meta.json'), `${JSON.stringify(meta, null, 2)}\n`);
        return { folder: out, name, collects: s.titles, leftOut: rules.filter((r) => !s.titles.includes(r.name)).map((r) => `${r.name} (${r.severity}: case rules act on Medium and higher)`), next: `case-rule.mjs check ${args.out}` };
      },
    },
    check: {
      summary: "Offline: the filter takes only this set's custom detections, Medium and higher, group_by carries the rule's name, Test state, no assignee",
      args: '<folder>',
      minPositionals: 1,
      options: RULES_OPT,
      run: async (ctx, args, [dir]) => {
        const entry = loadCase(dir);
        const r = validateRuleEntry(entry, { detection: detectionFor(entry, args.rules) });
        for (const p of r.problems) log(`${p.level === 'error' ? 'ERROR' : 'warn '} ${p.message}`);
        return { ok: r.ok, folder: entry.dir, errors: r.problems.filter((p) => p.level === 'error').length, warnings: r.problems.filter((p) => p.level === 'warning').length, problems: r.problems, caseRule: r.caseRule ? { name: r.caseRule.rule.name, state: r.caseRule.rule.state, collects: r.caseRule.titles, template: r.caseRule.template.name } : null };
      },
    },
    install: {
      summary: 'Install the case rule and its template in Test state (default: import, then one more save), as ZZTest_ copies',
      write: true,
      args: '<folder>',
      minPositionals: 1,
      options: {
        ...RULES_OPT,
        method: { type: 'string', default: 'import', help: 'import (default: import, then save once more with updateCaseRule) or create (import the template, then createCaseRule after the last rule)' },
        'as-is': { type: 'boolean', help: 'Install under the real names, collecting the real rule names, not the ZZ Test copies' },
      },
      gateDescription: (args, [dir]) => `installing the case rule in ${dir} in Test state${args['as-is'] ? ', under its real name' : ', as a ZZTest_ copy'}`,
      run: async (ctx, args, [dir]) => {
        if (!['import', 'create'].includes(args.method)) throw new UsageError('--method is import or create.');
        const entry = loadCase(dir);
        const check = validateRuleEntry(entry, { detection: detectionFor(entry, args.rules) });
        if (!check.ok) return { ok: false, error: { code: 'check_failed', message: 'The offline check failed. Run case-rule.mjs check and fix it first.' }, problems: check.problems.filter((p) => p.level === 'error') };
        const original = entry.files.find((f) => f.path === 'case-rule.yaml').content;
        const copy = args['as-is'] ? { text: original, ...readCaseRuleYaml(original) } : C.makeTestCopy(original);
        const { rule, template } = copy;
        const before = await C.listCaseRules(ctx.client);
        const clash = before.find((r) => r.name === rule.name);
        if (clash) throw new SfsError(`The tenant already has a case rule named ${rule.name} (order ${clash.order}, ${clash.state}). Nothing was installed.`, { code: 'duplicate' });
        if (await C.getCaseTemplate(ctx.client, { name: template.name })) throw new SfsError(`The tenant already has a case template named ${template.name}. Nothing was installed.`, { code: 'duplicate' });
        const target = await ctx.session.target();
        const rec = (kind, obj, parentId = null) => record({ kind, id: String(obj.id), name: obj.name, tenantId: target.tenantId, profile: ctx.profile.name, parentId, detail: { dir: entry.dir } }, { runId: ctx.args['run-id'], env: ctx.env });
        const last = before.reduce((m, r) => Math.max(m, r.order || 0), 0);
        const steps = [];
        let tpl;
        let made;
        if (args.method === 'import') {
          const res = await C.importYaml(ctx.client, copy.text);
          steps.push('imported case-rule.yaml');
          tpl = res.find((x) => /Template/.test(x.__typename) && x.name === template.name) || (await C.readUntil(() => C.getCaseTemplate(ctx.client, { name: template.name }), (v) => v && v.id)).value;
          if (tpl?.id) rec('caseTemplate', tpl);
          const imported = res.find((x) => /Rule/.test(x.__typename) && x.name === rule.name) || null;
          if (imported?.id) rec('caseRule', imported, tpl?.id ? String(tpl.id) : null);
          const read = await C.readUntil(() => C.getCaseRule(ctx.client, { name: rule.name }), (v) => v && v.id);
          if (!read.ok) return { ok: false, steps, error: { code: 'not_found', message: `The import answered, but no case rule named ${rule.name} reads back. Roll back with ledger.mjs rollback.` } };
          if (!imported?.id) rec('caseRule', read.value, tpl?.id ? String(tpl.id) : null);
          else if (imported.id !== read.value.id) return { ok: false, steps, error: { code: 'id_mismatch', message: `The import answered with case rule ${imported.id}, but ${rule.name} reads back as ${read.value.id}. Check both by hand before rolling back.` } };
          // An imported rule opened no case until it was saved once more (lab T3b to T3f, 21/11 to 22/11/2026).
          made = await C.updateCaseRule(ctx.client, C.resaveInput(read.value));
          steps.push('saved once more with updateCaseRule, with no change');
        } else {
          await C.importYaml(ctx.client, C.templateText(copy.text), 'case-template.yaml');
          const t = await C.readUntil(() => C.getCaseTemplate(ctx.client, { name: template.name }), (v) => v && v.id);
          if (!t.ok) return { ok: false, steps, error: { code: 'not_found', message: `The import answered, but no case template named ${template.name} reads back.` } };
          tpl = t.value;
          rec('caseTemplate', tpl);
          steps.push('imported the template');
          made = await C.createCaseRule(ctx.client, C.createInput(rule, tpl.id, last + 1));
          if (made?.id) rec('caseRule', made, String(tpl.id));
          steps.push(`created the rule with createCaseRule at order ${last + 1}`);
        }
        const back = await C.readUntil(() => C.getCaseRule(ctx.client, { id: String(made.id) }), (v) => v && v.id === made.id && v.template?.name === template.name);
        const after = await C.listCaseRules(ctx.client);
        const moved = C.movedRules(before, after);
        const v = back.value;
        return {
          ok: back.ok && v.state === rule.state && moved.length === 0,
          tenant: await ctx.tenantSummary(),
          method: args.method,
          caseRule: { id: v?.id ?? made.id, name: rule.name, state: v?.state ?? null, order: v?.order ?? null, template: v?.template?.name ?? null, collects: check.caseRule.titles.map((t) => (args['as-is'] ? t : `${C.TEST_TITLE_PREFIX}${t}`)) },
          template: { id: tpl?.id ?? null, name: template.name },
          steps,
          movedOtherRules: moved,
          next: `Read its Rule Logs: case-rule.mjs logs --id ${v?.id ?? made.id}. Enabled is its own step: case-rule.mjs enable --id <id> --yes. ${ENABLE_NOTE}`,
        };
      },
    },
    enable: {
      summary: 'Set a case rule to Enabled, so it opens cases',
      write: true,
      options: { id: { type: 'string', required: true, help: 'Case rule ID' } },
      gateDescription: (args) => `ENABLING case rule ${args.id}. ${ENABLE_NOTE}`,
      run: async (ctx, args) => ({ ...(await setState(ctx, args.id, 'ENABLED')), note: ENABLE_NOTE }),
    },
    'test-state': {
      summary: 'Set a case rule back to Test state, so it only writes Rule Logs',
      write: true,
      options: { id: { type: 'string', required: true, help: 'Case rule ID' } },
      gateDescription: (args) => `setting case rule ${args.id} to Test state`,
      run: async (ctx, args) => setState(ctx, args.id, 'TEST'),
    },
    logs: {
      summary: "A case rule's Rule Logs: what it did, or would have done in Test state. Read-only",
      options: { id: { type: 'string', required: true, help: 'Case rule ID' }, since: { type: 'string', help: 'Only entries from this ISO time' } },
      run: async (ctx, args) => {
        const l = await C.ruleLogs(ctx.client, String(args.id), { since: args.since ?? null });
        const entries = l.entries.slice().sort((a, b) => String(a.created_at).localeCompare(String(b.created_at)));
        return { id: String(args.id), total: l.totalCount, entries: entries.map((e) => ({ at: e.created_at, level: e.level, event: e.event, case: e.investigation || null, detection: e.alert || null, message: typeof e.message === 'object' ? e.message?.message ?? e.message : e.message })) };
      },
    },
    list: {
      summary: "List the tenant's case rules in order. Read-only",
      run: async (ctx) => {
        const all = await C.listCaseRules(ctx.client);
        return { count: all.length, items: all.sort((a, b) => a.order - b.order).map((r) => ({ id: r.id, name: r.name, order: r.order, state: r.state, template: r.template?.name, inLedger: Boolean(findRecorded('caseRule', String(r.id), ctx.env)) })) };
      },
    },
    counts: {
      summary: 'Count case rules and case templates (before and after a test). Read-only',
      run: async (ctx) => {
        const rules = await C.listCaseRules(ctx.client);
        const templates = await C.listCaseTemplates(ctx.client);
        return { tenant: await ctx.tenantSummary(), counts: { caseRules: rules.length, caseTemplates: templates.length, testCopies: rules.filter((r) => /^zz/i.test(r.name)).length + templates.filter((t) => /^zz/i.test(t.name)).length } };
      },
    },
    contribute: {
      summary: 'Opt-in: build a library case entry folder, and the upload link',
      args: '<folder>',
      minPositionals: 1,
      options: { ...RULES_OPT, out: { type: 'string', required: true, help: 'Folder to write the entry to, outside any repository' } },
      notes: 'meta.json links.detection_rules must be the library path of the detection entry, which goes in first. Nothing is posted.',
      run: async (ctx, args, [dir]) => {
        const entry = loadCase(dir);
        const r = validateRuleEntry(entry, { detection: detectionFor(entry, args.rules), library: true });
        if (!r.ok) return { ok: false, problems: r.problems };
        const files = entry.files.filter((f) => ['meta.json', 'case-rule.yaml', 'README.md'].includes(f.path));
        return { ok: true, problems: r.problems, ...writeRuleEntry(entry.id, files, args.out), note: 'Nothing was posted. The library reviews every rule entry by hand.' };
      },
    },
  },
};

main(spec);
