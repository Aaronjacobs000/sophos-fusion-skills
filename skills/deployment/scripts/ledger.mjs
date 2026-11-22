#!/usr/bin/env node
// The ledger of created objects, and rollback: delete a run's objects newest
// first, children before parents, and read back that each one is gone.

import { main } from '../../../lib/cli.mjs';
import { SfsError, UsageError } from '../../../lib/errors.mjs';
import { ledgerPath, liveObjects, markObject, readLedger, rollbackOrder, startRun } from '../../../lib/ledger.mjs';
import * as F from '../../../lib/fusion.mjs';
import { findParser, removeParser } from '../../../lib/parsers.mjs';
import { readLiveRule, removeRule } from '../../../lib/detection-rules.mjs';
import { deleteCaseRule, deleteCaseTemplate, getCaseRule, getCaseTemplate } from '../../../lib/case-rules.mjs';
import { log } from '../../../lib/log.mjs';
import { redactText } from '../../../lib/redact.mjs';

// How rollback reads and removes each kind. Parsers and detection rules go off before they are
// deleted. A parser counts as gone only when a parser list read without error lacks it: reading a
// deleted parser by ID answers "Internal server error", the same as a failed read.
const HANDLERS = {
  parser: {
    read: (client, id) => findParser(client, id),
    remove: async (client, id) => removeParser(client, id),
  },
  detectionRule: {
    read: (client, id) => readLiveRule(client, id),
    remove: async (client, id) => removeRule(client, id),
  },
  caseRule: {
    read: (client, id) => getCaseRule(client, { id: String(id) }),
    remove: async (client, id) => {
      await deleteCaseRule(client, String(id));
      return F.pollUntil(async () => !(await getCaseRule(client, { id: String(id) })));
    },
  },
  caseTemplate: {
    read: (client, id) => getCaseTemplate(client, { id: String(id) }),
    remove: async (client, id) => {
      await deleteCaseTemplate(client, String(id));
      return F.pollUntil(async () => !(await getCaseTemplate(client, { id: String(id) })));
    },
  },
};

const readAny = (client, kind, id) => (HANDLERS[kind] ? HANDLERS[kind].read(client, id) : F.readObject(client, kind, id));

async function removeAny(client, kind, id) {
  if (HANDLERS[kind]) return HANDLERS[kind].remove(client, id);
  await F.deleteObject(client, kind, id);
  return F.pollUntil(async () => !(await F.readObject(client, kind, id)));
}

function pickRun(ledger, runId) {
  const id = runId || ledger.currentRun;
  if (!id || !ledger.runs[id]) throw new UsageError(runId ? `No run ${runId} in the ledger.` : 'The ledger has no current run.');
  return ledger.runs[id];
}

const spec = {
  name: 'ledger.mjs',
  summary: 'Show the ledger of objects these scripts created, and roll a run back.',
  subcommands: {
    show: {
      summary: 'Show one run (default: the current run)',
      options: { run: { type: 'string', help: 'Run ID' } },
      run: async (ctx, args) => {
        const ledger = readLedger(ctx.env);
        if (!args.run && !ledger.currentRun) return { file: ledgerPath(ctx.env), currentRun: null, objects: [] };
        const run = pickRun(ledger, args.run);
        return { file: ledgerPath(ctx.env), currentRun: ledger.currentRun, run: run.id, label: run.label, startedAt: run.startedAt, objects: run.objects, live: run.objects.filter((o) => o.status !== 'deleted' && o.status !== 'gone').length };
      },
    },
    runs: {
      summary: 'List runs, with how many of their objects are still live',
      run: async (ctx) => {
        const ledger = readLedger(ctx.env);
        return {
          file: ledgerPath(ctx.env),
          currentRun: ledger.currentRun,
          runs: Object.values(ledger.runs).map((r) => ({ id: r.id, label: r.label, startedAt: r.startedAt, objects: r.objects.length, live: r.objects.filter((o) => o.status === 'live' || o.status === 'delete_failed').length })),
          liveTotal: liveObjects(ctx.env).length,
        };
      },
    },
    start: {
      summary: 'Start a new run; later creates are recorded under it',
      options: { label: { type: 'string', help: 'A short note, for example "EPSS connector test"' } },
      run: async (ctx, args) => ({ started: startRun({ label: args.label ?? null, env: ctx.env }) }),
    },
    plan: {
      summary: 'Show what rollback would delete, in order. Read-only',
      options: { run: { type: 'string', help: 'Run ID (default: the current run)' } },
      run: async (ctx, args) => {
        const run = pickRun(readLedger(ctx.env), args.run);
        return { run: run.id, order: rollbackOrder(run.objects).map((o) => ({ seq: o.seq, kind: o.kind, id: o.id, name: o.name, tenantId: o.tenantId })) };
      },
    },
    rollback: {
      summary: "Delete a run's live objects newest first, reading back each delete",
      write: true,
      options: { run: { type: 'string', help: 'Run ID (default: the current run)' } },
      gateDescription: (args) => `rolling back ${args.run || 'the current run'}: deleting every object it created`,
      run: async (ctx, args) => {
        const run = pickRun(readLedger(ctx.env), args.run);
        const target = await ctx.session.target();
        const order = rollbackOrder(run.objects);
        const elsewhere = order.filter((o) => o.tenantId && o.tenantId !== target.tenantId);
        if (elsewhere.length) {
          throw new SfsError(`This run created objects on another tenant (${[...new Set(elsewhere.map((o) => o.tenantId))].join(', ')}). Run rollback with the profile for that tenant.`, { code: 'wrong_tenant' });
        }
        const results = [];
        for (const o of order) {
          try {
            const before = await readAny(ctx.client, o.kind, o.id);
            if (!before) {
              markObject(run.id, o.seq, 'gone', 'not on the tenant at rollback', ctx.env);
              results.push({ seq: o.seq, kind: o.kind, name: o.name, result: 'already gone' });
              continue;
            }
            if (before.name && before.name !== o.name) {
              markObject(run.id, o.seq, 'delete_failed', `name changed to ${before.name}`, ctx.env);
              results.push({ seq: o.seq, kind: o.kind, name: o.name, result: 'skipped', reason: `Its name is now "${before.name}", not the recorded "${o.name}". Check it by hand.` });
              continue;
            }
            const gone = await removeAny(ctx.client, o.kind, o.id);
            markObject(run.id, o.seq, gone.ok ? 'deleted' : 'delete_failed', gone.ok ? null : 'still readable 30 s after delete', ctx.env);
            results.push({ seq: o.seq, kind: o.kind, name: o.name, result: gone.ok ? 'deleted' : 'still there', waitedMs: gone.waitedMs });
            log(`${gone.ok ? 'deleted' : 'NOT deleted'}: ${o.kind} ${o.name}`);
          } catch (error) {
            markObject(run.id, o.seq, 'delete_failed', redactText(error.message).slice(0, 200), ctx.env);
            results.push({ seq: o.seq, kind: o.kind, name: o.name, result: 'error', error: error.message });
          }
        }
        const failed = results.filter((r) => !['deleted', 'already gone'].includes(r.result));
        return { ok: failed.length === 0, run: run.id, tenant: { tenantId: target.tenantId, region: target.region }, results, remaining: failed.length };
      },
    },
  },
};

main(spec);
