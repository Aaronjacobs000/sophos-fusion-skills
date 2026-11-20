#!/usr/bin/env node
// Execution: run Generic Trigger instances with parameters (or a test event),
// watch runs, read logs, diagnose failures, cancel.
//
// Fusion's API runs only Generic Trigger instances. User Initiated instances
// answer REAUTH_REQUIRED, so they are tested through a Generic Trigger twin of
// the same template.

import fs from 'node:fs';
import { intArg, main } from '../../../lib/cli.mjs';
import { SfsError, UsageError, GraphQLError, MutationUnconfirmedError } from '../../../lib/errors.mjs';
import * as F from '../../../lib/fusion.mjs';
import { findLeaks } from '../../../lib/redact.mjs';
import { diagnose, logTask, templateMarkers, REAUTH_HELP } from '../../../lib/diagnose.mjs';
import { log } from '../../../lib/log.mjs';
import { sleep } from '../../../lib/retry.mjs';

function readJsonArg(value, label) {
  if (value === undefined) return undefined;
  const text = value.startsWith('@') ? fs.readFileSync(value.slice(1), 'utf8') : value;
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new UsageError(`${label} is not valid JSON: ${error.message}`);
  }
}

function seconds(value, label, { min = 1, max = 3600 } = {}) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < min || n > max) throw new UsageError(`${label} must be a number of seconds from ${min} to ${max}.`);
  return n;
}

async function watch(client, id, { timeoutSec = 300, intervalSec = 5 } = {}) {
  const deadline = Date.now() + timeoutSec * 1000;
  let last = null;
  for (;;) {
    last = await F.getExecution(client, id);
    if (last && F.TERMINAL_STATES.includes(last.state)) return { done: true, execution: last };
    if (Date.now() >= deadline) return { done: false, execution: last };
    await sleep(intervalSec * 1000);
  }
}

const spec = {
  name: 'run.mjs',
  summary: 'Run Generic Trigger playbook instances, watch them, read logs, and diagnose failures.',
  subcommands: {
    execute: {
      summary: 'Run a Generic Trigger instance with parameters (executePlaybookInstanceV2)',
      write: true,
      options: {
        instance: { type: 'string', required: true, help: 'Instance ID' },
        params: { type: 'string', help: 'Run parameters as JSON, or @file.json. They override the instance inputs' },
        event: { type: 'string', help: 'A test event (JSON or @file.json), merged into the parameters, for example {"case": {...}}' },
        'target-resource': { type: 'string', default: '', help: 'Target resource ID (default empty, which Fusion accepts)' },
        reason: { type: 'string', help: 'Reason recorded on the run' },
        watch: { type: 'boolean', help: 'Wait for the run to finish' },
        timeout: { type: 'string', default: '300', help: 'Seconds to wait with --watch (default 300)' },
      },
      gateDescription: (args) => `running playbook instance ${args.instance}`,
      run: async (ctx, args) => {
        const inst = await F.getInstance(ctx.client, args.instance);
        if (!inst) throw new SfsError('No instance with that ID.', { code: 'not_found' });
        const type = inst.trigger?.type?.name;
        if (type !== 'generic') {
          return { ok: false, instance: inst.id, trigger: type, error: { code: 'not_generic', message: `This instance's trigger is ${type === 'actions' ? 'User Initiated' : type}. ${REAUTH_HELP}` } };
        }
        if (!inst.enabled) {
          return { ok: false, instance: inst.id, enabled: false, error: { code: 'instance_disabled', message: `Fusion will not run a disabled instance (PB12). Instances are created disabled. A Generic Trigger instance runs only when someone starts it or a schedule fires, so enabling it is low risk: ask the user, then run deploy.mjs enable --instance ${inst.id} --yes, and disable it again afterwards.` } };
        }
        const parameters = { ...(readJsonArg(args.params, '--params') || {}), ...(readJsonArg(args.event, '--event') || {}) };
        const markers = templateMarkers(parameters);
        if (markers.length) {
          throw new UsageError(`Fusion evaluates run parameters as templates, so a value holding "\${" fails the run. Remove it from: ${markers.slice(0, 5).join(', ')}.`);
        }
        const leaks = findLeaks(parameters);
        if (leaks.length) throw new UsageError(`The parameters hold secret-looking values (${leaks.map((l) => l.path).join(', ')}). Fusion would keep them in the execution log permanently. Remove them.`);
        if (args.watch) seconds(args.timeout, '--timeout');
        let execution;
        try {
          execution = await F.executeInstance(ctx.client, { playbookInstanceId: inst.id, parameters, targetResource: args['target-resource'], ...(args.reason ? { reason: args.reason } : {}) });
        } catch (error) {
          if (error instanceof GraphQLError && /REAUTH/i.test(error.message)) {
            return { ok: false, instance: inst.id, error: { code: 'reauth_required', message: REAUTH_HELP } };
          }
          if (error instanceof MutationUnconfirmedError) {
            throw new SfsError(`${error.message} A run may have started. Check run.mjs list --instance ${inst.id} before starting another.`, { code: 'write_unconfirmed' });
          }
          throw error;
        }
        if (!execution?.id) {
          throw new SfsError(`Fusion answered the run request without an execution ID. A run may have started: check run.mjs list --instance ${inst.id} before starting another.`, { code: 'write_unconfirmed' });
        }
        log(`Started execution ${execution.id} (${execution.state}).`);
        const result = { instance: { id: inst.id, name: inst.name, enabled: inst.enabled }, execution: { id: execution.id, state: execution.state } };
        if (!args.watch) return { ...result, next: `run.mjs watch --execution ${execution.id}` };
        const w = await watch(ctx.client, execution.id, { timeoutSec: seconds(args.timeout, '--timeout') });
        return { ...result, ok: w.done, finished: w.done, execution: w.execution, next: `run.mjs logs --execution ${execution.id}` };
      },
    },
    watch: {
      summary: 'Poll a run until it finishes',
      options: {
        execution: { type: 'string', required: true, help: 'Execution ID' },
        timeout: { type: 'string', default: '300', help: 'Seconds to wait (default 300)' },
        interval: { type: 'string', default: '5', help: 'Seconds between polls (default 5)' },
      },
      run: async (ctx, args) => {
        const w = await watch(ctx.client, args.execution, { timeoutSec: seconds(args.timeout, '--timeout'), intervalSec: seconds(args.interval, '--interval', { min: 1, max: 300 }) });
        return { ok: w.done, finished: w.done, execution: w.execution };
      },
    },
    show: {
      summary: 'One run in full: inputs, outputs, and task events',
      options: { execution: { type: 'string', required: true, help: 'Execution ID' } },
      run: async (ctx, args) => {
        const e = await F.getExecutionSettled(ctx.client, args.execution, { full: true });
        if (!e) throw new SfsError('No execution with that ID.', { code: 'not_found' });
        return { execution: e };
      },
    },
    logs: {
      summary: 'Read the execution log, and flag secret-looking strings in it',
      options: {
        execution: { type: 'string', required: true, help: 'Execution ID' },
        raw: { type: 'boolean', help: 'Return the full log entries, not the summary' },
      },
      run: async (ctx, args) => {
        const logs = await F.executionLogs(ctx.client, args.execution);
        const leaks = findLeaks(logs);
        return { execution: args.execution, entries: logs.length, secretLooking: leaks, ...(args.raw ? { logs } : { tasks: logs.map(logTask) }) };
      },
    },
    list: {
      summary: 'Recent runs of an instance',
      options: {
        instance: { type: 'string', help: 'Instance ID (default: all instances)' },
        first: { type: 'string', default: '20', help: 'How many (default 20)' },
      },
      run: async (ctx, args) => {
        const r = await F.listExecutions(ctx.client, { instanceId: args.instance, first: intArg(args.first, '--first') });
        return { total: r.totalCount, executions: r.playbookExecutions };
      },
    },
    diagnose: {
      summary: 'Explain a run: silent UNKNOWN outcomes, missing connections, CEL errors, REAUTH, secrets in logs',
      options: { execution: { type: 'string', required: true, help: 'Execution ID' } },
      run: async (ctx, args) => {
        const e = await F.getExecutionSettled(ctx.client, args.execution, { full: true });
        const logs = e ? await F.executionLogs(ctx.client, args.execution) : [];
        const failedEvents = (e?.events || []).filter((ev) => ['Failed', 'TimedOut', 'Canceled'].includes(ev.state)).map((ev) => ({ name: ev.name, state: ev.state, reason: ev.reason }));
        return { execution: e ? { id: e.id, state: e.state, outcomeStatus: e.outcomeStatus, outcomeMessage: e.outcomeMessage } : null, failedTasks: failedEvents, findings: diagnose(e, logs) };
      },
    },
    cancel: {
      summary: 'Cancel a run that is still going',
      write: true,
      options: { execution: { type: 'string', required: true, help: 'Execution ID' }, reason: { type: 'string', default: 'Cancelled from the execution skill', help: 'Reason' } },
      gateDescription: (args) => `cancelling execution ${args.execution}`,
      run: async (ctx, args) => {
        const r = await F.cancelExecutions(ctx.client, [args.execution], args.reason);
        const back = await F.pollUntil(async () => {
          const e = await F.getExecution(ctx.client, args.execution);
          return e && F.TERMINAL_STATES.includes(e.state) ? e : null;
        });
        return { ok: back.ok, cancelled: r, state: back.value?.state ?? null };
      },
    },
  },
};

main(spec);
