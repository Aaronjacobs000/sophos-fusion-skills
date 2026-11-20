#!/usr/bin/env node
// Live smoke test against a real Sophos Fusion tenant. Never runs in CI.
//
//   node tools/live-smoke.mjs --profile lab --level read
//   node tools/live-smoke.mjs --profile lab --level read --roundtrip --yes
//   node tools/live-smoke.mjs --profile lab --level full --yes
//
// read:      self-test, catalog reads, tenant DSL check of every example, CEL cases. No writes.
// roundtrip: adds one test-copy import, export-and-diff, and rollback.
// full:      the whole cycle: test-copy imports of every example, a disabled instance,
//            one lookup-only run, a paused schedule, a disabled platform instance and its
//            filter, a connector test against a public API, rollback, and counts before
//            and after.
//
// Only a profile marked test is accepted. Writes need --yes. It drives the real
// CLI scripts, so it tests what the skills run.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { selectProfile } from '../lib/profiles.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const S = (skill, script) => path.join(ROOT, 'skills', skill, 'scripts', script);
const PROFILE_SCRIPT = S('setup', 'profile.mjs');
const CATALOG = S('authoring', 'catalog.mjs');
const VALIDATE = S('validation', 'validate.mjs');
const DEPLOY = S('deployment', 'deploy.mjs');
const LEDGER = S('deployment', 'ledger.mjs');
const RUN = S('execution', 'run.mjs');
const CONNECTOR = S('connectors', 'connector.mjs');
const EX = (p) => path.join(ROOT, 'examples', p);

const { values: args } = parseArgs({
  options: {
    profile: { type: 'string' },
    tenant: { type: 'string' },
    level: { type: 'string', default: 'read' },
    roundtrip: { type: 'boolean' },
    yes: { type: 'boolean' },
    out: { type: 'string' },
    help: { type: 'boolean', short: 'h' },
  },
});

if (args.help) {
  process.stdout.write(fs.readFileSync(fileURLToPath(import.meta.url), 'utf8').split('\n').slice(1, 17).map((l) => l.replace(/^\/\/ ?/, '')).join('\n') + '\n');
  process.exit(0);
}

const steps = [];
const common = [...(args.profile ? ['--profile', args.profile] : []), ...(args.tenant ? ['--tenant', args.tenant] : [])];

function sh(script, argv, { write = false } = {}) {
  const full = [script, ...argv, ...common, ...(write ? ['--yes'] : []), '--quiet'];
  const r = spawnSync(process.execPath, full, { encoding: 'utf8', env: process.env, cwd: ROOT, timeout: 600_000 });
  let json = null;
  try {
    json = JSON.parse(r.stdout);
  } catch {
    json = { ok: false, error: { message: (r.stderr || r.stdout || '').slice(0, 500) } };
  }
  return { status: r.status, json };
}

function step(name, operations, script, argv, opts = {}, check = (j) => j.ok) {
  process.stderr.write(`- ${name} ... `);
  const r = sh(script, argv, opts);
  let ok = false;
  try {
    ok = Boolean(check(r.json));
  } catch {
    ok = false;
  }
  const entry = { step: name, operations, ok, exit: r.status, ...(ok ? {} : { error: r.json?.error?.message ?? 'check failed' }) };
  steps.push(entry);
  process.stderr.write(`${ok ? 'ok' : 'FAILED'}\n`);
  return { ...r, ok };
}

function finish(extra = {}) {
  const failed = steps.filter((s) => !s.ok);
  const report = { ok: failed.length === 0, level: args.level, roundtrip: Boolean(args.roundtrip), at: new Date().toISOString(), passed: steps.length - failed.length, failed: failed.length, steps, ...extra };
  if (args.out) fs.writeFileSync(args.out, `${JSON.stringify(report, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.ok ? 0 : 1;
}

// ---------------------------------------------------------------- guards

const profile = selectProfile({ name: args.profile });
if (profile.kind !== 'test') {
  process.stderr.write(`Profile "${profile.name}" is marked ${profile.kind}. The smoke test runs only on a profile marked test.\n`);
  process.exit(3);
}
const writes = args.level === 'full' || args.roundtrip;
if (writes && !args.yes) {
  process.stderr.write('This run writes test copies to the tenant and removes them again. Re-run with --yes once that is approved.\n');
  process.exit(3);
}
if (!['read', 'full'].includes(args.level)) {
  process.stderr.write('--level must be read or full.\n');
  process.exit(2);
}

// ---------------------------------------------------------------- read level

const self = step('self-test (token, whoami, counts, permissions)', ['oauth2 token', 'whoami', 'playbooks, connectors, connections, playbookInstances, playbookSchedules', 'authzPermissions'], PROFILE_SCRIPT, ['test'], {}, (j) => j.ok && j.steps.every((s) => s.ok));
const tenant = self.json?.target ?? null;
if (!self.ok) {
  finish({ tenant });
  process.exit();
}

step('catalog: connector search', ['connectorsSearch'], CATALOG, ['connectors', '--search', 'add a comment to a case', '--limit', '3'], {}, (j) => j.ok && j.results.length > 0);
step('catalog: connector detail', ['connector', 'connectorVersions'], CATALOG, ['connector', '--name', 'Taegis.Case', '--action', 'addComment'], {}, (j) => j.ok && j.actions.length === 1);
step('catalog: trigger types', ['playbookTriggerTypesV2'], CATALOG, ['triggers'], {}, (j) => j.ok && j.platform.sources.some((s) => s.source === 'case'));
step('catalog: case event shape', ['playbookTriggerTypesV2 definitions'], CATALOG, ['event-shape', '--source', 'case'], {}, (j) => j.ok && j.inputsKey === 'case');
step('catalog: CEL functions', ['suggestExpression'], CATALOG, ['functions', '--search', 'caseShort'], {}, (j) => j.ok && j.count >= 1);
step('catalog: interfaces', ['playbookInterfaces'], CATALOG, ['interfaces'], {}, (j) => j.ok && j.count > 0);
step('catalog: User Initiated actions', ['playbookActionsV2'], CATALOG, ['actions'], {}, (j) => j.ok);
step('catalog: templates', ['playbooks'], CATALOG, ['templates', '--search', 'Lookup'], {}, (j) => j.ok && j.count > 0);

const PLAYBOOKS = ['case-reference-lookup', 'closed-case-detection-note', 'case-ip-threat-feed-block'];
for (const p of PLAYBOOKS) {
  step(`tenant DSL check: ${p}`, ['connectorVersions', 'playbookVersion', 'playbookValidateDSLV2'], VALIDATE, ['tenant', EX(`playbooks/${p}/template.yaml`)], {}, (j) => j.ok && j.errors === 0);
  step(`CEL cases: ${p}`, ['evaluateExpr (one per case)'], VALIDATE, ['cel', EX(`playbooks/${p}/cel-cases.json`)], {}, (j) => j.ok && j.failed === 0);
}

if (!writes) {
  finish({ tenant });
  process.exit();
}

// ---------------------------------------------------------------- writes

const before = step('counts before', ['playbooks, connectors, connections, playbookInstances, playbookSchedules'], DEPLOY, ['counts']).json?.counts;
const run = step('ledger: start run', [], LEDGER, ['start', '--label', `live smoke ${args.level}`], {}, (j) => j.ok && j.started?.id).json?.started?.id;
const R = ['--run-id', run];

if (args.level === 'read' && args.roundtrip) {
  step('import test copy: case-reference-lookup', ['importPlaybookV2', 'playbook (read back)', 'playbookExport (diff)'], DEPLOY, ['import', EX('playbooks/case-reference-lookup/template.yaml'), ...R], { write: true }, (j) => j.ok && j.readBack.found && j.diff.matches);
  step('diff against the tenant copy', ['playbookExport'], DEPLOY, ['diff', EX('playbooks/case-reference-lookup/template.yaml')], {}, (j) => j.ok && j.matches);
} else {
  const lookup = step('import test copy: case-reference-lookup', ['importPlaybookV2', 'playbook (read back)', 'playbookExport (diff)'], DEPLOY, ['import', EX('playbooks/case-reference-lookup/template.yaml'), ...R], { write: true }, (j) => j.ok && j.readBack.found && j.diff.matches);
  step('import test copy: closed-case-detection-note', ['importPlaybookV2', 'playbook (read back)', 'playbookExport (diff)'], DEPLOY, ['import', EX('playbooks/closed-case-detection-note/template.yaml'), ...R], { write: true }, (j) => j.ok && j.readBack.found && j.diff.matches);
  step('import test copy: case-ip-threat-feed-block', ['importPlaybookV2', 'playbook (read back)', 'playbookExport (diff)'], DEPLOY, ['import', EX('playbooks/case-ip-threat-feed-block/template.yaml'), ...R], { write: true }, (j) => j.ok && j.readBack.found && j.diff.matches);
  step('duplicate check sees the copy', ['playbooks'], DEPLOY, ['check', EX('playbooks/case-reference-lookup/template.yaml')], {}, (j) => j.ok && j.verdict === 'same_version_exists');

  if (lookup.ok) {
    const inst = step('disabled Generic Trigger instance: lookup', ['playbookTriggerTypesV2', 'playbookExport', 'connections', 'createPlaybookInstance', 'playbookInstance (read back)'], DEPLOY, ['instance-create', '--template', 'ZZTest_CaseReferenceLookup', '--name', 'ZZ Test case reference lookup', '--trigger', 'generic', ...R], { write: true }, (j) => j.ok && j.instance.enabled === false);
    const id = inst.json?.instance?.id;
    if (id) {
      step('a disabled instance is not run', ['playbookInstance'], RUN, ['execute', '--instance', id], { write: true }, (j) => j.ok === false && j.error.code === 'instance_disabled');
      step('a schedule needs an enabled instance', ['playbookInstance'], DEPLOY, ['schedule-create', '--instance', id, '--name', 'ZZ Test weekly lookup', '--cron', '0 7 * * 1', ...R], { write: true }, (j) => j.ok === false && j.error.code === 'instance_disabled');
      step('enable the Generic Trigger instance', ['updatePlaybookInstanceV2', 'playbookInstance (read back)'], DEPLOY, ['enable', '--instance', id], { write: true }, (j) => j.ok && j.enabled === true);
      step('paused schedule on the instance', ['createPlaybookSchedule', 'playbookSchedules (read back)'], DEPLOY, ['schedule-create', '--instance', id, '--name', 'ZZ Test weekly lookup', '--cron', '0 7 * * 1', '--time-zone', 'UTC', ...R], { write: true }, (j) => j.ok && j.schedule.paused === true);
      const ex = step('run the lookup and watch it', ['playbookInstance', 'executePlaybookInstanceV2', 'playbookExecution (poll)'], RUN, ['execute', '--instance', id, '--params', '{"include_automation_verdicts": false}', '--watch', '--timeout', '240'], { write: true }, (j) => j.ok && j.execution.state === 'Completed' && j.execution.outcomeStatus === 'SUCCESS');
      const xid = ex.json?.execution?.id;
      steps[steps.length - 1].executionId = xid ?? null;
      if (xid) {
        const shown = step('run outputs (single-quoted literal kept)', ['playbookExecution'], RUN, ['show', '--execution', xid], {}, (j) => j.ok && j.execution.outputs.source === 'Fusion case reference data' && j.execution.outputs.closed_verdict_names.length > 0);
        if (shown.json?.execution?.eventsError) steps[steps.length - 1].note = `task events not readable: ${shown.json.execution.eventsError.slice(0, 200)}`;
        step('execution log, no secrets', ['playbookExecutionLogs'], RUN, ['logs', '--execution', xid], {}, (j) => j.ok && j.entries > 0 && j.secretLooking.length === 0);
        step('diagnosis', ['playbookExecution', 'playbookExecutionLogs'], RUN, ['diagnose', '--execution', xid], {}, (j) => j.ok && j.findings.some((f) => f.kind === 'ok'));
        step('list runs', ['playbookExecutionsV2'], RUN, ['list', '--instance', id], {}, (j) => j.ok && j.total >= 1);
      }
      step('disable the instance again', ['updatePlaybookInstanceV2', 'playbookInstance (read back)'], DEPLOY, ['disable', '--instance', id], { write: true }, (j) => j.ok && j.enabled === false);
    }
  }

  const filter = "casePrimaryStatusName(inputs) == 'closed' && (caseFieldChanged(inputs, 'primaryStatus.id') || caseFieldChanged(inputs, 'primaryStatusId'))";
  const pinst = step('disabled platform instance: case closed note', ['createPlaybookInstance', 'playbookInstance (read back)'], DEPLOY, ['instance-create', '--template', 'ZZTest_ClosedCaseDetectionNote', '--name', 'ZZ Test closed case note', '--trigger', 'platform', '--source', 'case', '--events', 'Update', '--filter', filter, ...R], { write: true }, (j) => j.ok && j.instance.enabled === false);
  const pid = pinst.json?.instance?.id;
  if (pid) {
    step('set its trigger filter', ['updatePlaybookInstanceV2', 'playbookInstance (read back)'], DEPLOY, ['set-filter', '--instance', pid, '--filter', `${filter} && casePrimaryVerdictName(inputs) != 'false_positive'`], { write: true }, (j) => j.ok && j.readBack.matches);
    step('a platform instance is not run through the API', ['playbookInstance'], RUN, ['execute', '--instance', pid], { write: true }, (j) => j.ok === false && ['not_generic', 'instance_disabled'].includes(j.error.code));
  }

  const conn = step('import test copy: FIRST EPSS connector', ['importConnector', 'connector (read back)', 'connectorExport (diff)'], DEPLOY, ['import', EX('connectors/first-epss/connector.yaml'), ...R], { write: true }, (j) => j.ok && j.readBack.found && j.diff.matches);
  if (conn.ok) {
    step('connection check (validate action)', ['validateConnectionInput'], VALIDATE, ['connection', '--connector', 'ZZTest_FirstEpss', '--auth-type', 'None'], { write: true }, (j) => j.ok && j.valid);
    const c = step('connection with no credentials', ['createConnection', 'connection (read back)'], DEPLOY, ['connection-create', '--connector', 'ZZTest_FirstEpss', '--name', 'ZZ Test FIRST EPSS', '--auth-type', 'None', ...R], { write: true }, (j) => j.ok);
    const cid = c.json?.connection?.id;
    if (cid) {
      step('connector action: getScores for a public CVE', ['executeConnectionAction'], CONNECTOR, ['test-action', '--connection', cid, '--action', 'getScores', '--inputs', '{"cves":["CVE-2021-44228"]}'], { write: true }, (j) => j.ok && j.result.outcome === 'success' && j.result.scores[0].cve === 'CVE-2021-44228');
      step('connector action from the local file: getScoresOnDate', ['verifyConnectorActionV2'], CONNECTOR, ['verify', EX('connectors/first-epss/connector.yaml'), '--connection', cid, '--action', 'getScoresOnDate', '--inputs', '{"cves":["CVE-2021-44228"],"date":"2026-11-01"}'], { write: true }, (j) => j.ok && j.result.outcome === 'success');
    }
  }
}

step('rollback plan', [], LEDGER, ['plan', '--run', run], {}, (j) => j.ok);
const rb = step('rollback (newest first, each delete read back)', ['deletePlaybookSchedule', 'deletePlaybookInstance', 'deleteConnection', 'deletePlaybook', 'deleteConnector', 'reads to confirm each is gone'], LEDGER, ['rollback', '--run', run], { write: true }, (j) => j.ok && j.remaining === 0);
const after = step('counts after', ['playbooks, connectors, connections, playbookInstances, playbookSchedules'], DEPLOY, ['counts']).json?.counts;
const ledger = step('ledger run is empty', [], LEDGER, ['show', '--run', run], {}, (j) => j.ok && j.live === 0).json;
const same = before && after && JSON.stringify(before) === JSON.stringify(after);
steps.push({ step: 'counts match', operations: [], ok: Boolean(same) });
finish({ tenant, runId: run, countsBefore: before, countsAfter: after, ledgerLive: ledger?.live ?? null, rollback: rb.json?.results?.map((r) => ({ kind: r.kind, name: r.name, result: r.result })) });
