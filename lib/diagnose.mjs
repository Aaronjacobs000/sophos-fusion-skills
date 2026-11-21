// Reading a finished run: what went wrong, in plain words.

import { findIdentifiers, findLeaks } from './redact.mjs';

/** Paths of strings holding "${", which Fusion would try to evaluate in run parameters. */
export function templateMarkers(value, path = '$', out = []) {
  if (typeof value === 'string' && value.includes('${')) out.push(path);
  else if (Array.isArray(value)) value.forEach((v, i) => templateMarkers(v, `${path}[${i}]`, out));
  else if (value && typeof value === 'object') for (const [k, v] of Object.entries(value)) templateMarkers(v, `${path}.${k}`, out);
  return out;
}

export const REAUTH_HELP =
  'Fusion only runs Generic Trigger instances through the API. A User Initiated instance answers REAUTH_REQUIRED, because it expects a signed-in person. To test the same template through the API: give the template a generic trigger hint (usage: other), create a second instance of it with --trigger generic (the test twin), keep dry_run on, and run that one with a test event in --event.';

/** One log entry's task name, completion, and error text. */
export function logTask(entry) {
  const m = entry?.message || {};
  const status = m.status && typeof m.status === 'object' ? m.status : {};
  return {
    taskID: entry?.taskID ?? null,
    parentID: entry?.parentID ?? null,
    name: m.task ?? null,
    type: m.taskType ?? null,
    completion: status.Completion ?? null,
    error: status.Error || m.error || null,
    optional: m.isOptional ?? null,
    noLog: m.noLog ?? null,
    createdAt: entry?.createdAt ?? null,
  };
}

/** Error text only: task errors, a failed run's outputs and reason, and failed events. */
function errorText(execution, logs) {
  const parts = [];
  for (const l of logs || []) {
    const t = logTask(l);
    if (t.error) parts.push(t.error);
    for (const s of Array.isArray(l?.statusLogs) ? l.statusLogs : []) {
      const st = s?.message?.status;
      if (st?.Error) parts.push(st.Error);
    }
  }
  if (execution?.state && execution.state !== 'Completed') {
    parts.push(typeof execution.outputs === 'string' ? execution.outputs : JSON.stringify(execution.outputs ?? ''));
    if (execution.reason) parts.push(execution.reason);
  }
  if (execution?.outcomeStatus === 'FAIL' && execution.outcomeMessage) parts.push(execution.outcomeMessage);
  for (const ev of execution?.events || []) if (ev?.reason && ['Failed', 'TimedOut', 'Canceled'].includes(ev.state)) parts.push(ev.reason);
  return parts.join('\n');
}

/** Plain-language reading of a finished run and its logs. The run may be null when only its log is left. */
export function diagnose(execution, logs) {
  const findings = [];
  if (!execution) {
    if (!logs?.length) return [{ kind: 'not_found', message: 'No execution with that ID.' }];
    findings.push({ kind: 'record_gone', message: 'Fusion no longer returns this run, as seen after its instance and template are deleted, but its log is still there. These findings come from the log alone.' });
  }
  const errors = errorText(execution, logs);
  const failedTasks = (logs || []).map(logTask).filter((t) => t.error || (t.completion && t.completion !== 'Success'));
  if (execution?.state === 'Completed' && (execution.outcomeStatus === 'UNKNOWN' || !execution.outcomeStatus)) {
    findings.push({ kind: 'silent_outcome', message: 'The run ended Completed with outcome UNKNOWN. Fusion marks a run Completed even when a step failed or answered "not found", so this often hides a failure. Check the failed tasks below, and give the template an outcomeStatus that reads the step results so failures show as FAIL.' });
  }
  if (execution?.outcomeStatus === 'FAIL') findings.push({ kind: 'outcome_fail', message: `The playbook reported FAIL: ${execution.outcomeMessage || 'no message'}.` });
  if (failedTasks.length) findings.push({ kind: 'failed_tasks', message: `${failedTasks.length} task(s) did not succeed.`, tasks: failedTasks.map((t) => ({ name: t.name, completion: t.completion, error: t.error, optional: t.optional })) });
  if (/no such key/i.test(errors)) findings.push({ kind: 'no_such_key', message: 'A step read a value that was not there ("no such key"). The usual cause: reading a task that was skipped by its condition, or a field the vendor did not return. Guard the read with has(task, \'outputs.x\') or task.?outputs.x.orValue(...). The offline validator flags these as ref.skipped.' });
  if (/undeclared reference/i.test(errors)) findings.push({ kind: 'undeclared_reference', message: 'A step read a name that does not exist at that point ("undeclared reference"), often a task inside a loop read from outside it, or a typo. The offline validator flags these as ref.undeclared and ref.nested.' });
  if (/Syntax error|mismatched input|extraneous input/i.test(errors)) findings.push({ kind: 'cel_syntax', message: 'A CEL expression did not parse. Run the offline validator; for literal text use YAML single quotes or a CEL string.' });
  if (/found no matching overload|type conversion error/i.test(errors)) findings.push({ kind: 'cel_type', message: 'A CEL function got the wrong type (for example a string where a number was expected). Convert explicitly with int(), double() or string().' });
  if (/connection (not found|is missing|required)|no connection|missing connection|credentials? (invalid|rejected|missing)|unauthori[sz]ed|\b40[13]\b/i.test(errors)) findings.push({ kind: 'connection', message: 'A connector call failed on its connection: missing, not bound to the instance, or its credentials were rejected. Check the instance\'s connections, and test the connection with the connectors skill.' });
  if (/REAUTH_REQUIRED/i.test(errors)) findings.push({ kind: 'reauth', message: REAUTH_HELP });
  if (/timed? ?out/i.test(errors) || execution?.state === 'TimedOut') findings.push({ kind: 'timeout', message: 'The run or a step timed out. Check the vendor is reachable from Fusion, and add retry to the action.' });
  if (execution?.state === 'PendingApproval') findings.push({ kind: 'pending_approval', message: 'The run is waiting for approval in the console.' });
  const leaks = findLeaks(logs);
  if (leaks.length) findings.push({ kind: 'secret_in_log', message: `The execution log holds ${leaks.length} secret-looking value(s). Fusion keeps logs permanently and they cannot be deleted: rotate the secret, and add nolog: true to the step that carried it.`, where: leaks.slice(0, 10) });
  if (!findings.length && execution?.state === 'Completed') findings.push({ kind: 'ok', message: `The run completed with outcome ${execution.outcomeStatus}, and every task succeeded.` });
  const ids = findIdentifiers(logs);
  if (ids.length) {
    const names = [...new Set(ids.map((i) => i.identifier))].join(' and ');
    findings.push({ kind: 'identifier_in_log', message: `The log holds the ${names} in ${ids.length} place(s). Fusion records the caller's ID on what it changes, for example as a case's creator or updater. It is an identifier, not a secret, so nothing needs rotating.`, where: ids.slice(0, 10) });
  }
  return findings;
}
