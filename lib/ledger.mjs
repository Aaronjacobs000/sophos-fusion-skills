// The local ledger: every object the scripts create in a tenant, grouped by
// run. Rollback reads it to delete a run's objects newest first.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { SfsError } from './errors.mjs';
import { isWindowsBusy, replaceFile } from './fsx.mjs';

// Children before parents. Used to break ties and to keep rollback safe when
// objects were recorded out of order. A case rule goes before its template, and both before the
// detection rules it collects; a child parser before its parent follows parentId.
export const KIND_ORDER = ['execution', 'schedule', 'instance', 'connection', 'caseRule', 'caseTemplate', 'detectionRule', 'parser', 'playbookVersion', 'playbook', 'connectorVersion', 'connector'];

// Windows keeps per-user state in %LOCALAPPDATA%; macOS and Linux use the XDG state folder.
export function stateDir(env = process.env) {
  if (env.SOPHOS_FUSION_STATE_DIR) return env.SOPHOS_FUSION_STATE_DIR;
  const base = process.platform === 'win32'
    ? env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local')
    : env.XDG_STATE_HOME || path.join(os.homedir(), '.local', 'state');
  return path.join(base, 'sophos-fusion-skills');
}

export function ledgerPath(env = process.env) {
  return path.join(stateDir(env), 'ledger.json');
}

function empty() {
  return { version: 1, currentRun: null, runs: {} };
}

export function readLedger(env = process.env) {
  const file = ledgerPath(env);
  if (!fs.existsSync(file)) return empty();
  try {
    const data = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!data || typeof data.runs !== 'object') return empty();
    return data;
  } catch {
    throw new SfsError(`The ledger at ${file} is not valid JSON. Do not delete it: it lists objects that may still exist in a tenant. Repair it by hand.`, { code: 'bad_ledger' });
  }
}

export function writeLedger(ledger, env = process.env) {
  const dir = stateDir(env);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = ledgerPath(env);
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(ledger, null, 2)}\n`, { mode: 0o600 });
  replaceFile(tmp, file);
}

/**
 * Run fn while holding the ledger lock, so two scripts writing at once cannot
 * lose an entry. The lock is a folder (mkdir is atomic). A lock older than
 * 30 s is from a crashed script and is taken over.
 */
export function withLock(env, fn) {
  const dir = stateDir(env);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const lock = path.join(dir, 'ledger.lock');
  const wait = new Int32Array(new SharedArrayBuffer(4));
  const deadline = Date.now() + 10_000;
  let busySince = null;
  for (;;) {
    try {
      fs.mkdirSync(lock);
      break;
    } catch (error) {
      // On Windows a lock folder that was just removed can refuse a new one for a moment (EPERM).
      // A refusal that lasts is a real permission problem, so it is reported as itself.
      if (error.code !== 'EEXIST' && !isWindowsBusy(error)) throw error;
      if (error.code === 'EEXIST') {
        busySince = null;
      } else {
        busySince ??= Date.now();
        if (Date.now() - busySince > 2_000 && !fs.existsSync(lock)) throw error;
      }
      try {
        if (Date.now() - fs.statSync(lock).mtimeMs > 30_000) fs.rmSync(lock, { recursive: true, force: true });
      } catch {
        // another script just released or took it
      }
      if (Date.now() > deadline) throw new SfsError(`The ledger is locked (${lock}). If no other script is running, remove that folder.`, { code: 'ledger_locked' });
      Atomics.wait(wait, 0, 0, 50);
    }
  }
  try {
    return fn();
  } finally {
    fs.rmSync(lock, { recursive: true, force: true, maxRetries: 5, retryDelay: 20 });
  }
}

export function newRunId(now = new Date()) {
  const stamp = now.toISOString().replace(/[-:]/g, '').replace(/\..*$/, '').replace('T', '-');
  return `run-${stamp}-${crypto.randomBytes(2).toString('hex')}`;
}

export function startRun({ label = null, env = process.env } = {}) {
  return withLock(env, () => {
    const ledger = readLedger(env);
    const id = newRunId();
    ledger.runs[id] = { id, label, startedAt: new Date().toISOString(), objects: [] };
    ledger.currentRun = id;
    writeLedger(ledger, env);
    return ledger.runs[id];
  });
}

/** The run to record into: the given ID, else the current run, else a new one. */
export function resolveRun(runId, env = process.env) {
  const id = withLock(env, () => {
    const ledger = readLedger(env);
    if (runId) {
      if (!ledger.runs[runId]) {
        ledger.runs[runId] = { id: runId, label: null, startedAt: new Date().toISOString(), objects: [] };
        writeLedger(ledger, env);
      }
      return runId;
    }
    return ledger.currentRun && ledger.runs[ledger.currentRun] ? ledger.currentRun : null;
  });
  return id ?? startRun({ env }).id;
}

/** Record one created object. Called right after the create returns its ID. */
export function record(entry, { runId, env = process.env } = {}) {
  const id = resolveRun(runId, env);
  return withLock(env, () => {
  const ledger = readLedger(env);
  const run = ledger.runs[id];
  const seq = run.objects.reduce((m, o) => Math.max(m, o.seq), 0) + 1;
  const obj = {
    seq,
    kind: entry.kind,
    id: entry.id,
    name: entry.name,
    tenantId: entry.tenantId,
    profile: entry.profile,
    parentId: entry.parentId ?? null,
    createdAt: new Date().toISOString(),
    status: 'live',
    // What a later step checks against, such as the sha256 of the code a parser was saved with.
    ...(entry.detail ? { detail: entry.detail } : {}),
  };
  if (!KIND_ORDER.includes(obj.kind)) throw new SfsError(`Unknown ledger kind ${obj.kind}.`, { code: 'internal' });
  run.objects.push(obj);
  writeLedger(ledger, env);
  return { runId: id, ...obj };
  });
}

export function markObject(runId, seq, status, note, env = process.env) {
  withLock(env, () => {
    const ledger = readLedger(env);
    const obj = ledger.runs[runId]?.objects.find((o) => o.seq === seq);
    if (!obj) return;
    obj.status = status;
    obj.updatedAt = new Date().toISOString();
    if (note) obj.note = note;
    writeLedger(ledger, env);
  });
}

/** Objects still live in a run, in the order rollback deletes them. */
export function rollbackOrder(objects) {
  // Newest first, ties broken children-before-parents by kind.
  const remaining = objects
    .filter((o) => o.status === 'live' || o.status === 'delete_failed')
    .slice()
    .sort((a, b) => (b.seq !== a.seq ? b.seq - a.seq : KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind)));
  // Then make sure no object goes before a child that names it as parent,
  // whatever order they were recorded in.
  const out = [];
  while (remaining.length) {
    const i = remaining.findIndex((o) => !remaining.some((c) => c !== o && c.parentId && c.parentId === o.id));
    out.push(...remaining.splice(i === -1 ? 0 : i, 1));
  }
  return out;
}

export function liveObjects(env = process.env) {
  const ledger = readLedger(env);
  return Object.values(ledger.runs).flatMap((r) => r.objects.filter((o) => o.status === 'live' || o.status === 'delete_failed').map((o) => ({ runId: r.id, ...o })));
}

export function isRecorded(kind, id, env = process.env) {
  const ledger = readLedger(env);
  return Object.values(ledger.runs).some((r) => r.objects.some((o) => o.kind === kind && o.id === id));
}

/** The newest ledger entry for an object, with its run ID, or null. IDs compare as text. */
export function findRecorded(kind, id, env = process.env) {
  const ledger = readLedger(env);
  let hit = null;
  for (const r of Object.values(ledger.runs)) {
    for (const o of r.objects) if (o.kind === kind && String(o.id) === String(id)) hit = { runId: r.id, ...o };
  }
  return hit;
}

/** Merge fields into an entry's detail, for example after a parser's code is updated. */
export function updateDetail(runId, seq, detail, env = process.env) {
  withLock(env, () => {
    const ledger = readLedger(env);
    const obj = ledger.runs[runId]?.objects.find((o) => o.seq === seq);
    if (!obj) return;
    obj.detail = { ...(obj.detail || {}), ...detail };
    obj.updatedAt = new Date().toISOString();
    writeLedger(ledger, env);
  });
}
