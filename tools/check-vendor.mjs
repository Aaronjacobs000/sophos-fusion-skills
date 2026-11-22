#!/usr/bin/env node
// Checks the vendored library files against the sha256 values in vendor/xdr-siem-library/VENDORED.md,
// and that nothing else sits in that folder.
//
//   node tools/check-vendor.mjs                      the hash check CI runs on every push
//   node tools/check-vendor.mjs --library <clone>    also compares the files with the clone's HEAD
//                                                    (the weekly drift job clones the library's main)
//
// Exit 0 when everything matches, 1 with a file list when it doesn't. Read-only.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { VENDOR_DIR, CORE_DIR, EXTRA_FILES, readVendored, sha256 } from './sync-library.mjs';

function walk(dir, base = dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, base, out);
    else out.push(path.relative(base, p).split(path.sep).join('/'));
  }
  return out;
}

/** Problems with the vendored copy as it is on disk: changed, missing and unlisted files. */
export function checkHashes(dir = VENDOR_DIR) {
  const problems = [];
  let listed;
  try {
    listed = readVendored(dir);
  } catch (error) {
    return { sha: null, files: 0, problems: [`VENDORED.md cannot be read: ${error.message}`] };
  }
  if (!listed.sha) problems.push('VENDORED.md names no commit');
  if (!listed.files.length) problems.push('VENDORED.md lists no files');
  for (const f of listed.files) {
    const p = path.join(dir, ...f.path.split('/'));
    if (!fs.existsSync(p)) problems.push(`${f.path}: missing`);
    else if (sha256(fs.readFileSync(p)) !== f.sha256) problems.push(`${f.path}: changed since the sync (its sha256 differs from VENDORED.md)`);
  }
  const names = new Set(listed.files.map((f) => f.path));
  for (const rel of walk(dir)) if (rel !== 'VENDORED.md' && !names.has(rel)) problems.push(`${rel}: not listed in VENDORED.md`);
  return { sha: listed.sha, files: listed.files.length, problems };
}

/** Differences between the vendored files and a library clone's HEAD (or another ref). */
export function checkDrift(clone, { dir = VENDOR_DIR, ref = 'HEAD' } = {}) {
  const git = (args) => spawnSync('git', ['-C', clone, ...args], { encoding: 'buffer', maxBuffer: 64 * 1024 * 1024 });
  const head = git(['rev-parse', ref]);
  if (head.status !== 0) return { ref, commit: null, differ: [`git rev-parse ${ref} failed: ${head.stderr.toString().trim()}`] };
  const commit = head.stdout.toString().trim();
  const listed = readVendored(dir);
  const tree = git(['ls-tree', '--name-only', `${commit}:${CORE_DIR}`]);
  const upstream = [...tree.stdout.toString().split('\n').filter((f) => f.endsWith('.js')).map((f) => `${CORE_DIR}/${f}`), ...EXTRA_FILES];
  const differ = [];
  for (const rel of upstream) {
    const show = git(['show', `${commit}:${rel}`]);
    const mine = listed.files.find((f) => f.path === rel);
    if (show.status !== 0) differ.push(`${rel}: not in the library at ${commit.slice(0, 12)}`);
    else if (!mine) differ.push(`${rel}: new in the library, not vendored`);
    else if (sha256(show.stdout) !== mine.sha256) differ.push(`${rel}: changed in the library`);
  }
  for (const f of listed.files) if (!upstream.includes(f.path)) differ.push(`${f.path}: vendored, but gone from the library`);
  return { ref, commit, pinned: listed.sha, differ };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { values } = parseArgs({ options: { library: { type: 'string' }, ref: { type: 'string', default: 'HEAD' }, help: { type: 'boolean', short: 'h' } } });
  if (values.help) {
    process.stdout.write(fs.readFileSync(fileURLToPath(import.meta.url), 'utf8').split('\n').slice(1, 9).map((l) => l.replace(/^\/\/ ?/, '')).join('\n') + '\n');
  } else {
    const hashes = checkHashes();
    const drift = values.library ? checkDrift(values.library, { ref: values.ref }) : null;
    const ok = hashes.problems.length === 0 && (!drift || drift.differ.length === 0);
    const out = { ok, pinned: hashes.sha, files: hashes.files, problems: hashes.problems, ...(drift ? { drift } : {}) };
    if (drift?.differ.length) out.next = `The library has moved on. Read its changes, then run node tools/sync-library.mjs <clone> --sha ${drift.commit} and the tests.`;
    process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
    process.exitCode = ok ? 0 : 1;
  }
}
