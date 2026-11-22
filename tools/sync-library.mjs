#!/usr/bin/env node
// Copies the library's emulator, schema data, rule query reader and parser generator into
// vendor/xdr-siem-library, unmodified, from one commit of a local clone of
// Aaronjacobs000/sophos-xdr-siem-library, and rewrites VENDORED.md with the commit and a sha256
// per file.
//
//   node tools/sync-library.mjs <library clone> --sha <commit>
//
// The clone is only read: files come from "git show <commit>:<path>", so its working tree and
// branch don't matter and nothing in it changes. Pin a commit on the library's main branch.
// After a sync, run node --test and node tools/check-vendor.mjs, and read the diff.

import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const VENDOR_DIR = path.join(ROOT, 'vendor', 'xdr-siem-library');
export const REPO = 'https://github.com/Aaronjacobs000/sophos-xdr-siem-library';
// Every file directly in studio/core, then these. LICENSE and ATTRIBUTIONS.md carry the library's
// license and its gitleaks and schema data attributions.
export const EXTRA_FILES = ['studio/app/plan.js', 'LICENSE', 'ATTRIBUTIONS.md'];
export const CORE_DIR = 'studio/core';

function git(clone, args) {
  const r = spawnSync('git', ['-C', clone, ...args], { encoding: 'buffer', maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${r.stderr.toString().trim()}`);
  return r.stdout;
}

/** The files to vendor at a commit: every .js file directly in studio/core, then EXTRA_FILES. */
export function filesAt(clone, sha) {
  const core = git(clone, ['ls-tree', '--name-only', `${sha}:${CORE_DIR}`]).toString().split('\n').filter((f) => f.endsWith('.js')).sort();
  return [...core.map((f) => `${CORE_DIR}/${f}`), ...EXTRA_FILES];
}

export const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

export function vendoredText({ sha, date, files }) {
  const rows = files.map((f) => `| \`${f.path}\` | \`${f.sha256}\` |`).join('\n');
  return `# Vendored: Unofficial Sophos Fusion XDR and SIEM Library

- Upstream: ${REPO}
- Commit: ${sha}
- Synced: ${date}
- License: MIT, see \`LICENSE\` in this folder. \`ATTRIBUTIONS.md\` credits gitleaks (MIT) for \`studio/core/gitleaks-rule.js\` and \`studio/core/gitleaks.js\`, and says where \`studio/core/schema-data.js\` comes from.
- Files: every file in \`studio/core\`, and \`studio/app/plan.js\`, copied without changes. The scripts import them through \`lib/xsl.mjs\` only.
- Why vendored: the parsers and detection-rules skills run the library's emulator, schema data, rule query reader and parser generator offline, with no \`npm install\` and no download at run time.

To update, run \`node tools/sync-library.mjs <library clone> --sha <commit on main>\`, then \`node --test\` and \`node tools/check-vendor.mjs\`. CI checks every hash below, and a weekly job fails when the library's main branch differs.

| File | sha256 |
| --- | --- |
${rows}
`;
}

/** Reads the commit and the file hashes back from VENDORED.md. */
export function readVendored(dir = VENDOR_DIR) {
  const text = fs.readFileSync(path.join(dir, 'VENDORED.md'), 'utf8');
  const sha = /^- Commit: ([0-9a-f]{40})$/m.exec(text)?.[1] ?? null;
  const files = [...text.matchAll(/^\| `([^`]+)` \| `([0-9a-f]{64})` \|$/gm)].map((m) => ({ path: m[1], sha256: m[2] }));
  return { sha, files };
}

export function sync(clone, sha, { dir = VENDOR_DIR, now = new Date() } = {}) {
  const full = git(clone, ['rev-parse', '--verify', `${sha}^{commit}`]).toString().trim();
  const wanted = filesAt(clone, full);
  const before = fs.existsSync(path.join(dir, 'VENDORED.md')) ? readVendored(dir).files.map((f) => f.path) : [];
  const out = [];
  for (const rel of wanted) {
    const buf = git(clone, ['show', `${full}:${rel}`]);
    const dest = path.join(dir, ...rel.split('/'));
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, buf);
    out.push({ path: rel, sha256: sha256(buf) });
  }
  // A file the library dropped since the last sync goes too, so nothing stale stays importable.
  for (const rel of before.filter((p) => !wanted.includes(p))) fs.rmSync(path.join(dir, ...rel.split('/')), { force: true });
  fs.writeFileSync(path.join(dir, 'VENDORED.md'), vendoredText({ sha: full, date: now.toISOString().slice(0, 10), files: out }));
  return { sha: full, files: out.length, removed: before.filter((p) => !wanted.includes(p)) };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { values, positionals } = parseArgs({ options: { sha: { type: 'string' }, help: { type: 'boolean', short: 'h' } }, allowPositionals: true });
  if (values.help || positionals.length !== 1 || !values.sha) {
    process.stdout.write('Usage: node tools/sync-library.mjs <library clone> --sha <commit>\nCopies studio/core and studio/app/plan.js from that commit into vendor/xdr-siem-library and rewrites VENDORED.md.\n');
    process.exitCode = values.help ? 0 : 2;
  } else {
    try {
      process.stdout.write(`${JSON.stringify({ ok: true, ...sync(positionals[0], values.sha) }, null, 2)}\n`);
    } catch (error) {
      process.stdout.write(`${JSON.stringify({ ok: false, error: error.message }, null, 2)}\n`);
      process.exitCode = 1;
    }
  }
}
