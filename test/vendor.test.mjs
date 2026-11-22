import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { checkDrift, checkHashes } from '../tools/check-vendor.mjs';
import { readVendored, sync, VENDOR_DIR } from '../tools/sync-library.mjs';
import * as xsl from '../lib/xsl.mjs';
import { ROOT, tempDir } from './helpers/scenario.mjs';

const hasGit = spawnSync('git', ['--version']).status === 0;
const git = (dir, ...args) => {
  const r = spawnSync('git', ['-C', dir, ...args], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(r.stderr);
  return r.stdout.trim();
};

/** A small library clone: a commit with studio/core, plan.js, LICENSE and ATTRIBUTIONS.md. */
function fakeLibrary() {
  const dir = tempDir();
  git(dir, 'init', '-q');
  git(dir, 'config', 'user.email', 'test@example.com');
  git(dir, 'config', 'user.name', 'Test');
  fs.mkdirSync(path.join(dir, 'studio', 'core'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'studio', 'app'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'studio', 'core', 'a.js'), 'export const a = 1;\n');
  fs.writeFileSync(path.join(dir, 'studio', 'core', 'b.js'), 'export const b = 2;\n');
  fs.writeFileSync(path.join(dir, 'studio', 'app', 'plan.js'), 'export const plan = 3;\n');
  fs.writeFileSync(path.join(dir, 'LICENSE'), 'MIT License\n');
  fs.writeFileSync(path.join(dir, 'ATTRIBUTIONS.md'), '# Third-party attributions\n');
  git(dir, 'add', '.');
  git(dir, 'commit', '-q', '-m', 'one');
  return { dir, sha: git(dir, 'rev-parse', 'HEAD') };
}

describe('the vendored library', () => {
  test('every file matches its sha256 in VENDORED.md, pinned to a commit', () => {
    const r = checkHashes();
    assert.deepEqual(r.problems, []);
    assert.match(r.sha, /^[0-9a-f]{40}$/);
    assert.ok(r.files >= 25);
    assert.ok(readVendored().files.some((f) => f.path === 'studio/app/plan.js'));
    assert.ok(fs.existsSync(path.join(VENDOR_DIR, 'LICENSE')) && fs.existsSync(path.join(VENDOR_DIR, 'ATTRIBUTIONS.md')));
  });

  test('lib/xsl.mjs is the one import point, and every export resolves', () => {
    for (const [k, v] of Object.entries(xsl)) assert.notEqual(v, undefined, k);
    const offenders = [];
    for (const dir of ['lib', 'skills', 'tools']) {
      const walk = (d) => {
        for (const e of fs.readdirSync(d, { withFileTypes: true })) {
          const p = path.join(d, e.name);
          if (e.isDirectory()) walk(p);
          else if (/\.mjs$/.test(e.name) && p !== path.join(ROOT, 'lib', 'xsl.mjs') && /vendor\/xdr-siem-library/.test(fs.readFileSync(p, 'utf8').split('\n').filter((l) => /^import/.test(l)).join('\n'))) offenders.push(path.relative(ROOT, p));
        }
      };
      walk(path.join(ROOT, dir));
    }
    assert.deepEqual(offenders, []);
  });

  test('sync copies a commit\'s files unmodified, and the hash check catches an edit or a stray file', { skip: !hasGit }, () => {
    const lib = fakeLibrary();
    const dest = tempDir();
    const r = sync(lib.dir, lib.sha, { dir: dest, now: new Date('2026-11-22T00:00:00Z') });
    assert.equal(r.sha, lib.sha);
    assert.equal(r.files, 5);
    assert.equal(fs.readFileSync(path.join(dest, 'studio', 'core', 'a.js'), 'utf8'), 'export const a = 1;\n');
    assert.match(fs.readFileSync(path.join(dest, 'VENDORED.md'), 'utf8'), new RegExp(`Commit: ${lib.sha}`));
    assert.deepEqual(checkHashes(dest).problems, []);
    fs.appendFileSync(path.join(dest, 'studio', 'core', 'a.js'), '// edited\n');
    fs.writeFileSync(path.join(dest, 'studio', 'core', 'extra.js'), '');
    const bad = checkHashes(dest).problems;
    assert.ok(bad.some((p) => /a\.js: changed/.test(p)));
    assert.ok(bad.some((p) => /extra\.js: not listed/.test(p)));
  });

  test('drift: a change on the library\'s main is listed by file', { skip: !hasGit }, () => {
    const lib = fakeLibrary();
    const dest = tempDir();
    sync(lib.dir, lib.sha, { dir: dest });
    assert.deepEqual(checkDrift(lib.dir, { dir: dest }).differ, []);
    fs.writeFileSync(path.join(lib.dir, 'studio', 'core', 'b.js'), 'export const b = 22;\n');
    fs.writeFileSync(path.join(lib.dir, 'studio', 'core', 'c.js'), 'export const c = 3;\n');
    git(lib.dir, 'add', '.');
    git(lib.dir, 'commit', '-q', '-m', 'two');
    const d = checkDrift(lib.dir, { dir: dest });
    assert.deepEqual(d.differ.sort(), ['studio/core/b.js: changed in the library', 'studio/core/c.js: new in the library, not vendored']);
  });
});
