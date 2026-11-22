import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { addToWorkspace, assertPrivatePath, localSampleLines, maskText, sampleLines } from '../lib/samples.mjs';
import { analyse, buildPlan, runParsers, writeParsers } from '../lib/xsl.mjs';
import { recordSummary, firstSchema } from '../lib/parsers.mjs';
import { ROOT, runScript, tempDir } from './helpers/scenario.mjs';

const RAW = fs.readFileSync(path.join(ROOT, 'test', 'fixtures', 'parsers', 'acme-raw.log'), 'utf8');

describe('masking', () => {
  test('is deterministic and consistent within one file', () => {
    const a = maskText(RAW);
    const b = maskText(RAW);
    assert.equal(a.text, b.text);
    const lines = sampleLines(a.text);
    // The same source address maps to the same documentation address on both lines it appears on.
    const src = lines.map((l) => /src=(\S+)/.exec(l)[1]);
    assert.equal(src[0], src[1]);
    assert.notEqual(src[0], src[2]);
  });

  test('replaces addresses, names and accounts, and keeps structure, keys, times and event codes', () => {
    const { text, counts } = maskText(RAW);
    for (const real of ['10.20.30.40', '172.16.5.10', '192.168.1.77', 'jsmith', 'lap-0042', 'desk-0007', '00:1A:2B:3C:4D:5E']) {
      assert.ok(!text.includes(real), `${real} still in the masked text`);
    }
    // Reserved example domains are safe already, so they stay.
    assert.ok(text.includes('fw-edge-01.corp.example.com') && text.includes('mlee@example.com'));
    assert.match(text, /src=192\.0\.2\.\d+ /);
    assert.match(text, /mac=00:00:5e:00:53:/);
    assert.match(text, /suser=user\d+ /);
    assert.match(text, /shost=host\d+ /);
    assert.match(text, /CEF:0\|Acme\|EdgeWall\|7\.2\|1001\|Admin login failed\|5\|/);
    assert.match(text, /rt=Nov 21 2026 09:14:02 /);
    assert.ok(counts.ipv4 >= 3 && counts.user >= 1 && counts.host >= 2 && counts.mac === 1);
  });

  test('masks IPv6, emails outside example domains, JSON user keys and secret values, and long tokens', () => {
    const m = maskText('{"user": "alice", "password": "hunter2!", "ip6": "fe80::1ff:fe23:4567:890a", "mail": "bob@acme.io", "hash": "d41d8cd98f00b204e9800998ecf8427e"}').text;
    assert.match(m, /"user": "user1"/);
    assert.ok(!m.includes('hunter2!') && /"password": "X+\d"/.test(m));
    assert.match(m, /"ip6": "2001:db8::1"/);
    assert.match(m, /"mail": "user\d+@example\.com"/);
    assert.match(m, /"hash": "0{31}\d"/);
  });

  test('leaves times, versions and file names alone', () => {
    const line = 'time=03:20:54.570033 ver=1.2.3 file=opencanary.conf proto=SSH-2.0-OpenSSH_9.6 at=2026-11-10T03:20:54Z';
    assert.equal(maskText(line).text, line);
  });

  test('the emulator gives the same schema and field names on raw and masked lines', () => {
    const raw = sampleLines(RAW);
    const masked = sampleLines(maskText(RAW).text);
    const plan = buildPlan(analyse(raw), { vendor: 'Acme', product: 'EdgeWall' });
    const made = writeParsers(plan, raw);
    const parent = made.find((p) => p.role === 'parent')?.name;
    const parsers = made.map((p) => ({ name: p.name, text: p.text, parent: p.role === 'child' ? parent : undefined }));
    const now = '2026-11-22T00:00:00Z';
    const a = runParsers(parsers, raw, { now });
    const b = runParsers(parsers, masked, { now });
    assert.equal(a.length, b.length);
    a.forEach((r, i) => {
      assert.equal(firstSchema(r.schema), firstSchema(b[i].schema), `line ${i + 1} schema`);
      assert.deepEqual(recordSummary(r.normalized, firstSchema(r.schema)).fields, recordSummary(b[i].normalized, firstSchema(b[i].schema)).fields, `line ${i + 1} fields`);
    });
    assert.ok(a.some((r) => firstSchema(r.schema) !== 'scwx.generic'), 'the generated parser reaches a schema');
  });
});

describe('the sample workspace', () => {
  test('writes raw and masked copies with private modes, and lists their lines for the contribution check', () => {
    const state = tempDir();
    const r = addToWorkspace(RAW, { env: { SOPHOS_FUSION_STATE_DIR: state } });
    assert.ok(r.workspace.startsWith(path.join(state, 'samples')));
    assert.equal(r.lines, 4);
    assert.equal(fs.readFileSync(r.raw, 'utf8'), `${sampleLines(RAW).join('\n')}\n`);
    assert.ok(!fs.readFileSync(r.masked, 'utf8').includes('10.20.30.40'));
    if (process.platform !== 'win32') {
      assert.equal(fs.statSync(r.workspace).mode & 0o777, 0o700);
      assert.equal(fs.statSync(r.raw).mode & 0o777, 0o600);
      assert.equal(fs.statSync(r.masked).mode & 0o777, 0o600);
    }
    const local = localSampleLines({ env: { SOPHOS_FUSION_STATE_DIR: state } });
    assert.equal(local.size, 8);
  });

  test('refuses a folder inside a git work tree unless git ignores it', { skip: spawnSync('git', ['--version']).status !== 0 }, () => {
    const repo = tempDir();
    spawnSync('git', ['init', '-q', repo]);
    assert.throws(() => assertPrivatePath(path.join(repo, 'samples')), /git work tree/);
    fs.writeFileSync(path.join(repo, '.gitignore'), 'private/\n');
    assert.doesNotThrow(() => assertPrivatePath(path.join(repo, 'private', 'acme')));
    assert.doesNotThrow(() => assertPrivatePath(tempDir()));
  });

  test('samples add prints counts and paths, never a sample value', () => {
    const dir = tempDir();
    const file = path.join(dir, 'acme.log');
    fs.writeFileSync(file, RAW);
    const r = runScript('skills/parsers/scripts/parser.mjs', ['samples', 'add', file, '--quiet']);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.equal(r.json.lines, 4);
    assert.equal(r.json.format, 'cef');
    for (const v of ['10.20.30.40', 'jsmith', 'lap-0042']) assert.ok(!r.stdout.includes(v) && !r.stderr.includes(v));
    assert.equal(r.calls.length, 0);
  });
});
