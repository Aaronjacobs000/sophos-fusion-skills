// Behavior that has to hold on Windows as well as macOS and Linux: files saved
// with CRLF line endings, and Windows refusing a rename or a new folder for a
// moment while another process holds the path.

import { test, describe, mock, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { validateText } from '../lib/rules.mjs';
import { loadCases } from '../lib/cel-cases.mjs';
import { makeTestCopy } from '../lib/template.mjs';
import { isWindowsBusy, replaceFile } from '../lib/fsx.mjs';
import { readLedger, record, startRun, withLock } from '../lib/ledger.mjs';
import { ROOT, tempDir } from './helpers/scenario.mjs';

const crlf = (text) => text.replace(/\r?\n/g, '\r\n');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

const platform = Object.getOwnPropertyDescriptor(process, 'platform');
function pretendPlatform(name) {
  Object.defineProperty(process, 'platform', { ...platform, value: name });
}
afterEach(() => {
  Object.defineProperty(process, 'platform', platform);
  mock.restoreAll();
});

function busyError(code = 'EPERM') {
  return Object.assign(new Error(`${code}: operation not permitted`), { code });
}

describe('files saved with CRLF line endings', () => {
  const files = [
    'examples/playbooks/case-reference-lookup/template.yaml',
    'examples/playbooks/closed-case-detection-note/template.yaml',
    'examples/playbooks/case-ip-threat-feed-block/template.yaml',
    'examples/connectors/first-epss/connector.yaml',
    'test/fixtures/bad/kitchen-sink.yaml',
    'test/fixtures/bad/response-no-guards.yaml',
    'test/fixtures/bad/connector-bad.yaml',
  ];
  for (const f of files) {
    test(`${f} gets the same findings, on the same lines`, () => {
      const lf = validateText(read(f), f);
      const win = validateText(crlf(read(f)), f);
      const key = (r) => r.findings.map((x) => `${x.level} ${x.rule} ${x.path ?? ''} ${x.line ?? ''}`).sort();
      assert.equal(win.ok, lf.ok);
      assert.deepEqual(key(win), key(lf));
    });
  }

  test('a test copy of a CRLF template matches the copy of the LF one', () => {
    const f = 'examples/playbooks/closed-case-detection-note/template.yaml';
    assert.equal(makeTestCopy(crlf(read(f))).text, makeTestCopy(read(f)).text);
  });

  test('a CRLF cases file and template give the same expressions', () => {
    const dir = tempDir('sfs-crlf-');
    const src = path.join(ROOT, 'examples/playbooks/closed-case-detection-note');
    for (const name of fs.readdirSync(src)) fs.writeFileSync(path.join(dir, name), crlf(fs.readFileSync(path.join(src, name), 'utf8')));
    const win = loadCases(path.join(dir, 'cel-cases.json'));
    const lf = loadCases(path.join(src, 'cel-cases.json'));
    assert.deepEqual(win.cases.map((c) => [c.expression, c.inputs]), lf.cases.map((c) => [c.expression, c.inputs]));
  });
});

describe('Windows busy paths', () => {
  test('only Windows EPERM, EACCES and EBUSY count as busy', () => {
    pretendPlatform('win32');
    assert.ok(isWindowsBusy(busyError('EPERM')) && isWindowsBusy(busyError('EACCES')) && isWindowsBusy(busyError('EBUSY')));
    assert.ok(!isWindowsBusy(busyError('ENOENT')));
    pretendPlatform('linux');
    assert.ok(!isWindowsBusy(busyError('EPERM')));
  });

  test('a rename onto a busy file is retried on Windows', () => {
    pretendPlatform('win32');
    const dir = tempDir();
    const tmp = path.join(dir, 'a.tmp');
    const file = path.join(dir, 'a.json');
    fs.writeFileSync(tmp, 'new');
    fs.writeFileSync(file, 'old');
    const real = fs.renameSync;
    let refusals = 2;
    mock.method(fs, 'renameSync', (from, to) => {
      if (refusals-- > 0) throw busyError();
      return real(from, to);
    });
    replaceFile(tmp, file);
    assert.equal(fs.readFileSync(file, 'utf8'), 'new');
    assert.equal(fs.renameSync.mock.callCount(), 3);
  });

  test('elsewhere the same failure is not retried', () => {
    pretendPlatform('linux');
    mock.method(fs, 'renameSync', () => {
      throw busyError();
    });
    assert.throws(() => replaceFile('a', 'b'), /EPERM/);
    assert.equal(fs.renameSync.mock.callCount(), 1);
  });

  test('a busy rename that never clears still fails', () => {
    pretendPlatform('win32');
    mock.method(fs, 'renameSync', () => {
      throw busyError('EBUSY');
    });
    assert.throws(() => replaceFile('a', 'b', { attempts: 5, waitMs: 1 }), /EBUSY/);
    assert.equal(fs.renameSync.mock.callCount(), 5);
  });

  test('the ledger lock waits while Windows refuses a lock folder that is being removed', () => {
    pretendPlatform('win32');
    const env = { SOPHOS_FUSION_STATE_DIR: tempDir() };
    startRun({ env });
    const real = fs.mkdirSync;
    let refusals = 2;
    mock.method(fs, 'mkdirSync', (p, opts) => {
      if (p.endsWith('ledger.lock') && refusals-- > 0) throw busyError();
      return real(p, opts);
    });
    record({ kind: 'connection', id: 'c1', name: 'ZZ Test c', tenantId: 't', profile: 'p' }, { env });
    assert.equal(Object.values(readLedger(env).runs)[0].objects.length, 1);
    assert.ok(!fs.existsSync(path.join(env.SOPHOS_FUSION_STATE_DIR, 'ledger.lock')));
  });

  test('on Windows a refusal that lasts is reported as itself, not as a lock', () => {
    pretendPlatform('win32');
    const env = { SOPHOS_FUSION_STATE_DIR: tempDir() };
    const real = fs.mkdirSync;
    mock.method(fs, 'mkdirSync', (p, opts) => {
      if (p.endsWith('ledger.lock')) throw busyError('EACCES');
      return real(p, opts);
    });
    const started = Date.now();
    assert.throws(() => withLock(env, () => 1), (e) => e.code === 'EACCES');
    assert.ok(Date.now() - started < 9_000);
  });

  test('elsewhere a refused lock folder is an error, not a wait', () => {
    pretendPlatform('linux');
    const env = { SOPHOS_FUSION_STATE_DIR: tempDir() };
    const real = fs.mkdirSync;
    mock.method(fs, 'mkdirSync', (p, opts) => {
      if (p.endsWith('ledger.lock')) throw busyError();
      return real(p, opts);
    });
    assert.throws(() => withLock(env, () => 1), /EPERM/);
  });
});
