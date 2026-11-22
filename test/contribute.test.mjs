import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { contributeParser, copiedLines, lineValues } from '../lib/contribute.mjs';
import { addToWorkspace, maskText, sampleLines } from '../lib/samples.mjs';
import { unpackBundle, validateEntry } from '../lib/xsl.mjs';
import { setQuiet } from '../lib/log.mjs';
import { ROOT, runScript, tempDir } from './helpers/scenario.mjs';

setQuiet(true);

const EXAMPLE = path.join(ROOT, 'examples', 'parsers', 'opencanary');
const RAW = fs.readFileSync(path.join(ROOT, 'test', 'fixtures', 'parsers', 'acme-raw.log'), 'utf8');

describe('copied lines', () => {
  test('values come from JSON, key=value text, quoted strings and long numbers', () => {
    const v = lineValues('{"user": "alice", "port": 51515} src=192.0.2.4 msg="hello there" id=99 code 4625');
    for (const x of ['alice', '51515', '192.0.2.4', 'hello there', '4625']) assert.ok(v.has(x), x);
    assert.ok(!v.has('99'));
  });

  test('an equal line and a near copy are found; a line written fresh is not', () => {
    const masked = sampleLines(maskText(RAW).text);
    const local = new Set(masked);
    const near = masked[0].replace(/spt=\d+/, 'spt=60000');
    const fresh = fs.readFileSync(path.join(ROOT, 'test', 'fixtures', 'parsers', 'acme-synthetic.log'), 'utf8').trim();
    const r = copiedLines([masked[1], near, fresh], local);
    assert.deepEqual(r.map((x) => x.line), [1, 2]);
    assert.match(r[0].reason, /the same as/);
    assert.match(r[1].reason, /shares \d+ of its \d+ values/);
  });
});

describe('contributeParser', () => {
  test('refuses a masked line copied from a workspace, without printing it', () => {
    const state = tempDir();
    const ws = addToWorkspace(fs.readFileSync(path.join(EXAMPLE, 'samples.log'), 'utf8'), { env: { SOPHOS_FUSION_STATE_DIR: state } });
    const out = tempDir();
    const r = contributeParser(EXAMPLE, { samplesFile: ws.masked, out, env: { SOPHOS_FUSION_STATE_DIR: state } });
    assert.equal(r.ok, false);
    assert.ok(r.problems.every((p) => p.code === 'copied'));
    assert.equal(fs.readdirSync(out).length, 0, 'nothing is written');
  });

  test('the OpenCanary example passes, writes the entry outside any repo, and its bundle round-trips', () => {
    const out = tempDir();
    const r = contributeParser(EXAMPLE, { samplesFile: path.join(EXAMPLE, 'samples.log'), out, env: { SOPHOS_FUSION_STATE_DIR: tempDir() } });
    assert.equal(r.ok, true, JSON.stringify(r.problems));
    assert.equal(r.folder, path.join(out, 'parsers', 'thinkst', 'opencanary'));
    assert.deepEqual(fs.readdirSync(r.folder).sort(), ['OPENCANARY_JSON_CHILD_THIRDPARTYALERT.parser.txt', 'OPENCANARY_JSON_PARENT.parser.txt', 'expected.json', 'meta.json', 'samples.log']);
    assert.equal(r.links.upload, 'https://github.com/Aaronjacobs000/sophos-xdr-siem-library/upload/main/parsers/thinkst/opencanary');
    const entry = unpackBundle(fs.readFileSync(r.bundleFile, 'utf8'));
    assert.equal(entry.id, 'thinkst/opencanary');
    assert.equal(entry.samples.length, 48);
    assert.equal(validateEntry({ ...entry, id: 'thinkst/opencanary' }).ok, true);
  });

  test('refuses an output folder inside a git work tree', () => {
    const r = runScript('skills/parsers/scripts/parser.mjs', ['contribute', EXAMPLE, '--samples', path.join(EXAMPLE, 'samples.log'), '--out', path.join(ROOT, 'test', '.tmp-contribute'), '--quiet']);
    assert.equal(r.status, 2);
    assert.match(r.json.error.message, /git work tree/);
    assert.ok(!fs.existsSync(path.join(ROOT, 'test', '.tmp-contribute')));
  });

  test('the folder\'s own samples count as the user\'s unless meta.json says they are synthetic', () => {
    const dir = tempDir();
    for (const f of fs.readdirSync(EXAMPLE)) fs.copyFileSync(path.join(EXAMPLE, f), path.join(dir, f));
    const meta = JSON.parse(fs.readFileSync(path.join(dir, 'meta.json'), 'utf8'));
    delete meta.sample_source;
    fs.writeFileSync(path.join(dir, 'meta.json'), JSON.stringify(meta));
    const r = contributeParser(dir, { samplesFile: path.join(dir, 'samples.log'), out: tempDir(), env: { SOPHOS_FUSION_STATE_DIR: tempDir() } });
    assert.equal(r.ok, false);
    assert.equal(r.problems.filter((p) => p.code === 'copied').length, 48);
  });
});

describe('rule contributions', () => {
  test('a detection set goes to rules/<vendor>/<name> once its parser is a library entry', () => {
    const out = tempDir();
    const r = runScript('skills/detection-rules/scripts/rules.mjs', ['contribute', path.join(ROOT, 'examples', 'rules', 'opencanary-honeypot-activity'), '--parser-entry', EXAMPLE, '--out', out, '--quiet']);
    assert.equal(r.status, 0, r.stdout);
    assert.equal(r.json.folder, path.join(out, 'rules', 'thinkst', 'opencanary-honeypot-activity'));
    assert.deepEqual(fs.readdirSync(r.json.folder).sort(), ['meta.json', 'rules.yaml', 'tests.json']);
    assert.match(r.json.links.upload, /upload\/main\/rules\/thinkst\/opencanary-honeypot-activity$/);
  });

  test('a case entry goes in after its detection entry', () => {
    const out = tempDir();
    const r = runScript('skills/detection-rules/scripts/case-rule.mjs', ['contribute', path.join(ROOT, 'examples', 'rules', 'opencanary-one-case-per-source-ip'), '--out', out, '--quiet']);
    assert.equal(r.status, 0, r.stdout);
    assert.ok(fs.existsSync(path.join(out, 'rules', 'thinkst', 'opencanary-one-case-per-source-ip', 'case-rule.yaml')));
  });
});
