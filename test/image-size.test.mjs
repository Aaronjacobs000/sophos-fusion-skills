import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { imageSize } from '../lib/image-size.mjs';
import { ROOT, tempDir } from './helpers/scenario.mjs';

const fixture = (name) => fs.readFileSync(path.join(ROOT, 'test', 'fixtures', 'images', name));

describe('image sizes', () => {
  test('reads a baseline JPEG with an EXIF segment before the frame', () => {
    assert.deepEqual(imageSize(fixture('square-512.jpg')), { type: 'jpeg', width: 512, height: 512 });
  });

  test('reads a progressive JPEG, width and height the right way round', () => {
    assert.deepEqual(imageSize(fixture('progressive-64x48.jpg')), { type: 'jpeg', width: 64, height: 48 });
  });

  test('skips fill bytes between JPEG segments', () => {
    const sof = Buffer.from([0xff, 0xc0, 0x00, 0x11, 0x08, 0x02, 0x00, 0x01, 0x80, 0x03, 0x01, 0x22, 0x00, 0x02, 0x11, 0x01, 0x03, 0x11, 0x01]);
    const buf = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xff, 0xff]), sof.subarray(1)]);
    assert.deepEqual(imageSize(buf), { type: 'jpeg', width: 384, height: 512 });
  });

  test('a JPEG cut off before its frame header has no size', () => {
    assert.deepEqual(imageSize(fixture('square-512.jpg').subarray(0, 40)), { type: 'jpeg', width: null, height: null });
  });

  test('still reads PNG and SVG', () => {
    assert.deepEqual(imageSize(fs.readFileSync(path.join(ROOT, 'assets', 'icon.png'))), { type: 'png', width: 1024, height: 1024 });
    const svg = imageSize(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"></svg>'));
    assert.deepEqual(svg, { type: 'svg', width: 64, height: 64 });
  });

  test('names formats it cannot read', () => {
    assert.equal(imageSize(Buffer.from('GIF89a\x10\x00\x10\x00', 'latin1')).type, 'gif');
    assert.equal(imageSize(Buffer.from('RIFF\x24\x00\x00\x00WEBPVP8 ', 'latin1')).type, 'webp');
    assert.deepEqual(imageSize(Buffer.from('just some text')), { type: 'unknown', width: null, height: null });
  });
});

describe('check-manifests icons', () => {
  // A copy of the repository, so a test can swap the Claude Code icon
  function repoCopy() {
    const dir = tempDir('sfs-manifests-');
    const skip = new Set(['.git', 'node_modules', 'test']);
    fs.cpSync(ROOT, dir, { recursive: true, filter: (src) => !skip.has(path.basename(src)) });
    return dir;
  }
  function check(dir, iconRel, bytes) {
    fs.writeFileSync(path.join(dir, iconRel), bytes);
    const manifest = path.join(dir, '.claude-plugin', 'plugin.json');
    const m = JSON.parse(fs.readFileSync(manifest, 'utf8'));
    m.icon = `./${iconRel}`;
    fs.writeFileSync(manifest, JSON.stringify(m, null, 2));
    const r = spawnSync(process.execPath, [path.join(dir, 'tools', 'check-manifests.mjs')], { encoding: 'utf8' });
    return { status: r.status, out: JSON.parse(r.stdout) };
  }

  test('a square JPEG Claude Code icon passes', () => {
    const r = check(repoCopy(), 'assets/icon.jpg', fixture('square-512.jpg'));
    assert.equal(r.status, 0, JSON.stringify(r.out.problems));
    assert.equal(r.out.ok, true);
  });

  test('a format it cannot read, or a JPEG with no readable size, is named plainly', () => {
    const dir = repoCopy();
    const gif = check(dir, 'assets/icon.gif', Buffer.from('GIF89a\x00\x02\x00\x02', 'latin1'));
    assert.equal(gif.status, 1);
    assert.deepEqual(gif.out.problems, ['.claude-plugin/plugin.json icon: ./assets/icon.gif is a GIF file. This check reads PNG, JPEG, and SVG only']);
    const cut = check(dir, 'assets/cut.jpg', fixture('square-512.jpg').subarray(0, 40));
    assert.deepEqual(cut.out.problems, ['.claude-plugin/plugin.json icon: ./assets/cut.jpg is a JPEG file, but its size could not be read']);
    const small = check(dir, 'assets/small.jpg', fixture('progressive-64x48.jpg'));
    assert.deepEqual(small.out.problems, ['.claude-plugin/plugin.json icon: ./assets/small.jpg is jpeg 64x48, 535 bytes, which this format does not accept']);
  });
});
