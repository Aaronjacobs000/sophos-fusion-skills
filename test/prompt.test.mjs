import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { promptHidden } from '../lib/prompt.mjs';
import { UsageError } from '../lib/errors.mjs';

/** A stand-in terminal: input in raw mode delivers whatever is written to it, as a real one does. */
function terminal() {
  const input = new PassThrough();
  input.isTTY = true;
  input.isRaw = false;
  input.setRawMode = (on) => {
    input.isRaw = on;
    return input;
  };
  const shown = [];
  const output = { write: (s) => shown.push(s) };
  return { input, output, shown };
}

describe('hidden prompt', () => {
  test('a pasted secret that ends in CRLF ends the prompt, without the line ending', { timeout: 2000 }, async () => {
    const t = terminal();
    const answer = promptHidden('secret: ', t);
    t.input.write('pasted-secret-value\r\n');
    assert.equal(await answer, 'pasted-secret-value');
    assert.equal(t.input.isRaw, false);
    assert.equal(t.input.listenerCount('data'), 0);
    assert.deepEqual(t.shown, ['secret: ', '\n'], 'the secret is never echoed');
  });

  test('a paste ending in a bare CR or LF ends it the same way', { timeout: 2000 }, async () => {
    for (const ending of ['\r', '\n']) {
      const t = terminal();
      const answer = promptHidden('secret: ', t);
      t.input.write(`pasted-secret-value${ending}`);
      assert.equal(await answer, 'pasted-secret-value');
    }
  });

  test('only the first line counts', { timeout: 2000 }, async () => {
    const t = terminal();
    const answer = promptHidden('secret: ', t);
    t.input.write('first-line\r\nsecond-line\r\n');
    assert.equal(await answer, 'first-line');
  });

  test('typed keys, backspace, and Enter', { timeout: 2000 }, async () => {
    const t = terminal();
    const answer = promptHidden('secret: ', t);
    for (const key of ['a', 'b', 'x', '\u007f', 'c', '\r']) t.input.write(key);
    assert.equal(await answer, 'abc');
  });

  test('no terminal is a usage error', async () => {
    const t = terminal();
    t.input.isTTY = false;
    await assert.rejects(() => promptHidden('secret: ', t), UsageError);
  });
});
