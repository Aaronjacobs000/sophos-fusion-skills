// Hidden terminal input, for the client secret.

import { UsageError } from './errors.mjs';

/**
 * Read one line from the terminal without echoing it. The prompt ends at the first return or
 * newline, so a pasted value that brings its own Enter keystroke (often "\r\n") ends it at once,
 * and the line ending is never part of the value.
 */
export function promptHidden(question, { input = process.stdin, output = process.stderr } = {}) {
  return new Promise((resolve, reject) => {
    if (!input.isTTY) {
      reject(new UsageError('No terminal to prompt on. Use --secret-stdin, --secret-env or an op:// reference.'));
      return;
    }
    output.write(question);
    let value = '';
    input.setRawMode(true);
    input.resume();
    input.setEncoding('utf8');
    const onData = (chunk) => {
      // A paste arrives as one chunk, so read it a character at a time
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n' || ch === '\u0004') {
          input.setRawMode(false);
          input.pause();
          input.off('data', onData);
          output.write('\n');
          resolve(value);
          return;
        }
        if (ch === '\u0003') {
          input.setRawMode(false);
          reject(new UsageError('Canceled.'));
          return;
        }
        if (ch === '\u007f' || ch === '\b') value = value.slice(0, -1);
        else value += ch;
      }
    };
    input.on('data', onData);
  });
}
