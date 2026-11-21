// File helpers that behave the same on Windows. There, a file or folder that
// another process holds open for a moment (a reader, a virus scanner) can make
// a rename, or a new folder of the same name, fail with EPERM, EACCES, or EBUSY.
// Those failures pass, so the helpers wait a little and try again.

import fs from 'node:fs';

const BUSY = new Set(['EPERM', 'EACCES', 'EBUSY']);
const pause = new Int32Array(new SharedArrayBuffer(4));

/** True for the short-lived refusals Windows gives while another process holds the path. */
export function isWindowsBusy(error) {
  return process.platform === 'win32' && BUSY.has(error?.code);
}

/** Replace file with tmp in one step. On Windows a busy target is retried for about a second. */
export function replaceFile(tmp, file) {
  for (let attempt = 1; ; attempt++) {
    try {
      fs.renameSync(tmp, file);
      return;
    } catch (error) {
      if (!isWindowsBusy(error) || attempt >= 20) throw error;
      Atomics.wait(pause, 0, 0, 50);
    }
  }
}
