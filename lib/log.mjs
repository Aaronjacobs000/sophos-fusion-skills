// Messages for people go to stderr, always redacted. stdout carries only JSON.

import { redactText } from './redact.mjs';

let quiet = false;

export function setQuiet(value) {
  quiet = Boolean(value);
}

export function log(message) {
  if (quiet) return;
  process.stderr.write(`${redactText(String(message))}\n`);
}
