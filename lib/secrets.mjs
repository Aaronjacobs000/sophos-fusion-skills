// Resolves a credential value. A value that starts with op:// is a 1Password
// secret reference and is read with the 1Password CLI, so the secret itself
// never has to sit in a file or an environment variable.

import { execFileSync } from 'node:child_process';
import { SfsError } from './errors.mjs';
import { addIdentifier, addSecret } from './redact.mjs';

export function isOpReference(value) {
  return typeof value === 'string' && value.startsWith('op://');
}

/** The 1Password CLI binary. SOPHOS_FUSION_OP_BIN overrides it (the tests point it at a stub). */
export function opBinary(env = process.env) {
  return env.SOPHOS_FUSION_OP_BIN || 'op';
}

/**
 * The value itself, read from 1Password for an op:// reference. Either way it is registered for
 * redaction: as a secret, or with identifier set (the client ID) as an identifier named by label.
 */
export function resolveSecret(value, { env = process.env, label = 'value', identifier = false } = {}) {
  const register = (v) => (identifier ? addIdentifier(v, label) : addSecret(v));
  if (!isOpReference(value)) {
    register(value);
    return value;
  }
  let out;
  try {
    out = execFileSync(opBinary(env), ['read', '--no-newline', value], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 60_000,
      env,
    });
  } catch (error) {
    const reason = error?.code === 'ENOENT' ? 'the 1Password CLI (op) is not installed or not on PATH' : 'op read failed (is the CLI signed in, and does the reference exist?)';
    throw new SfsError(`Could not read the ${label} from 1Password: ${reason}.`, { code: 'secret_unavailable' });
  }
  const secret = out.replace(/\r?\n$/, '');
  if (!secret) throw new SfsError(`1Password returned an empty ${label}.`, { code: 'secret_unavailable' });
  register(secret);
  return secret;
}
