// Redaction for everything a script prints or stores. Known secret values are
// replaced wherever they appear, and anything shaped like a token or sitting
// under a secret-looking key is replaced too.

const MARK = '[redacted]';
const known = new Set();

// Keys whose values are never printed.
const SECRET_KEY = /^(client_?secret|secret|password|passwd|pass|token|access_?token|refresh_?token|id_?token|authorization|api_?key|apikey|x-api-key|credentials|private_?key|client_?assertion|signature|sig)$/i;

const PATTERNS = [
  // Bearer and Basic authorization values
  [/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi, (_, kind) => `${kind} ${MARK}`],
  // JSON Web Tokens
  [/\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b/g, MARK],
  // key=value pairs in query strings and form bodies
  [/\b(client_secret|access_token|refresh_token|password|api_key|apikey|token|sig|signature)=([^&\s"']+)/gi, (_, k) => `${k}=${MARK}`],
];

/** Register a value that must never appear in output. Short values are ignored. */
export function addSecret(value) {
  if (typeof value === 'string' && value.length >= 6) known.add(value);
}

export function clearSecrets() {
  known.clear();
}

export function redactText(text) {
  if (typeof text !== 'string' || text === '') return text;
  let out = text;
  for (const secret of known) {
    if (out.includes(secret)) out = out.split(secret).join(MARK);
  }
  for (const [re, rep] of PATTERNS) out = out.replace(re, rep);
  return out;
}

/** Deep copy of a value with secrets replaced. */
export function redact(value, stack = new Set()) {
  if (typeof value === 'string') return redactText(value);
  if (value === null || typeof value !== 'object') return value;
  // Only a value inside itself is circular; the same object twice is fine.
  if (stack.has(value)) return '[circular]';
  stack.add(value);
  let out;
  if (Array.isArray(value)) {
    out = value.map((v) => redact(v, stack));
  } else {
    out = {};
    for (const [k, v] of Object.entries(value)) {
      if (SECRET_KEY.test(k) && v !== null && v !== undefined && v !== '' && typeof v !== 'boolean') {
        out[k] = MARK;
      } else {
        out[k] = redact(v, stack);
      }
    }
  }
  stack.delete(value);
  return out;
}

// Strings in execution logs that look like a secret slipped through: a token,
// a signed URL, a webhook address, or a key=value secret.
const LEAK_PATTERNS = [
  ['bearer_token', /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/i],
  ['jwt', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
  ['signed_url', /[?&](sig|signature|X-Amz-Signature|se|sp|sv)=[^&\s"']{8,}/i],
  ['webhook_url', /https:\/\/(hooks\.slack\.com\/services|[a-z0-9-]+\.webhook\.office\.com|[a-z0-9.-]*logic\.azure\.com|discord(app)?\.com\/api\/webhooks|chat\.googleapis\.com\/v1\/spaces)[^\s"']*/i],
  ['secret_pair', /\b(client_secret|api_key|apikey|password|access_token)["']?\s*[:=]\s*["']?(?![$<{])[^\s"',}&<>]{6,}/i],
  ['private_key', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['aws_key', /\bAKIA[0-9A-Z]{16}\b/],
];

/** Find secret-looking strings inside any value. Returns [{kind, path, sample}] with samples redacted. */
export function findLeaks(value, path = '$', found = []) {
  if (typeof value === 'string') {
    for (const [kind, re] of LEAK_PATTERNS) {
      const m = value.match(re);
      if (m) found.push({ kind, path, sample: `${m[0].slice(0, 12)}...` });
    }
    for (const secret of known) {
      if (value.includes(secret)) found.push({ kind: 'known_secret', path, sample: MARK });
    }
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => findLeaks(v, `${path}[${i}]`, found));
  } else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) findLeaks(v, `${path}.${k}`, found);
  }
  return found;
}
