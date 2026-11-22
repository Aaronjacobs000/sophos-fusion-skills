// Sample lines from a customer's source: a private workspace for them, and the masking the agent's
// copy goes through. The raw lines stay on the machine; the agent reads only masked.log.
//
// Masking is consistent within one file (the same value always becomes the same placeholder, in the
// order values first appear, so a second run gives the same output) and keeps structure, keys,
// timestamps and event codes. No map of real to masked values is kept.

import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { SfsError, UsageError } from './errors.mjs';
import { stateDir } from './ledger.mjs';
import { findGenericApiKeys } from './xsl.mjs';

// ---------------------------------------------------------------- what counts as what

const USER_KEYS = new Set(['user', 'username', 'user_name', 'userid', 'user_id', 'account', 'accountname', 'account_name', 'suser', 'duser', 'src_user', 'dst_user', 'srcuser', 'dstuser', 'source_user', 'target_user', 'upn', 'userprincipalname', 'user_principal_name', 'targetusername', 'subjectusername', 'target_user_name', 'subject_user_name', 'login', 'logon', 'login_name', 'logonname', 'principal', 'principalname', 'actor', 'owner', 'email_user', 'samaccountname', 'usrname', 'uname']);
const HOST_KEYS = new Set(['host', 'hostname', 'host_name', 'computer', 'computername', 'computer_name', 'device', 'devicename', 'device_name', 'dhost', 'shost', 'dvchost', 'src_host_name', 'dst_host_name', 'srchost', 'dsthost', 'workstation', 'workstationname', 'workstation_name', 'machine', 'machinename', 'machine_name', 'client_hostname', 'server_name', 'servername', 'node', 'node_id', 'nodename', 'fqdn', 'endpoint', 'endpoint_name', 'agent_hostname']);
const SECRET_KEYS = /^(password|passwd|pass|pwd|secret|client_secret|token|access_token|refresh_token|api_?key|apikey|access_?key|secret_?key|auth|authorization|credential|credentials|community|private_?key|session_?key|cookie)$/i;
// Values that stay as they are: empty, placeholders and dashes.
const KEEP_VALUE = /^(?:|-|--|n\/a|na|null|nil|none|unknown|\(null\)|system|local system|anonymous|anonymous logon)$/i;
const TLDS = new Set('com net org edu gov mil int io co info biz local lan internal corp home intra arpa cloud app dev ai me tv us uk au nz ca de fr jp cn in br ru nl se no es it ch eu asia online site tech xyz top club live store'.split(' '));
const FILE_EXT = new Set('txt log json xml py js mjs sh md csv conf cfg ini yaml yml exe dll sys html htm php asp aspx jsp pdf doc docx xls xlsx zip gz tar tgz bat ps1 vbs jar class png jpg gif svg msi bin dat tmp bak'.split(' '));
const RESERVED_DOMAIN = /(^|\.)(example\.(com|net|org)|example|test|invalid|localhost)$/i;

const DOC_V4 = ['192.0.2', '198.51.100', '203.0.113'];
const KEEP_V4 = new Set(['0.0.0.0', '127.0.0.1', '255.255.255.255']);

const RE = {
  email: /\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b/g,
  ipv4: /(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\d)/g,
  ipv6: /(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{0,4}|(?:\d{1,3}\.){3}\d{1,3})(?![\w:])/g,
  mac: /\b[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}\b/g,
  fqdn: /(?<![\w@.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![\w-]|\.[A-Za-z0-9])/g,
  hex: /\b[0-9a-fA-F]{32,}\b/g,
  b64: /(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{40,}={0,2}(?![A-Za-z0-9+/=_-])/g,
};

function isIPv4(s) {
  return net.isIPv4(s);
}

function isFqdn(s) {
  if (RESERVED_DOMAIN.test(s)) return false;
  const labels = s.split('.');
  const tld = labels[labels.length - 1].toLowerCase();
  if (/^\d+$/.test(tld) || FILE_EXT.has(tld)) return false;
  return TLDS.has(tld) || labels.length >= 3;
}

// ---------------------------------------------------------------- the masker

class Masker {
  constructor() {
    this.maps = { ipv4: new Map(), ipv6: new Map(), email: new Map(), host: new Map(), user: new Map(), mac: new Map(), token: new Map() };
    this.warnings = new Set();
  }

  /** The placeholder for a value of a kind, the same every time within this file. */
  get(kind, value, make) {
    const m = this.maps[kind];
    if (!m.has(value)) m.set(value, make(m.size + 1));
    return m.get(value);
  }

  ipv4(v) {
    if (KEEP_V4.has(v) || !isIPv4(v)) return v;
    return this.get('ipv4', v, (n) => {
      const i = (n - 1) % (DOC_V4.length * 254);
      if (n > DOC_V4.length * 254) this.warnings.add(`More than ${DOC_V4.length * 254} distinct IPv4 addresses: documentation addresses are reused, so two real addresses can share one.`);
      return `${DOC_V4[Math.floor(i / 254)]}.${(i % 254) + 1}`;
    });
  }

  ipv6(v) {
    if (!net.isIPv6(v) || v === '::' || v === '::1') return v;
    return this.get('ipv6', v.toLowerCase(), (n) => `2001:db8::${n.toString(16)}`);
  }

  email(v) {
    if (RESERVED_DOMAIN.test(v.split('@')[1] || '')) return v;
    return this.get('email', v.toLowerCase(), (n) => `user${n}@example.com`);
  }

  host(v, { fqdn = false } = {}) {
    if (KEEP_VALUE.test(v) || RESERVED_DOMAIN.test(v)) return v;
    if (isIPv4(v)) return this.ipv4(v);
    return this.get('host', v.toLowerCase(), (n) => (fqdn || v.includes('.') ? `host${n}.example.com` : `host${n}`));
  }

  user(v) {
    if (KEEP_VALUE.test(v) || /^user\d+(@example\.com)?$/.test(v)) return v;
    if (/^[^@\s]+@[^@\s]+\.[A-Za-z]{2,24}$/.test(v)) return this.email(v);
    return this.get('user', v.toLowerCase(), (n) => `user${n}`);
  }

  mac(v, sep) {
    return this.get('mac', v.toLowerCase(), (n) => {
      if (n > 256) this.warnings.add('More than 256 distinct MAC addresses: documentation MAC addresses are reused.');
      return ['00', '00', '5e', '00', '53', ((n - 1) % 256).toString(16).padStart(2, '0')].join(sep);
    });
  }

  token(v) {
    return this.get('token', v, (n) => {
      const id = String(n);
      if (/^[0-9a-f]+$/i.test(v)) return id.padStart(v.length, '0');
      return `${'X'.repeat(Math.max(0, v.length - id.length))}${id}`.slice(-v.length);
    });
  }

  secret(v) {
    if (KEEP_VALUE.test(v)) return v;
    return this.token(v);
  }

  counts() {
    return Object.fromEntries(Object.entries(this.maps).map(([k, m]) => [k, m.size]));
  }
}

// Replace the value of a key in JSON ("key": "value"), key=value text (CEF, LEEF, KV, quoted or
// not), and XML (<Key>value</Key> and Name="Key">value<).
function maskKeyed(line, test, fn) {
  let out = line.replace(/"([A-Za-z_][\w.-]*)"(\s*:\s*)"((?:[^"\\]|\\.)*)"/g, (m, k, sep, v) => (test(k) ? `"${k}"${sep}"${fn(v, k)}"` : m));
  out = out.replace(/(^|[\s|,;{?&])([A-Za-z_][\w.-]*)=("([^"]*)"|'([^']*)'|((?:\\=|[^=\t|])*?))(?=\s+[A-Za-z_][\w.-]*=|\t|\||[,;&]\s*[A-Za-z_][\w.-]*=|"|$)/g, (m, pre, k, whole, dq, sq, bare) => {
    if (!test(k)) return m;
    if (dq !== undefined) return `${pre}${k}="${fn(dq, k)}"`;
    if (sq !== undefined) return `${pre}${k}='${fn(sq, k)}'`;
    const trimmed = bare.replace(/\s+$/, '');
    return `${pre}${k}=${trimmed ? fn(trimmed, k) : trimmed}${bare.slice(trimmed.length)}`;
  });
  out = out.replace(/<([A-Za-z_][\w.-]*)>([^<]+)<\/\1>/g, (m, k, v) => (test(k) ? `<${k}>${fn(v, k)}</${k}>` : m));
  out = out.replace(/(Name=["'])([A-Za-z_][\w.-]*)(["'][^>]*>)([^<]+)</g, (m, a, k, b, v) => (test(k) ? `${a}${k}${b}${fn(v, k)}<` : m));
  return out;
}

const lastKey = (k) => k.toLowerCase().split('.').pop();
const isUserKey = (k) => USER_KEYS.has(lastKey(k)) || /(user_?name|usrname|user_?principal_?name|account_?name|logon_?name)$/.test(lastKey(k));
const isHostKey = (k) => HOST_KEYS.has(lastKey(k)) || /(host_?name|computer_?name|device_?name|workstation_?name|machine_?name)$/.test(lastKey(k));

// The host in a syslog header: RFC 3164 (<pri>Mmm dd hh:mm:ss host) and RFC 5424 (<pri>1 time host).
function maskSyslogHost(line, masker) {
  return line
    .replace(/^(<\d{1,3}>)?([A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}) (?!\d{1,3}(?:\.\d{1,3}){3}\b)([A-Za-z0-9][\w.-]*) /, (m, pri = '', time, host) => `${pri}${time} ${masker.host(host)} `)
    .replace(/^(<\d{1,3}>\d{1,2} \S+) (?!\d{1,3}(?:\.\d{1,3}){3}\b)(?!-\s)([A-Za-z0-9][\w.-]*) /, (m, head, host) => `${head} ${masker.host(host)} `);
}

/** Mask one line with a masker that the whole file shares. */
export function maskLine(line, masker) {
  let s = line;
  // Secrets first, so a token is never read as a host name or an address.
  for (const f of findGenericApiKeys(s)) if (f.secret && s.includes(f.secret)) s = s.split(f.secret).join(masker.token(f.secret));
  s = maskKeyed(s, (k) => SECRET_KEYS.test(k.split('.').pop()), (v) => masker.secret(v));
  s = s.replace(RE.hex, (v) => masker.token(v));
  s = s.replace(RE.b64, (v) => (/[A-Z]/.test(v) && /[a-z]/.test(v) && /\d/.test(v) ? masker.token(v) : v));
  // Then the values of user and host keys, which no pattern can tell apart from other text.
  s = maskKeyed(s, isUserKey, (v) => masker.user(v));
  s = maskKeyed(s, isHostKey, (v) => masker.host(v));
  s = maskSyslogHost(s, masker);
  // Then anything that looks like an address or a name wherever it sits.
  s = s.replace(RE.email, (v) => masker.email(v));
  s = s.replace(RE.mac, (v, sep) => masker.mac(v, sep));
  s = s.replace(RE.ipv6, (v) => masker.ipv6(v));
  s = s.replace(RE.ipv4, (v) => masker.ipv4(v));
  s = s.replace(RE.fqdn, (v) => (isFqdn(v) ? masker.host(v, { fqdn: true }) : v));
  return s;
}

/** Mask a whole file's text: { text, counts, warnings }. Line breaks are kept. */
export function maskText(text) {
  const masker = new Masker();
  const out = String(text).split(/(\r?\n)/).map((part, i) => (i % 2 ? part : maskLine(part, masker))).join('');
  return { text: out, counts: masker.counts(), warnings: [...masker.warnings] };
}

// ---------------------------------------------------------------- the workspace

/** The git work tree a path is in, or null. Looks for .git upward without running git. */
export function gitWorkTree(p) {
  let dir = path.resolve(p);
  for (;;) {
    if (fs.existsSync(path.join(dir, '.git'))) return dir;
    const up = path.dirname(dir);
    if (up === dir) return null;
    dir = up;
  }
}

/** True when git says the path is ignored. A path git can't be asked about counts as not ignored. */
export function gitIgnored(p) {
  const tree = gitWorkTree(p);
  if (!tree) return false;
  const r = spawnSync('git', ['-C', tree, 'check-ignore', '-q', '--no-index', path.relative(tree, path.resolve(p)) || '.'], { encoding: 'utf8' });
  return r.status === 0;
}

/** Refuse a folder for customer lines that a commit could pick up. */
export function assertPrivatePath(p, what = 'The sample workspace') {
  const tree = gitWorkTree(p);
  if (tree && !gitIgnored(p)) {
    throw new UsageError(`${what} ${p} is inside the git work tree ${tree} and git doesn't ignore it, so a commit could take customer lines with it. Use a folder outside any repository (the default is under the state folder), or add it to .gitignore first.`);
  }
}

export function samplesRoot(env = process.env) {
  return path.join(stateDir(env), 'samples');
}

function writePrivate(file, text) {
  fs.writeFileSync(file, text, { mode: 0o600 });
  try {
    fs.chmodSync(file, 0o600);
  } catch {
    // Windows has no POSIX modes
  }
}

function makePrivateDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(dir, 0o700);
  } catch {
    // Windows has no POSIX modes
  }
}

export function newWorkspaceId(now = new Date()) {
  return `s-${now.toISOString().replace(/[-:]/g, '').replace(/\..*$/, '').replace('T', '-')}-${crypto.randomBytes(2).toString('hex')}`;
}

/** Lines with content, without trailing line breaks. */
export function sampleLines(text) {
  return String(text).replace(/\r\n?/g, '\n').split('\n').filter((l) => l.trim() !== '');
}

/**
 * Put raw lines in a workspace with a masked copy beside them. Returns the paths and the counts;
 * never the lines themselves.
 */
export function addToWorkspace(rawText, { workspace, env = process.env, label = null } = {}) {
  const dir = workspace ? path.resolve(workspace) : path.join(samplesRoot(env), newWorkspaceId());
  assertPrivatePath(dir);
  makePrivateDir(dir);
  const lines = sampleLines(rawText);
  if (!lines.length) throw new UsageError('The file has no sample lines.');
  const raw = `${lines.join('\n')}\n`;
  const masked = maskText(raw);
  writePrivate(path.join(dir, 'raw.log'), raw);
  writePrivate(path.join(dir, 'masked.log'), masked.text);
  writePrivate(path.join(dir, 'workspace.json'), `${JSON.stringify({ createdAt: new Date().toISOString(), label, lines: lines.length }, null, 2)}\n`);
  return { workspace: dir, raw: path.join(dir, 'raw.log'), masked: path.join(dir, 'masked.log'), lines: lines.length, maskedValues: masked.counts, warnings: masked.warnings };
}

/** Every raw and masked line in the workspaces under the state folder, and in any extra folders. */
export function localSampleLines({ env = process.env, extra = [] } = {}) {
  const out = new Set();
  const dirs = [...extra];
  const root = samplesRoot(env);
  if (fs.existsSync(root)) for (const d of fs.readdirSync(root, { withFileTypes: true })) if (d.isDirectory()) dirs.push(path.join(root, d.name));
  for (const d of dirs) {
    for (const f of ['raw.log', 'masked.log']) {
      const p = path.join(d, f);
      if (fs.existsSync(p)) for (const l of sampleLines(fs.readFileSync(p, 'utf8'))) out.add(l);
    }
  }
  return out;
}

export function readSampleFile(file) {
  if (!fs.existsSync(file)) throw new SfsError(`No file at ${file}.`, { code: 'not_found' });
  return fs.readFileSync(file, 'utf8');
}
