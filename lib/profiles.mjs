// Credential profiles. Environment variables win; otherwise a named profile
// from profiles.json in the config folder (folder 0700, file 0600).

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { SfsError, UsageError } from './errors.mjs';
import { isOpReference } from './secrets.mjs';
import { addSecret } from './redact.mjs';
import { replaceFile } from './fsx.mjs';

export const KINDS = ['test', 'production'];
const NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function configDir(env = process.env) {
  return env.SOPHOS_FUSION_CONFIG_DIR || path.join(os.homedir(), '.config', 'sophos-fusion-skills');
}

export function profilesPath(env = process.env) {
  return path.join(configDir(env), 'profiles.json');
}

function emptyStore() {
  return { version: 1, default: null, profiles: {} };
}

export function readStore(env = process.env) {
  const file = profilesPath(env);
  if (!fs.existsSync(file)) return emptyStore();
  let data;
  try {
    data = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    throw new SfsError(`${file} is not valid JSON. Fix or remove it, then run the setup again.`, { code: 'bad_profiles' });
  }
  if (!data || typeof data !== 'object' || typeof data.profiles !== 'object') return emptyStore();
  return { version: 1, default: data.default ?? null, profiles: data.profiles };
}

export function writeStore(store, env = process.env) {
  const dir = configDir(env);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  const file = profilesPath(env);
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(store, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(tmp, 0o600);
  replaceFile(tmp, file);
  fs.chmodSync(file, 0o600);
  return file;
}

export function validateProfileName(name) {
  if (typeof name !== 'string' || !NAME.test(name) || name === 'env') {
    throw new UsageError('Profile names use letters, digits, dot, dash and underscore, up to 63 characters, and "env" is reserved.');
  }
  return name;
}

export function validateKind(kind) {
  if (!KINDS.includes(kind)) throw new UsageError(`--kind must be one of: ${KINDS.join(', ')}.`);
  return kind;
}

export function validateTenantId(id) {
  if (id === undefined || id === null || id === '') return null;
  if (!UUID.test(id)) throw new UsageError('A tenant ID is the Sophos tenant UUID, for example 3f2c...-....');
  return id.toLowerCase();
}

export function saveProfile(name, fields, env = process.env) {
  validateProfileName(name);
  const store = readStore(env);
  const existing = store.profiles[name] || {};
  const profile = {
    clientId: fields.clientId ?? existing.clientId,
    clientSecret: fields.clientSecret ?? existing.clientSecret,
    kind: validateKind(fields.kind ?? existing.kind ?? 'production'),
    tenantId: fields.tenantId !== undefined ? validateTenantId(fields.tenantId) : existing.tenantId ?? null,
    label: fields.label ?? existing.label ?? null,
  };
  if (!profile.clientId || !profile.clientSecret) {
    throw new UsageError('A profile needs both a client ID and a client secret (a value or an op:// reference).');
  }
  store.profiles[name] = profile;
  if (fields.makeDefault || !store.default) store.default = name;
  const file = writeStore(store, env);
  return { file, name, profile: describeProfile(name, profile, store.default) };
}

export function removeProfile(name, env = process.env) {
  const store = readStore(env);
  if (!store.profiles[name]) throw new SfsError(`No profile named ${name}.`, { code: 'no_profile' });
  delete store.profiles[name];
  if (store.default === name) store.default = Object.keys(store.profiles)[0] ?? null;
  writeStore(store, env);
  return { removed: name, default: store.default };
}

export function setDefault(name, env = process.env) {
  const store = readStore(env);
  if (!store.profiles[name]) throw new SfsError(`No profile named ${name}.`, { code: 'no_profile' });
  store.default = name;
  writeStore(store, env);
  return { default: name };
}

/** A profile as it may be printed: the secret is never shown, only how it is stored. */
export function describeProfile(name, p, defaultName) {
  return {
    name,
    kind: p.kind,
    default: name === defaultName,
    clientId: isOpReference(p.clientId) ? p.clientId : maskId(p.clientId),
    clientSecret: isOpReference(p.clientSecret) ? '1Password reference' : 'stored in profile file',
    tenantId: p.tenantId ?? null,
    label: p.label ?? null,
  };
}

function maskId(id) {
  if (typeof id !== 'string' || id.length < 8) return '[set]';
  return `${id.slice(0, 4)}...${id.slice(-4)}`;
}

export function listProfiles(env = process.env) {
  const store = readStore(env);
  return Object.entries(store.profiles).map(([n, p]) => describeProfile(n, p, store.default));
}

/**
 * Pick the credential to use. Order: SOPHOS_FUSION_CLIENT_ID and
 * SOPHOS_FUSION_CLIENT_SECRET in the environment, then the --profile name,
 * then SOPHOS_FUSION_PROFILE, then the default profile.
 * Returns raw values (possibly op:// references), not resolved secrets.
 */
export function selectProfile({ name, env = process.env } = {}) {
  const envId = env.SOPHOS_FUSION_CLIENT_ID;
  const envSecret = env.SOPHOS_FUSION_CLIENT_SECRET;
  if (!name && (envId || envSecret)) {
    if (!envId || !envSecret) {
      throw new UsageError('Set both SOPHOS_FUSION_CLIENT_ID and SOPHOS_FUSION_CLIENT_SECRET, or neither.');
    }
    if (!isOpReference(envSecret)) addSecret(envSecret);
    const envTenant = validateTenantId(env.SOPHOS_FUSION_TENANT_ID || null);
    return {
      name: 'env',
      source: 'environment',
      clientId: envId,
      clientSecret: envSecret,
      kind: validateKind(env.SOPHOS_FUSION_PROFILE_KIND || 'production'),
      tenantId: envTenant,
      savedTenantId: envTenant,
      label: null,
    };
  }
  const store = readStore(env);
  const chosen = name || env.SOPHOS_FUSION_PROFILE || store.default;
  if (!chosen) {
    throw new SfsError('No credentials found. Run the setup skill to add a profile, or set SOPHOS_FUSION_CLIENT_ID and SOPHOS_FUSION_CLIENT_SECRET.', {
      code: 'no_credentials',
    });
  }
  const p = store.profiles[chosen];
  if (!p) throw new SfsError(`No profile named ${chosen}. List profiles with: profile.mjs list`, { code: 'no_profile' });
  if (!isOpReference(p.clientSecret)) addSecret(p.clientSecret);
  return {
    name: chosen,
    source: 'profile',
    clientId: p.clientId,
    clientSecret: p.clientSecret,
    kind: validateKind(p.kind || 'production'),
    tenantId: env.SOPHOS_FUSION_TENANT_ID ? validateTenantId(env.SOPHOS_FUSION_TENANT_ID) : p.tenantId ?? null,
    // The tenant the profile was saved for. The write gate compares the target with it,
    // so SOPHOS_FUSION_TENANT_ID pointing elsewhere counts like --tenant.
    savedTenantId: p.tenantId ?? null,
    label: p.label ?? null,
  };
}
