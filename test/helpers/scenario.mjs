// Helpers for tests that run a real CLI script in a child process against the mock fetch.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
// --import takes a module specifier, and a bare Windows path (C:\...) is not one.
const MOCK = pathToFileURL(path.join(ROOT, 'test', 'helpers', 'mock-fetch.mjs')).href;

export const FAKE = {
  clientId: 'test-client-id-0001',
  clientSecret: 'test-client-secret-value-0001',
  token: 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJldGVzdA',
  tenantId: '11111111-2222-4333-8444-555555555555',
};

/** Token and whoami rules for a tenant credential in eu02. */
export function authRules({ region = 'eu02', idType = 'tenant', id = FAKE.tenantId } = {}) {
  return [
    { match: { url: 'id.sophos.com/api/v2/oauth2/token' }, respond: { status: 200, json: { access_token: FAKE.token, expires_in: 3600, token_type: 'bearer', errorCode: 'success' } } },
    { match: { url: 'api.central.sophos.com/whoami/v1' }, respond: { status: 200, json: { id, idType, apiHosts: { global: 'https://api.central.sophos.com', ...(idType === 'tenant' ? { dataRegion: `https://api-${region}.central.sophos.com` } : {}) } } } },
  ];
}

export function tempDir(prefix = 'sfs-test-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/**
 * Run a script with the mock fetch. Returns { status, stdout, stderr, json, calls }.
 * env adds to a clean environment that carries the fake credential.
 */
export function runScript(script, args, { rules = [], env = {}, kind = 'test', stateDir, configDir } = {}) {
  const dir = tempDir('sfs-run-');
  const scenario = path.join(dir, 'scenario.json');
  const log = path.join(dir, 'calls.jsonl');
  fs.writeFileSync(scenario, JSON.stringify(rules));
  const childEnv = {
    PATH: process.env.PATH,
    HOME: dir,
    USERPROFILE: dir,
    SFS_MOCK_SCENARIO: scenario,
    SFS_MOCK_LOG: log,
    SOPHOS_FUSION_CLIENT_ID: FAKE.clientId,
    SOPHOS_FUSION_CLIENT_SECRET: FAKE.clientSecret,
    SOPHOS_FUSION_PROFILE_KIND: kind,
    SOPHOS_FUSION_STATE_DIR: stateDir ?? path.join(dir, 'state'),
    SOPHOS_FUSION_CONFIG_DIR: configDir ?? path.join(dir, 'config'),
    ...env,
  };
  const r = spawnSync(process.execPath, ['--import', MOCK, path.join(ROOT, script), ...args], { env: childEnv, encoding: 'utf8', cwd: ROOT, timeout: 60_000 });
  let json = null;
  try {
    json = JSON.parse(r.stdout);
  } catch {
    json = null;
  }
  const calls = fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, json, calls };
}
