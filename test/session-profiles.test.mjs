import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { Session, regionFromHost } from '../lib/session.mjs';
import { saveProfile, selectProfile, listProfiles, readStore, profilesPath, removeProfile, setDefault } from '../lib/profiles.mjs';
import { resolveSecret } from '../lib/secrets.mjs';
import { HostNotAllowedError, SfsError, UsageError } from '../lib/errors.mjs';
import { setSleep } from '../lib/retry.mjs';
import { setQuiet } from '../lib/log.mjs';
import { clearSecrets, redactText } from '../lib/redact.mjs';
import { installFetch } from './helpers/mock-fetch.mjs';
import { authRules, FAKE, tempDir } from './helpers/scenario.mjs';

setQuiet(true);
setSleep(async () => {});

const profile = (extra = {}) => ({ name: 'p', source: 'profile', clientId: FAKE.clientId, clientSecret: FAKE.clientSecret, kind: 'test', tenantId: null, label: null, ...extra });

describe('region and tenant resolution', () => {
  let mock;
  afterEach(() => mock?.restore());

  test('reads the region from the data region host', () => {
    assert.equal(regionFromHost('https://api-eu02.central.sophos.com'), 'eu02');
    assert.equal(regionFromHost('https://api-us01.central.sophos.com/'), 'us01');
    assert.equal(regionFromHost('https://api.central.sophos.com'), null);
  });

  test('a tenant credential targets its own tenant and region', async () => {
    mock = installFetch(authRules({ region: 'us01' }));
    const s = new Session(profile());
    const t = await s.target();
    assert.equal(t.tenantId, FAKE.tenantId);
    assert.equal(t.idType, 'tenant');
    assert.equal(t.region, 'us01');
    const tokenCall = mock.calls.find((c) => c.url.includes('oauth2/token'));
    assert.match(tokenCall.body, /grant_type=client_credentials/);
    assert.equal(tokenCall.redirect, 'manual');
    const who = mock.calls.find((c) => c.url.includes('whoami'));
    assert.equal(who.headers.authorization, `Bearer ${FAKE.token}`);
  });

  test('a tenant credential refuses a different --tenant', async () => {
    mock = installFetch(authRules());
    const s = new Session(profile(), { tenantOverride: '99999999-2222-4333-8444-555555555555' });
    await assert.rejects(() => s.target(), UsageError);
  });

  test('a partner credential needs a target tenant', async () => {
    mock = installFetch(authRules({ idType: 'partner', id: 'partner-0001' }));
    await assert.rejects(() => new Session(profile()).target(), (e) => e instanceof SfsError && e.code === 'tenant_required');
  });

  test('a partner credential picks its tenant from all pages of the tenant list', async () => {
    const wanted = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
    mock = installFetch([
      ...authRules({ idType: 'partner', id: 'partner-0001' }),
      { match: { url: 'partner/v1/tenants?page=1' }, respond: { status: 200, json: { pages: { current: 1, total: 2 }, items: [{ id: '00000000-0000-4000-8000-000000000001', name: 'First', dataRegion: 'eu01', apiHost: 'https://api-eu01.central.sophos.com' }] } } },
      { match: { url: 'partner/v1/tenants?page=2' }, respond: { status: 200, json: { pages: { current: 2, total: 2 }, items: [{ id: wanted, name: 'Second', dataRegion: 'au01', apiHost: 'https://api-au01.central.sophos.com' }] } } },
    ]);
    const s = new Session(profile({ tenantId: wanted }));
    const t = await s.target();
    assert.equal(t.tenantId, wanted);
    assert.equal(t.tenantName, 'Second');
    assert.equal(t.region, 'au01');
    assert.equal(t.idType, 'partner');
    const list = mock.calls.filter((c) => c.url.includes('partner/v1/tenants'));
    assert.equal(list.length, 2);
    assert.equal(list[0].headers['x-partner-id'], 'partner-0001');
  });

  test('an organization credential sends X-Organization-ID and rejects an unknown tenant', async () => {
    mock = installFetch([
      ...authRules({ idType: 'organization', id: 'org-0001' }),
      { match: { url: 'organization/v1/tenants' }, respond: { status: 200, json: { pages: { total: 1 }, items: [{ id: '00000000-0000-4000-8000-000000000001', name: 'Only', dataRegion: 'us02', apiHost: 'https://api-us02.central.sophos.com' }] } } },
    ]);
    const s = new Session(profile({ tenantId: '00000000-0000-4000-8000-000000000009' }));
    await assert.rejects(() => s.target(), (e) => e.code === 'tenant_not_visible');
    assert.equal(mock.calls.find((c) => c.url.includes('organization/v1')).headers['x-organization-id'], 'org-0001');
  });

  test('a host in an answer that is not Sophos is refused before the token goes there', async () => {
    mock = installFetch([
      ...authRules({ idType: 'partner', id: 'partner-0001' }),
      { match: { url: 'partner/v1/tenants' }, respond: { status: 200, json: { pages: { total: 1 }, items: [{ id: '00000000-0000-4000-8000-000000000001', name: 'Odd', apiHost: 'https://api.attacker.example' }] } } },
    ]);
    const s = new Session(profile({ tenantId: '00000000-0000-4000-8000-000000000001' }));
    await assert.rejects(() => s.target(), HostNotAllowedError);
    assert.ok(!mock.calls.some((c) => c.url.includes('attacker')));
  });

  test('bad credentials give a plain message without the secret', async () => {
    clearSecrets();
    mock = installFetch([{ match: { url: 'oauth2/token' }, respond: { status: 401, json: { errorCode: 'oauth.invalid_client_secret', message: 'bad' } } }]);
    const s = new Session(profile());
    await assert.rejects(() => s.token(), (e) => e.code === 'auth_failed' && !e.message.includes(FAKE.clientSecret));
    assert.equal(redactText(`x ${FAKE.clientSecret} y`), 'x [redacted] y');
  });
});

describe('profiles', () => {
  const env = (dir, extra = {}) => ({ SOPHOS_FUSION_CONFIG_DIR: dir, PATH: process.env.PATH, ...extra });

  test('a saved profile file is 0600 in a 0700 folder and never echoes the secret', () => {
    const dir = path.join(tempDir(), 'cfg');
    const r = saveProfile('lab', { clientId: 'client-abcdef123', clientSecret: 'very-secret-value', kind: 'test' }, env(dir));
    assert.equal(fs.statSync(profilesPath(env(dir))).mode & 0o777, 0o600);
    assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
    assert.equal(r.profile.clientSecret, 'stored in profile file');
    assert.equal(r.profile.clientId, 'clie...f123');
    assert.ok(!JSON.stringify(listProfiles(env(dir))).includes('very-secret-value'));
  });

  test('profiles default to production, and the kind is checked', () => {
    const dir = tempDir();
    saveProfile('prod', { clientId: 'a', clientSecret: 'b' }, env(dir));
    assert.equal(readStore(env(dir)).profiles.prod.kind, 'production');
    assert.throws(() => saveProfile('x', { clientId: 'a', clientSecret: 'b', kind: 'staging' }, env(dir)), UsageError);
    assert.throws(() => saveProfile('env', { clientId: 'a', clientSecret: 'b' }, env(dir)), UsageError);
  });

  test('environment variables win over profiles; --profile wins over both', () => {
    const dir = tempDir();
    saveProfile('lab', { clientId: 'file-id', clientSecret: 'file-secret', kind: 'test', makeDefault: true }, env(dir));
    const e = env(dir, { SOPHOS_FUSION_CLIENT_ID: 'env-id', SOPHOS_FUSION_CLIENT_SECRET: 'env-secret' });
    assert.equal(selectProfile({ env: e }).name, 'env');
    assert.equal(selectProfile({ env: e }).kind, 'production');
    assert.equal(selectProfile({ env: { ...e, SOPHOS_FUSION_PROFILE_KIND: 'test' } }).kind, 'test');
    assert.equal(selectProfile({ name: 'lab', env: e }).clientId, 'file-id');
    assert.equal(selectProfile({ env: env(dir) }).name, 'lab');
  });

  test('a half-set environment is an error, and no credentials says what to do', () => {
    assert.throws(() => selectProfile({ env: { SOPHOS_FUSION_CLIENT_ID: 'x', SOPHOS_FUSION_CONFIG_DIR: tempDir() } }), UsageError);
    assert.throws(() => selectProfile({ env: { SOPHOS_FUSION_CONFIG_DIR: tempDir() } }), (e) => e.code === 'no_credentials');
  });

  test('partner profiles keep a target tenant, which must be a UUID', () => {
    const dir = tempDir();
    saveProfile('mssp', { clientId: 'a', clientSecret: 'b', tenantId: 'AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE' }, env(dir));
    assert.equal(readStore(env(dir)).profiles.mssp.tenantId, 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee');
    assert.throws(() => saveProfile('bad', { clientId: 'a', clientSecret: 'b', tenantId: '12345' }, env(dir)), UsageError);
  });

  test('default and remove', () => {
    const dir = tempDir();
    saveProfile('a', { clientId: 'a', clientSecret: 'b' }, env(dir));
    saveProfile('b', { clientId: 'a', clientSecret: 'b' }, env(dir));
    setDefault('b', env(dir));
    assert.equal(readStore(env(dir)).default, 'b');
    removeProfile('b', env(dir));
    assert.equal(readStore(env(dir)).default, 'a');
  });
});

describe('1Password references (stubbed op)', () => {
  function stubOp(dir, { fail = false } = {}) {
    const bin = path.join(dir, 'op-stub.mjs');
    fs.writeFileSync(bin, `#!${process.execPath}\nconst [cmd, flag, ref] = process.argv.slice(2);\nif (${fail} || cmd !== 'read' || flag !== '--no-newline' || !ref.startsWith('op://')) { process.stderr.write('stub refused'); process.exit(1); }\nprocess.stdout.write('stub-secret-for-' + ref.split('/').pop());\n`, { mode: 0o755 });
    return bin;
  }

  test('reads an op:// reference through the op CLI', () => {
    const dir = tempDir();
    const v = resolveSecret('op://Vault/Item/client_secret', { env: { SOPHOS_FUSION_OP_BIN: stubOp(dir), PATH: process.env.PATH } });
    assert.equal(v, 'stub-secret-for-client_secret');
    assert.equal(redactText('x stub-secret-for-client_secret'), 'x [redacted]');
  });

  test('a failed op read says so without leaking anything', () => {
    const dir = tempDir();
    assert.throws(() => resolveSecret('op://Vault/Item/x', { env: { SOPHOS_FUSION_OP_BIN: stubOp(dir, { fail: true }), PATH: process.env.PATH } }), (e) => e.code === 'secret_unavailable');
  });

  test('a missing op binary is reported plainly', () => {
    assert.throws(() => resolveSecret('op://Vault/Item/x', { env: { SOPHOS_FUSION_OP_BIN: '/nonexistent/op', PATH: '' } }), (e) => /not installed/.test(e.message));
  });

  test('plain values pass through', () => {
    assert.equal(resolveSecret('plain-value-123'), 'plain-value-123');
  });

  test('a session resolves op:// references for the token request', async () => {
    const dir = tempDir();
    const mock = installFetch(authRules());
    try {
      const s = new Session(profile({ clientId: 'op://V/I/id', clientSecret: 'op://V/I/secret' }), { env: { SOPHOS_FUSION_OP_BIN: stubOp(dir), PATH: process.env.PATH } });
      await s.token();
      const body = mock.calls[0].body;
      assert.match(body, /client_id=stub-secret-for-id/);
      assert.match(body, /client_secret=stub-secret-for-secret/);
    } finally {
      mock.restore();
    }
  });
});
