import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { addIdentifier, addSecret, clearSecrets, findIdentifiers, findLeaks, redact, redactText } from '../lib/redact.mjs';

describe('redaction', () => {
  beforeEach(() => clearSecrets());

  test('replaces registered secret values anywhere', () => {
    addSecret('s3cr3t-client-value');
    assert.equal(redactText('secret is s3cr3t-client-value, again s3cr3t-client-value'), 'secret is [redacted], again [redacted]');
  });

  test('ignores very short values so it does not shred text', () => {
    addSecret('abc');
    assert.equal(redactText('abc def'), 'abc def');
  });

  test('replaces bearer tokens, JWTs and secret query pairs', () => {
    const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlYWJj';
    assert.equal(redactText('Authorization: Bearer abcdefgh12345678'), 'Authorization: Bearer [redacted]');
    assert.equal(redactText(`token ${jwt} end`), 'token [redacted] end');
    assert.equal(redactText('grant_type=x&client_secret=hunter2hunter2&scope=token'), 'grant_type=x&client_secret=[redacted]&scope=token');
  });

  test('replaces values under secret-looking keys, deep in objects', () => {
    const out = redact({ a: { clientSecret: 'x1', password: 'p', token: 't', list: [{ api_key: 'k' }] }, safe: 'ok', flag: true });
    assert.deepEqual(out, { a: { clientSecret: '[redacted]', password: '[redacted]', token: '[redacted]', list: [{ api_key: '[redacted]' }] }, safe: 'ok', flag: true });
  });

  test('the same object twice is not mistaken for a loop', () => {
    const shared = { tenantId: 'x' };
    assert.deepEqual(redact({ a: shared, b: shared }), { a: { tenantId: 'x' }, b: { tenantId: 'x' } });
    const loop = { name: 'n' };
    loop.self = loop;
    assert.equal(redact(loop).self, '[circular]');
  });
});

describe('leak detection in logs', () => {
  beforeEach(() => clearSecrets());

  test('finds tokens, webhook URLs, signed URLs and key pairs', () => {
    const logs = [
      { message: { request: { url: 'https://hooks.slack.com/services/T000/B000/XXXXXXXX' } } },
      { message: { request: { headers: 'Bearer abcdefghijklmnopqrstuvwxyz' } } },
      { message: { response: 'https://x.blob.core.windows.net/c?sv=2020&sig=abcdefghijklmnop' } },
      { message: { body: '{"password": "Winter2026!!"}' } },
      { message: { body: '-----BEGIN RSA PRIVATE KEY-----' } },
    ];
    const kinds = findLeaks(logs).map((l) => l.kind).sort();
    assert.deepEqual(kinds, ['bearer_token', 'private_key', 'secret_pair', 'signed_url', 'webhook_url']);
  });

  test('does not flag a template that reads a secret at run time', () => {
    assert.deepEqual(findLeaks({ url: 'https://api.example.com/login?password=${inputs.password}' }), []);
  });

  test('flags a registered secret and never shows it', () => {
    addSecret('the-real-client-secret');
    const found = findLeaks({ note: 'oops the-real-client-secret here' });
    assert.equal(found.length, 1);
    assert.equal(found[0].kind, 'known_secret');
    assert.equal(found[0].sample, '[redacted]');
  });
});

describe('the client ID in logs', () => {
  beforeEach(() => clearSecrets());

  // The shape Fusion puts in a case event when the API credential closed the case
  const event = (actor) => ({
    message: {
      inputs: {
        case: {
          createdById: actor,
          updatedById: actor,
          contributorIds: [actor],
          delta: { changes: { closed_by_id: { before: null, after: actor } } },
        },
      },
    },
  });

  test('is listed as an identifier, not a secret', () => {
    addSecret('the-real-client-secret');
    addIdentifier('11111111-aaaa-4bbb-8ccc-222222222222', 'client ID');
    const logs = [event('11111111-aaaa-4bbb-8ccc-222222222222')];
    assert.deepEqual(findLeaks(logs), []);
    const ids = findIdentifiers(logs);
    assert.deepEqual(ids.map((i) => i.path).sort(), [
      '$[0].message.inputs.case.contributorIds[0]',
      '$[0].message.inputs.case.createdById',
      '$[0].message.inputs.case.delta.changes.closed_by_id.after',
      '$[0].message.inputs.case.updatedById',
    ]);
    assert.ok(ids.every((i) => i.identifier === 'client ID'));
  });

  test('stays out of output, behind a marker that names it', () => {
    addIdentifier('11111111-aaaa-4bbb-8ccc-222222222222', 'client ID');
    assert.equal(redactText('closed by 11111111-aaaa-4bbb-8ccc-222222222222'), 'closed by [client ID]');
    assert.deepEqual(redact({ createdById: '11111111-aaaa-4bbb-8ccc-222222222222' }), { createdById: '[client ID]' });
  });

  test('a shorter secret inside the client ID cannot leave part of it showing', () => {
    addSecret('4bbb-8ccc');
    addIdentifier('11111111-aaaa-4bbb-8ccc-222222222222', 'client ID');
    assert.equal(redactText('by 11111111-aaaa-4bbb-8ccc-222222222222, then 4bbb-8ccc'), 'by [client ID], then [redacted]');
  });

  test('is an identifier even when another path also registered it as a secret', () => {
    addSecret('11111111-aaaa-4bbb-8ccc-222222222222');
    addIdentifier('11111111-aaaa-4bbb-8ccc-222222222222', 'client ID');
    assert.deepEqual(findLeaks(event('11111111-aaaa-4bbb-8ccc-222222222222')), []);
    assert.equal(redactText('11111111-aaaa-4bbb-8ccc-222222222222'), '[client ID]');
  });

  test('a real secret is still flagged, in an ID field or next to the client ID', () => {
    addSecret('the-real-client-secret');
    addIdentifier('11111111-aaaa-4bbb-8ccc-222222222222', 'client ID');
    const kinds = (v) => findLeaks(v).map((l) => l.kind);
    assert.deepEqual(kinds(event('the-real-client-secret')), ['known_secret', 'known_secret', 'known_secret', 'known_secret']);
    assert.deepEqual(kinds({ body: 'client_id=11111111-aaaa-4bbb-8ccc-222222222222&client_secret=the-real-client-secret' }), ['secret_pair', 'known_secret']);
    assert.deepEqual(kinds({ updatedById: 'Bearer abcdefghijklmnopqrstuvwxyz' }), ['bearer_token']);
  });
});
