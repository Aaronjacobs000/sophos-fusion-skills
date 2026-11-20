import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { isAllowedUrl, assertAllowedUrl, allowedBase, safeFetch, TimeoutError } from '../lib/http.mjs';
import { retryAfterMs, MAX_RETRY_AFTER_MS } from '../lib/retry-after.mjs';
import { sendWithRetry, setSleep } from '../lib/retry.mjs';
import { HostNotAllowedError, MutationUnconfirmedError, RedirectRefusedError, TenantNotOnFusionError } from '../lib/errors.mjs';
import { setQuiet } from '../lib/log.mjs';
import { installFetch } from './helpers/mock-fetch.mjs';

setQuiet(true);
const sleeps = [];
setSleep(async (ms) => {
  sleeps.push(ms);
});

describe('host allowlist', () => {
  test('allows the Sophos API hosts', () => {
    for (const u of ['https://id.sophos.com/api/v2/oauth2/token', 'https://api.central.sophos.com/whoami/v1', 'https://api-eu02.central.sophos.com/x', 'https://api-us01.central.sophos.com', 'https://api.taegis.sophos.com/graphql']) {
      assert.equal(isAllowedUrl(u), true, u);
    }
  });

  test('refuses everything else', () => {
    for (const u of ['http://api.taegis.sophos.com/graphql', 'https://api.taegis.sophos.com.evil.com/graphql', 'https://evil.com/?h=api.taegis.sophos.com', ['https://user:pw', 'api.taegis.sophos.com/graphql'].join('@'), 'https://api.taegis.sophos.com:8443/graphql', 'https://api-eu02.central.sophos.com.example.org', 'https://www.sophos.com', 'not a url', 'https://api-xx1.central.sophos.com']) {
      assert.equal(isAllowedUrl(u), false, u);
    }
    assert.throws(() => assertAllowedUrl('https://evil.com/graphql'), HostNotAllowedError);
  });

  test('allowedBase accepts scheme and host only', () => {
    assert.equal(allowedBase('https://api-eu02.central.sophos.com/'), 'https://api-eu02.central.sophos.com');
    assert.throws(() => allowedBase('https://api-eu02.central.sophos.com/path'), HostNotAllowedError);
    assert.throws(() => allowedBase('https://evil.example'), HostNotAllowedError);
  });
});

describe('safeFetch', () => {
  let mock;
  afterEach(() => mock?.restore());

  test('sends nothing to a host that is not allowed', async () => {
    mock = installFetch([{ match: {}, respond: { status: 200, json: {} } }]);
    await assert.rejects(() => safeFetch('https://evil.example/graphql', { method: 'POST' }), HostNotAllowedError);
    assert.equal(mock.calls.length, 0);
  });

  test('refuses redirects and asks fetch not to follow them', async () => {
    mock = installFetch([{ match: {}, respond: { status: 307, headers: { location: 'https://evil.example/steal' } } }]);
    await assert.rejects(() => safeFetch('https://api.taegis.sophos.com/graphql', { method: 'POST' }), (e) => e instanceof RedirectRefusedError && /evil\.example/.test(e.message));
    assert.equal(mock.calls[0].redirect, 'manual');
  });

  test('turns an abort into a TimeoutError', async () => {
    mock = installFetch([{ match: {}, throws: 'timeout' }]);
    await assert.rejects(() => safeFetch('https://api.taegis.sophos.com/graphql', {}, { timeoutMs: 5 }), TimeoutError);
  });
});

describe('Retry-After', () => {
  const now = Date.parse('2026-11-21T00:00:00Z');
  test('reads seconds', () => assert.equal(retryAfterMs('7', 1000, now), 7000));
  test('reads an HTTP date', () => assert.equal(retryAfterMs('Sat, 21 Nov 2026 00:00:30 GMT', 1000, now), 30_000));
  test('reads an asctime date as UTC', () => assert.equal(retryAfterMs('Sat Nov 21 00:00:10 2026', 1000, now), 10_000));
  test('a date in the past means now', () => assert.equal(retryAfterMs('Fri, 20 Nov 2026 23:00:00 GMT', 1000, now), 0));
  test('caps at 60 seconds', () => {
    assert.equal(retryAfterMs('3600', 1000, now), MAX_RETRY_AFTER_MS);
    assert.equal(retryAfterMs('Sun, 22 Nov 2026 00:00:00 GMT', 1000, now), MAX_RETRY_AFTER_MS);
  });
  test('falls back on junk or a missing header', () => {
    assert.equal(retryAfterMs('soon', 1234, now), 1234);
    assert.equal(retryAfterMs('1.5', 1234, now), 1234);
    assert.equal(retryAfterMs(null, 1234, now), 1234);
    assert.equal(retryAfterMs('', 99_000, now), MAX_RETRY_AFTER_MS);
  });
});

describe('sendWithRetry', () => {
  let mock;
  const URL_ = 'https://api.taegis.sophos.com/graphql';
  beforeEach(() => sleeps.splice(0));
  afterEach(() => mock?.restore());

  test('a read retries a 429 and honors Retry-After', async () => {
    mock = installFetch([{ match: {}, responses: [{ status: 429, headers: { 'retry-after': '2' } }, { status: 200, json: { data: { ok: true } } }] }]);
    const r = await sendWithRetry(URL_, { method: 'POST' }, { write: false, retries: 3 });
    assert.equal(r.status, 200);
    assert.equal(mock.calls.length, 2);
    assert.equal(sleeps[0], 2000);
  });

  test('a read retries 5xx, timeouts and dropped connections', async () => {
    mock = installFetch([{ match: {}, responses: [{ status: 502 }, { throws: 'timeout' }, { throws: 'network' }, { status: 200, json: {} }] }]);
    const r = await sendWithRetry(URL_, { method: 'POST' }, { write: false, retries: 3 });
    assert.equal(r.status, 200);
    assert.equal(mock.calls.length, 4);
  });

  test('a read gives up after the retry budget', async () => {
    mock = installFetch([{ match: {}, respond: { status: 500 } }]);
    const r = await sendWithRetry(URL_, { method: 'POST' }, { write: false, retries: 2 });
    assert.equal(r.status, 500);
    assert.equal(mock.calls.length, 3);
  });

  test('a write is never retried after a 5xx', async () => {
    mock = installFetch([{ match: {}, respond: { status: 500, json: { message: 'boom' } } }]);
    await assert.rejects(() => sendWithRetry(URL_, { method: 'POST' }, { write: true }), (e) => e instanceof MutationUnconfirmedError && e.failure === 'server_error');
    assert.equal(mock.calls.length, 1);
  });

  test('a write is never retried after a timeout', async () => {
    mock = installFetch([{ match: {}, throws: 'timeout' }]);
    await assert.rejects(() => sendWithRetry(URL_, { method: 'POST' }, { write: true, timeoutMs: 5 }), (e) => e instanceof MutationUnconfirmedError && e.failure === 'timeout');
    assert.equal(mock.calls.length, 1);
  });

  test('a write is never retried after a dropped connection', async () => {
    mock = installFetch([{ match: {}, throws: 'network' }]);
    await assert.rejects(() => sendWithRetry(URL_, { method: 'POST' }, { write: true }), (e) => e instanceof MutationUnconfirmedError && e.failure === 'connection');
    assert.equal(mock.calls.length, 1);
  });

  test('a write is retried on 429, which Sophos sends before doing anything', async () => {
    mock = installFetch([{ match: {}, responses: [{ status: 429 }, { status: 200, json: {} }] }]);
    const r = await sendWithRetry(URL_, { method: 'POST' }, { write: true });
    assert.equal(r.status, 200);
    assert.equal(mock.calls.length, 2);
  });

  test('the "tenant not found" 503 is reported plainly and not retried', async () => {
    const body = { errors: [{ message: 'tenant 0c4d-x not found or not accessible' }] };
    for (const write of [false, true]) {
      mock = installFetch([{ match: {}, respond: { status: 503, json: body } }]);
      await assert.rejects(() => sendWithRetry(URL_, { method: 'POST' }, { write }), (e) => e instanceof TenantNotOnFusionError && /not found or is not accessible/.test(e.message));
      assert.equal(mock.calls.length, 1);
      mock.restore();
    }
    mock = null;
  });

  test('a redirect ends the attempt at once', async () => {
    mock = installFetch([{ match: {}, respond: { status: 302, headers: { location: 'https://elsewhere.example' } } }]);
    await assert.rejects(() => sendWithRetry(URL_, { method: 'POST' }, { write: false }), RedirectRefusedError);
    assert.equal(mock.calls.length, 1);
  });
});
