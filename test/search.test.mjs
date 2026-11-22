import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { durationMs, qlString, qlTime, rowDay, searchRows, SearchFailedError } from '../lib/search.mjs';
import { setSleep } from '../lib/retry.mjs';
import { setQuiet } from '../lib/log.mjs';
import { FusionClient } from '../lib/graphql.mjs';
import { installFetch } from './helpers/mock-fetch.mjs';
import { FAKE } from './helpers/scenario.mjs';

setQuiet(true);

const session = { token: async () => FAKE.token, target: async () => ({ tenantId: FAKE.tenantId }) };
const client = () => new FusionClient(session, { backoffBaseMs: 1 });
const search = (status, success = 'ALL', extra = {}) => ({ urn: 'urn:search:1', status, errors: [], queryText: 'q', createTime: '2026-11-22T00:00:00Z', endTime: null, expireTime: '2999-01-01T00:00:00Z', outcome: { success, errors: [] }, ...extra });

describe('Data Lake Search', () => {
  before(() => setSleep(async () => {}));
  after(() => setSleep((ms) => new Promise((r) => setTimeout(r, ms))));

  test('starts once, polls until COMPLETE, and pages the rows by cursor', async () => {
    const mock = installFetch([
      { match: { op: 'createSearch' }, respond: { json: { data: { createSearch: search('RUNNING', null) } } } },
      { match: { op: 'search' }, responses: [{ json: { data: { search: search('RUNNING', null) } } }, { json: { data: { search: search('COMPLETE') } } }] },
      {
        match: { op: 'searchResults' },
        responses: [
          { json: { data: { searchResults: { values: [{ a: 1 }, { a: 2 }], totals: { total: { value: 3 } }, nextCursor: 'c2' } } } },
          { json: { data: { searchResults: { values: [JSON.stringify({ a: 3 })], totals: null, nextCursor: null } } } },
        ],
      },
    ]);
    try {
      const r = await searchRows(client(), 'from generic where sensor_type = \'x\'');
      assert.deepEqual(r.rows, [{ a: 1 }, { a: 2 }, { a: 3 }]);
      assert.equal(r.total, 3);
      assert.equal(r.partial, false);
      assert.equal(mock.calls.filter((c) => c.op === 'createSearch').length, 1);
      assert.equal(mock.calls.filter((c) => c.op === 'search').length, 2);
      const page2 = JSON.parse(mock.calls.filter((c) => c.op === 'searchResults')[1].body).variables;
      assert.equal(page2.cursor, 'c2');
    } finally {
      mock.restore();
    }
  });

  test('never sends createSearch twice after a 5xx: a repeat would start a second search', async () => {
    const mock = installFetch([{ match: { op: 'createSearch' }, respond: { status: 502, text: 'bad gateway' } }]);
    try {
      await assert.rejects(searchRows(client(), 'from generic'), (e) => e instanceof SearchFailedError && /could not be started/.test(e.message));
      assert.equal(mock.calls.length, 1);
    } finally {
      mock.restore();
    }
  });

  test('keeps a PARTIAL outcome and reports it; fails NONE', async () => {
    const mock = installFetch([
      { match: { op: 'createSearch' }, respond: { json: { data: { createSearch: search('COMPLETE', 'PARTIAL') } } } },
      { match: { op: 'searchResults' }, respond: { json: { data: { searchResults: { values: [], totals: { total: { value: 0 } }, nextCursor: null } } } } },
    ]);
    try {
      const r = await searchRows(client(), 'from generic');
      assert.equal(r.partial, true);
    } finally {
      mock.restore();
    }
    const bad = installFetch([{ match: { op: 'createSearch' }, respond: { json: { data: { createSearch: search('COMPLETE', 'NONE', { outcome: { success: 'NONE', errors: [{ urn: 'p', errors: ['partition down'] }] } }) } } } }]);
    try {
      await assert.rejects(searchRows(client(), 'from generic'), /partition down/);
    } finally {
      bad.restore();
    }
  });

  test('quotes values and writes time bounds', () => {
    assert.equal(qlString("it's a \\ test"), "'it\\'s a \\\\ test'");
    assert.equal(qlTime({ earliest: '-7d' }), ' earliest=-7d');
    assert.equal(qlTime({ earliest: '2026-11-01T00:00:00Z', latest: 'now' }), " earliest='2026-11-01T00:00:00Z' latest=now");
    assert.equal(durationMs('-24h'), 86400e3);
    assert.equal(durationMs('30m'), 1800e3);
    assert.equal(durationMs('soon'), null);
    assert.equal(rowDay({ event_time_usec: 1794280891577952 }), '2026-11-10');
    assert.equal(rowDay({}), 'unknown');
  });
});
