import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { FusionClient, isMutation } from '../lib/graphql.mjs';
import { Session } from '../lib/session.mjs';
import { GraphQLError, HttpError, MutationUnconfirmedError } from '../lib/errors.mjs';
import { setSleep } from '../lib/retry.mjs';
import { setQuiet } from '../lib/log.mjs';
import { installFetch } from './helpers/mock-fetch.mjs';
import { authRules, FAKE } from './helpers/scenario.mjs';

setQuiet(true);
setSleep(async () => {});

function client() {
  return new FusionClient(new Session({ name: 'p', clientId: FAKE.clientId, clientSecret: FAKE.clientSecret, kind: 'test', tenantId: null }));
}

describe('FusionClient', () => {
  let mock;
  afterEach(() => mock?.restore());

  test('spots mutations, comments included', () => {
    assert.equal(isMutation('mutation { a }'), true);
    assert.equal(isMutation('  # note\nmutation X { a }'), true);
    assert.equal(isMutation('query { a }'), false);
    assert.equal(isMutation('{ mutationLike }'), false);
  });

  test('sends the tenant header and returns data', async () => {
    mock = installFetch([...authRules(), { match: { op: 'playbooks' }, respond: { status: 200, json: { data: { playbooks: [] } } } }]);
    const r = await client().request('query { playbooks { id } }');
    assert.deepEqual(r, { data: { playbooks: [] }, warnings: [] });
    const call = mock.calls.find((c) => c.op === 'playbooks');
    assert.equal(call.headers['x-tenant-id'], FAKE.tenantId);
    assert.equal(call.headers.authorization, `Bearer ${FAKE.token}`);
  });

  test('a 200 with errors and no data is an error', async () => {
    mock = installFetch([...authRules(), { match: { op: 'playbook' }, respond: { status: 200, json: { data: { playbook: null }, errors: [{ message: 'PB21: record not found', path: ['playbook'] }] } } }]);
    await assert.rejects(() => client().request('query { playbook(playbookId: "x") { id } }'), (e) => e instanceof GraphQLError && e.notFound);
  });

  test('errors beside usable data come back as warnings', async () => {
    mock = installFetch([...authRules(), { match: { op: 'a' }, respond: { status: 200, json: { data: { a: 1, b: null }, errors: [{ message: 'b failed', path: ['b'] }] } } }]);
    const r = await client().request('query { a b }');
    assert.equal(r.data.a, 1);
    assert.deepEqual(r.warnings, ['b failed (path: b)']);
  });

  test('a schema rejection (HTTP 400 with errors) keeps the message', async () => {
    mock = installFetch([...authRules(), { match: { op: 'x' }, respond: { status: 400, json: { errors: [{ message: 'Cannot query field "x"', extensions: { code: 'GRAPHQL_VALIDATION_FAILED' } }] } } }]);
    await assert.rejects(() => client().request('query { x }'), (e) => e instanceof GraphQLError && /Cannot query field/.test(e.message));
  });

  test('a query is retried on 5xx', async () => {
    mock = installFetch([...authRules(), { match: { op: 'playbooks' }, responses: [{ status: 502 }, { status: 200, json: { data: { playbooks: [] } } }] }]);
    await client().request('query { playbooks { id } }');
    assert.equal(mock.calls.filter((c) => c.op === 'playbooks').length, 2);
  });

  test('a mutation is sent once on 5xx and reported as unconfirmed', async () => {
    mock = installFetch([...authRules(), { match: { op: 'deletePlaybook' }, respond: { status: 503, json: { message: 'busy' } } }]);
    await assert.rejects(() => client().request('mutation { deletePlaybook(input: {playbookId: "x"}) { id } }'), MutationUnconfirmedError);
    assert.equal(mock.calls.filter((c) => c.op === 'deletePlaybook').length, 1);
  });

  test('a mutation answered with an empty body is unconfirmed, not success', async () => {
    mock = installFetch([...authRules(), { match: { op: 'createConnection' }, respond: { status: 200, text: '' } }]);
    await assert.rejects(() => client().request('mutation { createConnection { id } }'), MutationUnconfirmedError);
  });

  test('a read retries the transient "error response from central" fault', async () => {
    const fault = { status: 200, json: { data: { playbooks: null }, errors: [{ message: 'error response from central: ', path: ['tenant', 'centralTenant'], extensions: { code: 'DOWNSTREAM_SERVICE_ERROR' } }] } };
    mock = installFetch([...authRules(), { match: { op: 'playbooks' }, responses: [fault, fault, { status: 200, json: { data: { playbooks: [] } } }] }]);
    const r = await client().request('query { playbooks { id } }');
    assert.deepEqual(r.data.playbooks, []);
    assert.equal(mock.calls.filter((c) => c.op === 'playbooks').length, 3);
  });

  test('a write is not retried on that fault', async () => {
    const fault = { status: 200, json: { data: { importPlaybookV2: null }, errors: [{ message: 'error response from central: ', path: ['tenant', 'centralTenant'] }] } };
    mock = installFetch([...authRules(), { match: { op: 'deletePlaybook' }, respond: fault }]);
    await assert.rejects(() => client().request('mutation { deletePlaybook(input: {playbookId: "x"}) { id } }'), GraphQLError);
    assert.equal(mock.calls.filter((c) => c.op === 'deletePlaybook').length, 1);
  });

  test('other GraphQL errors on a read are not retried', async () => {
    mock = installFetch([...authRules(), { match: { op: 'playbook' }, respond: { status: 200, json: { data: { playbook: null }, errors: [{ message: 'PB21: record not found' }] } } }]);
    await assert.rejects(() => client().request('query { playbook(playbookId: "x") { id } }'), GraphQLError);
    assert.equal(mock.calls.filter((c) => c.op === 'playbook').length, 1);
  });

  test('a persistent 429 surfaces as an HTTP error after retries', async () => {
    mock = installFetch([...authRules(), { match: { op: 'playbooks' }, respond: { status: 429 } }]);
    await assert.rejects(() => client().request('query { playbooks { id } }'), (e) => e instanceof HttpError && e.status === 429);
  });

  test('uploads use the multipart request format with the file at variables.input.file', async () => {
    let seen;
    const original = globalThis.fetch;
    mock = installFetch([...authRules(), { match: { op: 'importPlaybookV2' }, respond: { status: 200, json: { data: { importPlaybookV2: { id: 'pb1', name: 'ZZTest_X', head: { id: 'v1', version: '1.0.0', published: '2026-01-01' } } } } } }]);
    const inner = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      if (init?.body instanceof FormData) seen = init;
      return inner(url, init);
    };
    try {
      const r = await client().upload('mutation($input: ImportPlaybookInput!) { importPlaybookV2(input: $input) { id name } }', { filename: 'template.yaml', content: 'kind: Playbook\n' });
      assert.equal(r.data.importPlaybookV2.id, 'pb1');
      assert.equal(JSON.parse(seen.body.get('map'))['0'][0], 'variables.input.file');
      assert.equal(JSON.parse(seen.body.get('operations')).variables.input.file, null);
      assert.equal(await seen.body.get('0').text(), 'kind: Playbook\n');
      assert.equal(new Headers(seen.headers).get('apollo-require-preflight'), 'true');
    } finally {
      globalThis.fetch = original;
    }
  });
});
