// Scripted fetch for tests. Two ways to use it:
//
// 1. In-process: import { installFetch } and give it rules.
// 2. For a CLI run in a child process: node --import ./test/helpers/mock-fetch.mjs
//    with SFS_MOCK_SCENARIO pointing at a JSON file of rules and SFS_MOCK_LOG at a
//    file that receives one JSON line per request.
//
// A rule: { match: { url?: substring, op?: GraphQL root field, method? },
//           respond: { status, json?, text?, headers? } | responses: [ ... ] | throws: 'timeout'|'network' }
// With responses, each call takes the next one and the last one repeats.

import fs from 'node:fs';

export function graphqlOp(body) {
  let query = '';
  if (typeof body === 'string') {
    try {
      query = JSON.parse(body).query || '';
    } catch {
      query = '';
    }
  } else if (body && typeof body.get === 'function') {
    try {
      query = JSON.parse(body.get('operations')).query || '';
    } catch {
      query = '';
    }
  }
  const m = /^\s*(?:(?:query|mutation)\b[^{]*)?\{\s*([A-Za-z_][A-Za-z0-9_]*)/.exec(query);
  return m ? m[1] : null;
}

export function isMutationBody(body) {
  try {
    const q = typeof body === 'string' ? JSON.parse(body).query : JSON.parse(body.get('operations')).query;
    return /^\s*mutation\b/.test(q || '');
  } catch {
    return false;
  }
}

function makeResponse(r) {
  const headers = new Headers(r.headers || {});
  let body = r.text ?? (r.json !== undefined ? JSON.stringify(r.json) : '');
  if (r.json !== undefined && !headers.has('content-type')) headers.set('content-type', 'application/json');
  return new Response(r.status === 204 ? null : body, { status: r.status ?? 200, headers });
}

export function createFetch(rules, onCall = () => {}) {
  const counters = new Map();
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    const u = String(url);
    const op = graphqlOp(init.body);
    const call = { url: u, method: init.method || 'GET', op, mutation: isMutationBody(init.body), headers: Object.fromEntries(new Headers(init.headers || {}).entries()), redirect: init.redirect ?? null, body: typeof init.body === 'string' ? init.body : init.body ? '[form]' : null };
    calls.push(call);
    onCall(call);
    const idx = rules.findIndex((r) => (!r.match.url || u.includes(r.match.url)) && (!r.match.op || r.match.op === op) && (!r.match.method || r.match.method === call.method));
    if (idx === -1) throw new Error(`mock fetch: no rule for ${call.method} ${u} ${op || ''}`);
    const rule = rules[idx];
    const n = counters.get(idx) ?? 0;
    counters.set(idx, n + 1);
    const step = rule.responses ? rule.responses[Math.min(n, rule.responses.length - 1)] : rule;
    if (step.throws === 'timeout') {
      const e = new Error('aborted');
      e.name = 'AbortError';
      throw e;
    }
    if (step.throws === 'network') throw new TypeError('fetch failed');
    if (step.bodyError || step.bodyStall) {
      const stream = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('{"data":'));
          if (step.bodyError) controller.error(new TypeError('terminated'));
          if (step.bodyStall && init.signal) init.signal.addEventListener('abort', () => controller.error(Object.assign(new Error('aborted'), { name: 'AbortError' })));
        },
      });
      return new Response(stream, { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return makeResponse(step.respond ?? step);
  };
  return { fetch: fetchImpl, calls };
}

export function installFetch(rules) {
  const original = globalThis.fetch;
  const mock = createFetch(rules);
  globalThis.fetch = mock.fetch;
  return { calls: mock.calls, restore: () => (globalThis.fetch = original) };
}

// Child-process mode
if (process.env.SFS_MOCK_SCENARIO) {
  const rules = JSON.parse(fs.readFileSync(process.env.SFS_MOCK_SCENARIO, 'utf8'));
  const logFile = process.env.SFS_MOCK_LOG;
  const mock = createFetch(rules, (call) => {
    if (logFile) fs.appendFileSync(logFile, `${JSON.stringify(call)}\n`);
  });
  globalThis.fetch = mock.fetch;
}
