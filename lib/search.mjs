// Data Lake Search, through the documented Search GraphQL API on the same Fusion endpoint as
// everything else. A search is asynchronous: createSearch starts it, search(urn) is polled until
// COMPLETE, outcome.success says whether every partition worked, and searchResults pages the rows
// by cursor.
//
// createSearch is a mutation but changes no configuration, so it needs no --yes. It is never sent
// twice for one search: FusionClient treats it as a write and doesn't retry it after a 5xx, a
// timeout or a dropped connection, because a repeat would start a second search. The polls and
// page reads are queries and retry as usual.
//
// Rows can hold customer data. Callers print field names and counts, and values only when the
// user asks for them.

import { MutationUnconfirmedError, SfsError } from './errors.mjs';
import { sleep } from './retry.mjs';

// searchResults refuses a limit above 1000, and a search returns at most 10,000 rows, newest first.
export const MAX_PAGE = 1000;
export const ROW_CAP = 10_000;

const SEARCH_FIELDS = 'urn status errors queryText createTime endTime expireTime outcome { success errors { urn errors } }';

export class SearchFailedError extends SfsError {
  constructor(message) {
    super(message, { code: 'search_failed' });
    this.name = 'SearchFailedError';
  }
}

/** Quotes a value for a QL string literal. */
export function qlString(s) {
  return `'${String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`;
}

/** The time bounds of a QL search, with a leading space: " earliest=-7d latest='2026-10-31T00:00:00Z'". */
export function qlTime({ earliest = '-7d', latest = null } = {}) {
  const one = (k, v) => (v ? ` ${k}=${/^-\d+[smhdw]$/.test(v) || v === 'now' ? v : qlString(v)}` : '');
  return `${one('earliest', earliest)}${one('latest', latest)}`;
}

/** A relative time such as -24h, -7d or 30m, as milliseconds. */
export function durationMs(text) {
  const m = /^-?(\d+)(s|m|h|d|w)$/.exec(String(text || '').trim());
  if (!m) return null;
  return Number(m[1]) * { s: 1e3, m: 60e3, h: 3600e3, d: 86400e3, w: 7 * 86400e3 }[m[2]];
}

async function startSearch(client, text) {
  try {
    const { data } = await client.request(`mutation($input: CreateSearchInput) { createSearch(input: $input) { ${SEARCH_FIELDS} } }`, { input: { text } }, { operation: 'createSearch' });
    if (!data.createSearch?.urn) throw new SearchFailedError('Data Lake Search answered createSearch without a search ID.');
    return data.createSearch;
  } catch (error) {
    // A search changes nothing on the tenant, so an unconfirmed start is just a failed read.
    if (error instanceof MutationUnconfirmedError) throw new SearchFailedError(`The search could not be started (${error.failure}). Nothing on the tenant changed; run the command again.`);
    throw error;
  }
}

/** Polls until COMPLETE. PARTIAL is kept and reported; NONE or UNKNOWN fails. */
export async function waitForSearch(client, search, { pollMs = 2000, maxWaitMs = 15 * 60_000 } = {}) {
  const started = Date.now();
  let s = search;
  let delay = pollMs;
  while (s.status !== 'COMPLETE') {
    if (Date.now() - started > maxWaitMs) throw new SearchFailedError(`The search was still ${s.status} after ${Math.round(maxWaitMs / 60_000)} minutes.`);
    await sleep(delay);
    delay = Math.min(delay * 1.5, 10_000);
    const { data } = await client.request(`query($urn: URN!) { search(urn: $urn) { ${SEARCH_FIELDS} } }`, { urn: s.urn }, { operation: 'search' });
    s = data.search;
    if (!s) throw new SearchFailedError('The search is gone before it finished.');
  }
  const success = s.outcome?.success;
  const partitionErrors = (s.outcome?.errors || []).flatMap((p) => p.errors || []);
  if (success === 'ALL') return { search: s, partial: false, partitionErrors };
  if (success === 'PARTIAL') return { search: s, partial: true, partitionErrors };
  const why = partitionErrors.join('; ') || (s.errors || []).join('; ') || 'no error given';
  throw new SearchFailedError(`The search failed (outcome ${success || 'UNKNOWN'}): ${why}`);
}

/** Pages searchResults by cursor until there is no next cursor or max rows are in hand. */
export async function readRows(client, search, { max = ROW_CAP } = {}) {
  const rows = [];
  let cursor = null;
  let total = null;
  do {
    const { data } = await client.request(
      'query($urn: URN!, $cursor: String, $limit: Int) { searchResults(urn: $urn, cursor: $cursor, limit: $limit) { values totals { total { value } } nextCursor } }',
      { urn: search.urn, cursor, limit: Math.max(1, Math.min(MAX_PAGE, max - rows.length)) },
      { operation: 'searchResults' },
    );
    const page = data.searchResults || {};
    const values = Array.isArray(page.values) ? page.values : typeof page.values === 'string' ? JSON.parse(page.values) : [];
    rows.push(...values.map((v) => (typeof v === 'string' ? JSON.parse(v) : v)));
    if (total === null && page.totals?.total) total = Number(page.totals.total.value);
    cursor = page.nextCursor || null;
  } while (cursor && rows.length < max);
  return { rows, total };
}

/**
 * Runs a QL query to completion: { rows, total, partial, partitionErrors, capped }. capped is true
 * when the search hit its 10,000-row limit, so counts are lower bounds.
 */
export async function searchRows(client, text, { max = ROW_CAP, pollMs, maxWaitMs } = {}) {
  const started = await startSearch(client, text);
  const done = await waitForSearch(client, started, { pollMs, maxWaitMs });
  const { rows, total } = await readRows(client, done.search, { max });
  return { rows, total, partial: done.partial, partitionErrors: done.partitionErrors, capped: (total ?? rows.length) >= ROW_CAP };
}

/** The UTC day of a row, from its event or ingest time in microseconds. */
export function rowDay(row) {
  const usec = Number(row?.event_time_usec) || Number(row?.ingest_time_usec) || 0;
  return usec > 0 ? new Date(Math.floor(usec / 1000)).toISOString().slice(0, 10) : 'unknown';
}
