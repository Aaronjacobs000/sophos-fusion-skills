// GraphQL client for the Sophos Fusion automation API. One endpoint for
// every region; the tenant goes in X-Tenant-ID.
//
// A 200 is not success until the body is read: GraphQL errors come back as
// HTTP 200 with an errors array. Errors beside usable data are returned as
// warnings so the caller can surface them.

import { FUSION_GRAPHQL_URL } from './constants.mjs';
import { sendWithRetry, sleep } from './retry.mjs';
import { log } from './log.mjs';

// A read-only fault Fusion sometimes answers with, then not on the next try:
// "error response from central" at path tenant.centralTenant (seen 21/11/2026,
// four times in one session on a list of templates). Reads retry it; writes never do.
export function isTransientReadError(error) {
  return error instanceof GraphQLError && error.errors.length > 0 && error.errors.every((e) => /error response from central/i.test(e.message || '') || (Array.isArray(e.path) && e.path[0] === 'tenant' && e.path[1] === 'centralTenant'));
}
import { GraphQLError, HttpError, MutationUnconfirmedError, SfsError, formatGraphQLError } from './errors.mjs';

/** True when the document's first operation is a mutation (comments skipped). */
export function isMutation(document) {
  return /^(?:\s|#[^\n]*\n)*mutation\b/.test(document);
}

export class FusionClient {
  constructor(session, { url = FUSION_GRAPHQL_URL, timeoutMs = 60_000, retries = 3, backoffBaseMs = 1000 } = {}) {
    this.session = session;
    this.url = url;
    this.timeoutMs = timeoutMs;
    this.retries = retries;
    this.backoffBaseMs = backoffBaseMs;
  }

  async headers(extra = {}) {
    const token = await this.session.token();
    const target = await this.session.target();
    return {
      authorization: `Bearer ${token}`,
      'x-tenant-id': target.tenantId,
      accept: 'application/json',
      ...extra,
    };
  }

  /**
   * Run a query or mutation. Returns { data, warnings }. Mutations must be
   * passed through the write gate before they get here; this layer only
   * decides retries.
   */
  async request(document, variables = {}, { operation, timeoutMs } = {}) {
    const write = isMutation(document);
    for (let attempt = 0; ; attempt++) {
      const headers = await this.headers({ 'content-type': 'application/json' });
      const res = await sendWithRetry(
        this.url,
        { method: 'POST', headers, body: JSON.stringify({ query: document, variables }) },
        { write, retries: this.retries, backoffBaseMs: this.backoffBaseMs, timeoutMs: timeoutMs ?? this.timeoutMs, label: operation || (write ? 'Fusion write' : 'Fusion query') },
      );
      try {
        return await this.readBody(res, { write, operation });
      } catch (error) {
        if (write || attempt >= this.retries || !isTransientReadError(error)) throw error;
        const wait = Math.round(this.backoffBaseMs * (attempt + 1) * (0.5 + Math.random()));
        log(`${operation || 'Fusion query'}: transient "error response from central", retrying in ${wait} ms (attempt ${attempt + 1} of ${this.retries})`);
        await sleep(wait);
      }
    }
  }

  /**
   * Multipart upload (GraphQL multipart request spec) for importPlaybookV2 and
   * importConnector: the file goes in variables.input.file.
   */
  async upload(document, { variablePath = 'variables.input.file', filename, content, contentType = 'application/x-yaml', variables } = {}, { operation } = {}) {
    if (!isMutation(document)) throw new SfsError('upload() is only for mutations.', { code: 'internal' });
    const vars = variables ?? { input: { file: null } };
    const form = new FormData();
    form.append('operations', JSON.stringify({ query: document, variables: vars }));
    form.append('map', JSON.stringify({ 0: [variablePath] }));
    form.append('0', new Blob([content], { type: contentType }), filename);
    const headers = await this.headers({ 'apollo-require-preflight': 'true' });
    const res = await sendWithRetry(this.url, { method: 'POST', headers, body: form }, { write: true, retries: this.retries, backoffBaseMs: this.backoffBaseMs, timeoutMs: this.timeoutMs, label: operation || 'Fusion upload' });
    return this.readBody(res, { write: true, operation });
  }

  async readBody(res, { write, operation }) {
    const text = await res.text();
    let body = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = null;
    }
    if (!res.ok) {
      const errors = Array.isArray(body?.errors) ? body.errors : [];
      if (errors.length) throw new GraphQLError(errors, { operation });
      const detail = body?.message || body?.error || text.slice(0, 300) || 'no body';
      const note = res.status === 429 ? ' Still rate limited after retries.' : '';
      throw new HttpError(res.status, `Sophos Fusion answered HTTP ${res.status}${operation ? ` for ${operation}` : ''}: ${detail}.${note}`);
    }
    if (!body || typeof body !== 'object') {
      if (write) throw new MutationUnconfirmedError(`Sophos Fusion answered ${operation || 'the write'} with an empty or unreadable body.`, 'no_result');
      throw new SfsError(`Sophos Fusion answered ${operation || 'the query'} with an empty or unreadable body.`, { code: 'bad_response' });
    }
    const errors = Array.isArray(body.errors) ? body.errors : [];
    const data = body.data;
    const usable = data && typeof data === 'object' && Object.values(data).some((v) => v !== null && v !== undefined);
    if (errors.length && !usable) throw new GraphQLError(errors, { operation });
    if (!data || typeof data !== 'object') {
      if (write) throw new MutationUnconfirmedError(`Sophos Fusion answered ${operation || 'the write'} with neither data nor errors.`, 'no_result');
      throw new SfsError('Sophos Fusion returned neither data nor errors.', { code: 'bad_response' });
    }
    return { data, warnings: errors.map(formatGraphQLError) };
  }
}
