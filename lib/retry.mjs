// Retry policy, shared by the token, REST and GraphQL calls.
//
// Reads retry on 429, 5xx, timeouts and dropped connections. Writes retry
// only on 429, which Sophos sends before doing any work. A write that hits a
// 5xx, a timeout or a dropped connection is never sent again, because it may
// already have taken effect.

import { retryAfterMs } from './retry-after.mjs';
import { safeFetch, TimeoutError } from './http.mjs';
import { HostNotAllowedError, MutationUnconfirmedError, RedirectRefusedError, TenantNotOnFusionError } from './errors.mjs';
import { log } from './log.mjs';

export const DEFAULTS = { retries: 3, backoffBaseMs: 1000, timeoutMs: 30_000 };

const TENANT_NOT_ON_FUSION = /\btenant (\S+) not found or not accessible\b/i;

let sleeper = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Tests replace the sleep so retries run instantly. */
export function setSleep(fn) {
  sleeper = fn;
}

export function sleep(ms) {
  return sleeper(ms);
}

/**
 * Send a request with the retry policy. Returns the Response for any status
 * that is not retried; the caller reads the body. Throws for errors that end
 * the attempt for good.
 */
export async function sendWithRetry(url, init, { write = false, retries = DEFAULTS.retries, backoffBaseMs = DEFAULTS.backoffBaseMs, timeoutMs = DEFAULTS.timeoutMs, label = 'request' } = {}) {
  for (let attempt = 0; ; attempt++) {
    let response;
    try {
      response = await safeFetch(url, init, { timeoutMs });
    } catch (error) {
      if (error instanceof HostNotAllowedError || error instanceof RedirectRefusedError) throw error;
      const timedOut = error instanceof TimeoutError;
      if (write) {
        throw new MutationUnconfirmedError(`The ${label} ${timedOut ? 'timed out' : 'lost its connection'}.`, timedOut ? 'timeout' : 'connection');
      }
      if (attempt >= retries) throw error;
      const wait = backoff(backoffBaseMs, attempt);
      log(`${label}: ${timedOut ? 'timed out' : 'connection failed'}, retrying in ${wait} ms (attempt ${attempt + 1} of ${retries})`);
      await sleep(wait);
      continue;
    }

    if (response.status === 429) {
      if (attempt >= retries) return response;
      const wait = retryAfterMs(response.headers.get('retry-after'), backoff(backoffBaseMs, attempt) + backoffBaseMs);
      await drain(response);
      log(`${label}: rate limited, waiting ${wait} ms (attempt ${attempt + 1} of ${retries})`);
      await sleep(wait);
      continue;
    }

    if (response.status >= 500) {
      if (response.status === 503) {
        const text = await response.clone().text().catch(() => '');
        const m = TENANT_NOT_ON_FUSION.exec(text);
        if (m) throw new TenantNotOnFusionError(m[1].replace(/[^A-Za-z0-9-]/g, ''), shortDetail(text));
      }
      if (write) {
        const text = await response.text().catch(() => '');
        throw new MutationUnconfirmedError(`The ${label} got HTTP ${response.status} (${shortDetail(text)}).`, 'server_error');
      }
      if (attempt >= retries) return response;
      const wait = retryAfterMs(response.headers.get('retry-after'), backoff(backoffBaseMs, attempt));
      await drain(response);
      log(`${label}: HTTP ${response.status}, retrying in ${wait} ms (attempt ${attempt + 1} of ${retries})`);
      await sleep(wait);
      continue;
    }

    return response;
  }
}

function backoff(base, attempt) {
  // Full jitter on an exponential cap
  return Math.round(Math.random() * base * 2 ** attempt);
}

async function drain(response) {
  try {
    await response.body?.cancel();
  } catch {
    // nothing to release
  }
}

function shortDetail(text) {
  if (!text) return 'no body';
  try {
    const j = JSON.parse(text);
    const msg = j?.errors?.[0]?.message || j?.message || j?.error;
    if (msg) return String(msg).slice(0, 300);
  } catch {
    // not JSON
  }
  return text.slice(0, 300);
}
