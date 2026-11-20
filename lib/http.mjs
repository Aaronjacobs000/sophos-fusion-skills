// The one place a request leaves the machine. It checks the host against the
// allowlist, refuses redirects, and applies a timeout.

import { ALLOWED_HOSTS } from './constants.mjs';
import { HostNotAllowedError, RedirectRefusedError } from './errors.mjs';

export function isAllowedUrl(url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (u.protocol !== 'https:') return false;
  if (u.username || u.password || u.port) return false;
  return ALLOWED_HOSTS.some((re) => re.test(u.hostname));
}

export function assertAllowedUrl(url) {
  if (!isAllowedUrl(url)) {
    let host = null;
    try {
      host = new URL(url).host;
    } catch {
      host = String(url).slice(0, 60);
    }
    throw new HostNotAllowedError(host);
  }
}

/** A base URL (scheme and host only) that Sophos named in an answer, checked before use. */
export function allowedBase(host) {
  const value = typeof host === 'string' ? host.replace(/\/+$/, '') : '';
  let u;
  try {
    u = new URL(value);
  } catch {
    throw new HostNotAllowedError(value);
  }
  if (u.pathname !== '/' || u.search || u.hash || !isAllowedUrl(value)) throw new HostNotAllowedError(u.host);
  return `${u.protocol}//${u.host}`;
}

export class TimeoutError extends Error {
  constructor(ms) {
    super(`Request timed out after ${ms} ms`);
    this.name = 'TimeoutError';
  }
}

/**
 * fetch with the safety rules applied. Throws HostNotAllowedError before
 * anything is sent, RedirectRefusedError for any 3xx, TimeoutError on timeout.
 * Other network failures surface as the fetch error.
 */
export async function safeFetch(url, init = {}, { timeoutMs = 30_000 } = {}) {
  assertAllowedUrl(url);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let response;
    try {
      response = await globalThis.fetch(url, { ...init, redirect: 'manual', signal: controller.signal });
    } catch (error) {
      if (error?.name === 'AbortError') throw new TimeoutError(timeoutMs);
      throw error;
    }
    if (response.status >= 300 && response.status <= 399) {
      try {
        await response.body?.cancel();
      } catch {
        // nothing to release
      }
      throw new RedirectRefusedError(response.status, url, response.headers.get('location'));
    }
    // Read the whole body under the same timeout, so a stalled or dropped body
    // counts as a failed request (and, for a write, an unconfirmed one).
    let body;
    try {
      body = await response.arrayBuffer();
    } catch (error) {
      if (error?.name === 'AbortError' || controller.signal.aborted) throw new TimeoutError(timeoutMs);
      throw new TypeError(`connection dropped while reading the answer: ${error?.message || error}`);
    }
    return new Response(response.status === 204 || response.status === 304 ? null : body, { status: response.status, statusText: response.statusText, headers: response.headers });
  } finally {
    clearTimeout(timer);
  }
}
