// Retry-After (RFC 9110 section 10.2.3) is either whole seconds or an HTTP date.

export const MAX_RETRY_AFTER_MS = 60_000;

// IMF-fixdate, RFC 850 and asctime dates all start with a day name. Checking
// for it stops Date.parse from reading "1.5" or "60" as a date.
const HTTP_DATE_START = /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*,?\s/i;

/**
 * Milliseconds to wait before a retry. A date in the past means now. A missing
 * or unreadable header gives fallbackMs. Never more than MAX_RETRY_AFTER_MS.
 */
export function retryAfterMs(header, fallbackMs, now = Date.now()) {
  const value = typeof header === 'string' ? header.trim() : '';
  if (!value) return Math.min(fallbackMs, MAX_RETRY_AFTER_MS);
  let ms;
  if (/^\d+$/.test(value)) {
    ms = Number(value) * 1000;
  } else if (HTTP_DATE_START.test(value)) {
    // asctime dates carry no zone and are UTC
    const at = Date.parse(/\b(GMT|UTC)\b/i.test(value) ? value : `${value} GMT`);
    if (Number.isNaN(at)) return Math.min(fallbackMs, MAX_RETRY_AFTER_MS);
    ms = Math.max(0, at - now);
  } else {
    return Math.min(fallbackMs, MAX_RETRY_AFTER_MS);
  }
  return Math.min(ms, MAX_RETRY_AFTER_MS);
}
