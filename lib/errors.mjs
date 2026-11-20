// Error types the scripts raise on purpose. Each carries a stable code so the
// JSON output can be read by an agent without parsing the message.

export class SfsError extends Error {
  constructor(message, { code = 'failed', exitCode = 1, details } = {}) {
    super(message);
    this.name = 'SfsError';
    this.code = code;
    this.exitCode = exitCode;
    if (details !== undefined) this.details = details;
  }
}

export class UsageError extends SfsError {
  constructor(message) {
    super(message, { code: 'usage', exitCode: 2 });
    this.name = 'UsageError';
  }
}

// A write was asked for without the confirmation flags it needs.
export class GateError extends SfsError {
  constructor(message, details) {
    super(message, { code: 'write_not_confirmed', exitCode: 3, details });
    this.name = 'GateError';
  }
}

export class HostNotAllowedError extends SfsError {
  constructor(host) {
    super(`Refused to call ${host || 'an unnamed host'}: only Sophos API hosts on the allowlist are called.`, {
      code: 'host_not_allowed',
    });
    this.name = 'HostNotAllowedError';
  }
}

export class RedirectRefusedError extends SfsError {
  constructor(status, url, location) {
    const where = safeHost(location, url);
    super(
      `Sophos answered ${describeUrl(url)} with a ${status} redirect${where ? ` to ${where}` : ''}. Redirects are never followed, so nothing was sent there.`,
      { code: 'redirect_refused' },
    );
    this.name = 'RedirectRefusedError';
    this.status = status;
  }
}

// Fusion's 503 for a tenant it does not hold, or one this credential cannot
// reach. The answer is the same every time, so it is never retried.
export class TenantNotOnFusionError extends SfsError {
  constructor(tenantId, detail) {
    super(
      `Sophos Fusion says tenant ${tenantId} was not found or is not accessible to this credential. Check the tenant ID and that the tenant is on Sophos Fusion. Not retried.${detail ? ` Fusion said: ${detail}` : ''}`,
      { code: 'tenant_not_on_fusion' },
    );
    this.name = 'TenantNotOnFusionError';
    this.tenantId = tenantId;
  }
}

// A write that failed in a way that leaves its effect unknown.
export class MutationUnconfirmedError extends SfsError {
  constructor(message, failure) {
    super(
      `${message} The write was not retried because it may already have taken effect. Read the object back before trying again.`,
      { code: 'write_unconfirmed', details: { failure } },
    );
    this.name = 'MutationUnconfirmedError';
    this.failure = failure;
  }
}

export class GraphQLError extends SfsError {
  constructor(errors, { operation } = {}) {
    const text = errors.map(formatGraphQLError).join('; ');
    super(`Sophos Fusion returned an error${operation ? ` for ${operation}` : ''}: ${text}`, {
      code: 'graphql_error',
      details: { errors: errors.map((e) => ({ message: e.message, path: e.path, code: e.extensions?.code })) },
    });
    this.name = 'GraphQLError';
    this.errors = errors;
  }

  get notFound() {
    return this.errors.length > 0 && this.errors.every((e) => /not found|unable to get .* from database|does not exist/i.test(e.message || ''));
  }
}

export class HttpError extends SfsError {
  constructor(status, message) {
    super(message, { code: `http_${status}` });
    this.name = 'HttpError';
    this.status = status;
  }
}

export function formatGraphQLError(error) {
  const parts = [error?.message || 'unknown error'];
  if (Array.isArray(error?.path) && error.path.length) parts.push(`(path: ${error.path.join('.')})`);
  const code = error?.extensions?.code;
  if (typeof code === 'string' && code) parts.push(`[${code}]`);
  return parts.join(' ');
}

function describeUrl(url) {
  try {
    const u = new URL(url);
    return `${u.host}${u.pathname}`;
  } catch {
    return 'the request';
  }
}

function safeHost(location, base) {
  if (!location) return null;
  try {
    return new URL(location, base).host;
  } catch {
    return null;
  }
}
