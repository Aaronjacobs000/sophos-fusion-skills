// A signed-in session: token, caller identity, and the tenant every Fusion call
// goes to. Tenant credentials target their own tenant. Partner and
// organization credentials need a target tenant ID, which is checked against
// the tenants the credential can see.

import { AUTH_URL, GLOBAL_API } from './constants.mjs';
import { allowedBase } from './http.mjs';
import { sendWithRetry } from './retry.mjs';
import { HttpError, SfsError, UsageError } from './errors.mjs';
import { resolveSecret } from './secrets.mjs';
import { selectProfile, validateTenantId } from './profiles.mjs';
import { addSecret } from './redact.mjs';
import { log } from './log.mjs';

const REGION = /^https:\/\/api-([a-z]{2}\d{2})\.central\.sophos\.com$/;

export function regionFromHost(host) {
  const m = REGION.exec(String(host || '').replace(/\/+$/, ''));
  return m ? m[1] : null;
}

export class Session {
  constructor(profile, { env = process.env, tenantOverride } = {}) {
    this.profile = profile;
    this.env = env;
    this.tenantOverride = tenantOverride ? validateTenantId(tenantOverride) : null;
    this._token = null;
    this._expiresAt = 0;
    this._identity = null;
    this._target = null;
    this._tenants = null;
  }

  get kind() {
    return this.profile.kind;
  }

  async token() {
    if (this._token && Date.now() < this._expiresAt - 60_000) return this._token;
    const clientId = resolveSecret(this.profile.clientId, { env: this.env, label: 'client ID' });
    const clientSecret = resolveSecret(this.profile.clientSecret, { env: this.env, label: 'client secret' });
    const body = new URLSearchParams({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret, scope: 'token' });
    const res = await sendWithRetry(
      AUTH_URL,
      { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' }, body: body.toString() },
      { label: 'token request' },
    );
    const text = await res.text();
    let data = null;
    try {
      data = JSON.parse(text);
    } catch {
      // handled below
    }
    if (!res.ok || !data?.access_token) {
      const reason = data?.errorCode || data?.error || data?.message || `HTTP ${res.status}`;
      throw new SfsError(`Sophos refused the client credentials (${String(reason).slice(0, 120)}). Check the client ID and secret.`, { code: 'auth_failed' });
    }
    addSecret(data.access_token);
    this._token = data.access_token;
    this._expiresAt = Date.now() + Number(data.expires_in || 3600) * 1000;
    return this._token;
  }

  async getJson(url, headers = {}, label = 'request') {
    const token = await this.token();
    const res = await sendWithRetry(url, { method: 'GET', headers: { authorization: `Bearer ${token}`, accept: 'application/json', ...headers } }, { label });
    const text = await res.text();
    if (!res.ok) throw new HttpError(res.status, `${label} failed with HTTP ${res.status}: ${text.slice(0, 300)}`);
    try {
      return JSON.parse(text);
    } catch {
      throw new SfsError(`${label} returned a body that is not JSON.`, { code: 'bad_response' });
    }
  }

  /** whoami: { id, idType: tenant|partner|organization, apiHosts: { global, dataRegion? } } */
  async identity() {
    if (this._identity) return this._identity;
    const who = await this.getJson(`${GLOBAL_API}/whoami/v1`, {}, 'whoami');
    if (!who?.id || !['tenant', 'partner', 'organization'].includes(who.idType)) {
      throw new SfsError('whoami returned an identity this tool does not understand.', { code: 'bad_identity' });
    }
    this._identity = who;
    return who;
  }

  /** Tenants a partner or organization credential can see. */
  async tenants() {
    if (this._tenants) return this._tenants;
    const who = await this.identity();
    if (who.idType === 'tenant') {
      this._tenants = [];
      return this._tenants;
    }
    const global = allowedBase(who.apiHosts?.global || GLOBAL_API);
    const pathPart = who.idType === 'partner' ? '/partner/v1/tenants' : '/organization/v1/tenants';
    const header = who.idType === 'partner' ? { 'X-Partner-ID': who.id } : { 'X-Organization-ID': who.id };
    const all = [];
    let page = 1;
    let total = 1;
    while (page <= total && page <= 500) {
      const url = `${global}${pathPart}?page=${page}${page === 1 ? '&pageTotal=true' : ''}`;
      const data = await this.getJson(url, header, 'tenant list');
      if (page === 1) total = Number(data?.pages?.total || 1);
      for (const t of data?.items || []) {
        all.push({ id: t.id, name: t.name, dataRegion: t.dataRegion || regionFromHost(t.apiHost), apiHost: t.apiHost, status: t.status ?? null });
      }
      page++;
    }
    this._tenants = all;
    return all;
  }

  /**
   * The tenant Fusion calls go to: { tenantId, tenantName, idType, region, apiHost, callerId }.
   * Partner and organization credentials need --tenant, SOPHOS_FUSION_TENANT_ID or the profile's tenantId.
   */
  async target() {
    if (this._target) return this._target;
    const who = await this.identity();
    if (who.idType === 'tenant') {
      if (this.tenantOverride && this.tenantOverride !== who.id.toLowerCase()) {
        throw new UsageError('This is a tenant credential, so it can only reach its own tenant. Drop --tenant or use a partner or organization credential.');
      }
      const apiHost = who.apiHosts?.dataRegion ? allowedBase(who.apiHosts.dataRegion) : null;
      this._target = { tenantId: who.id, tenantName: null, idType: 'tenant', region: regionFromHost(apiHost), apiHost, callerId: who.id };
      return this._target;
    }
    const wanted = this.tenantOverride || this.profile.tenantId;
    if (!wanted) {
      throw new SfsError(
        `This is a ${who.idType} credential, so it needs a target tenant. List them with "profile.mjs tenants", then pass --tenant <id> or save it on the profile with "profile.mjs add --tenant <id>".`,
        { code: 'tenant_required' },
      );
    }
    const list = await this.tenants();
    const hit = list.find((t) => String(t.id).toLowerCase() === wanted);
    if (!hit) {
      throw new SfsError(`Tenant ${wanted} is not one of the ${list.length} tenants this ${who.idType} credential can see.`, { code: 'tenant_not_visible' });
    }
    const apiHost = hit.apiHost ? allowedBase(hit.apiHost) : null;
    this._target = { tenantId: hit.id, tenantName: hit.name, idType: who.idType, region: hit.dataRegion || regionFromHost(apiHost), apiHost, callerId: who.id };
    log(`Target tenant: ${hit.name} (${hit.id}), region ${this._target.region || 'unknown'}`);
    return this._target;
  }
}

/** Build a session from --profile, --tenant and the environment. */
export function openSession({ profile, tenant, env = process.env } = {}) {
  const selected = selectProfile({ name: profile, env });
  return new Session(selected, { env, tenantOverride: tenant });
}
