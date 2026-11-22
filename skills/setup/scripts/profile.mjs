#!/usr/bin/env node
// Credential profiles and the connection self-test.

import { main } from '../../../lib/cli.mjs';
import { UsageError, SfsError } from '../../../lib/errors.mjs';
import { listProfiles, profilesPath, readStore, removeProfile, saveProfile, setDefault, describeProfile, selectProfile } from '../../../lib/profiles.mjs';
import { isOpReference, resolveSecret } from '../../../lib/secrets.mjs';
import { promptHidden } from '../../../lib/prompt.mjs';
import { automationAbilities, counts, permissions, summarizePermissions } from '../../../lib/fusion.mjs';
import { listParsers } from '../../../lib/parsers.mjs';
import { listRules } from '../../../lib/detection-rules.mjs';
import { log } from '../../../lib/log.mjs';

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '');
}

async function secretFrom(args, env) {
  const sources = ['client-secret-op', 'secret-env', 'secret-stdin', 'prompt'].filter((k) => args[k]);
  if (sources.length > 1) throw new UsageError('Give the secret one way: --client-secret-op, --secret-env, --secret-stdin or --prompt.');
  if (args['client-secret-op']) {
    if (!isOpReference(args['client-secret-op'])) throw new UsageError('--client-secret-op takes an op://vault/item/field reference.');
    return args['client-secret-op'];
  }
  if (args['secret-env']) {
    const v = env[args['secret-env']];
    if (!v) throw new UsageError(`Environment variable ${args['secret-env']} is empty or not set.`);
    return v;
  }
  if (args['secret-stdin']) return readStdin();
  if (args.prompt) return promptHidden('Sophos API client secret (input hidden): ');
  return undefined;
}

const spec = {
  name: 'profile.mjs',
  summary: 'Store Sophos API credentials as profiles and check that they reach Sophos Fusion.',
  subcommands: {
    add: {
      summary: 'Add or update a profile (written 0600 under the config folder)',
      options: {
        name: { type: 'string', required: true, help: 'Profile name' },
        kind: { type: 'string', help: 'test or production (default production)' },
        'client-id': { type: 'string', help: 'Client ID, or an op:// reference' },
        'client-secret-op': { type: 'string', help: 'Client secret as an op://vault/item/field reference' },
        'secret-env': { type: 'string', help: 'Read the client secret from this environment variable' },
        'secret-stdin': { type: 'boolean', help: 'Read the client secret from stdin' },
        prompt: { type: 'boolean', help: 'Prompt for the client secret on the terminal, hidden' },
        label: { type: 'string', help: 'A note to show with the profile, for example the tenant name' },
        default: { type: 'boolean', help: 'Make this the default profile' },
      },
      notes: `
Never paste a client secret into a chat. Give it with --prompt in your own
terminal, --secret-env, --secret-stdin, or a 1Password reference.
For a partner or organization credential, add --tenant <tenant ID> to save the
target tenant on the profile (list them with "profile.mjs tenants").`,
      run: async (ctx, args) => {
        const existing = readStore(ctx.env).profiles[args.name];
        const clientSecret = await secretFrom(args, ctx.env);
        if (!existing && (!args['client-id'] || !clientSecret)) {
          throw new UsageError('A new profile needs --client-id and a client secret (--prompt, --secret-env, --secret-stdin or --client-secret-op).');
        }
        const saved = saveProfile(
          args.name,
          { clientId: args['client-id'], clientSecret, kind: args.kind, tenantId: args.tenant, label: args.label, makeDefault: args.default },
          ctx.env,
        );
        log(`Saved profile ${args.name} to ${saved.file} (mode 0600). Next: profile.mjs test --profile ${args.name}`);
        return { saved: saved.profile, file: saved.file };
      },
    },
    list: {
      summary: 'List profiles (secrets are never shown)',
      run: async (ctx) => ({ file: profilesPath(ctx.env), profiles: listProfiles(ctx.env), environment: Boolean(ctx.env.SOPHOS_FUSION_CLIENT_ID) }),
    },
    show: {
      summary: 'Show which credential a command would use, without calling Sophos',
      run: async (ctx, args) => {
        const p = selectProfile({ name: args.profile, env: ctx.env });
        return { profile: { ...describeProfile(p.name, p, null), source: p.source, default: undefined } };
      },
    },
    use: {
      summary: 'Make a profile the default',
      options: { name: { type: 'string', required: true, help: 'Profile name' } },
      run: async (ctx, args) => setDefault(args.name, ctx.env),
    },
    remove: {
      summary: 'Delete a profile from the profile file',
      options: { name: { type: 'string', required: true, help: 'Profile name' } },
      run: async (ctx, args) => removeProfile(args.name, ctx.env),
    },
    whoami: {
      summary: 'Get a token and show the credential type, region and target tenant',
      run: async (ctx) => {
        const who = await ctx.session.identity();
        let target = null;
        try {
          target = await ctx.tenantSummary();
        } catch (error) {
          if (!(error instanceof SfsError && error.code === 'tenant_required')) throw error;
        }
        return { profile: ctx.profile.name, kind: ctx.profile.kind, credentialType: who.idType, callerId: who.id, target };
      },
    },
    tenants: {
      summary: 'List the tenants a partner or organization credential can reach',
      options: { search: { type: 'string', help: 'Only tenants whose name contains this text' } },
      run: async (ctx, args) => {
        const who = await ctx.session.identity();
        if (who.idType === 'tenant') return { credentialType: 'tenant', tenants: [], note: 'A tenant credential reaches only its own tenant.' };
        let list = await ctx.session.tenants();
        if (args.search) list = list.filter((t) => String(t.name).toLowerCase().includes(args.search.toLowerCase()));
        return { credentialType: who.idType, count: list.length, tenants: list.map((t) => ({ id: t.id, name: t.name, region: t.dataRegion, status: t.status })) };
      },
    },
    test: {
      summary: 'Self-test: token, whoami, one read-only Fusion query, and a permission summary',
      run: async (ctx) => {
        const steps = [];
        const step = async (name, fn) => {
          try {
            const detail = await fn();
            steps.push({ step: name, ok: true, ...(detail ? { detail } : {}) });
            return detail;
          } catch (error) {
            steps.push({ step: name, ok: false, error: error.message });
            throw Object.assign(error, { steps });
          }
        };
        try {
          await step('token', async () => {
            await ctx.session.token();
            return 'issued';
          });
          const who = await step('whoami', async () => {
            const w = await ctx.session.identity();
            return { credentialType: w.idType };
          });
          const target = await step('target tenant', () => ctx.tenantSummary());
          await step('Fusion read (object counts)', () => counts(ctx.client));
          const perms = await step('permissions', async () => {
            const p = await permissions(ctx.client);
            return { abilities: automationAbilities(p), objects: summarizePermissions(p) };
          });
          const missing = Object.entries(perms.abilities).filter(([, v]) => !v).map(([k]) => k);
          // authzPermissions has no parser object, so the parsers and detection-rules skills are checked by a read.
          // They need Sophos NG-SIEM; a failed read here doesn't fail the self-test.
          const canRead = async (fn) => {
            try {
              return { ok: true, count: (await fn(ctx.client)).length };
            } catch (error) {
              return { ok: false, error: error.message.slice(0, 200) };
            }
          };
          const parsersAndRules = { customParsers: await canRead(listParsers), customRules: await canRead(listRules) };
          return {
            profile: ctx.profile.name,
            kind: ctx.profile.kind,
            credentialType: who.credentialType,
            target,
            steps,
            ready: missing.length === 0,
            parsersAndRules,
            ...(missing.length ? { missing, note: 'The credential lacks some automation permissions. Check its role on the API Credentials page in Sophos Fusion.' } : {}),
          };
        } catch (error) {
          return { ok: false, profile: ctx.profile?.name, steps: error.steps || steps, error: { code: error.code || 'failed', message: error.message } };
        }
      },
    },
    'op-check': {
      summary: 'Check that op:// references in a profile resolve (values are never printed)',
      run: async (ctx, args) => {
        const p = selectProfile({ name: args.profile, env: ctx.env });
        const checked = [];
        for (const [field, value] of [['clientId', p.clientId], ['clientSecret', p.clientSecret]]) {
          if (!isOpReference(value)) {
            checked.push({ field, reference: false });
            continue;
          }
          const v = resolveSecret(value, { env: ctx.env, label: field });
          checked.push({ field, reference: true, resolved: Boolean(v), length: v.length });
        }
        return { profile: p.name, checked };
      },
    },
  },
};

main(spec);
