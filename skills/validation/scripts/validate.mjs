#!/usr/bin/env node
// Validation in three levels: offline rules (no credentials), the tenant's
// own DSL check, and CEL cases run in Fusion's engine. All read-only, apart
// from the connection check, which Fusion runs by calling the vendor.

import fs from 'node:fs';
import path from 'node:path';
import { main, splitList } from '../../../lib/cli.mjs';
import { SfsError, UsageError } from '../../../lib/errors.mjs';
import { validateFile } from '../../../lib/rules.mjs';
import { tenantValidate } from '../../../lib/tenant-check.mjs';
import { loadCases, offlineCheck, runCases, truthTable } from '../../../lib/cel-cases.mjs';
import { getConnector, validateConnectionInput } from '../../../lib/fusion.mjs';
import { log } from '../../../lib/log.mjs';
import { addSecret } from '../../../lib/redact.mjs';

function readJsonArg(value, label) {
  if (value === undefined) return undefined;
  const text = value.startsWith('@') ? fs.readFileSync(value.slice(1), 'utf8') : value;
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new UsageError(`${label} is not valid JSON: ${error.message}`);
  }
}

/** Every template, connector and cases file under a folder. */
function collect(dir) {
  const out = { yaml: [], cases: [] };
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (e.name.startsWith('.') || e.name === 'node_modules') continue;
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(ya?ml)$/i.test(e.name)) out.yaml.push(p);
      else if (/cel-cases\.json$/i.test(e.name)) out.cases.push(p);
    }
  };
  walk(dir);
  return { yaml: out.yaml.sort(), cases: out.cases.sort() };
}

function offline(files, strict) {
  const results = files.map((f) => validateFile(f));
  const errors = results.reduce((n, r) => n + r.errors, 0);
  const warnings = results.reduce((n, r) => n + r.warnings, 0);
  for (const r of results) {
    for (const x of r.findings) log(`${x.level === 'error' ? 'ERROR' : 'warn '} ${r.file}${x.line ? `:${x.line}` : ''} [${x.rule}] ${x.message}`);
  }
  const ok = errors === 0 && (!strict || warnings === 0);
  return { ok, files: results.length, errors, warnings, results };
}

const spec = {
  name: 'validate.mjs',
  summary: 'Validate Sophos Fusion templates and connectors: offline, on the tenant, and CEL cases.',
  subcommands: {
    offline: {
      summary: 'Offline checks, no credentials: structure, names, CEL, task references, nolog, dry run and cap, data hygiene',
      args: '<file.yaml> [more files]',
      minPositionals: 1,
      options: { strict: { type: 'boolean', help: 'Treat warnings as failures' } },
      run: async (ctx, args, files) => offline(files, args.strict),
    },
    tenant: {
      summary: "Fusion's own DSL check (playbookValidateDSLV2), plus action and input checks it skips. Read-only",
      args: '<template.yaml>',
      minPositionals: 1,
      run: async (ctx, args, [file]) => {
        const text = fs.readFileSync(file, 'utf8');
        const r = await tenantValidate(ctx.client, text);
        for (const x of r.findings) log(`${x.level === 'error' ? 'ERROR' : 'warn '} ${file}${x.line ? `:${x.line}` : ''} [${x.rule}] ${x.message.split('\n')[0]}`);
        return { file, tenant: await ctx.tenantSummary(), ...r };
      },
    },
    cel: {
      summary: 'Run a CEL cases file through evaluateExpr and print a truth table (--offline: parse only)',
      args: '<cel-cases.json>',
      minPositionals: 1,
      options: { offline: { type: 'boolean', help: 'Only check that every expression parses; no tenant' } },
      run: async (ctx, args, [file]) => {
        const cases = loadCases(file);
        if (args.offline) {
          const rows = offlineCheck(cases);
          const bad = rows.filter((r) => !r.ok);
          return { ok: bad.length === 0, file, mode: 'offline', cases: rows.length, failures: bad };
        }
        const rows = await runCases(ctx.client, cases);
        const table = truthTable(rows);
        log(table);
        const failed = rows.filter((r) => r.result !== 'PASS');
        return { ok: failed.length === 0, file, mode: 'tenant', tenant: await ctx.tenantSummary(), passed: rows.length - failed.length, failed: failed.length, rows, table: table.split('\n') };
      },
    },
    connection: {
      summary: "Check a connection before creating it (validateConnectionInput). Fusion runs the connector's validate action against the vendor",
      write: true,
      options: {
        connector: { type: 'string', required: true, help: 'Connector name' },
        'auth-type': { type: 'string', help: 'Auth type (default: the connector\'s first)' },
        config: { type: 'string', help: 'Connection parameters as JSON, or @file.json' },
        'credentials-env': { type: 'string', multiple: true, help: 'key=ENV_VAR: read a credential field from an environment variable (repeatable)' },
      },
      gateDescription: (args) => `checking a ${args.connector} connection, which makes Fusion call the vendor`,
      run: async (ctx, args) => {
        const c = await getConnector(ctx.client, { name: args.connector });
        if (!c) throw new SfsError(`No connector named ${args.connector} on this tenant.`, { code: 'not_found' });
        const credentials = {};
        for (const pair of splitList(args['credentials-env'])) {
          const [k, envName] = pair.split('=');
          if (!k || !envName || !ctx.env[envName]) throw new UsageError(`--credentials-env ${pair}: give key=ENV_VAR with the variable set.`);
          addSecret(ctx.env[envName]);
          credentials[k] = ctx.env[envName];
        }
        const connection = {
          name: 'ZZ Test connection check',
          authType: args['auth-type'] || c.head?.authTypes?.[0] || 'None',
          versionStrategy: 'FollowMajorVersion',
          config: readJsonArg(args.config, '--config') || {},
          ...(Object.keys(credentials).length ? { credentials } : {}),
        };
        try {
          await validateConnectionInput(ctx.client, c.id, connection);
          return { connector: c.name, authType: connection.authType, valid: true };
        } catch (error) {
          return { ok: false, connector: c.name, authType: connection.authType, valid: false, error: { code: error.code || 'failed', message: error.message } };
        }
      },
    },
    all: {
      summary: 'Offline checks for every template and connector under a folder, and parse checks for every CEL cases file',
      args: '<folder>',
      minPositionals: 1,
      options: { strict: { type: 'boolean', help: 'Treat warnings as failures' } },
      run: async (ctx, args, [dir]) => {
        const found = collect(dir);
        const yaml = offline(found.yaml, args.strict);
        const cases = found.cases.map((f) => {
          try {
            const rows = offlineCheck(loadCases(f));
            return { file: f, ok: rows.every((r) => r.ok), cases: rows.length, failures: rows.filter((r) => !r.ok) };
          } catch (error) {
            return { file: f, ok: false, error: error.message };
          }
        });
        const ok = yaml.ok && cases.every((c) => c.ok);
        return { ok, folder: dir, templatesAndConnectors: { files: yaml.files, errors: yaml.errors, warnings: yaml.warnings, results: yaml.results.map((r) => ({ file: r.file, kind: r.kind, name: r.name, ok: r.ok, errors: r.errors, warnings: r.warnings, findings: r.findings })) }, celCases: cases };
      },
    },
  },
};

main(spec);
