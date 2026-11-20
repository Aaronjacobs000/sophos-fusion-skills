#!/usr/bin/env node
// Custom connectors: scaffold a connector file, list its actions, and test
// one action live. A live test makes Fusion call the vendor for real, so it
// is a write: it needs --yes, and Fusion logs the request and response.

import fs from 'node:fs';
import path from 'node:path';
import { main } from '../../../lib/cli.mjs';
import { SfsError, UsageError } from '../../../lib/errors.mjs';
import * as F from '../../../lib/fusion.mjs';
import { findLeaks } from '../../../lib/redact.mjs';
import { validateText } from '../../../lib/rules.mjs';
import { parseOrThrow } from '../../../lib/template.mjs';
import { TEMPLATE_NAME } from '../../../lib/fusion-facts.mjs';
import { scaffoldConnector } from '../../../lib/scaffold.mjs';

function readJsonArg(value, label) {
  if (value === undefined) return undefined;
  const text = value.startsWith('@') ? fs.readFileSync(value.slice(1), 'utf8') : value;
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new UsageError(`${label} is not valid JSON: ${error.message}`);
  }
}

function actionFromFile(file, actionName) {
  const { value } = parseOrThrow(fs.readFileSync(file, 'utf8'), file);
  if (value.kind !== 'Connector') throw new UsageError(`${file} is not a connector.`);
  const a = (value.actions || []).find((x) => x.name === actionName);
  if (!a) throw new UsageError(`${file} has no action ${actionName}. Actions: ${(value.actions || []).map((x) => x.name).join(', ')}`);
  return { value, action: a };
}

const spec = {
  name: 'connector.mjs',
  summary: 'Write custom Sophos Fusion connectors and test one action live.',
  subcommands: {
    scaffold: {
      summary: 'Write a connector skeleton (validate action plus one GET action) that passes offline validation',
      options: {
        name: { type: 'string', required: true, help: 'Connector name, for example Acme_Inventory' },
        title: { type: 'string', required: true, help: 'Title people see' },
        'base-url': { type: 'string', required: true, help: 'https://host/base/path of the API' },
        auth: { type: 'string', default: 'None', help: 'None, APIKey or Basic (default None)' },
        vendor: { type: 'string', help: 'Vendor name' },
        product: { type: 'string', help: 'Product name' },
        out: { type: 'string', required: true, help: 'File to write' },
        force: { type: 'boolean', help: 'Overwrite an existing file' },
      },
      run: async (ctx, args) => {
        if (!TEMPLATE_NAME.test(args.name)) throw new UsageError('--name uses letters, digits and underscores, for example Acme_Inventory.');
        if (!['None', 'APIKey', 'Basic'].includes(args.auth)) throw new UsageError('--auth must be None, APIKey or Basic. Edit authTypes by hand for others.');
        if (fs.existsSync(args.out) && !args.force) throw new UsageError(`${args.out} exists. Use --force to overwrite.`);
        const text = scaffoldConnector({ name: args.name, title: args.title, baseUrl: args['base-url'], auth: args.auth, vendor: args.vendor, product: args.product });
        fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true });
        fs.writeFileSync(args.out, text);
        const check = validateText(text, args.out);
        return { written: args.out, offlineValidation: { ok: check.ok, errors: check.errors, warnings: check.warnings }, next: 'Replace getItem with the real actions, then validate.mjs offline, then deploy.mjs import' };
      },
    },
    actions: {
      summary: "List a local connector file's actions with their inputs and outputs. Offline",
      args: '<connector.yaml>',
      minPositionals: 1,
      run: async (ctx, args, [file]) => {
        const { value } = parseOrThrow(fs.readFileSync(file, 'utf8'), file);
        if (value.kind !== 'Connector') throw new UsageError(`${file} is not a connector.`);
        return {
          name: value.name,
          version: value.version,
          authTypes: value.authTypes,
          actions: (value.actions || []).map((a) => ({ name: a.name, description: a.description, method: a.config?.method, url: a.config?.url, inputs: Object.keys(a.inputs?.properties || {}), required: a.inputs?.required || [], outputs: Object.keys(a.config?.outputs || {}) })),
        };
      },
    },
    'test-action': {
      summary: 'Run one action on an existing connection (executeConnectionAction). Fusion calls the vendor for real',
      write: true,
      options: {
        connection: { type: 'string', required: true, help: 'Connection ID' },
        action: { type: 'string', required: true, help: 'Action name' },
        inputs: { type: 'string', help: 'Action inputs as JSON, or @file.json' },
      },
      gateDescription: (args) => `running action ${args.action} on connection ${args.connection}, which calls the vendor`,
      run: async (ctx, args) => {
        const conn = await F.getConnection(ctx.client, args.connection);
        if (!conn) throw new SfsError('No connection with that ID.', { code: 'not_found' });
        const inputs = readJsonArg(args.inputs, '--inputs') || {};
        const leaks = findLeaks(inputs);
        if (leaks.length) throw new UsageError(`The inputs hold secret-looking values (${leaks.map((l) => l.path).join(', ')}). Keep secrets in the connection.`);
        const result = await F.executeConnectionAction(ctx.client, conn.id, args.action, inputs);
        const resultLeaks = findLeaks(result);
        return { connection: { id: conn.id, name: conn.name, connector: conn.connector?.name }, action: args.action, result, ...(resultLeaks.length ? { warning: 'The result holds secret-looking values.', secretLooking: resultLeaks } : {}) };
      },
    },
    verify: {
      summary: "Test an action definition from a local file before publishing it (verifyConnectorActionV2). Fusion calls the vendor",
      write: true,
      args: '<connector.yaml>',
      minPositionals: 1,
      options: {
        connection: { type: 'string', required: true, help: 'ID of an existing connection of that connector (Fusion needs one to test against)' },
        action: { type: 'string', required: true, help: 'Action name in the file' },
        inputs: { type: 'string', help: 'Action inputs as JSON, or @file.json' },
      },
      notes: `
Tests the action as written in the local file, using an existing connection's
credentials, so you can check a change before importing a new version.`,
      gateDescription: (args) => `testing action ${args.action} against the vendor`,
      run: async (ctx, args, [file]) => {
        const { value, action } = actionFromFile(file, args.action);
        const conn = await F.getConnection(ctx.client, args.connection);
        if (!conn) throw new SfsError('No connection with that ID.', { code: 'not_found' });
        const c = await F.getConnector(ctx.client, { id: conn.connector.id });
        const input = {
          connection: { connectionId: conn.id, name: conn.name, authType: conn.authType },
          connectionMethodName: value.method || 'http',
          // Fusion wants the full Connector.action name here
          action: { name: `${c?.name ?? conn.connector.name}.${action.name}`, description: action.description, inputs: action.inputs, outputs: action.outputs, config: action.config },
          inputs: readJsonArg(args.inputs, '--inputs') || {},
        };
        const result = await F.verifyConnectorAction(ctx.client, c.id, input);
        return { connector: c?.name ?? conn.connector?.name, connection: conn.name, action: action.name, result };
      },
    },
  },
};

main(spec);
