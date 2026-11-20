// Command-line frame shared by every script: argument parsing, help text,
// JSON output, error handling, and the write gate.
//
// The write gate is the safety model's core. A subcommand marked as a write
// does nothing unless --yes is given, and a profile marked production also
// needs --production. Skills tell the agent to pass these only after the user
// approves that specific write.

import { parseArgs } from 'node:util';
import { EXIT, VERSION } from './constants.mjs';
import { GateError, SfsError, UsageError } from './errors.mjs';
import { redact } from './redact.mjs';
import { log, setQuiet } from './log.mjs';
import { openSession } from './session.mjs';
import { FusionClient } from './graphql.mjs';
import { selectProfile } from './profiles.mjs';

const GLOBAL_OPTIONS = {
  profile: { type: 'string', help: 'Credential profile to use (default: environment variables, then the default profile)' },
  tenant: { type: 'string', help: 'Target tenant ID, for partner and organization credentials' },
  quiet: { type: 'boolean', help: 'No progress messages on stderr' },
  help: { type: 'boolean', short: 'h', help: 'Show help' },
};

const WRITE_OPTIONS = {
  yes: { type: 'boolean', help: 'Confirm this write. Pass it only after the user has approved this specific write' },
  production: { type: 'boolean', help: 'Also required when the profile is marked production' },
  'run-id': { type: 'string', help: 'Ledger run to record created objects under (default: the current run)' },
};

export function printJson(value) {
  process.stdout.write(`${JSON.stringify(redact(value), null, 2)}\n`);
}

function optionHelp(options) {
  return Object.entries(options)
    .map(([name, o]) => {
      const flag = `--${name}${o.type === 'string' ? ' <value>' : ''}${o.multiple ? ' (repeatable)' : ''}`;
      return `  ${flag.padEnd(34)} ${o.help || ''}`;
    })
    .join('\n');
}

function topHelp(spec) {
  const subs = Object.entries(spec.subcommands)
    .map(([n, s]) => `  ${n.padEnd(22)} ${s.summary}${s.write ? '  [write]' : ''}`)
    .join('\n');
  return `${spec.name} ${VERSION}\n${spec.summary}\n\nUsage: node ${spec.name} <command> [options]\n\nCommands:\n${subs}\n\nGlobal options:\n${optionHelp(GLOBAL_OPTIONS)}\n\nRun "node ${spec.name} <command> --help" for a command's options.\nOutput is JSON on stdout. Messages go to stderr. Exit codes: 0 ok, 1 failed, 2 usage, 3 write refused by the safety gate.\n`;
}

function subHelp(spec, name, sub) {
  const opts = { ...(sub.options || {}), ...(sub.write ? WRITE_OPTIONS : {}), ...GLOBAL_OPTIONS };
  const args = sub.args ? ` ${sub.args}` : '';
  const notes = sub.notes ? `\n${sub.notes.trim()}\n` : '';
  const gate = sub.write
    ? '\nThis is a write. It needs --yes, and --production as well when the profile is marked production.\n'
    : '';
  return `node ${spec.name} ${name}${args} [options]\n${sub.summary}\n${notes}${gate}\nOptions:\n${optionHelp(opts)}\n`;
}

/**
 * Throws GateError unless the write is confirmed. `what` describes the write
 * in plain words; it is echoed back so the agent can show the user.
 */
export function requireWrite(args, profile, what) {
  const where = profile.tenantId ? `tenant ${profile.tenantId}` : profile.label ? profile.label : `the tenant of profile "${profile.name}"`;
  if (!args.yes) {
    throw new GateError(`Not done: ${what} is a write to ${where}. Ask the user to approve this specific write, then run the same command with --yes.`, {
      write: what,
      profile: profile.name,
      kind: profile.kind,
      needs: profile.kind === 'production' ? ['--yes', '--production'] : ['--yes'],
    });
  }
  if (profile.kind === 'production' && !args.production) {
    throw new GateError(
      `Not done: profile "${profile.name}" is marked production (${where}). Name the tenant to the user, get their approval for this write on that tenant, then run the command with --yes --production.`,
      { write: what, profile: profile.name, kind: profile.kind, needs: ['--yes', '--production'] },
    );
  }
}

class Context {
  constructor(args, sub, env) {
    this.args = args;
    this.sub = sub;
    this.env = env;
    this._session = null;
    this._client = null;
    this._profile = null;
  }

  get profile() {
    if (!this._profile) this._profile = this.session.profile;
    return this._profile;
  }

  get session() {
    if (!this._session) this._session = openSession({ profile: this.args.profile, tenant: this.args.tenant, env: this.env });
    return this._session;
  }

  get client() {
    if (!this._client) this._client = new FusionClient(this.session);
    return this._client;
  }

  /** Raw profile without opening a session (no network). */
  peekProfile() {
    return selectProfile({ name: this.args.profile, env: this.env });
  }

  confirmWrite(what) {
    requireWrite(this.args, this.peekProfile(), what);
  }

  async tenantSummary() {
    const t = await this.session.target();
    return { tenantId: t.tenantId, tenantName: t.tenantName, idType: t.idType, region: t.region };
  }
}

/**
 * Run a CLI. spec = { name, summary, subcommands: { name: { summary, args,
 * options, write, positionals, run(ctx, args, positionals) } } }.
 * `write` may be true or a function of the parsed args.
 */
export async function runCli(spec, argv = process.argv.slice(2), env = process.env) {
  const [subName, ...rest] = argv;
  if (!subName || subName === '--help' || subName === '-h' || subName === 'help') {
    process.stdout.write(topHelp(spec));
    return EXIT.ok;
  }
  if (subName === '--version') {
    printJson({ ok: true, version: VERSION });
    return EXIT.ok;
  }
  const sub = spec.subcommands[subName];
  if (!sub) {
    printJson({ ok: false, command: `${spec.name} ${subName}`, error: { code: 'usage', message: `Unknown command "${subName}". Run with --help.` } });
    return EXIT.usage;
  }
  const options = { ...(sub.options || {}), ...(sub.write ? WRITE_OPTIONS : {}), ...GLOBAL_OPTIONS };
  const parseSpec = {};
  for (const [k, o] of Object.entries(options)) {
    parseSpec[k] = { type: o.type, ...(o.short ? { short: o.short } : {}), ...(o.multiple ? { multiple: true } : {}) };
  }
  let parsed;
  try {
    parsed = parseArgs({ args: rest, options: parseSpec, allowPositionals: true, strict: true });
  } catch (error) {
    printJson({ ok: false, command: `${spec.name} ${subName}`, error: { code: 'usage', message: error.message } });
    return EXIT.usage;
  }
  const args = parsed.values;
  if (args.help) {
    process.stdout.write(subHelp(spec, subName, sub));
    return EXIT.ok;
  }
  setQuiet(args.quiet);
  for (const [k, o] of Object.entries(options)) {
    if (args[k] === undefined && o.default !== undefined) args[k] = o.default;
  }
  const command = `${spec.name} ${subName}`;
  try {
    const positionals = parsed.positionals;
    if (sub.minPositionals && positionals.length < sub.minPositionals) {
      throw new UsageError(`${command} needs ${sub.args}. Run with --help.`);
    }
    for (const [k, o] of Object.entries(sub.options || {})) {
      if (o.required && (args[k] === undefined || args[k] === '')) throw new UsageError(`--${k} is required. Run with --help.`);
    }
    const ctx = new Context(args, sub, env);
    const isWrite = typeof sub.write === 'function' ? sub.write(args, positionals) : Boolean(sub.write);
    // Checked before any network call, so an unconfirmed write sends nothing.
    if (isWrite) ctx.confirmWrite(sub.gateDescription ? sub.gateDescription(args, positionals) : sub.summary);
    const result = await sub.run(ctx, args, positionals);
    const exitCode = result && typeof result === 'object' && result.ok === false ? EXIT.failed : EXIT.ok;
    printJson({ ok: exitCode === EXIT.ok, command, ...(result || {}) });
    return exitCode;
  } catch (error) {
    const known = error instanceof SfsError;
    const code = known ? error.code : 'failed';
    const message = known ? error.message : `Unexpected error: ${error?.message || error}`;
    log(message);
    printJson({ ok: false, command, error: { code, message, ...(known && error.details ? { details: error.details } : {}) } });
    if (error instanceof GateError) return EXIT.refused;
    if (error instanceof UsageError) return EXIT.usage;
    return known ? error.exitCode || EXIT.failed : EXIT.failed;
  }
}

/** Entry point helper: run and set the exit code. */
export async function main(spec) {
  const code = await runCli(spec);
  process.exitCode = code;
}

export function splitList(values) {
  if (values === undefined || values === null) return [];
  const arr = Array.isArray(values) ? values : [values];
  return arr.flatMap((v) => String(v).split(',')).map((s) => s.trim()).filter(Boolean);
}
