#!/usr/bin/env node
// Write a playbook template skeleton with the conventions built in. Offline.

import fs from 'node:fs';
import path from 'node:path';
import { main, splitList } from '../../../lib/cli.mjs';
import { UsageError } from '../../../lib/errors.mjs';
import { scaffoldPlaybook } from '../../../lib/scaffold.mjs';
import { validateText } from '../../../lib/rules.mjs';
import { TEMPLATE_NAME } from '../../../lib/fusion-facts.mjs';

const spec = {
  name: 'scaffold.mjs',
  summary: 'Write a playbook template skeleton with dry run, cap, guards and outcomes built in. Offline.',
  subcommands: {
    playbook: {
      summary: 'Write template.yaml and an empty cel-cases.json into a folder',
      options: {
        name: { type: 'string', required: true, help: 'Template name: letters, digits, underscores (for example CaseOwnerNote)' },
        title: { type: 'string', required: true, help: 'Title people see' },
        tier: { type: 'string', default: 'lookup', help: 'lookup (reads only), notify (writes inside Fusion), or response (changes things outside Fusion)' },
        trigger: { type: 'string', default: 'generic', help: 'generic, platform, or actions (User Initiated)' },
        source: { type: 'string', default: 'case', help: 'Platform source (with --trigger platform)' },
        events: { type: 'string', default: 'Update', help: 'Platform events, comma separated' },
        context: { type: 'string', default: 'case', help: 'User Initiated context (with --trigger actions)' },
        out: { type: 'string', required: true, help: 'Folder to write into' },
        force: { type: 'boolean', help: 'Overwrite existing files' },
      },
      run: async (ctx, args) => {
        if (!TEMPLATE_NAME.test(args.name) || args.name.startsWith('Taegis.')) throw new UsageError('--name uses letters, digits and underscores, and must not start with Taegis. (Sophos uses that prefix).');
        const file = path.join(args.out, 'template.yaml');
        const casesFile = path.join(args.out, 'cel-cases.json');
        if ((fs.existsSync(file) || fs.existsSync(casesFile)) && !args.force) throw new UsageError(`${args.out} already has a template or cases file. Use --force to overwrite.`);
        const text = scaffoldPlaybook({ name: args.name, title: args.title, tier: args.tier, trigger: args.trigger, source: args.source, events: splitList(args.events), context: args.context });
        fs.mkdirSync(args.out, { recursive: true });
        fs.writeFileSync(file, text);
        const cases = {
          template: 'template.yaml',
          cases: [
            args.tier === 'response'
              ? { name: 'dry run is on when nothing is configured', from: 'task:settings.let.dry_run', inputs: {}, expect: true }
              : { name: 'note defaults to empty', from: 'task:settings.let.note', inputs: {}, expect: '' },
          ],
        };
        fs.writeFileSync(casesFile, `${JSON.stringify(cases, null, 2)}\n`);
        const check = validateText(text, file);
        return { written: [file, casesFile], tier: args.tier, trigger: args.trigger, offlineValidation: { ok: check.ok, errors: check.errors, warnings: check.warnings, findings: check.findings } };
      },
    },
  },
};

main(spec);
