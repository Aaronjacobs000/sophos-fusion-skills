# Contributing

Issues and pull requests are welcome.

## Before you open a pull request

1. Run the tests: `node --test`. They need no credentials.
2. Run the offline checks: `node skills/validation/scripts/validate.mjs all examples` and `node tools/check-manifests.mjs`.
3. Add or update tests for what you changed.
4. Keep the scripts dependency-free (Node 22 or later, ES modules).

## Rules for changes

- Writes stay behind `--yes` (and `--production` for production profiles). New write commands use the same gate in `lib/cli.mjs`.
- Requests go only to the Sophos hosts in `lib/constants.mjs`.
- No tenant names, tenant IDs, credentials, internal hostnames, or personal data in any file, fixture, or commit message. Use example values (192.0.2.0/24, example.com, all-zero UUIDs).
- New platform facts in the references say how they were measured and when.
- Docs use US spelling, the Oxford comma, and short sentences.

## Live tests

If you change how the scripts call Fusion, run `tools/live-smoke.mjs` against a test tenant you own, and say in the pull request that you did.

## Commit messages

Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`.
