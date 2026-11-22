# Contributing

Issues and pull requests are welcome.

## Before you open a pull request

1. Run the tests: `node --test`. They need no credentials.
2. Run the offline checks: `node skills/validation/scripts/validate.mjs all examples`, `node tools/check-manifests.mjs`, and `node tools/check-vendor.mjs`.
3. Add or update tests for what you changed.
4. Keep the scripts dependency-free (Node 22 or later, ES modules).

## Rules for changes

- Writes stay behind `--yes` (and `--production` for production profiles). New write commands use the same gate in `lib/cli.mjs`.
- Requests go only to the Sophos hosts in `lib/constants.mjs`.
- No tenant names, tenant IDs, credentials, internal hostnames, or personal data in any file, fixture, or commit message. Use example values (192.0.2.0/24, example.com, all-zero UUIDs).
- New platform facts in the references say how they were measured and when.
- `vendor/xdr-siem-library` stays as the library ships it. Change the library upstream, then re-sync with `tools/sync-library.mjs`.
- No customer log lines anywhere in the repository, masked or not. Parser and rule fixtures are synthetic.
- Docs use US spelling, the Oxford comma, and short sentences.

## Live tests

If you change how the scripts call Fusion, run `tools/live-smoke.mjs` against a test tenant you own, and say in the pull request that you did.

## Commit messages

Conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`.
