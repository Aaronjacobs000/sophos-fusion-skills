# Vendored: Unofficial Sophos Fusion XDR and SIEM Library

- Upstream: https://github.com/Aaronjacobs000/sophos-xdr-siem-library
- Commit: 343762cf61a3797e320df2babba8069a0b60a327
- Synced: 2026-11-22
- License: MIT, see `LICENSE` in this folder. `ATTRIBUTIONS.md` credits gitleaks (MIT) for `studio/core/gitleaks-rule.js` and `studio/core/gitleaks.js`, and says where `studio/core/schema-data.js` comes from.
- Files: every file in `studio/core`, and `studio/app/plan.js`, copied without changes. The scripts import them through `lib/xsl.mjs` only.
- Why vendored: the parsers and detection-rules skills run the library's emulator, schema data, rule query reader and parser generator offline, with no `npm install` and no download at run time.

To update, run `node tools/sync-library.mjs <library clone> --sha <commit on main>`, then `node --test` and `node tools/check-vendor.mjs`. CI checks every hash below, and a weekly job fails when the library's main branch differs.

| File | sha256 |
| --- | --- |
| `studio/core/auth0-log-types.js` | `efbd284c99c2cdcaa6d3e123a77ce40a1970c86cd0925c8815f4c99397e647d9` |
| `studio/core/detect.js` | `218ea730e016289e884ca946bd682dfd5c28a1344ce69d013c2ef3d888bcfa7a` |
| `studio/core/engine.js` | `fa2e84385f68a0d22bbfa66687237662dd24faa5bd378a82aa049cbf8d62717d` |
| `studio/core/formats.js` | `4c2343b3c6cb1f1b3dcf4dc3130e286f7df40f8c98ce58b21385e8bcd5e11cad` |
| `studio/core/functions.js` | `ac39d8d9d90e5a253d993cdf1383c0dd697bff2c2477cc355cfca87a45cb661f` |
| `studio/core/generate.js` | `a2eee387ff27d081bb9faef4eff90bc077462d8910734c3d58247637cc17573a` |
| `studio/core/gitleaks-rule.js` | `fcc240d4073aa811b56fc06a50d00789057d6b8667411c2d1cd502f2fbb72307` |
| `studio/core/gitleaks.js` | `70055ed0f0740f44067cd6bfd8fc59874a1253a31b9be445c5a3c60ea75d825d` |
| `studio/core/goregex.js` | `8dd2017971cad064b9df3724dcd71d8ba936957610f7051f48961c211ee53f45` |
| `studio/core/gotime.js` | `98a414c282433f2e95068d9945766af5d9cae0c752db4bd2b0476eaac1704f4d` |
| `studio/core/jsonpath.js` | `c271578590f9ed7f784ca9e33df56ecae79e9c030e09c59be20448c98f0706e6` |
| `studio/core/language.js` | `111b189a9284fd62f8dbbe7e521c41e5803622080b563f6d16360e71e4030a70` |
| `studio/core/library.js` | `11c41f6cb09b9a0b91fa38ce02e57e8008c1a793a85c2720218cf0b395030376` |
| `studio/core/lint.js` | `598317523175b6eb7b1eb93fad7fd0bf77687a9f80fef46afebab1245c981e91` |
| `studio/core/mapping.js` | `2ae3b213b77a55bffc0606fbb0537b9cb7d966811a0a7026198eb74e9b2c7784` |
| `studio/core/normalize.js` | `356e59c2008265cd0e8a5cf249acacea3ac9fd0020c95b9a0389107b46d2eed6` |
| `studio/core/notes.js` | `b57b9c389dee754ae5a718f63c7be70eecb18741c147e8705f148bd22840aac9` |
| `studio/core/ql.js` | `735b38ef2a8dbd0aadcd3a558664e5f24730fd9043be9de4b5a58e0f24b87e53` |
| `studio/core/rules.js` | `b30ee1a50a20de71bc3a304b6bbd958039859ba3352ead6377cf4e68933cf598` |
| `studio/core/scan.js` | `4546368eb40b33217e52ae8c4819b9e96c71e27f3fceaac931db7c1b51661a79` |
| `studio/core/schema-data.js` | `93df033601c6b5dbbb6c5336a8d4aaddeb7ea579d52e00d7819d38f4b0c52b36` |
| `studio/core/schemas.js` | `4f3c958222e4311602e271942d2b50f6ae57463691500cff0e56a628ec7e9990` |
| `studio/core/values.js` | `f5058b79b48ec07019b5fa4019acfc717c718e01643c8517c56354e0014f8f7e` |
| `studio/core/version.js` | `d3eb21f8bdcc4236e2e00a2a5386016cc222be8f09eb0b5b015dafcbce68b0bf` |
| `studio/core/zip.js` | `56075fe97db4328360f630f26247ed7d429d2581e0f5cf2f6e3c897896e42ce0` |
| `studio/app/plan.js` | `154f752cb49d1a59c70ce95e7b3d2dc86c7f93ba5fe1748cd6e4347b4956a7a8` |
| `LICENSE` | `5973c124f6234aec2c872b81b74b075fd97f5d3f9e883daae0faccd237305ac7` |
| `ATTRIBUTIONS.md` | `75da5ff88a536da15ed15d295a4fc32c987bccb61dd43c9da6a27de1c859246c` |
