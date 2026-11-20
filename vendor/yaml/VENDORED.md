# Vendored: yaml 2.9.1

- Upstream: https://github.com/eemeli/yaml (npm package `yaml`, version 2.9.1)
- License: ISC, see `LICENSE` in this folder
- Files: the package's `browser/dist/` ES module build, copied without changes into `dist/`
- Why vendored: the scripts run with no `npm install`, so the one parser they need ships with the repo

To update, run `npm pack yaml@<version>` in an empty temp folder, unpack it, and copy `package/browser/dist/` over `dist/` here. Then update the version in this file and in `index.js`, and run `node --test`.
