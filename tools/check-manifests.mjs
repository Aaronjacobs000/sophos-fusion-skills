#!/usr/bin/env node
// Checks every plugin manifest parses, agrees on name and version, and that
// every skill folder has a SKILL.md whose frontmatter fits the portable format.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadYaml } from '../lib/yamlx.mjs';
import { VERSION } from '../lib/constants.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const problems = [];
const read = (rel) => {
  try {
    return JSON.parse(fs.readFileSync(path.join(root, rel), 'utf8'));
  } catch (error) {
    problems.push(`${rel}: ${error.message}`);
    return null;
  }
};

const NAME = 'sophos-fusion-skills';
const AGENT_PLUGINS_KEYS = new Set(['$schema', 'name', 'version', 'description', 'author', 'homepage', 'repository', 'license', 'keywords', 'extensions']);
const manifests = {
  claude: read('.claude-plugin/plugin.json'),
  claudeMarket: read('.claude-plugin/marketplace.json'),
  codex: read('.codex-plugin/plugin.json'),
  cursor: read('.cursor-plugin/plugin.json'),
  agentPlugins: read('plugin.json'),
  codexMarket: read('.agents/plugins/marketplace.json'),
  pkg: read('package.json'),
};

for (const [k, m] of Object.entries(manifests)) {
  if (!m) continue;
  if (['claude', 'codex', 'cursor', 'agentPlugins', 'pkg'].includes(k)) {
    if (m.name !== NAME) problems.push(`${k}: name is ${m.name}, expected ${NAME}`);
    if (m.version !== VERSION) problems.push(`${k}: version ${m.version} does not match lib/constants.mjs ${VERSION}`);
    if (k !== 'pkg' && m.license !== 'MIT') problems.push(`${k}: license should be MIT`);
  }
}
const ap = manifests.agentPlugins;
if (ap) {
  if (ap.$schema !== 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json') problems.push('plugin.json: $schema must be the Agent Plugins 1.0.0 schema');
  if (!/^(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(ap.name) || ap.name.length > 64) problems.push('plugin.json: name does not match the Agent Plugins pattern');
  for (const k of Object.keys(ap)) if (!AGENT_PLUGINS_KEYS.has(k)) problems.push(`plugin.json: "${k}" is not an Agent Plugins 1.0.0 field`);
}
const cm = manifests.claudeMarket;
if (cm) {
  if (!cm.owner?.name) problems.push('marketplace.json: owner.name is required');
  const entry = (cm.plugins || []).find((p) => p.name === NAME);
  if (!entry) problems.push('marketplace.json: no plugin entry for sophos-fusion-skills');
  else {
    if (entry.source !== './') problems.push('marketplace.json: source should be "./"');
    if (entry.version !== VERSION) problems.push('marketplace.json: plugin version does not match');
  }
}
const xm = manifests.codexMarket;
if (xm) {
  const e = (xm.plugins || [])[0];
  if (!e?.policy?.installation || !e?.policy?.authentication || !e?.category) problems.push('.agents/plugins/marketplace.json: entries need policy.installation, policy.authentication and category');
}

// Icon and logo fields: the file must be in the repository, in a shape each format accepts.
// Claude Code wants a square PNG or JPEG of 512 to 2048 px under 2 MB; Codex a square image of at
// least 48 px (for SVG, a square viewBox of at least 48). This check reads PNG and SVG files only.
function imageSize(rel) {
  const file = path.join(root, rel);
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) return null;
  const buf = fs.readFileSync(file);
  if (buf.length >= 24 && buf.subarray(1, 4).toString('latin1') === 'PNG') return { type: 'png', width: buf.readUInt32BE(16), height: buf.readUInt32BE(20), bytes: buf.length };
  const vb = /<svg\b[^>]*\bviewBox="\s*[-\d.]+[\s,]+[-\d.]+[\s,]+([\d.]+)[\s,]+([\d.]+)\s*"/.exec(buf.toString('utf8'));
  if (vb) return { type: 'svg', width: Number(vb[1]), height: Number(vb[2]), bytes: buf.length };
  return { type: 'other', width: 0, height: 0, bytes: buf.length };
}
const DOT_SLASH = /^\.\/(?!.*\.\.)[^\\]+$/;
const RELATIVE = /^(?!\/|\.\.|[A-Za-z]:)(?!.*\.\.)[^\\]+$/;
const square = (min) => (s) => s.type !== 'other' && s.width === s.height && s.width >= min;
const icons = [
  ['.claude-plugin/plugin.json icon', manifests.claude?.icon, DOT_SLASH, (s) => s.type === 'png' && square(512)(s) && s.width <= 2048 && s.bytes < 2 * 1024 * 1024],
  ['.codex-plugin/plugin.json interface.composerIcon', manifests.codex?.interface?.composerIcon, DOT_SLASH, square(48)],
  ['.codex-plugin/plugin.json interface.logo', manifests.codex?.interface?.logo, DOT_SLASH, square(48)],
  ['plugin.json extensions.com.openai.interface.composerIcon', ap?.extensions?.['com.openai']?.interface?.composerIcon, DOT_SLASH, square(48)],
  ['plugin.json extensions.com.openai.interface.logo', ap?.extensions?.['com.openai']?.interface?.logo, DOT_SLASH, square(48)],
  ['.cursor-plugin/plugin.json logo', manifests.cursor?.logo, RELATIVE, (s) => s.type !== 'other'],
];
for (const [label, value, form, fits] of icons) {
  if (value === undefined) continue;
  if (typeof value !== 'string' || !form.test(value)) {
    problems.push(`${label}: ${value} must be a relative path inside the repository${form === DOT_SLASH ? ' that starts with ./' : ''}`);
    continue;
  }
  const size = imageSize(value.replace(/^\.\//, ''));
  if (!size) problems.push(`${label}: ${value} is not a file in the repository`);
  else if (size.type === 'other') problems.push(`${label}: ${value} is not a PNG or SVG, which is all this check can read`);
  else if (!fits(size)) problems.push(`${label}: ${value} is ${size.type} ${size.width}x${size.height}, ${size.bytes} bytes, which this format does not accept`);
}
// Claude Code reads the directory listing fields from plugin.json only; a marketplace entry may not carry them.
for (const entry of manifests.claudeMarket?.plugins || []) {
  for (const k of ['icon', 'documentationUrl', 'supportUrl', 'privacyPolicyUrl', 'termsOfServiceUrl']) {
    if (k in entry) problems.push(`.claude-plugin/marketplace.json: ${entry.name} sets ${k}, which belongs in .claude-plugin/plugin.json`);
  }
}

const skillsDir = path.join(root, 'skills');
const skills = fs.readdirSync(skillsDir, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name).sort();
const PORTABLE = new Set(['name', 'description', 'license', 'compatibility', 'metadata', 'allowed-tools']);
for (const s of skills) {
  const file = path.join(skillsDir, s, 'SKILL.md');
  if (!fs.existsSync(file)) {
    problems.push(`skills/${s}: no SKILL.md`);
    continue;
  }
  const text = fs.readFileSync(file, 'utf8');
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n/.exec(text);
  if (!m) {
    problems.push(`skills/${s}/SKILL.md: frontmatter must start on line 1`);
    continue;
  }
  const fm = loadYaml(m[1]);
  if (!fm.ok) {
    problems.push(`skills/${s}/SKILL.md: frontmatter is not valid YAML`);
    continue;
  }
  const v = fm.value;
  if (v.name !== s) problems.push(`skills/${s}/SKILL.md: name "${v.name}" must match the folder`);
  if (!v.description || v.description.length > 1024) problems.push(`skills/${s}/SKILL.md: description missing or over 1024 characters`);
  for (const k of Object.keys(v)) if (!PORTABLE.has(k)) problems.push(`skills/${s}/SKILL.md: "${k}" is not a portable frontmatter field`);
  if (text.split('\n').length > 500) problems.push(`skills/${s}/SKILL.md: over 500 lines`);
  for (const link of text.matchAll(/\]\(((?:references|scripts)\/[^)#]+)\)/g)) {
    if (!fs.existsSync(path.join(skillsDir, s, link[1]))) problems.push(`skills/${s}/SKILL.md: broken link ${link[1]}`);
  }
}

const result = { ok: problems.length === 0, skills, problems };
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
process.exitCode = result.ok ? 0 : 1;
