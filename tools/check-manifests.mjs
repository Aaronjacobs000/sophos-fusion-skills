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
