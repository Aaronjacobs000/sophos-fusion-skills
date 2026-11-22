// Library contributions, opt-in: a parser entry or a rule entry folder for the Unofficial Sophos
// Fusion XDR and SIEM Library, written outside any repository, with the links to upload it. The
// skills post nothing. The library takes no customer logs, even sanitized ones, so a parser entry
// needs new synthetic samples, and no line may be, or be close to, a line from the user's samples.

import fs from 'node:fs';
import path from 'node:path';
import { UsageError } from './errors.mjs';
import { assertPrivatePath, gitWorkTree, localSampleLines, sampleLines } from './samples.mjs';
import { emulate, firstSchema, lastParser, loadParserFolder } from './parsers.mjs';
import { entryId, expectedFrom, packBundle, scanFiles, validateEntry, LIBRARY_REPO } from './xsl.mjs';

export const LIBRARY_URL = `https://github.com/${LIBRARY_REPO}`;
export const uploadLink = (folder) => `${LIBRARY_URL}/upload/main/${folder}`;
export const PARSER_ISSUE_FORM = `${LIBRARY_URL}/issues/new?template=parser-submission.yml`;

/** The values in a line a near copy would share: JSON values, key=value values, quoted strings, numbers of 4 or more digits. */
export function lineValues(line) {
  const out = new Set();
  const add = (v) => {
    const s = String(v).trim();
    if (s.length < 3 || /^(true|false|null|none)$/i.test(s)) return;
    out.add(s);
  };
  for (const m of line.matchAll(/"[^"\\]*(?:\\.[^"\\]*)*"\s*:\s*("(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?)/g)) add(m[1].replace(/^"|"$/g, ''));
  for (const m of line.matchAll(/(?:^|[\s|,;])[A-Za-z_][\w.-]*=("[^"]*"|[^\s|,;"]+)/g)) add(m[1].replace(/^"|"$/g, ''));
  for (const m of line.matchAll(/"((?:[^"\\]|\\.){3,})"/g)) add(m[1]);
  for (const m of line.matchAll(/'([^']{3,})'/g)) add(m[1]);
  for (const m of line.matchAll(/(?<![\w.])\d{4,}(?![\w])/g)) add(m[0]);
  return out;
}

/**
 * Candidate lines that equal a local line, or share half or more of their values with one.
 * Returns [{line, reason}] without any line text.
 */
export function copiedLines(candidates, local) {
  const localList = [...local];
  const localValues = localList.map(lineValues);
  const out = [];
  candidates.forEach((c, i) => {
    if (local.has(c)) {
      out.push({ line: i + 1, reason: 'the same as a line of your samples' });
      return;
    }
    const mine = lineValues(c);
    if (!mine.size) return;
    for (const vals of localValues) {
      let shared = 0;
      for (const v of mine) if (vals.has(v)) shared++;
      if (shared * 2 >= mine.size) {
        out.push({ line: i + 1, reason: `shares ${shared} of its ${mine.size} values with a line of your samples` });
        return;
      }
    }
  });
  return out;
}

function assertOutside(dir) {
  const tree = gitWorkTree(dir);
  if (tree) throw new UsageError(`${dir} is inside the git work tree ${tree}. Write the contribution outside any repository, then upload it from there.`);
}

/** Every parser's !SAMPLE line becomes the first synthetic line that parser takes in the emulator. */
function withSyntheticSampleLines(folder, samples, results) {
  const texts = {};
  for (const p of folder.parsers) {
    const own = results.find((r) => (r.extractor_path || '').split(' > ').includes(p.name));
    const line = own ? own.sample : samples[0];
    const text = p.text.replace(/^!SAMPLE=.*$/m, () => `!SAMPLE=${line}`);
    texts[p.name] = /^!SAMPLE=/m.test(text) ? text : `!SAMPLE=${line}\n${text}`;
  }
  return texts;
}

/**
 * Builds a parser entry from a local parser folder and new synthetic samples. Returns
 * { ok, problems, folder, bundle, links }; writes only when the library's checks pass.
 */
export function contributeParser(dir, { samplesFile, out, env = process.env, workspaces = [] }) {
  const folder = loadParserFolder(dir);
  const samples = sampleLines(fs.readFileSync(samplesFile, 'utf8'));
  if (!samples.length) throw new UsageError(`${samplesFile} has no lines.`);
  const meta = { ...folder.meta };
  const problems = [];
  // The folder's own samples.log counts as the user's unless the folder says it is synthetic.
  const local = localSampleLines({ env, extra: workspaces });
  if (!['synthetic', 'vendor-docs'].includes(folder.meta.sample_source)) for (const l of folder.samples) local.add(l);
  for (const c of copiedLines(samples, local)) problems.push({ level: 'error', code: 'copied', message: `Line ${c.line} of ${path.basename(samplesFile)} ${c.reason}. Write each line from the vendor's public log format docs.` });
  if (problems.length) return { ok: false, problems };

  const results = emulate({ ...folder, samples }, samples);
  const texts = withSyntheticSampleLines(folder, samples, results);
  meta.parsers = folder.parsers.map((p) => ({ name: p.name, file: `${p.name}.parser.txt`, role: p.role, ...(p.parent ? { parent: p.parent } : {}), schema: p.schema }));
  const finalFolder = { ...folder, texts, parsers: folder.parsers.map((p) => ({ ...p, text: texts[p.name] })) };
  const final = emulate(finalFolder, samples);
  const expected = expectedFrom(final);
  const id = entryId(meta);
  const entry = { id, meta, texts, samples, expected };
  const check = validateEntry(entry, {});
  const files = [{ path: 'meta.json', content: `${JSON.stringify(meta, null, 2)}\n` }, ...meta.parsers.map((p) => ({ path: p.file, content: texts[p.name].endsWith('\n') ? texts[p.name] : `${texts[p.name]}\n` })), { path: 'samples.log', content: `${samples.join('\n')}\n` }];
  const scans = scanFiles(files.filter((f) => f.path !== 'meta.json'), {});
  const all = [...check.problems, ...scans.map((s) => ({ ...s, file: s.source }))];
  const seen = new Set();
  for (const p of all) {
    const key = `${p.level}|${p.code}|${p.message}|${p.file || ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    problems.push({ level: p.level, code: p.code, file: p.file || null, message: p.message });
  }
  const unclaimed = final.filter((r) => !r.extractor_path).length;
  if (unclaimed === samples.length) problems.push({ level: 'error', code: 'samples', message: 'No synthetic line is taken by these parsers in the emulator.' });
  if (problems.some((p) => p.level === 'error')) return { ok: false, problems, summary: summarize(final) };

  assertOutside(out);
  const entryDir = path.join(path.resolve(out), 'parsers', ...id.split('/'));
  fs.mkdirSync(entryDir, { recursive: true });
  for (const f of files) fs.writeFileSync(path.join(entryDir, f.path), f.content);
  fs.writeFileSync(path.join(entryDir, 'expected.json'), `${JSON.stringify(expected, null, 2)}\n`);
  const bundle = packBundle(entry);
  const bundleFile = path.join(path.resolve(out), `${id.replace('/', '-')}.bundle.txt`);
  fs.writeFileSync(bundleFile, `${bundle}\n`);
  return {
    ok: true,
    problems,
    folder: entryDir,
    bundleFile,
    summary: summarize(final),
    links: { upload: uploadLink(`parsers/${id}`), issueForm: PARSER_ISSUE_FORM },
    note: "The library's own checks on its main branch are the authority: this copy of them can lag. Nothing was posted.",
  };
}

function summarize(results) {
  const by = {};
  for (const r of results) {
    const k = `${lastParser(r.extractor_path) || '(none)'} ${firstSchema(r.schema)}`;
    by[k] = (by[k] || 0) + 1;
  }
  return { lines: results.length, byParserAndSchema: by };
}

/** Writes a checked rule entry (detection or case) to out/rules/<vendor>/<name>. */
export function writeRuleEntry(id, files, out) {
  assertOutside(out);
  const dir = path.join(path.resolve(out), 'rules', ...id.split('/'));
  fs.mkdirSync(dir, { recursive: true });
  for (const f of files) fs.writeFileSync(path.join(dir, f.path), f.content.endsWith('\n') ? f.content : `${f.content}\n`);
  return { folder: dir, links: { upload: uploadLink(`rules/${id}`) } };
}

export { assertPrivatePath };
