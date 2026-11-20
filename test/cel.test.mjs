import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { parseCel, checkField, splitTemplate, references, tokenize } from '../lib/cel.mjs';

const GOOD = [
  'true',
  'null',
  "'it''s'.size() > 0 || \"x\" == 'x'".replace("''", "\\'"),
  '1 + 2 * 3 % 4 - -5',
  '0x1F == 31 && 3u > 2u && 1.5e3 > .5',
  'inputs.a.b[0]["c"].d',
  'a ? b : c ? d : e',
  '!!(a in [1, 2, 3])',
  "{'k': [1, {'n': null}], 2: true}",
  "has(inputs, 'case.id') && has(inputs.case.id)",
  "x.?y.?z.orValue('d')",
  'list[?0].hasValue()',
  "[1, 2, 3].filter(i, i > 1).map(i, i * 2).exists(j, j == 4)",
  "m.all(k, k.startsWith('a'))",
  "cel.bind(v, [1, 2], v.size())",
  "base64.encode(b'abc') != ''",
  "r'\\d+' != ''",
  "'''multi\nline''' != ''",
  "timestamp('2026-01-01T00:00:00Z') < now()",
  "detectionIPs(d).filter(ip, !isPrivateIP(ip))",
  "type(x) == map || type(x) == list",
  "a // a comment\n + b",
  "google.protobuf.Value{null_value: 0}",
  "'Value: %d'.format([42])",
  "{?'k': optional.of(1)}",
  "[?optional.none()]",
];

const BAD = [
  ['', 'empty expression'],
  ['1 +', 'expected a value'],
  ['a = b', 'single "="'],
  ['a & b', 'single "&"'],
  ['30s', 'after a number'],
  ['two words', 'after a complete expression'],
  ["'unterminated", 'unterminated string'],
  ["'line\nbreak'", 'newline inside'],
  ['f(a, b', 'close the argument list'],
  ['[1, 2', 'close the list'],
  ["{'a' 1}", 'between a map key'],
  ['a.', 'field name'],
  ['if', 'reserved word'],
  ["'bad \\q escape'", 'unknown escape'],
  ['a ? b', '":"'],
  ['@x', 'unexpected character'],
];

describe('CEL parser', () => {
  for (const expr of GOOD) {
    test(`parses: ${expr.replace(/\n/g, '\\n')}`, () => {
      const r = parseCel(expr);
      assert.equal(r.ok, true, r.error?.message);
    });
  }
  for (const [expr, fragment] of BAD) {
    test(`rejects: ${JSON.stringify(expr)}`, () => {
      const r = parseCel(expr);
      assert.equal(r.ok, false);
      assert.match(r.error.message, new RegExp(fragment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
      assert.equal(typeof r.error.offset, 'number');
    });
  }

  test('reports line and column', () => {
    const r = parseCel('a &&\n  b +');
    assert.equal(r.ok, false);
    assert.equal(r.error.line, 2);
  });

  test('tokenizes numbers, strings and operators', () => {
    assert.deepEqual(tokenize("x.?y >= 1.5 in 'q'").map((t) => t.t), ['ident', 'op', 'op', 'ident', 'op', 'double', 'op', 'string', 'eof']);
  });

  test('deep nesting is stopped, not overflowed', () => {
    const r = parseCel(`${'('.repeat(400)}1${')'.repeat(400)}`);
    assert.equal(r.ok, false);
  });
});

describe('templates', () => {
  test('splits text and expressions, skipping braces inside strings', () => {
    const r = splitTemplate("a ${x.y} b ${f('}')} c");
    assert.equal(r.ok, true);
    assert.deepEqual(r.parts.map((p) => [p.kind, p.text]), [['text', 'a '], ['expr', 'x.y'], ['text', ' b '], ['expr', "f('}')"], ['text', ' c']]);
  });

  test('a map literal inside a template', () => {
    const r = checkField("${ {'a': 1}['a'] } items");
    assert.equal(r.ok, true);
    assert.equal(r.kind, 'template');
  });

  test('an unclosed template is an error', () => {
    assert.equal(splitTemplate('a ${b').ok, false);
    assert.equal(checkField('a ${b').ok, false);
  });

  test('a bad expression inside a template is located in the whole string', () => {
    const r = checkField('prefix ${1 +} end');
    assert.equal(r.ok, false);
    assert.ok(r.error.offset >= 'prefix ${'.length);
  });

  test('empty string is a literal, whitespace is not', () => {
    assert.equal(checkField('').ok, true);
    assert.equal(checkField('   ').ok, false);
  });
});

describe('references', () => {
  const refs = (e) => references(parseCel(e).ast);

  test('lists roots with their paths', () => {
    const r = refs("task_a.outputs.items[0].id + inputs.x");
    assert.deepEqual(r.refs.map((x) => [x.root, x.path.join('.')]), [['task_a', 'outputs.items.id'], ['inputs', 'x']]);
  });

  test('comprehension variables are not references', () => {
    const r = refs('t.outputs.list.filter(i, i.ok).map(j, j.name).exists(k, k == other)');
    assert.deepEqual([...new Set(r.refs.map((x) => x.root))].sort(), ['other', 't']);
  });

  test('cel.bind variables are not references', () => {
    const r = refs('cel.bind(v, a.variables.x, v + b)');
    assert.deepEqual(r.refs.map((x) => x.root).sort(), ['a', 'b']);
  });

  test('namespaced functions are not references', () => {
    assert.deepEqual(refs("base64.decode(x) + math.abs(y)").refs.map((r) => r.root).sort(), ['x', 'y']);
  });

  test('has() marks a guard, .? marks an optional read', () => {
    const r = refs("has(step, 'outputs.x') ? step.outputs.x : other.?outputs.y.orValue(1)");
    assert.ok(r.guards.has('step'));
    assert.equal(r.refs.find((x) => x.root === 'other').optional, true);
    assert.equal(r.refs.find((x) => x.root === 'step' && x.path.length).optional, false);
  });
});
