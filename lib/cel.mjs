// A syntax checker for the Common Expression Language as Sophos Fusion uses
// it. It parses, it does not evaluate: evaluation is Fusion's job
// (evaluateExpr). The parser follows the CEL grammar
// (https://github.com/google/cel-spec/blob/master/doc/langdef.md) plus the
// optional syntax Fusion accepts: x.?field, x[?index], {?key: v}, [?v].
//
// parseCel(text) returns { ok, ast, error }. references(ast) lists the root
// identifiers an expression reads, with the field path after each, so the
// validator can check task references.

const RESERVED = new Set(['as', 'break', 'const', 'continue', 'else', 'for', 'function', 'if', 'import', 'let', 'loop', 'package', 'namespace', 'return', 'var', 'void', 'while']);

// Functions whose leading identifier arguments are loop variables, not references.
const BINDING_FUNCTIONS = new Set(['all', 'exists', 'exists_one', 'existsOne', 'map', 'filter', 'sortBy', 'groupBy', 'transformList', 'transformMap', 'transformMapEntry', 'optMap', 'optFlatMap', 'collect']);

export class CelSyntaxError extends Error {
  constructor(message, offset, text) {
    const { line, column } = position(text, offset);
    super(message);
    this.name = 'CelSyntaxError';
    this.offset = offset;
    this.line = line;
    this.column = column;
  }
}

function position(text, offset) {
  let line = 1;
  let column = 1;
  for (let i = 0; i < offset && i < text.length; i++) {
    if (text[i] === '\n') {
      line++;
      column = 1;
    } else {
      column++;
    }
  }
  return { line, column };
}

// ---------------------------------------------------------------- lexer

const PUNCT = ['==', '!=', '<=', '>=', '&&', '||', '(', ')', '[', ']', '{', '}', '.', ',', ':', '?', '!', '-', '+', '*', '/', '%', '<', '>'];

function isDigit(c) {
  return c >= '0' && c <= '9';
}
function isIdentStart(c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c === '_';
}
function isIdentPart(c) {
  return isIdentStart(c) || isDigit(c);
}

export function tokenize(text) {
  const tokens = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f') {
      i++;
      continue;
    }
    if (c === '/' && text[i + 1] === '/') {
      while (i < n && text[i] !== '\n') i++;
      continue;
    }
    const start = i;
    // string and bytes literals, with optional r/b prefixes
    const prefix = /^(?:[rR][bB]?|[bB][rR]?)?(?=['"])/.exec(text.slice(i, i + 3));
    if (prefix && (text[i + prefix[0].length] === '"' || text[i + prefix[0].length] === "'")) {
      const p = prefix[0].toLowerCase();
      i += p.length;
      const raw = p.includes('r');
      const bytes = p.includes('b');
      const q = text[i];
      const triple = text.slice(i, i + 3) === q.repeat(3);
      const close = triple ? q.repeat(3) : q;
      i += close.length;
      let value = '';
      let closed = false;
      while (i < n) {
        if (text.startsWith(close, i)) {
          i += close.length;
          closed = true;
          break;
        }
        const ch = text[i];
        if (!triple && (ch === '\n' || ch === '\r')) {
          throw new CelSyntaxError('newline inside a single-line string literal', i, text);
        }
        if (ch === '\\' && !raw) {
          const esc = readEscape(text, i);
          value += esc.value;
          i = esc.end;
          continue;
        }
        if (ch === '\\' && raw) {
          // a raw string still cannot end on an escaped quote
          value += ch;
          i++;
          if (i < n) {
            value += text[i];
            i++;
          }
          continue;
        }
        value += ch;
        i++;
      }
      if (!closed) throw new CelSyntaxError('unterminated string literal', start, text);
      tokens.push({ t: bytes ? 'bytes' : 'string', v: value, pos: start });
      continue;
    }
    // numbers
    if (isDigit(c) || (c === '.' && isDigit(text[i + 1] || ''))) {
      const hex = /^0[xX][0-9a-fA-F]+[uU]?/.exec(text.slice(i));
      if (hex) {
        i += hex[0].length;
        tokens.push({ t: /[uU]$/.test(hex[0]) ? 'uint' : 'int', v: hex[0], pos: start });
      } else {
        const m = /^(?:\d+\.\d+(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?|\d+[eE][+-]?\d+|\d+[uU]?)/.exec(text.slice(i));
        i += m[0].length;
        const v = m[0];
        const t = /[uU]$/.test(v) ? 'uint' : /[.eE]/.test(v) ? 'double' : 'int';
        tokens.push({ t, v, pos: start });
      }
      if (i < n && isIdentStart(text[i])) throw new CelSyntaxError(`unexpected "${text[i]}" after a number`, i, text);
      continue;
    }
    if (isIdentStart(c)) {
      while (i < n && isIdentPart(text[i])) i++;
      const word = text.slice(start, i);
      if (word === 'true' || word === 'false') tokens.push({ t: 'bool', v: word === 'true', pos: start });
      else if (word === 'null') tokens.push({ t: 'null', v: null, pos: start });
      else if (word === 'in') tokens.push({ t: 'op', v: 'in', pos: start });
      else tokens.push({ t: 'ident', v: word, pos: start });
      continue;
    }
    const punct = PUNCT.find((p) => text.startsWith(p, i));
    if (punct) {
      i += punct.length;
      tokens.push({ t: 'op', v: punct, pos: start });
      continue;
    }
    if (c === '=') throw new CelSyntaxError('single "=" is not an operator; use "==" to compare', i, text);
    if (c === '&' || c === '|') throw new CelSyntaxError(`single "${c}" is not an operator; use "${c}${c}"`, i, text);
    throw new CelSyntaxError(`unexpected character "${c}"`, i, text);
  }
  tokens.push({ t: 'eof', v: null, pos: n });
  return tokens;
}

function readEscape(text, i) {
  const c = text[i + 1];
  const simple = { '\\': '\\', '"': '"', "'": "'", '`': '`', '?': '?', a: '\x07', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t', v: '\v' };
  if (c in simple) return { value: simple[c], end: i + 2 };
  if (c === 'x' || c === 'X') {
    const h = text.slice(i + 2, i + 4);
    if (!/^[0-9a-fA-F]{2}$/.test(h)) throw new CelSyntaxError('bad \\x escape', i, text);
    return { value: String.fromCharCode(parseInt(h, 16)), end: i + 4 };
  }
  if (c === 'u') {
    const h = text.slice(i + 2, i + 6);
    if (!/^[0-9a-fA-F]{4}$/.test(h)) throw new CelSyntaxError('bad \\u escape', i, text);
    return { value: String.fromCharCode(parseInt(h, 16)), end: i + 6 };
  }
  if (c === 'U') {
    const h = text.slice(i + 2, i + 10);
    if (!/^[0-9a-fA-F]{8}$/.test(h)) throw new CelSyntaxError('bad \\U escape', i, text);
    return { value: String.fromCodePoint(parseInt(h, 16)), end: i + 10 };
  }
  if (/^[0-3][0-7][0-7]$/.test(text.slice(i + 1, i + 4))) {
    return { value: String.fromCharCode(parseInt(text.slice(i + 1, i + 4), 8)), end: i + 4 };
  }
  throw new CelSyntaxError(`unknown escape "\\${c ?? ''}"`, i, text);
}

// ---------------------------------------------------------------- parser

class Parser {
  constructor(text) {
    this.text = text;
    this.tokens = tokenize(text);
    this.i = 0;
    this.depth = 0;
  }

  peek(k = 0) {
    return this.tokens[this.i + k];
  }

  next() {
    return this.tokens[this.i++];
  }

  isOp(v, k = 0) {
    const tok = this.peek(k);
    return tok.t === 'op' && tok.v === v;
  }

  expectOp(v, what) {
    const tok = this.peek();
    if (tok.t === 'op' && tok.v === v) return this.next();
    throw this.error(`expected "${v}"${what ? ` ${what}` : ''} but found ${describe(tok)}`, tok.pos);
  }

  error(message, pos) {
    return new CelSyntaxError(message, pos, this.text);
  }

  parse() {
    if (this.peek().t === 'eof') throw this.error('empty expression', 0);
    const node = this.expr();
    const tok = this.peek();
    if (tok.t !== 'eof') throw this.error(`unexpected ${describe(tok)} after a complete expression`, tok.pos);
    return node;
  }

  expr() {
    if (++this.depth > 250) throw this.error('expression nests too deeply', this.peek().pos);
    const test = this.or();
    let node = test;
    if (this.isOp('?')) {
      const q = this.next();
      const then = this.or();
      this.expectOp(':', 'in a ? : conditional');
      const otherwise = this.expr();
      node = { type: 'cond', test, then, else: otherwise, pos: q.pos };
    }
    this.depth--;
    return node;
  }

  or() {
    let left = this.and();
    while (this.isOp('||')) {
      const op = this.next();
      left = { type: 'binary', op: '||', left, right: this.and(), pos: op.pos };
    }
    return left;
  }

  and() {
    let left = this.relation();
    while (this.isOp('&&')) {
      const op = this.next();
      left = { type: 'binary', op: '&&', left, right: this.relation(), pos: op.pos };
    }
    return left;
  }

  relation() {
    let left = this.addition();
    for (;;) {
      const tok = this.peek();
      if (tok.t === 'op' && ['<', '<=', '>', '>=', '==', '!=', 'in'].includes(tok.v)) {
        this.next();
        left = { type: 'binary', op: tok.v, left, right: this.addition(), pos: tok.pos };
      } else {
        return left;
      }
    }
  }

  addition() {
    let left = this.multiplication();
    while (this.isOp('+') || this.isOp('-')) {
      const op = this.next();
      left = { type: 'binary', op: op.v, left, right: this.multiplication(), pos: op.pos };
    }
    return left;
  }

  multiplication() {
    let left = this.unary();
    while (this.isOp('*') || this.isOp('/') || this.isOp('%')) {
      const op = this.next();
      left = { type: 'binary', op: op.v, left, right: this.unary(), pos: op.pos };
    }
    return left;
  }

  unary() {
    if (this.isOp('!') || this.isOp('-')) {
      const op = this.next();
      return { type: 'unary', op: op.v, operand: this.unary(), pos: op.pos };
    }
    return this.member();
  }

  member() {
    let node = this.primary();
    for (;;) {
      if (this.isOp('.')) {
        const dot = this.next();
        let optional = false;
        if (this.isOp('?')) {
          this.next();
          optional = true;
        }
        const id = this.peek();
        if (id.t !== 'ident') throw this.error(`expected a field name after "."${optional ? '?' : ''} but found ${describe(id)}`, id.pos);
        this.next();
        if (this.isOp('(') && !optional) {
          const args = this.callArgs();
          node = { type: 'call', target: node, fn: id.v, args, pos: id.pos };
        } else if (!optional && /^[A-Z]/.test(id.v) && this.isOp('{') && qualifiedName(node)) {
          // A message literal with a qualified type name: google.protobuf.Value{...}
          node = this.struct({ v: `${qualifiedName(node)}.${id.v}`, pos: id.pos });
        } else {
          node = { type: 'select', operand: node, field: id.v, optional, pos: dot.pos };
        }
      } else if (this.isOp('[')) {
        const open = this.next();
        let optional = false;
        if (this.isOp('?')) {
          this.next();
          optional = true;
        }
        const index = this.expr();
        this.expectOp(']', 'to close the index');
        node = { type: 'index', operand: node, index, optional, pos: open.pos };
      } else {
        return node;
      }
    }
  }

  callArgs() {
    this.expectOp('(');
    const args = [];
    if (this.isOp(')')) {
      this.next();
      return args;
    }
    for (;;) {
      args.push(this.expr());
      if (this.isOp(',')) {
        this.next();
        continue;
      }
      this.expectOp(')', 'to close the argument list');
      return args;
    }
  }

  primary() {
    const tok = this.peek();
    if (tok.t === 'op' && tok.v === '.') {
      // leading dot: a fully qualified name
      this.next();
      const id = this.peek();
      if (id.t !== 'ident') throw this.error('expected a name after a leading "."', id.pos);
      return this.identTail();
    }
    if (tok.t === 'ident') return this.identTail();
    if (tok.t === 'op' && tok.v === '(') {
      this.next();
      const inner = this.expr();
      this.expectOp(')', 'to close the parenthesis');
      return inner;
    }
    if (tok.t === 'op' && tok.v === '[') return this.list();
    if (tok.t === 'op' && tok.v === '{') return this.map();
    if (['string', 'bytes', 'int', 'uint', 'double', 'bool', 'null'].includes(tok.t)) {
      this.next();
      return { type: 'literal', kind: tok.t, value: tok.v, pos: tok.pos };
    }
    throw this.error(`expected a value but found ${describe(tok)}`, tok.pos);
  }

  identTail() {
    const id = this.next();
    if (RESERVED.has(id.v)) throw this.error(`"${id.v}" is a reserved word in CEL`, id.pos);
    if (this.isOp('(')) {
      return { type: 'call', target: null, fn: id.v, args: this.callArgs(), pos: id.pos };
    }
    if (this.isOp('{') && /^[A-Z]/.test(id.v)) {
      return this.struct(id);
    }
    return { type: 'ident', name: id.v, pos: id.pos };
  }

  list() {
    const open = this.expectOp('[');
    const elems = [];
    while (!this.isOp(']')) {
      let optional = false;
      if (this.isOp('?')) {
        this.next();
        optional = true;
      }
      elems.push({ value: this.expr(), optional });
      if (this.isOp(',')) {
        this.next();
        continue;
      }
      break;
    }
    this.expectOp(']', 'to close the list');
    return { type: 'list', elems: elems.map((e) => e.value), optional: elems.map((e) => e.optional), pos: open.pos };
  }

  map() {
    const open = this.expectOp('{');
    const entries = [];
    while (!this.isOp('}')) {
      let optional = false;
      if (this.isOp('?')) {
        this.next();
        optional = true;
      }
      const key = this.expr();
      this.expectOp(':', 'between a map key and its value');
      const value = this.expr();
      entries.push({ key, value, optional });
      if (this.isOp(',')) {
        this.next();
        continue;
      }
      break;
    }
    this.expectOp('}', 'to close the map');
    return { type: 'map', entries, pos: open.pos };
  }

  struct(id) {
    this.expectOp('{');
    const fields = [];
    while (!this.isOp('}')) {
      const f = this.peek();
      if (f.t !== 'ident') throw this.error('expected a field name in a message literal', f.pos);
      this.next();
      this.expectOp(':');
      fields.push({ name: f.v, value: this.expr() });
      if (this.isOp(',')) {
        this.next();
        continue;
      }
      break;
    }
    this.expectOp('}', 'to close the message literal');
    return { type: 'struct', name: id.v, fields, pos: id.pos };
  }
}

/** a.b.c as a dotted name, or null when the node is not a plain name chain. */
function qualifiedName(node) {
  if (node.type === 'ident') return node.name;
  if (node.type === 'select' && !node.optional) {
    const left = qualifiedName(node.operand);
    return left ? `${left}.${node.field}` : null;
  }
  return null;
}

function describe(tok) {
  if (tok.t === 'eof') return 'the end of the expression';
  if (tok.t === 'op') return `"${tok.v}"`;
  if (tok.t === 'ident') return `name "${tok.v}"`;
  return `a ${tok.t} literal`;
}

/** Parse one CEL expression. Never throws. */
export function parseCel(text) {
  if (typeof text !== 'string') return { ok: false, error: { message: 'expression is not a string', offset: 0, line: 1, column: 1 } };
  try {
    const ast = new Parser(text).parse();
    return { ok: true, ast };
  } catch (error) {
    if (error instanceof CelSyntaxError) {
      return { ok: false, error: { message: error.message, offset: error.offset, line: error.line, column: error.column } };
    }
    throw error;
  }
}

// ---------------------------------------------------------------- templates

/**
 * Split a Fusion template string ("text ${expr} text") into its parts.
 * Returns { ok, parts: [{ kind: 'text'|'expr', text, offset }], error }.
 * Braces and quotes inside an expression are skipped over properly.
 */
export function splitTemplate(text) {
  const parts = [];
  let i = 0;
  let textStart = 0;
  while (i < text.length) {
    if (text[i] === '$' && text[i + 1] === '{') {
      if (i > textStart) parts.push({ kind: 'text', text: text.slice(textStart, i), offset: textStart });
      const exprStart = i + 2;
      const end = findClose(text, exprStart);
      if (end === -1) return { ok: false, error: { message: 'a "${" has no matching "}"', offset: i } };
      parts.push({ kind: 'expr', text: text.slice(exprStart, end), offset: exprStart });
      i = end + 1;
      textStart = i;
      continue;
    }
    i++;
  }
  if (textStart < text.length) parts.push({ kind: 'text', text: text.slice(textStart), offset: textStart });
  return { ok: true, parts };
}

function findClose(text, from) {
  let depth = 0;
  let i = from;
  while (i < text.length) {
    const c = text[i];
    if (c === '"' || c === "'") {
      const triple = text.slice(i, i + 3) === c.repeat(3);
      const close = triple ? c.repeat(3) : c;
      i += close.length;
      while (i < text.length && !text.startsWith(close, i)) {
        if (text[i] === '\\') i++;
        i++;
      }
      i += close.length;
      continue;
    }
    if (c === '{') depth++;
    if (c === '}') {
      if (depth === 0) return i;
      depth--;
    }
    i++;
  }
  return -1;
}

export function isTemplate(text) {
  return typeof text === 'string' && text.includes('${');
}

/**
 * Check a string the way Fusion reads a playbook field: a template when it
 * holds "${", otherwise one CEL expression. Returns
 * { ok, kind, expressions: [{ text, offset, ast }], error }.
 */
export function checkField(text) {
  // Fusion reads an empty string as an empty literal; whitespace alone is a syntax error.
  if (text === '') return { ok: true, kind: 'literal', expressions: [] };
  if (isTemplate(text)) {
    const split = splitTemplate(text);
    if (!split.ok) return { ok: false, kind: 'template', error: split.error, expressions: [] };
    const expressions = [];
    for (const part of split.parts.filter((p) => p.kind === 'expr')) {
      const r = parseCel(part.text);
      if (!r.ok) {
        return { ok: false, kind: 'template', error: { ...r.error, offset: part.offset + r.error.offset, inTemplate: true }, expressions };
      }
      expressions.push({ text: part.text, offset: part.offset, ast: r.ast });
    }
    return { ok: true, kind: 'template', expressions };
  }
  const r = parseCel(text);
  if (!r.ok) return { ok: false, kind: 'cel', error: r.error, expressions: [] };
  return { ok: true, kind: 'cel', expressions: [{ text, offset: 0, ast: r.ast }] };
}

// ---------------------------------------------------------------- analysis

/**
 * Root identifiers an expression reads, skipping loop variables bound by
 * comprehension functions and cel.bind. Each reference is
 * { root, path: [field, ...], optional: bool (first step used .? or [?]), pos }.
 * Also returns `guards`: roots named in a has(...) call, and `calls`: function names.
 */
export function references(ast) {
  const refs = [];
  const guards = new Set();
  const calls = new Set();

  function chain(node) {
    // Unwind a select/index chain down to its root.
    const path = [];
    let optional = false;
    let cur = node;
    while (cur && (cur.type === 'select' || cur.type === 'index')) {
      if (cur.type === 'select') path.unshift(cur.field);
      else path.unshift('[]');
      if (cur.optional) optional = true;
      cur = cur.operand;
    }
    return { root: cur, path, optional };
  }

  function walk(node, bound) {
    if (!node) return;
    switch (node.type) {
      case 'ident':
        if (!bound.has(node.name)) refs.push({ root: node.name, path: [], optional: false, pos: node.pos });
        return;
      case 'select':
      case 'index': {
        const c = chain(node);
        if (c.root?.type === 'ident' && !bound.has(c.root.name)) {
          refs.push({ root: c.root.name, path: c.path.filter((p) => p !== '[]'), optional: c.optional, pos: c.root.pos });
          // still walk index expressions inside the chain
          let cur = node;
          while (cur && (cur.type === 'select' || cur.type === 'index')) {
            if (cur.type === 'index') walk(cur.index, bound);
            cur = cur.operand;
          }
          return;
        }
        walk(node.operand, bound);
        if (node.type === 'index') walk(node.index, bound);
        return;
      }
      case 'call': {
        const name = node.target ? node.fn : node.fn;
        calls.add(node.target && node.target.type === 'ident' && node.target.name === 'cel' ? `cel.${node.fn}` : name);
        if (!node.target && node.fn === 'has') {
          const first = node.args[0];
          const c = first ? chain(first) : null;
          if (c?.root?.type === 'ident') guards.add(c.root.name);
        }
        // cel.bind(v, init, body)
        if (node.target?.type === 'ident' && node.target.name === 'cel' && node.fn === 'bind' && node.args[0]?.type === 'ident') {
          walk(node.args[1], bound);
          const inner = new Set(bound);
          inner.add(node.args[0].name);
          walk(node.args[2], inner);
          return;
        }
        // namespaced functions such as base64.decode or math.abs: the namespace is not a reference
        const namespaced = node.target?.type === 'ident' && ['base64', 'math', 'strings', 'lists', 'sets', 'regex', 'optional', 'cel'].includes(node.target.name) && !bound.has(node.target.name);
        if (node.target && !namespaced) walk(node.target, bound);
        if (node.target && BINDING_FUNCTIONS.has(node.fn) && node.args.length >= 2) {
          const inner = new Set(bound);
          let k = 0;
          while (k < node.args.length - 1 && node.args[k].type === 'ident') {
            inner.add(node.args[k].name);
            k++;
          }
          for (let j = k; j < node.args.length; j++) walk(node.args[j], inner);
          return;
        }
        for (const a of node.args) walk(a, bound);
        return;
      }
      case 'list':
        for (const e of node.elems) walk(e, bound);
        return;
      case 'map':
        for (const e of node.entries) {
          walk(e.key, bound);
          walk(e.value, bound);
        }
        return;
      case 'struct':
        for (const f of node.fields) walk(f.value, bound);
        return;
      case 'unary':
        walk(node.operand, bound);
        return;
      case 'binary':
        walk(node.left, bound);
        walk(node.right, bound);
        return;
      case 'cond':
        walk(node.test, bound);
        walk(node.then, bound);
        walk(node.else, bound);
        return;
      default:
    }
  }

  walk(ast, new Set());
  return { refs, guards, calls };
}

/** True when the expression is one string literal, e.g. 'SUCCESS'. */
export function isStringLiteral(ast) {
  return ast?.type === 'literal' && ast.kind === 'string';
}
