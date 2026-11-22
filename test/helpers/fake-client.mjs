// An in-process stand-in for FusionClient: each GraphQL root field answers from a handler.
// handlers: { fieldName: (variables, call) => data value | throws }. Calls are kept in order.

import { GraphQLError } from '../../lib/errors.mjs';

export function fakeClient(handlers) {
  const calls = [];
  const op = (doc) => /^\s*(?:(?:query|mutation)\b[^{]*)?\{\s*([A-Za-z_][A-Za-z0-9_]*)/.exec(doc)?.[1] ?? null;
  const answer = async (doc, variables) => {
    const name = op(doc);
    calls.push({ op: name, variables, mutation: /^\s*mutation\b/.test(doc) });
    const h = handlers[name];
    if (!h) throw new Error(`fake client: no handler for ${name}`);
    const value = await h(variables, calls);
    return { data: { [name]: value }, warnings: [] };
  };
  return {
    calls,
    request: (doc, variables = {}) => answer(doc, variables),
    upload: (doc, { content, variables } = {}) => answer(doc, { ...(variables || {}), content }),
  };
}

export const gqlError = (message) => new GraphQLError([{ message }]);
