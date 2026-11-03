import { parseScope } from "../src/scope.js";
import { buildServer } from "../src/server.js";

export const AUTH = { authorized_by: "Test Owner", date: "2026-01-01" };

export function makeScope(extra = {}) {
  return parseScope({ authorization: AUTH, ...extra });
}

/** Build a server with a fixed scope and return a call(name, args) helper. */
export function makeClient(scopeExtra, opts = {}) {
  const scope = makeScope(scopeExtra);
  const server = buildServer({ scopeSource: () => scope, ...opts });
  let id = 0;
  return {
    server,
    async call(name, args = {}) {
      const res = await server.handleMessage({ jsonrpc: "2.0", id: ++id, method: "tools/call", params: { name, arguments: args } });
      return { ...res.result, text: res.result.content[0].text };
    },
  };
}
