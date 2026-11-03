#!/usr/bin/env node
import { createServer } from "./mcp.js";
import { createFindingsStore } from "./findings.js";
import { loadScope } from "./scope.js";
import { createGithubTools } from "./tools/github.js";
import { createMetaTools } from "./tools/meta.js";
import { createReconTools } from "./tools/recon.js";

/** Build the server. `scopeSource` is a path or a function returning a parsed scope. */
export function buildServer({ scopeSource = process.env.OSINT_SCOPE_FILE ?? "osint-scope.json", env = process.env, cwd = process.cwd() } = {}) {
  let cached;
  const getScope = () => {
    if (typeof scopeSource === "function") return scopeSource();
    // Re-read on every call so scope edits (and expiry) take effect without a restart.
    cached = loadScope(scopeSource);
    return cached;
  };
  const store = createFindingsStore();
  const tools = [
    ...createMetaTools({ getScope, store, cwd }),
    ...createReconTools({ getScope }),
    ...createGithubTools({ getScope, env }),
  ];
  return createServer({
    name: "rea-osint-recon",
    version: "0.1.0",
    tools,
    onResult: (tool, args, out) => store.add(tool, args.host ?? args.org ?? args.repo ?? args.path, out.findings),
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  buildServer().serveStdio();
}
