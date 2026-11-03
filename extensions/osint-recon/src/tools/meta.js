import fs from "node:fs";
import path from "node:path";
import { KALI_CATALOG, annotateInstalled } from "../kaliCatalog.js";
import { renderMarkdown } from "../findings.js";
import { UserError } from "../validate.js";

const LOCAL = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };

export function createMetaTools({ getScope, store, cwd = process.cwd() }) {
  const scopeStatus = {
    name: "scope_status",
    description: "Show the authorization and scope every other tool enforces. Call this first.",
    annotations: LOCAL,
    inputSchema: { type: "object", properties: {} },
    async handler() {
      const s = getScope();
      return {
        summary: `Scope loaded: authorized by ${s.authorization.authorized_by} on ${s.authorization.date}`,
        data: {
          authorization: s.authorization,
          domains: s.domains, hosts: s.hosts, cidrs: s.cidrs.map((c) => c.text),
          github: s.github, limits: s.limits,
        },
      };
    },
  };

  const catalog = {
    name: "kali_tool_catalog",
    description:
      "Map of common Kali Linux tools to the equivalent tool in this server, with a check of which are installed locally. " +
      "Exploitation and credential-attack tools are listed for orientation only and are not wrapped.",
    annotations: LOCAL,
    inputSchema: {
      type: "object",
      properties: {
        category: { type: "string", maxLength: 40 },
        installed_only: { type: "boolean" },
      },
    },
    async handler({ category, installed_only = false }) {
      let rows = annotateInstalled(KALI_CATALOG);
      if (category) rows = rows.filter((r) => r.category === category.toLowerCase());
      if (installed_only) rows = rows.filter((r) => r.installed);
      const categories = [...new Set(KALI_CATALOG.map((r) => r.category))];
      return {
        summary: `${rows.length} catalog entries (${rows.filter((r) => r.covered_by).length} covered by this server, ${rows.filter((r) => r.installed).length} installed locally)`,
        data: { categories, tools: rows },
      };
    },
  };

  const report = {
    name: "report_export",
    description:
      "Collect every finding produced by the tools in this session into a Markdown or JSON report. " +
      "Optionally write it to a file under the working directory.",
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
    inputSchema: {
      type: "object",
      properties: {
        format: { type: "string", enum: ["markdown", "json"] },
        output_path: { type: "string", maxLength: 256, description: "Relative .md/.json path inside the working directory" },
        clear: { type: "boolean", description: "Clear stored findings after exporting" },
      },
    },
    async handler({ format = "markdown", output_path, clear = false }) {
      let authorization;
      try { authorization = getScope().authorization; } catch { /* report works without a scope */ }
      const items = store.all();
      const body = format === "json" ? JSON.stringify({ authorization, findings: items }, null, 2) : renderMarkdown(items, { authorization });
      let written;
      if (output_path) {
        written = resolveOutput(cwd, output_path, format);
        fs.mkdirSync(path.dirname(written), { recursive: true });
        fs.writeFileSync(written, body, { flag: "wx" });
      }
      if (clear) store.clear();
      return {
        summary: `${items.length} finding(s) exported${written ? ` to ${path.relative(cwd, written)}` : ""}`,
        data: written ? { written: path.relative(cwd, written), counts: store.counts() } : undefined,
        ...(written ? {} : { summary: `${items.length} finding(s)\n\n${body}` }),
      };
    },
  };

  return [scopeStatus, catalog, report];
}

/** Resolve an output path, refusing absolute paths, traversal, and unexpected extensions. */
export function resolveOutput(cwd, output, format) {
  if (path.isAbsolute(output)) throw new UserError("output_path must be relative to the working directory");
  const ext = format === "json" ? ".json" : ".md";
  if (path.extname(output) !== ext) throw new UserError(`output_path must end with ${ext}`);
  const full = path.resolve(cwd, output);
  const rel = path.relative(cwd, full);
  if (rel.startsWith("..") || path.isAbsolute(rel)) throw new UserError("output_path must stay inside the working directory");
  if (fs.existsSync(full)) throw new UserError(`${rel} already exists; choose a new file name`);
  return full;
}
