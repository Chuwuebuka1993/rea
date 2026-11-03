import readline from "node:readline";
import { UserError, validateArgs } from "./validate.js";

const SUPPORTED_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];

/**
 * Minimal MCP server over newline-delimited JSON-RPC (stdio transport).
 * tools: [{ name, description, inputSchema, annotations?, handler(args) -> {summary, data?, findings?} }]
 */
export function createServer({ name, version, tools, onResult }) {
  const byName = new Map(tools.map((t) => [t.name, t]));

  async function callTool(params) {
    const tool = byName.get(params?.name);
    if (!tool) return { error: { code: -32602, message: `Unknown tool: ${params?.name}` } };
    const errors = validateArgs(tool.inputSchema, params.arguments);
    if (errors.length) return { result: toolError(`Invalid arguments: ${errors.join("; ")}`) };
    try {
      const out = await tool.handler(params.arguments ?? {});
      onResult?.(tool.name, params.arguments ?? {}, out);
      return { result: toolText(out) };
    } catch (err) {
      if (err instanceof UserError) return { result: toolError(err.message) };
      process.stderr.write(`[${tool.name}] ${err?.stack ?? err}\n`);
      return { result: toolError(`${tool.name} failed: ${err?.message ?? String(err)}`) };
    }
  }

  /** Handle one parsed JSON-RPC message. Returns a response object, or undefined for notifications. */
  async function handleMessage(msg) {
    if (!msg || typeof msg !== "object" || typeof msg.method !== "string") {
      return msg?.id === undefined ? undefined : rpcError(msg.id, -32600, "Invalid Request");
    }
    const isNotification = msg.id === undefined;
    let outcome;
    switch (msg.method) {
      case "initialize": {
        const asked = msg.params?.protocolVersion;
        outcome = {
          result: {
            protocolVersion: SUPPORTED_VERSIONS.includes(asked) ? asked : SUPPORTED_VERSIONS[0],
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name, version },
            instructions:
              "Scope-gated GitHub OSINT and recon tools. Every network target must be listed in the scope file. " +
              "Call scope_status first.",
          },
        };
        break;
      }
      case "ping":
        outcome = { result: {} };
        break;
      case "tools/list":
        outcome = {
          result: {
            tools: tools.map(({ name: n, description, inputSchema, annotations }) => ({
              name: n, description, inputSchema, ...(annotations ? { annotations } : {}),
            })),
          },
        };
        break;
      case "tools/call":
        outcome = await callTool(msg.params);
        break;
      default:
        outcome = { error: { code: -32601, message: `Method not found: ${msg.method}` } };
    }
    if (isNotification) return undefined;
    return outcome.error
      ? rpcError(msg.id, outcome.error.code, outcome.error.message)
      : { jsonrpc: "2.0", id: msg.id, result: outcome.result };
  }

  function serveStdio(input = process.stdin, output = process.stdout) {
    const rl = readline.createInterface({ input });
    const pending = new Set();
    rl.on("line", (line) => {
      if (!line.trim()) return;
      const job = (async () => {
        let msg;
        try {
          msg = JSON.parse(line);
        } catch {
          output.write(`${JSON.stringify(rpcError(null, -32700, "Parse error"))}\n`);
          return;
        }
        const response = await handleMessage(msg);
        if (response) output.write(`${JSON.stringify(response)}\n`);
      })();
      pending.add(job);
      job.finally(() => pending.delete(job));
    });
    rl.on("close", () => Promise.allSettled([...pending]).then(() => process.exit(0)));
  }

  return { handleMessage, serveStdio };
}

function rpcError(id, code, message) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

function toolError(message) {
  return { isError: true, content: [{ type: "text", text: message }] };
}

function toolText(out) {
  const parts = [out.summary];
  if (out.findings?.length) {
    parts.push(`Findings (${out.findings.length}):\n${out.findings.map((f) => `- [${f.severity}] ${f.title}${f.detail ? ` — ${f.detail}` : ""}`).join("\n")}`);
  }
  if (out.data !== undefined) parts.push(JSON.stringify(out.data, null, 2));
  return { content: [{ type: "text", text: parts.filter(Boolean).join("\n\n") }] };
}
