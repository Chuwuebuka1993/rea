import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { makeClient } from "./helpers.js";

const LOOPBACK = { cidrs: ["127.0.0.0/8"], domains: ["example.com"] };

test("protocol: initialize, list, unknown method and tool", async () => {
  const { server } = makeClient(LOOPBACK);
  const init = await server.handleMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } });
  assert.equal(init.result.serverInfo.name, "rea-osint-recon");
  assert.equal(await server.handleMessage({ jsonrpc: "2.0", method: "notifications/initialized" }), undefined);
  const list = await server.handleMessage({ jsonrpc: "2.0", id: 2, method: "tools/list" });
  const names = list.result.tools.map((t) => t.name);
  for (const n of ["scope_status", "kali_tool_catalog", "recon_dns", "recon_whois", "recon_tls", "recon_http_headers", "recon_port_scan", "github_org_overview", "github_repo_overview", "github_exposure_scan", "github_workflow_audit", "report_export"]) {
    assert.ok(names.includes(n), n);
  }
  const bad = await server.handleMessage({ jsonrpc: "2.0", id: 3, method: "nope" });
  assert.equal(bad.error.code, -32601);
  const unknown = await server.handleMessage({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "nope" } });
  assert.equal(unknown.error.code, -32602);
});

test("argument validation rejects unknown and mistyped arguments", async () => {
  const c = makeClient(LOOPBACK);
  const r = await c.call("recon_port_scan", { host: "127.0.0.1", extra: 1 });
  assert.ok(r.isError);
  assert.match(r.text, /unknown argument "extra"/);
});

test("out-of-scope targets are refused before any network access", async () => {
  const c = makeClient(LOOPBACK);
  for (const [tool, args] of [["recon_dns", { host: "other.org" }], ["recon_port_scan", { host: "8.8.8.8" }], ["recon_tls", { host: "other.org" }], ["recon_http_headers", { host: "other.org" }], ["recon_whois", { host: "other.org" }], ["github_org_overview", { org: "someoneelse" }], ["github_repo_overview", { owner: "a", repo: "b" }]]) {
    const r = await c.call(tool, args);
    assert.ok(r.isError, tool);
    assert.match(r.text, /not in the authorized scope/, tool);
  }
});

test("missing scope fails closed with guidance", async () => {
  const { buildServer } = await import("../src/server.js");
  const server = buildServer({ scopeSource: "/nonexistent/scope.json" });
  const res = await server.handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "recon_dns", arguments: { host: "example.com" } } });
  assert.ok(res.result.isError);
  assert.match(res.result.content[0].text, /Cannot read scope file/);
});

test("port scan finds an open loopback port and records findings", async () => {
  const srv = net.createServer((s) => s.end());
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const { port } = srv.address();
  try {
    const c = makeClient(LOOPBACK);
    const r = await c.call("recon_port_scan", { host: "127.0.0.1", ports: String(port) });
    assert.ok(!r.isError, r.text);
    assert.match(r.text, new RegExp(`"port": ${port}`));
    assert.match(r.text, /"state": "open"/);
    const closed = await c.call("recon_port_scan", { host: "127.0.0.1", ports: "1" });
    assert.match(closed.text, /0 open of 1/);
    const tooMany = await c.call("recon_port_scan", { host: "127.0.0.1", ports: "1-500" });
    assert.ok(tooMany.isError);
  } finally {
    srv.close();
  }
});

test("http header audit flags missing headers and weak cookies", async () => {
  const srv = http.createServer((req, res) => {
    res.setHeader("server", "nginx/1.18.0");
    res.setHeader("set-cookie", "sid=abc; Path=/");
    res.end("ok");
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  try {
    const c = makeClient(LOOPBACK);
    const r = await c.call("recon_http_headers", { host: "127.0.0.1", port: srv.address().port, scheme: "http" });
    assert.ok(!r.isError, r.text);
    assert.match(r.text, /HTTP 200/);
    assert.match(r.text, /Missing Content-Security-Policy/);
    assert.match(r.text, /Server banner discloses a version/);
    assert.match(r.text, /Cookie "sid" missing HttpOnly/);
    const exported = await c.call("report_export", {});
    assert.match(exported.text, /Missing Content-Security-Policy/);
  } finally {
    srv.close();
  }
});

test("exposure scan masks secrets and workflow audit finds injection", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "osint-test-"));
  const awsKey = "AKIA" + "Q7XK2M9ZP4TR8WLB";
  fs.writeFileSync(path.join(dir, "config.env"), `AWS_KEY=${awsKey}\nNAME=demo\n`);
  fs.mkdirSync(path.join(dir, ".github", "workflows"), { recursive: true });
  fs.writeFileSync(path.join(dir, ".github", "workflows", "ci.yml"), [
    "on: pull_request_target", "jobs:", "  build:", "    steps:",
    "      - uses: actions/checkout@v4", "        with:", "          ref: ${{ github.event.pull_request.head.sha }}",
    "      - run: |", "          echo \"${{ github.event.pull_request.title }}\"", "",
  ].join("\n"));
  try {
    const c = makeClient(LOOPBACK);
    const scan = await c.call("github_exposure_scan", { path: dir });
    assert.ok(!scan.isError, scan.text);
    assert.match(scan.text, /AWS access key ID/);
    assert.ok(!scan.text.includes(awsKey), "full secret must never be returned");
    const wf = await c.call("github_workflow_audit", { path: dir });
    assert.match(wf.text, /Script injection/);
    assert.match(wf.text, /pull_request_target checks out untrusted PR code/);
    assert.match(wf.text, /not pinned/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("report_export refuses traversal and absolute paths and never overwrites", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "osint-report-"));
  try {
    const c = makeClient(LOOPBACK, { cwd: dir });
    assert.match((await c.call("report_export", { output_path: "../x.md" })).text, /inside the working directory/);
    assert.match((await c.call("report_export", { output_path: "/tmp/x.md" })).text, /relative/);
    assert.match((await c.call("report_export", { output_path: "x.txt" })).text, /must end with/);
    const ok = await c.call("report_export", { output_path: "out/r.md" });
    assert.ok(!ok.isError, ok.text);
    assert.ok(fs.existsSync(path.join(dir, "out", "r.md")));
    assert.match((await c.call("report_export", { output_path: "out/r.md" })).text, /already exists/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("kali catalog maps tools and hides nothing about what is not wrapped", async () => {
  const c = makeClient(LOOPBACK);
  const r = await c.call("kali_tool_catalog", { category: "exploitation" });
  assert.match(r.text, /Not wrapped by design/);
  assert.match(r.text, /"covered_by": null/);
});
