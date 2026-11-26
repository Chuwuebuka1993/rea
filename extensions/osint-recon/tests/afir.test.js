import test from "node:test"; import assert from "node:assert/strict";
import { AfirClient, maskSecrets, parseAfirUrl } from "../src/afir/client.js";
// Mock fetch only: no network, no real tokens, no AFIR process needed.
const TOKEN = "t".repeat(40), PRIVATE_POLICY = { tenant: "rea", data_class: "private", hosted_providers: false };
const resp = (status, body) => ({ ok: status < 400, status, text: async () => JSON.stringify(body) });
const fake = (routes) => { const calls = []; const f = async (url, init) => { calls.push({ url, init, body: init.body ? JSON.parse(init.body) : undefined }); return routes(new URL(url).pathname, init); }; f.calls = calls; return f; };

test("off unless configured; token required", () => {
  assert.throws(() => new AfirClient({ url: undefined, token: TOKEN }), /AFIR is off/);
  assert.throws(() => new AfirClient({ url: "http://127.0.0.1:8787", token: "short" }), /REA_AFIR_TOKEN/);
});
test("only loopback http URLs are accepted", () => {
  for (const ok of ["http://127.0.0.1:8787", "http://localhost:8787", "http://[::1]:8787"]) assert.doesNotThrow(() => parseAfirUrl(ok));
  for (const bad of ["https://127.0.0.1:8787", "http://example.com", "http://192.168.1.5:8787", "http://0.0.0.0:8787", "http://u:p@127.0.0.1:8787", "nonsense"]) assert.throws(() => parseAfirUrl(bad), undefined, bad);
});
test("connect() refuses a tenant that is not private-only with no hosted providers; nothing is sent", async () => {
  for (const p of [{ data_class: "any", hosted_providers: false }, { data_class: "private", hosted_providers: true }, {}]) {
    const f = fake(() => resp(200, p)); const c = new AfirClient({ url: "http://127.0.0.1:1", token: TOKEN, fetchImpl: f });
    await assert.rejects(c.explain({ id: "x" }), /private-only/); assert.equal(f.calls.filter((x) => x.url.endsWith("/v1/chat")).length, 0);
  }
});
test("explain(): data_class is always private, only whitelisted fields are sent, secrets are masked, redirects are refused", async () => {
  const f = fake((p) => (p === "/v1/policy" ? resp(200, PRIVATE_POLICY) : resp(200, { content: "Looks like a forwarding rule.", provider: "local", model: "m" })));
  const c = new AfirClient({ url: "http://127.0.0.1:8787", token: TOKEN, fetchImpl: f });
  const r = await c.explain({ id: "g1", severity: "high", title: "Forwarding rule", detail: "to a@b.c token ghp_" + "A".repeat(30), raw_body: "SHOULD-NOT-LEAVE", data_class: "public" });
  const chat = f.calls.find((x) => x.url.endsWith("/v1/chat"));
  assert.equal(chat.body.data_class, "private"); assert.equal(chat.body.provider, undefined);
  const sent = JSON.stringify(chat.body); assert.ok(!sent.includes("SHOULD-NOT-LEAVE") && !sent.includes("ghp_AAAA"));
  assert.equal(chat.init.redirect, "error"); assert.equal(chat.init.headers.authorization, `Bearer ${TOKEN}`);
  assert.equal(r.advisory, true); assert.match(r.note, /changes nothing and approves nothing/);
});
test("errors never include the token or the finding text", async () => {
  const f = fake((p) => (p === "/v1/policy" ? resp(200, PRIVATE_POLICY) : resp(429, { error: { code: "tenant_quota_exceeded", message: "FINDING-TEXT " + TOKEN } })));
  const c = new AfirClient({ url: "http://127.0.0.1:8787", token: TOKEN, fetchImpl: f });
  await assert.rejects(c.explain({ id: "g", title: "FINDING-TEXT" }), (e) => { assert.equal(e.code, "tenant_quota_exceeded"); assert.ok(!e.message.includes(TOKEN) && !e.message.includes("FINDING-TEXT")); return true; });
});
test("the client exposes no approval, permission, deployment or spend operations", () => {
  const names = Object.getOwnPropertyNames(AfirClient.prototype); assert.deepEqual(names.sort(), ["connect", "constructor", "explain"]);
});
test("maskSecrets hides token-shaped strings and keeps normal text", () => {
  assert.equal(maskSecrets("hello world"), "hello world"); assert.ok(!maskSecrets("Bearer abcdefghijkl").includes("abcdefghijkl")); assert.ok(!maskSecrets("x".repeat(60)).includes("xxxxxxxx"));
});
