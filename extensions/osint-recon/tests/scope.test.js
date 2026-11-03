import assert from "node:assert/strict";
import { test } from "node:test";
import { ScopeError, guardedLookup, hostInScope, ipInCidr, isNonPublicIp, parseCidr, parseScope } from "../src/scope.js";
import { parseHost, parsePorts, parseRepoSlug } from "../src/validate.js";
import { AUTH, makeScope } from "./helpers.js";

test("scope requires authorization details", () => {
  assert.throws(() => parseScope({ domains: ["example.com"] }), ScopeError);
  assert.throws(() => parseScope({ authorization: { authorized_by: "x", date: "soon" }, domains: ["example.com"] }), /YYYY-MM-DD/);
  assert.throws(() => parseScope({ authorization: AUTH }), /scope is empty/);
});

test("expired authorization is rejected", () => {
  assert.throws(() => parseScope({ authorization: { ...AUTH, expires: "2020-01-01" }, domains: ["example.com"] }), /expired/);
});

test("limits are clamped to hard maximums", () => {
  const s = makeScope({ domains: ["example.com"], limits: { max_ports: 99999, concurrency: 5000 } });
  assert.equal(s.limits.max_ports, 1024);
  assert.equal(s.limits.concurrency, 100);
});

test("domain scope covers subdomains but not look-alikes", () => {
  const s = makeScope({ domains: ["example.com"] });
  assert.ok(hostInScope(s, parseHost("example.com")));
  assert.ok(hostInScope(s, parseHost("API.Example.com.")));
  assert.ok(!hostInScope(s, parseHost("badexample.com")));
  assert.ok(!hostInScope(s, parseHost("example.com.evil.net")));
});

test("IP literals must be listed explicitly", () => {
  const s = makeScope({ domains: ["example.com"], cidrs: ["203.0.113.0/24"] });
  assert.ok(hostInScope(s, parseHost("203.0.113.77")));
  assert.ok(!hostInScope(s, parseHost("203.0.114.1")));
  assert.ok(!hostInScope(s, parseHost("93.184.216.34")));
});

test("CIDR matching and non-public detection", () => {
  assert.ok(ipInCidr("10.1.2.3", parseCidr("10.0.0.0/8")));
  assert.ok(!ipInCidr("11.0.0.1", parseCidr("10.0.0.0/8")));
  assert.ok(ipInCidr("::ffff:10.1.2.3", parseCidr("10.0.0.0/8")));
  for (const ip of ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1"]) {
    assert.ok(isNonPublicIp(ip), ip);
  }
  for (const ip of ["8.8.8.8", "93.184.216.34", "2606:4700::1111"]) assert.ok(!isNonPublicIp(ip), ip);
});

test("guarded lookup blocks non-public resolution of an in-scope name", async () => {
  const blocked = guardedLookup(makeScope({ domains: ["localhost"] }));
  await assert.rejects(() => new Promise((res, rej) => blocked("localhost", {}, (e, a) => (e ? rej(e) : res(a)))), ScopeError);
  const allowed = guardedLookup(makeScope({ domains: ["localhost"], cidrs: ["127.0.0.0/8"] }));
  const addr = await new Promise((res, rej) => allowed("localhost", { family: 4 }, (e, a) => (e ? rej(e) : res(a))));
  assert.equal(addr, "127.0.0.1");
});

test("port and host parsing", () => {
  assert.deepEqual(parsePorts("80,443,8000-8002", 100), [80, 443, 8000, 8001, 8002]);
  assert.throws(() => parsePorts("1-5000", 100), /exceeds/);
  assert.throws(() => parsePorts("70000", 100), /invalid port/);
  assert.throws(() => parseHost("exa mple.com"), /not a valid/);
  assert.throws(() => parseHost("a.com/../x"), /not a valid/);
  assert.deepEqual(parseRepoSlug("octo/repo-1"), { owner: "octo", repo: "repo-1" });
  assert.throws(() => parseRepoSlug("octo/../etc"), /owner\/name/);
  assert.throws(() => parseRepoSlug("octo/.."), /valid/);
});
