import assert from "node:assert/strict";
import { test } from "node:test";
import { auditWorkflow, scanDiff, scanText, summarizeOrg } from "../src/tools/github.js";
import { auditHeaders, summarizeRdap } from "../src/tools/recon.js";

test("scanText detects credentials, skips placeholders, masks output", () => {
  const ghToken = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
  const hits = scanText(`token = "${ghToken}"\nkey: AKIAIOSFODNN7EXAMPLE\npassword = "changeme-please"\n`, "a.txt");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].type, "GitHub token");
  assert.ok(!JSON.stringify(hits).includes(ghToken));
  assert.match(hits[0].masked, /^ghp_…/);
});

test("scanDiff tracks commit, file and line of added secrets only", () => {
  const key = "AKIA" + "Q7XK2M9ZP4TR8WLB";
  const diff = ["@@commit abc123def456", "diff --git a/x.env b/x.env", "--- a/x.env", "+++ b/x.env", "@@ -1,1 +1,3 @@", " keep", `-OLD=${key}`, `+NEW=${key}`, "+safe=1"].join("\n");
  const { findings, commits } = scanDiff(diff);
  assert.equal(commits, 1);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].commit, "abc123def456");
  assert.equal(findings[0].file, "x.env");
  assert.equal(findings[0].line, 2);
});

test("workflow audit: pinned actions and env-passed inputs are clean", () => {
  const sha = "a".repeat(40);
  const yml = ["on: push", "permissions:", "  contents: read", "jobs:", "  t:", "    steps:", `      - uses: actions/checkout@${sha}`, "      - run: echo \"$TITLE\"", "        env:", "          TITLE: ${{ github.event.pull_request.title }}"].join("\n");
  assert.deepEqual(auditWorkflow(yml, "ci.yml"), []);
});

test("workflow audit flags write-all, unpinned third-party action, inherit", () => {
  const yml = ["on: push", "permissions: write-all", "jobs:", "  t:", "    steps:", "      - uses: someone/action@v1", "      - uses: ./local", "  call:", "    secrets: inherit"].join("\n");
  const titles = auditWorkflow(yml, "ci.yml").map((i) => i.title);
  assert.ok(titles.includes("permissions: write-all"));
  assert.ok(titles.includes("Action not pinned to a commit SHA"));
  assert.ok(titles.includes("secrets: inherit"));
});

test("summarizeOrg aggregates languages and stale repos", () => {
  const old = new Date(Date.now() - 800 * 86_400_000).toISOString();
  const data = summarizeOrg({ login: "o", public_repos: 3 }, [
    { name: "a", language: "Go", pushed_at: old }, { name: "b", language: "Go", pushed_at: new Date().toISOString() },
    { name: "c", language: "Rust", archived: true, pushed_at: old },
  ]);
  assert.deepEqual(data.top_languages[0], ["Go", 2]);
  assert.deepEqual(data.stale_repos, ["a"]);
  assert.equal(data.archived_repos, 1);
});

test("header audit and RDAP summary", () => {
  const { missing } = auditHeaders({ "content-security-policy": "default-src 'self'; frame-ancestors 'none'" }, "https");
  assert.ok(missing.includes("strict-transport-security"));
  assert.ok(!missing.includes("x-frame-options"));
  const rdap = summarizeRdap({ ldhName: "EXAMPLE.COM", status: ["active"], entities: [{ roles: ["registrar"], vcardArray: ["vcard", [["fn", {}, "text", "Reg Inc"]]] }, { roles: ["registrant"], vcardArray: ["vcard", [["fn", {}, "text", "Private Person"]]] }], nameservers: [{ ldhName: "ns1.example.com" }] }, "example.com");
  assert.equal(rdap.registrar, "Reg Inc");
  assert.ok(!JSON.stringify(rdap).includes("Private Person"));
});
