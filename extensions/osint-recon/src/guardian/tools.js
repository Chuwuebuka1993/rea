import path from "node:path";
import { UserError } from "../validate.js";
import { auditGithub } from "./githubAudit.js";
import { triageAndroid, COLLECT_COMMANDS } from "./android.js";
import { FIRST_HOUR, getPlaybook, listPlatforms } from "./playbooks.js";
import { assessRegistry, loadRegistry, saveRegistry, upsertAccount } from "./registry.js";

const LOCAL = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };

function registryPath(env, cwd) {
  const p = path.resolve(cwd, env.GUARDIAN_REGISTRY ?? "guardian-accounts.json");
  if (path.relative(cwd, p).startsWith("..")) throw new UserError("GUARDIAN_REGISTRY must be inside the working directory");
  return p;
}

export function createGuardianTools({ env = process.env, cwd = process.cwd(), fetchImpl = fetch } = {}) {
  return [
    {
      name: "guardian_readiness",
      description:
        "Score every registered account for how hard it is to break into and how recoverable it is after a hack (2FA type, backup codes, " +
        "recovery email/phone, passkeys, second owner). Lists the weakest first with the exact next actions. An account is capped by the email that can reset it.",
      annotations: LOCAL,
      inputSchema: { type: "object", properties: {} },
      async handler() {
        const reg = loadRegistry(registryPath(env, cwd));
        if (!reg.accounts.length) return { summary: "No accounts registered yet. Use guardian_add_account.", data: { accounts: [] } };
        const res = assessRegistry(reg);
        const findings = res.accounts.filter((a) => a.score < 65).map((a) => ({ severity: a.score < 40 ? "high" : "medium", title: `${a.label}: ${a.grade} (${a.score}/100)`, detail: a.actions[0], target: a.id }));
        return { summary: `Overall recovery readiness ${res.overall}/100 across ${res.accounts.length} account(s)`, data: res, findings };
      },
    },
    {
      name: "guardian_add_account",
      description:
        "Add or update an account in the local registry. Stores only HOW the account is protected, never passwords, codes, or tokens. " +
        "Fields: id, platform, label, email_account (id of the account that resets this one), twofa (none|sms|totp|passkey|hardware), backup_codes_saved, recovery_email, recovery_phone, passkey_or_key, password_manager, unique_password, owners, critical, last_reviewed (YYYY-MM-DD).",
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: false },
      inputSchema: { type: "object", required: ["account"], properties: { account: { type: "object" } } },
      async handler({ account }) {
        const file = registryPath(env, cwd);
        const reg = loadRegistry(file);
        const saved = upsertAccount(reg, account);
        saveRegistry(file, reg);
        return { summary: `Saved "${saved.id}" (${reg.accounts.length} account(s) in registry)`, data: saved };
      },
    },
    {
      name: "guardian_recovery_playbook",
      description: `Official-source recovery steps for a platform, before and after a hack. Platforms: ${listPlatforms().join(", ")}. Each carries its source URL and verification date; vendors change flows, so confirm on the linked page.`,
      annotations: LOCAL,
      inputSchema: { type: "object", required: ["platform"], properties: { platform: { type: "string", maxLength: 30 } } },
      async handler({ platform }) {
        const pb = getPlaybook(platform);
        if (!pb) throw new UserError(`No playbook for "${platform}". Available: ${listPlatforms().join(", ")}`);
        return { summary: `${pb.name} recovery playbook (verified ${pb.verified_on})`, data: { ...pb, first_hour: FIRST_HOUR } };
      },
    },
    {
      name: "guardian_github_audit",
      description:
        "Read-only audit of YOUR OWN GitHub account: 2FA flag, SSH/GPG keys, deploy keys, webhooks, emails. Uses the token in env GUARDIAN_GITHUB_TOKEN (never pass it as an argument). " +
        "Returns a snapshot for baseline diffing.",
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: true },
      inputSchema: { type: "object", properties: { max_repos: { type: "integer", minimum: 1, maximum: 100 } } },
      async handler({ max_repos = 30 }) {
        const r = await auditGithub({ token: env.GUARDIAN_GITHUB_TOKEN, fetchImpl, maxRepos: max_repos });
        return { summary: r.summary, findings: r.findings, data: { snapshot: r.snapshot, limits: r.limits } };
      },
    },
    {
      name: "guardian_android_triage",
      description:
        "Triage Android command output for stalkerware tells (accessibility services, notification listeners, device admins, sideloaded apps). " +
        "Run the commands from guardian_android_commands yourself and paste the text. Triage only: cannot prove a phone is clean.",
      annotations: LOCAL,
      inputSchema: {
        type: "object",
        properties: {
          accessibility: { type: "string", maxLength: 20000 },
          notification_listeners: { type: "string", maxLength: 20000 },
          device_admins: { type: "string", maxLength: 200000 },
          third_party_packages: { type: "string", maxLength: 100000 },
          allow: { type: "array", items: { type: "string", maxLength: 100 }, maxItems: 200 },
          iocs: { type: "array", items: { type: "string", maxLength: 100 }, maxItems: 5000 },
        },
      },
      async handler({ allow, iocs, ...input }) {
        const r = triageAndroid(input, { ...(allow ? { allow } : {}), iocs: iocs ?? [] });
        return { summary: r.summary, findings: r.findings, data: { limits: r.limits } };
      },
    },
    {
      name: "guardian_android_commands",
      description: "The exact adb commands whose output guardian_android_triage understands.",
      annotations: LOCAL,
      inputSchema: { type: "object", properties: {} },
      async handler() {
        return { summary: "Run these with USB debugging on, from a trusted computer, then paste the output.", data: COLLECT_COMMANDS };
      },
    },
  ];
}
