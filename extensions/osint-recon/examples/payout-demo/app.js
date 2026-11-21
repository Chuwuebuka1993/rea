// Reference app: how a real service (Apex Mall, EarnBridge, SSNG) wires in Sentinel.
// Demo storage is in memory. In production use a database, HTTPS, and a real out-of-band channel (SMS/WhatsApp/email) for confirmation.
import crypto from "node:crypto";
import http from "node:http";

const MAX_BODY = 8 * 1024;
const COMMON = new Set(["password123", "1234567890", "qwertyuiop", "iloveyou12", "password12"]);
const hash = (pw, salt = crypto.randomBytes(16)) => `${salt.toString("hex")}:${crypto.scryptSync(pw, salt, 64).toString("hex")}`;
const verify = (pw, stored) => { const [s, h] = stored.split(":"); const x = crypto.scryptSync(pw, Buffer.from(s, "hex"), 64); const y = Buffer.from(h, "hex"); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const DUMMY = hash("dummy-password-for-timing");
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");

export function createApp({ sentinel, notifyOwner = () => {}, lockMs = 15 * 60000, failClosed = true, trustProxy = false, now = () => Date.now() }) {
  const users = new Map();      // id -> {pass, role, lockedUntil, payout, hold:{codeHash}|null}
  const sessions = new Map();   // token -> {user, device}
  const blockedIps = new Set();

  const ctxOf = (req) => ({ ip: trustProxy ? String(req.headers["x-forwarded-for"] ?? "").split(",")[0].trim() || req.socket.remoteAddress : req.socket.remoteAddress, device: String(req.headers["x-device-id"] ?? "").slice(0, 64) || undefined });
  const revokeUser = (id) => { for (const [t, s] of sessions) if (s.user === id) sessions.delete(t); };

  /** Report to Sentinel and apply the actions it recommends. Returns {actions, reachable}. */
  async function report(event) {
    const r = await sentinel.report(event);
    const actions = (r.alerts ?? []).map((a) => ({ ...a, actor: event.actor, ip: event.ip }));
    for (const a of actions) {
      if (a.action === "lock_user_temporarily" && users.has(event.actor)) { users.get(event.actor).lockedUntil = now() + lockMs; revokeUser(event.actor); }
      else if (a.action === "block_ip" && event.ip) blockedIps.add(event.ip);
      else if (a.action === "force_reauth_with_mfa" || a.action === "require_reauth_and_notify_owner") { if (users.has(event.actor)) { revokeUser(event.actor); notifyOwner(event.actor, a.message); } }
      else if (a.action?.startsWith("revoke_all_sessions")) sessions.clear();
    }
    return { actions, reachable: r.ok !== false };
  }

  /** Check a hold code with a guess limit: after 5 wrong tries the code is destroyed and a human must review (support). */
  function checkCode(u, code) {
    if (!u?.hold || u.hold.expires < now() || !u.hold.codeHash) return false;
    if (sha(String(code ?? "")) === u.hold.codeHash) return true;
    if (++u.hold.attempts >= 5) u.hold.codeHash = null;
    return false;
  }
  const holdPayout = (id, reason, pending) => {
    if (users.get(id).hold) return; // keep the first code: repeated attempts must not replace it
    const code = String(crypto.randomInt(0, 1e8)).padStart(8, "0");
    users.get(id).hold = { codeHash: sha(code), pending, expires: now() + 3600000, attempts: 0 };
    // Goes to the owner's OTHER, previously verified channel, never in the HTTP response.
    notifyOwner(id, `A payout change to account ending ${String(pending ?? "").slice(-4)} was held (${reason}). If this was you, approve it. If not, use recovery with code ${code}.`, { code });
  };

  async function route(req, res, body) {
    const ctx = ctxOf(req);
    const send = (status, obj) => { res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff" }); res.end(JSON.stringify(obj)); };
    if (blockedIps.has(ctx.ip)) return send(403, { error: "blocked" });
    let data = {};
    if (body) { try { data = JSON.parse(body); } catch { return send(400, { error: "bad json" }); } }
    const bearer = String(req.headers.authorization ?? "").replace(/^Bearer /, "");
    const session = sessions.get(bearer);
    const me = session ? users.get(session.user) : undefined;
    const url = `${req.method} ${req.url}`;

    if (url === "POST /register") {
      const { user, password } = data;
      if (!/^[a-z0-9_]{3,32}$/.test(user ?? "") || typeof password !== "string" || password.length < 10 || COMMON.has(password.toLowerCase())) return send(400, { error: "invalid input: user 3-32 chars a-z0-9_, password 10+ chars and not common" });
      if (users.has(user)) return send(409, { error: "unavailable" });
      users.set(user, { pass: hash(password), role: users.size === 0 ? "admin" : "user", lockedUntil: 0, payout: null, hold: null });
      return send(201, { ok: true });
    }
    if (url === "POST /login") {
      const u = users.get(data.user);
      if (u && u.lockedUntil > now()) return send(429, { error: "try later" });
      const ok = verify(String(data.password ?? ""), (u ?? { pass: DUMMY }).pass) && !!u; // same work whether or not the user exists
      if (!ok) { await report({ type: "login_failure", actor: String(data.user ?? "").slice(0, 64), ...ctx }); return send(401, { error: "invalid credentials" }); }
      const token = crypto.randomBytes(32).toString("hex");
      sessions.set(token, { user: data.user, device: ctx.device });
      await report({ type: "login_success", actor: data.user, ...ctx });
      if (!sessions.has(token)) return send(401, { error: "invalid credentials" }); // an action (e.g. takeover suspected) revoked it
      return send(200, { token });
    }
    if (url === "POST /recover") {
      // Regain control after a takeover using the code sent to the owner's verified channel. Wrong codes count as login failures.
      const u = users.get(data.user);
      const okCode = checkCode(u, data.code);
      if (!okCode || typeof data.newPassword !== "string" || data.newPassword.length < 10) { await report({ type: "login_failure", actor: String(data.user ?? "").slice(0, 64), ...ctx }); return send(403, { error: "invalid recovery" }); }
      u.pass = hash(data.newPassword); u.hold = null; u.lockedUntil = 0; revokeUser(data.user);
      await report({ type: "password_reset", actor: data.user, ...ctx, meta: { via: "recovery_code" } });
      return send(200, { ok: true });
    }
    if (url === "POST /logout" && me) { sessions.delete(bearer); return send(200, { ok: true }); }
    if (!me) {
      if (req.url === "/internal/api") { const key = req.headers["x-api-key"]; const label = key ? sentinel.isCanary(String(key)) : undefined; if (label) await report({ type: "canary_touch", resource: label, ...ctx }); return send(401, { error: "unauthorized" }); }
      return send(401, { error: "unauthorized" });
    }

    if (url === "POST /password") {
      if (!verify(String(data.current ?? ""), me.pass)) return send(403, { error: "wrong password" });
      if (typeof data.next !== "string" || data.next.length < 10) return send(400, { error: "password too short" });
      me.pass = hash(data.next);
      for (const [t, s] of sessions) if (s.user === session.user && t !== bearer) sessions.delete(t); // sign out other devices
      await report({ type: "password_reset", actor: session.user, ...ctx });
      return send(200, { ok: true });
    }
    if (url === "PUT /payout") {
      if (me.hold) return send(423, { error: "payout changes are on hold pending confirmation" });
      if (!verify(String(data.password ?? ""), me.pass)) return send(403, { error: "re-enter your password to change payout details" });
      if (!/^[0-9]{10}$/.test(data.account ?? "")) return send(400, { error: "account must be 10 digits" });
      const r = await report({ type: "payout_change", actor: session.user, ...ctx, device: ctx.device ?? session.device, meta: { bank: String(data.bank ?? "").slice(0, 40) } });
      const risky = r.actions.some((a) => a.action?.startsWith("hold_payout"));
      if (risky || (!r.reachable && failClosed)) {
        if (users.has(session.user)) holdPayout(session.user, risky ? "risk signal" : "monitoring unavailable", data.account);
        return send(423, { error: "payout change held: confirm with the code sent to your verified contact" });
      }
      me.payout = data.account;
      return send(200, { ok: true });
    }
    if (url === "POST /payout/confirm") {
      // Only for the owner's own, still-valid session: approving applies the held change.
      if (!checkCode(me, data.code)) return send(403, { error: "invalid code" });
      if (data.approve === true && me.hold.pending) me.payout = me.hold.pending;
      me.hold = null;
      return send(200, { ok: true });
    }
    if (url === "POST /admin/role") {
      if (me.role !== "admin") return send(403, { error: "forbidden" });
      const t = users.get(data.target);
      if (!t || !["user", "admin"].includes(data.role)) return send(400, { error: "bad request" });
      t.role = data.role;
      await report({ type: "role_change", actor: session.user, target: data.target, ...ctx, device: ctx.device ?? session.device, meta: { new_role: data.role } });
      return send(200, { ok: true });
    }
    return send(404, { error: "not found" });
  }

  const server = http.createServer((req, res) => {
    let size = 0; const chunks = [];
    req.on("data", (c) => { size += c.length; if (size > MAX_BODY) { res.writeHead(413).end(); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { if (size <= MAX_BODY) route(req, res, Buffer.concat(chunks).toString("utf8")).catch(() => { res.writeHead(500).end(JSON.stringify({ error: "server error" })); }); });
  });
  return { server, users, sessions, blockedIps, listen: (p = 0) => new Promise((r) => server.listen(p, "127.0.0.1", () => r(server.address().port))), close: () => new Promise((r) => server.close(r)) };
}
