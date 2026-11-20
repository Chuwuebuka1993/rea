// Android spyware triage from text you collect yourself with adb (or an on-device shell with the right access).
// Termux alone cannot see other apps, so this works on command output. It looks for the classic stalkerware tells:
// accessibility services, notification listeners and device admins held by apps you did not knowingly install,
// plus sideloaded apps. It is TRIAGE, not a scan: advanced spyware can evade it. A clean result is not proof of safety.

export const COLLECT_COMMANDS = {
  accessibility: "adb shell settings get secure enabled_accessibility_services",
  notification_listeners: "adb shell settings get secure enabled_notification_listeners",
  device_admins: "adb shell dumpsys device_policy",
  third_party_packages: "adb shell pm list packages -3 -i",
  install_unknown_sources: "adb shell appops query-op REQUEST_INSTALL_PACKAGES allow",
};

// Packages that legitimately use these powers. Extend this list for your own phone; do not trust it blindly.
export const DEFAULT_ALLOW = [
  "com.google.android.marvin.talkback", "com.android.talkback", "com.google.android.gms", "com.android.settings",
  "com.google.android.apps.accessibility", "com.samsung.android.accessibility", "com.google.android.inputmethod.latin",
  "com.google.android.gm", "com.whatsapp", "com.whatsapp.w4b", "org.telegram.messenger", "com.google.android.apps.messaging",
  "com.android.systemui", "com.android.vending", "com.transsion.", "com.tecno.", "com.android.", "com.google.android.",
];
const TRUSTED_INSTALLERS = ["com.android.vending", "com.google.android.packageinstaller", "com.samsung.android.scloud", "com.sec.android.app.samsungapps", "com.transsion.appstore"];

/** Extract package names from "pkg/Class:pkg2/Class2" (colon separated) or from dumpsys component lines. */
export function parseComponents(text) {
  const out = new Set();
  const t = String(text ?? "").trim();
  if (!t || t === "null") return [];
  for (const m of t.matchAll(/([a-zA-Z][\w]*(?:\.[\w]+)+)\/[\w.$]+/g)) out.add(m[1]);
  return [...out];
}

export function parseDeviceAdmins(dumpsys) {
  const out = new Set();
  for (const m of String(dumpsys ?? "").matchAll(/ComponentInfo\{([\w.]+)\/[\w.$]+\}|admin=ComponentInfo\{([\w.]+)\//g)) out.add(m[1] ?? m[2]);
  for (const m of String(dumpsys ?? "").matchAll(/^\s*([\w.]+)\/[\w.$]+:\s*$/gm)) out.add(m[1]);
  return [...out];
}

/** Parse `pm list packages -3 -i` lines: "package:com.x  installer=com.android.vending". */
export function parseThirdParty(text) {
  const rows = [];
  for (const line of String(text ?? "").split(/\r?\n/)) {
    const m = /^package:([\w.]+)(?:\s+installer=(\S+))?/.exec(line.trim());
    if (m) rows.push({ pkg: m[1], installer: m[2] && m[2] !== "null" ? m[2] : null });
  }
  return rows;
}

const allowed = (pkg, allow) => allow.some((a) => (a.endsWith(".") ? pkg.startsWith(a) : pkg === a));

/**
 * @param {object} input  {accessibility, notification_listeners, device_admins, third_party_packages} raw command output
 * @param {object} opts   {allow: string[], iocs: string[]} iocs = package names you obtained from a trusted indicator list
 */
export function triageAndroid(input = {}, { allow = DEFAULT_ALLOW, iocs = [] } = {}) {
  const findings = [];
  const add = (severity, title, detail) => findings.push({ severity, title, detail });
  const ioc = new Set(iocs.map((x) => x.toLowerCase()));
  const acc = parseComponents(input.accessibility);
  const nl = parseComponents(input.notification_listeners);
  const admins = parseDeviceAdmins(input.device_admins);
  const apps = parseThirdParty(input.third_party_packages);

  for (const a of apps) if (ioc.has(a.pkg.toLowerCase())) add("high", "Package matches your indicator list", `${a.pkg}. Treat as compromised: see the Guardian recovery first-hour list, and prefer a factory reset after backing up only photos and contacts.`);
  for (const p of acc) if (ioc.has(p.toLowerCase()) || !allowed(p, allow)) add(ioc.has(p.toLowerCase()) ? "high" : "medium", "Accessibility service enabled", `${p}. Accessibility can read the screen and keystrokes. Keep only if you set it up on purpose (password manager, screen reader).`);
  for (const p of nl) if (!allowed(p, allow)) add("medium", "Notification access granted", `${p}. It can read every notification, including login codes.`);
  for (const p of admins) if (!allowed(p, allow) && !/^com\.(android|google)\./.test(p)) add("high", "Device administrator app", `${p}. Admin apps can block uninstall and wipe or lock the phone. Remove it in Settings, Security, Device admin apps.`);
  const side = apps.filter((a) => !a.installer || !TRUSTED_INSTALLERS.includes(a.installer));
  if (side.length) add("low", `${side.length} app(s) not installed from a known store`, side.slice(0, 15).map((a) => `${a.pkg} (${a.installer ?? "unknown installer"})`).join(", "));
  if (apps.length > 0 && apps.some((a) => /^(com\.)?(system|android|google)\.?(service|update|sync|framework)s?$/i.test(a.pkg))) add("medium", "App with a system-like disguised name", "Spyware often names itself like a system component.");

  const checked = ["accessibility", "notification_listeners", "device_admins", "third_party_packages"].filter((k) => input[k] !== undefined);
  return {
    summary: `Android triage: ${findings.filter((f) => f.severity === "high").length} high, ${findings.filter((f) => f.severity === "medium").length} medium, ${findings.filter((f) => f.severity === "low").length} low (${checked.length}/4 inputs provided)`,
    findings,
    limits: [
      "Triage only. Advanced spyware may hide from these checks, and a clean result is not proof of safety.",
      "If you suspect targeted surveillance, use a forensic tool such as MVT with a trained helper, and use a different device to change passwords.",
      "If the person who controls the phone is someone you fear, plan your safety first: removing stalkerware can alert them.",
    ],
  };
}
