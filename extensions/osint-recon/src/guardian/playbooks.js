// Recovery playbooks. URLs and facts were checked against the official pages on 2026-11-19.
// Vendors change these flows often: every playbook carries `verified_on` and a source URL so staleness is visible.

export const VERIFIED_ON = "2026-11-19";

export const PLAYBOOKS = {
  google: {
    name: "Google / Gmail",
    entry: "https://accounts.google.com/signin/recovery",
    hacked: "https://support.google.com/accounts?p=ar_haco",
    source: "https://support.google.com/accounts/answer/7682439",
    prepare: [
      "Add a recovery phone AND a recovery email, and keep both reachable.",
      "Print or save backup codes offline. Add a passkey or security key if you can.",
      "Changing recovery info can take up to 7 days to take effect, so do it now, not during an emergency.",
    ],
    recover: [
      "Open the recovery page and answer the questions as best you can. Wrong guesses do not lock you out of the process and there is no attempt limit.",
      "Do it from a phone or computer and a place you have used with this account before.",
      "Use the recovery phone/email and the full name on the account when asked.",
      "If it is a hijack, use the hacked-account flow linked above.",
    ],
    after: [
      "Reset the password, review 'Your devices' and sign out unknown ones, remove unknown app access, check mail forwarding and filters, re-enable 2-step verification.",
    ],
    notes: ["Work, school or group accounts may need the administrator instead."],
  },
  github: {
    name: "GitHub",
    entry: "https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/recovering-your-account-if-you-lose-your-2fa-credentials",
    source: "https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/recovering-your-account-if-you-lose-your-2fa-credentials",
    prepare: [
      "Download the recovery codes (default file name github-recovery-codes.txt) and store them offline and in your password manager.",
      "Keep an SSH key or personal access token you can still use, because these can serve as a recovery verification factor.",
      "Register more than one 2FA method (an authenticator app plus a passkey or security key).",
    ],
    recover: [
      "Use a recovery code if you have one.",
      "No codes? If you know your password, choose a recovery verification factor such as an SSH key or personal access token.",
      "GitHub Support reviews the request and emails you. If approved you get a link to finish recovery. Allow up to 3 business days.",
      "Click the password-reset email link within 3 hours. Your 2FA credentials or recovery codes still work during the 3-5 day waiting period.",
    ],
    after: [
      "Review SSH keys, GPG keys, deploy keys, personal access tokens, authorized OAuth apps, webhooks and recent security log entries. Rotate any secret that lived in a repo or Actions.",
    ],
    notes: ["Run the guardian github audit to list these items."],
  },
  whatsapp: {
    name: "WhatsApp",
    entry: "https://faq.whatsapp.com/1131652977717250",
    source: "https://faq.whatsapp.com/1131652977717250",
    prepare: [
      "Turn on two-step verification and add a recovery email so the PIN can be reset.",
      "Never share a 6-digit registration code with anyone, even a friend or 'support'.",
    ],
    recover: [
      "Re-register your number: tap Log back in, then Continue, then enter the 6-digit code sent by SMS or call. WhatsApp's page says this is how you remove someone who took over the account.",
      "If a two-step verification PIN blocks you, use the email reset flow (https://faq.whatsapp.com/1082491466048496).",
      "If you cannot receive the code, contact the carrier about a SIM swap and contact WhatsApp support from the app.",
    ],
    after: [
      "Check Linked devices and log out unknown ones. Warn your contacts and groups that the account was compromised.",
    ],
    notes: ["Unrequested codes: https://faq.whatsapp.com/479314433984258"],
  },
  facebook: {
    name: "Facebook",
    entry: "https://www.facebook.com/hacked",
    source: "https://www.facebook.com/hacked",
    prepare: ["Turn on two-factor authentication, save backup codes, keep your recovery email and phone current, and add trusted contacts if offered."],
    recover: [
      "Open the hacked page and follow the security steps. Start on a device you normally use for Facebook if you can.",
    ],
    after: ["Review login activity, remove unknown devices and apps, and check the page and ad accounts connected to the profile."],
    notes: [],
  },
  instagram: {
    name: "Instagram",
    entry: "https://www.instagram.com/hacked",
    source: "https://help.instagram.com/368191326593075/",
    prepare: ["Turn on two-factor authentication and confirm that the email and phone in settings are correct."],
    recover: [
      "Ask for a login link (https://help.instagram.com/149494825257596): enter your username, email or phone, finish the captcha, then use the link you receive.",
      "If you cannot access that email or phone, use https://www.instagram.com/hacked and follow the on-screen steps.",
    ],
    after: ["Review login activity and connected apps, and change the password on any account that shared it."],
    notes: [],
  },
  telegram: {
    name: "Telegram",
    entry: "https://telegram.org/faq",
    source: "https://telegram.org/blog/sessions-and-2-step-verification",
    prepare: [
      "Turn on Two-Step Verification with a strong password and a recovery email, and remember that forgetting both can lock you out.",
      "Review Active Sessions regularly and close any you do not recognize.",
    ],
    recover: [
      "Log in with the code sent to your number, then open Settings, Devices and terminate every session you do not recognize.",
      "Telegram notes that a very recent login may be restricted from ending other sessions for a while, so act as soon as you regain control and check again later.",
    ],
    after: ["Set Two-Step Verification, check privacy settings and who can see your number."],
    notes: ["Sensitive details: read the FAQ for current wording before relying on any timing."],
  },
  x: {
    name: "X (Twitter)",
    entry: "https://help.x.com/en/forms/account-access/regain-access/hacked-or-compromised",
    source: "https://help.x.com/en/safety-and-security/x-account-compromised",
    prepare: ["Turn on two-factor authentication (prefer an authenticator app or security key over SMS) and keep the account email current."],
    recover: [
      "Change the password (use Forgot Password if you are logged out).",
      "Secure the account with two-factor authentication and review connected apps.",
      "If you still cannot get in, contact Support from the email address associated with the account.",
    ],
    after: ["Revoke unknown connected apps and review the sessions list."],
    notes: [],
  },
  generic: {
    name: "Your own apps (SSNG, Igboukwu Labs, AFA Alpha, Apex Mall, and so on)",
    entry: null,
    source: "Guardian generic checklist",
    prepare: [
      "Keep at least two owner accounts with different 2FA methods, so one hacked owner cannot lock out the other.",
      "Store hosting, domain registrar, database and payment-provider recovery codes offline.",
      "Keep secrets in environment variables or a secret manager, never in the repo.",
    ],
    recover: [
      "Revoke every session and API key, then rotate database credentials, JWT or session secrets, and payment and email provider keys.",
      "Rotate in this order: email and domain registrar, hosting, source control, database, payment, then third-party APIs.",
      "Restore from a clean backup if code or data was changed, and compare against git history.",
    ],
    after: ["Write a short timeline of what happened, what was exposed, and who was told. Tell users if their data was involved."],
    notes: [],
  },
};

export function listPlatforms() {
  return Object.keys(PLAYBOOKS);
}

export function getPlaybook(platform) {
  const key = String(platform ?? "").toLowerCase().trim();
  const alias = { gmail: "google", fb: "facebook", ig: "instagram", twitter: "x", wa: "whatsapp", tg: "telegram", git: "github" };
  const pb = PLAYBOOKS[alias[key] ?? key];
  return pb ? { ...pb, verified_on: VERIFIED_ON } : undefined;
}

export const FIRST_HOUR = [
  "Use a device you trust and that is clean. If the phone itself may be infected, use another device for steps 1 to 3.",
  "Secure your email first, since it can reset everything else. Then your phone number/SIM, then other accounts.",
  "Change passwords (unique, from a password manager), sign out all sessions, and turn on app or key-based 2FA.",
  "Revoke unknown app access, forwarding rules, linked devices, SSH keys and tokens.",
  "Tell your contacts and team, and report the account to the platform.",
  "Do not pay anyone who offers to 'recover' accounts for money: this is a common scam.",
];
