// Money is integer kobo (1 naira = 100 kobo). Floats never touch a balance.
export function toKobo(v) {
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Error("amount must be an integer number of kobo (or a string like \"1234.50\")");
    return v;
  }
  const m = /^(-)?(\d{1,15})(?:\.(\d{1,2}))?$/.exec(String(v).trim().replace(/,/g, ""));
  if (!m) throw new Error(`bad amount "${v}": use digits with at most 2 decimals`);
  const k = Number(m[2]) * 100 + Number((m[3] ?? "").padEnd(2, "0") || 0);
  return m[1] ? -k : k;
}
export function formatNaira(kobo) {
  const neg = kobo < 0, a = Math.abs(kobo);
  return `${neg ? "-" : ""}₦${Math.floor(a / 100).toLocaleString("en-NG")}.${String(a % 100).padStart(2, "0")}`;
}
