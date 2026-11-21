// Breach clock. Nigeria's NDPA requires notifying the NDPC within 72 hours of becoming aware of a breach likely to risk
// people's rights. Confirm the current rule with a lawyer: this records the facts and the deadline, it does not decide for you.
const H = 3600e3;
export class IncidentLog {
  constructor({ now = () => Date.now() } = {}) { this.now = now; this.items = new Map(); }
  open({ id, summary, awareAt = this.now(), by }) {
    if (!id || !by) throw new Error("id and by are required");
    const i = { id, summary, awareAt, by, assessment: null, notified: null, deadline: awareAt + 72 * H };
    this.items.set(id, i); return i;
  }
  /** A human decides whether the breach is likely to risk people's rights. The software never decides this. */
  assess(id, { likelyRisk, by, notes = "" }) {
    const i = this.items.get(id); if (!i) throw new Error("unknown incident");
    if (typeof likelyRisk !== "boolean" || !by) throw new Error("likelyRisk (true/false) and by are required");
    i.assessment = { likelyRisk, by, notes, at: this.now() }; return i;
  }
  markNotified(id, { by, reference }) { const i = this.items.get(id); if (!i) throw new Error("unknown incident"); i.notified = { by, reference, at: this.now() }; return i; }
  status(id) {
    const i = this.items.get(id); if (!i) throw new Error("unknown incident");
    const left = i.deadline - this.now(), hrs = Math.floor(left / H);
    if (i.notified) return { state: "notified", hoursLeft: hrs, message: "Notification recorded." };
    if (!i.assessment) return { state: left <= 0 ? "overdue_unassessed" : "needs_assessment", hoursLeft: hrs, message: `Nobody has assessed the risk yet. ${left > 0 ? `${hrs}h left on the 72-hour clock.` : "The 72-hour clock has run out: assess and consult counsel now."}` };
    if (!i.assessment.likelyRisk) return { state: "documented_no_notice", hoursLeft: hrs, message: "Assessed as unlikely to risk people's rights. Keep this record." };
    return { state: left <= 0 ? "overdue" : "notify_due", hoursLeft: hrs, message: left <= 0 ? "OVERDUE: notify the NDPC immediately and tell counsel." : `Notify the NDPC within ${hrs}h.` };
  }
}
