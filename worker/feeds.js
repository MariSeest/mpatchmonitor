/** Calendar of upcoming Patch Tuesdays (second Tuesday of each month) and the CSIRT Italia RSS feed. */

export function patchTuesdays(from = new Date(), count = 12) {
  const out = [];
  let y = from.getUTCFullYear(), m = from.getUTCMonth();
  while (out.length < count) {
    const first = new Date(Date.UTC(y, m, 1));
    const offset = (2 - first.getUTCDay() + 7) % 7;      // first Tuesday
    const day = new Date(Date.UTC(y, m, 1 + offset + 7)); // second Tuesday
    if (day >= new Date(Date.UTC(from.getUTCFullYear(), from.getUTCMonth(), from.getUTCDate()))) out.push(day);
    m++; if (m > 11) { m = 0; y++; }
  }
  return out;
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const ymd = (d) => d.toISOString().slice(0, 10).replace(/-/g, "");
const icsEscape = (s) => String(s).replace(/[\;,]/g, (c) => `\\${c}`).replace(/\n/g, "\\n");

export function patchTuesdayIcs(base, now = new Date()) {
  const stamp = now.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
  const lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//MPatchMonitor//Patch Tuesday//EN", "CALSCALE:GREGORIAN",
    "X-WR-CALNAME:Microsoft Patch Tuesday", "METHOD:PUBLISH"];
  for (const d of patchTuesdays(now)) {
    const next = new Date(d.getTime() + 86_400_000);
    const id = `${d.getUTCFullYear()}-${MONTHS[d.getUTCMonth()]}`;
    lines.push("BEGIN:VEVENT", `UID:patch-tuesday-${id}@mpatchmonitor`, `DTSTAMP:${stamp}`,
      `DTSTART;VALUE=DATE:${ymd(d)}`, `DTEND;VALUE=DATE:${ymd(next)}`,
      `SUMMARY:${icsEscape(`Microsoft Patch Tuesday ${id}`)}`,
      `DESCRIPTION:${icsEscape(`Microsoft security updates are released around 10:00 Pacific time. ${base}/release/${id}`)}`,
      `URL:${base}/release/${id}`, "TRANSP:TRANSPARENT", "END:VEVENT");
  }
  lines.push("END:VCALENDAR");
  return lines.join("\r\n") + "\r\n";
}

const x = (s) => String(s ?? "").replace(/[<>&'"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;" }[c]));

export function acnRss(base, rows) {
  const items = rows.map((r) => `<item><title>${x(r.title)}</title><link>${x(r.link)}</link><guid isPermaLink="true">${x(r.link)}</guid>` +
    `<pubDate>${x(new Date(r.published).toUTCString())}</pubDate><description>${x(r.summary || "")}</description></item>`).join("");
  return `<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>MPatchMonitor: CSIRT Italia bulletins mentioning Microsoft</title>` +
    `<link>${x(base)}/acn</link><description>Bulletins from CSIRT Italia (Agenzia per la Cybersicurezza Nazionale) that mention Microsoft.</description>` +
    `<generator>MPatchMonitor</generator>${items}</channel></rss>`;
}
