/**
 * Embeddable card: /embed/patch-tuesday.svg?lang=it|en&theme=light|dark
 * A static SVG image (no script, no external resource) other sites can put in an <img>.
 */
import { wt } from "./i18n.js";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const THEMES = {
  light: { bg: "#ffffff", line: "#d5dce8", ink: "#0f1a2b", muted: "#4a5a73", crit: "#c42633", accent: "#3f63d0" },
  dark: { bg: "#0f1a2b", line: "#2a3a55", ink: "#e8eef8", muted: "#a7b4c9", crit: "#ff7a80", accent: "#8ea2ff" },
};

export const EMBED_HEADERS = {
  "Content-Type": "image/svg+xml; charset=utf-8",
  "Content-Security-Policy": "default-src 'none'",
  "Cross-Origin-Resource-Policy": "cross-origin",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "public, max-age=1800",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
};

export function monthLabel(id, lang) {
  const m = /^(\d{4})-([A-Z][a-z]{2})$/.exec(String(id || ""));
  if (!m || !MONTHS.includes(m[2])) return "";
  const d = new Date(Date.UTC(Number(m[1]), MONTHS.indexOf(m[2]), 15));
  return d.toLocaleDateString(lang === "it" ? "it-IT" : "en-GB", { month: "long", year: "numeric", timeZone: "UTC" });
}

/** summary: KV "summary" ({latest:{id,total,exploited,critical,public_exploit}, generated_at}) */
export function embedSvg(summary, lang = "en", theme = "light", host = "") {
  const c = THEMES[theme] || THEMES.light;
  const l = summary?.latest;
  const n = (v) => (Number.isFinite(Number(v)) ? String(Math.max(0, Math.round(Number(v)))) : "–");
  const title = l ? wt("Patch Tuesday {month}", lang, { month: monthLabel(l.id, lang) }) : "Patch Tuesday";
  const figs = [
    [n(l?.total), wt("Vulnerabilities", lang), c.ink],
    [n(l?.exploited), wt("Zero-days", lang), c.crit],
    [n(l?.critical), wt("Critical", lang), c.ink],
    [n(l?.public_exploit), wt("Public exploit", lang), c.ink],
  ];
  const cells = figs.map(([v, label, color], i) => {
    const x = 20 + i * 95;
    return `<text x="${x}" y="78" font-size="26" font-weight="700" fill="${color}">${esc(v)}</text>` +
      `<text x="${x}" y="98" font-size="11" fill="${c.muted}">${esc(label)}</text>`;
  }).join("");
  const updated = summary?.generated_at ? wt("Updated {date}", lang, { date: new Date(summary.generated_at).toLocaleDateString(lang === "it" ? "it-IT" : "en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" }) }) : "";
  return `<svg xmlns="http://www.w3.org/2000/svg" width="400" height="140" viewBox="0 0 400 140" role="img" aria-label="${esc(`${title}: ${figs.map((f) => `${f[0]} ${f[1]}`).join(", ")}`)}">
<title>${esc(title)}</title>
<rect x="0.5" y="0.5" width="399" height="139" rx="10" fill="${c.bg}" stroke="${c.line}"/>
<g font-family="system-ui, -apple-system, Segoe UI, Roboto, sans-serif">
<text x="20" y="34" font-size="15" font-weight="650" fill="${c.ink}">${esc(title)}</text>
${cells}
<text x="20" y="124" font-size="10.5" fill="${c.muted}">MPatchMonitor${host ? ` · ${esc(host)}` : ""}</text>
<text x="380" y="124" font-size="10.5" fill="${c.muted}" text-anchor="end">${esc(updated)}</text>
<rect x="20" y="44" width="40" height="3" rx="1.5" fill="${c.accent}"/>
</g>
</svg>`;
}
