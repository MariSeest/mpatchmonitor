/**
 * MPatchMonitor - language helpers for the Worker.
 * English is the source; Italian strings come from i18n/it.json through the generated
 * i18n-pages.js (run `python tools/i18n.py build` after changing a translated string).
 */
import I18N from "./i18n-pages.js";

export const LANGS = ["en", "it"];
export { I18N };

/** Translate a Worker string; {name} placeholders are filled from vars. */
export function wt(s, lang, vars) {
  let out = lang === "it" && Object.hasOwn(I18N.strings, s) ? I18N.strings[s] : s;
  if (vars) out = out.replace(/\{(\w+)\}/g, (m, k) => (Object.hasOwn(vars, k) ? String(vars[k]) : m));
  return out;
}

/** ?lang= (then remembered in a cookie), the cookie, or the browser's first preferred language. */
export function pickLang(request) {
  const q = new URL(request.url).searchParams.get("lang");
  if (LANGS.includes(q)) return { lang: q, set: true };
  const c = (request.headers.get("Cookie") || "").match(/(?:^|;\s*)mpm-lang=(en|it)(?:;|$)/);
  if (c) return { lang: c[1], set: false };
  const first = (request.headers.get("Accept-Language") || "").split(",")[0].trim().toLowerCase();
  return { lang: first.startsWith("it") ? "it" : "en", set: false };
}

/** Language of a Telegram user from their app setting. */
export const telegramLang = (code) => (/^it\b/i.test(String(code || "")) ? "it" : "en");
