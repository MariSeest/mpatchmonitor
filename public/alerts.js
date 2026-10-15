"use strict";

/* MPatchMonitor — /alerts: Telegram bot, followed items, public alert log */

const BOT_TOPICS = [
  ["/watch all", t("Everything below")],
  ["/watch patchtuesday", t("Microsoft Patch Tuesday releases")],
  ["/watch exploited", t("Microsoft vulnerabilities newly exploited or added to CISA KEV")],
  ["/watch kev", t("Every new CISA KEV entry, all vendors")],
  ["/watch oob", t("Out-of-band Microsoft updates")],
  ["/watch reinstall", t("Microsoft asking to reinstall a re-released update")],
  ["/watch acn", t("CSIRT Italia bulletins that mention Microsoft")],
  ["/watch issues", t("New known issues of Windows updates (release health)")],
  ["/watch CVE-2026-21345", t("One CVE: any revision, exploitation or new update")],
  ["/watch KB5070112", t("One security update: re-release, known issue, replacement")],
  ["/list", t("What you follow")],
  ["/unwatch <topic>", t("Stop one topic")],
  ["/lang it", t("Messages in Italian (or /lang en for English)")],
  ["/stop", t("Delete everything stored about you")],
];

document.addEventListener("DOMContentLoaded", async () => {
  initTheme();
  setHTML($("#topics"), BOT_TOPICS.map(([c, d]) => `<tr><td><code>${esc(c)}</code></td><td>${esc(d)}</td></tr>`).join(""));
  renderFollowing();
  document.addEventListener("mpm-follow", renderFollowing);
  initPush();
  const [status, log] = await Promise.all([fetchJson("/api/status").catch(() => ({})), fetchJson("/api/watch-alerts").catch(() => ({ alerts: [] }))]);
  const bot = String(status.watch_bot || "").replace(/[^A-Za-z0-9_]/g, "");
  setHTML($("#botLink"), bot
    ? `<a class="btn" href="https://t.me/${esc(bot)}" rel="noopener noreferrer" target="_blank">${te("Open @{bot}", { bot })}</a>`
    : `<span class="hint">${te("The bot is being set up. Feeds and in-browser alerts work already.")}</span>`);
  setHTML($("#alertLog"), (log.alerts || []).map((a) => {
    const title = (MPM_LANG === "it" && a.title_it) || a.title;
    const text = (MPM_LANG === "it" && a.text_it) || a.text;
    return `<li><p class="when">${esc(fmtDateTime(a.ts))}, ${esc(a.topics.join(", "))}</p>
    <p><strong>${a.link ? `<a href="${esc(safeUrl(a.link))}">${esc(title)}</a>` : esc(title)}</strong></p>${text ? `<p class="hint">${esc(text)}</p>` : ""}</li>`;
  }).join("") || `<li class="hint">${te("No alert sent yet.")}</li>`);
});

function renderFollowing() {
  const list = follows.list();
  setHTML($("#following"), list.map((id) => {
    const [kind, ref] = id.split(":");
    return `<li><a href="/${kind}/${esc(ref)}">${esc(ref)}</a> ${followButton(id)}</li>`;
  }).join("") || `<li class="hint">${te("Nothing yet. Use Follow on a CVE or update page.")}</li>`);
}

/* ------------------------------------------------------------------ browser notifications (Web Push) */
const PUSH = { key: null, reg: null, sub: null };

function pushSupported() {
  return "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
}

function pushTopics() {
  const picked = $$("#pushTopics input:checked").map((i) => i.value);
  const out = picked.filter((v) => v !== "follows");
  if (picked.includes("follows")) out.push(...follows.list().slice(0, 20));
  return out;
}

function pushStatus(text, on) {
  $("#pushState").textContent = text;
  $("#pushOn").textContent = on ? t("Save topics") : t("Turn on notifications");
  $("#pushOff").hidden = !on;
}

async function initPush() {
  if (!$("#pushOn")) return;
  const saved = (() => { try { return JSON.parse(store.get("mpm-push-topics") || "null"); } catch { return null; } })();
  if (Array.isArray(saved)) $$("#pushTopics input").forEach((i) => { i.checked = saved.includes(i.value); });
  if (!pushSupported()) {
    $("#pushOn").disabled = true;
    return pushStatus(t("This browser does not support notifications. On iPhone and iPad, add the site to the Home Screen first."), false);
  }
  try {
    const k = await fetchJson("/api/push/key");
    PUSH.key = k.key;
  } catch {
    $("#pushOn").disabled = true;
    return pushStatus(t("Browser notifications are being set up. Telegram and feeds work already."), false);
  }
  PUSH.reg = await navigator.serviceWorker.ready;
  PUSH.sub = await PUSH.reg.pushManager.getSubscription();
  pushStatus(PUSH.sub ? t("Notifications are on in this browser.") : "", Boolean(PUSH.sub));
  $("#pushOn").addEventListener("click", pushOn);
  $("#pushOff").addEventListener("click", pushOff);
}

function keyBytes(b64) {
  const s = atob(b64.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64.length + 3) % 4));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}

async function pushOn() {
  const topics = pushTopics();
  store.set("mpm-push-topics", JSON.stringify($$("#pushTopics input:checked").map((i) => i.value)));
  if (!topics.length) return pushStatus(t("Choose at least one topic."), Boolean(PUSH.sub));
  const perm = await Notification.requestPermission();
  if (perm !== "granted") return pushStatus(t("Allow notifications for this site in the browser settings, then try again."), false);
  try {
    PUSH.sub ||= await PUSH.reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(PUSH.key) });
    const res = await fetch("/api/push/subscribe", {
      method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin",
      body: JSON.stringify({ subscription: PUSH.sub.toJSON(), topics, lang: MPM_LANG }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    pushStatus(t("Notifications are on in this browser."), true);
  } catch {
    pushStatus(t("Could not turn on notifications. Try again later."), Boolean(PUSH.sub));
  }
}

async function pushOff() {
  const sub = PUSH.sub;
  if (!sub) return;
  try {
    await fetch("/api/push/unsubscribe", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin", body: JSON.stringify({ endpoint: sub.endpoint }) });
  } catch { /* the push service forgets it anyway */ }
  await sub.unsubscribe().catch(() => {});
  PUSH.sub = null;
  pushStatus(t("Notifications are off. Nothing about this browser is stored any more."), false);
}
