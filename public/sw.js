"use strict";

/* MPatchMonitor service worker: makes the site installable, shows browser notifications
 * and an offline page. It never caches data: every page and API call goes to the network. */

const CACHE = "mpm-offline-v1";
const OFFLINE = ["/offline", "/styles.css", "/favicon.svg", "/icon-192.png", "/fonts/archivo.woff2"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(OFFLINE)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET" || new URL(req.url).origin !== self.location.origin) return;
  if (req.mode === "navigate") {
    e.respondWith(fetch(req).catch(() => caches.match("/offline")));
  }
});

/* Payload: {title, body, url, tag, urgent} encrypted by the Worker for this browser only. */
self.addEventListener("push", (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch { d = {}; }
  const title = String(d.title || "MPatchMonitor").slice(0, 200);
  let url = "/alerts";
  try {
    const u = new URL(String(d.url || "/alerts"), self.location.origin);
    // same site, or a CSIRT Italia bulletin; anything else opens the alerts page
    if (u.origin === self.location.origin || (u.protocol === "https:" && /(^|\.)acn\.gov\.it$/.test(u.hostname))) url = u.href;
  } catch { /* keep default */ }
  e.waitUntil(self.registration.showNotification(title, {
    body: String(d.body || "").slice(0, 400),
    icon: "/icon-192.png",
    badge: "/icon-192.png",
    tag: String(d.tag || "mpm"),
    lang: d.lang === "it" ? "it" : "en",
    requireInteraction: Boolean(d.urgent),
    data: { url },
  }));
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const url = e.notification.data?.url || "/alerts";
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((list) => {
    const same = list.find((c) => c.url === url);
    return same ? same.focus() : self.clients.openWindow(url);
  }));
});
