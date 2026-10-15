import { test } from "node:test";
import assert from "node:assert/strict";
import { encryptPayload, vapidAuth, validEndpoint, cleanTopics, handlePush, b64u } from "./push.js";
import { embedSvg, monthLabel } from "./embed.js";

const { subtle } = globalThis.crypto;
const enc = new TextEncoder();
async function hkdf(salt, ikm, info, n) {
  const k = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, n * 8));
}
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };

/** Browser side of RFC 8291, written independently from the Worker code. */
async function decrypt(body, ua, uaPublic, auth) {
  const salt = body.slice(0, 16), rs = new DataView(body.buffer, body.byteOffset).getUint32(16), idlen = body[20];
  const asPublic = body.slice(21, 21 + idlen), cipher = body.slice(21 + idlen);
  assert.equal(rs, 4096);
  const asKey = await subtle.importKey("raw", asPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: asKey }, ua.privateKey, 256));
  const ikm = await hkdf(auth, shared, cat(enc.encode("WebPush: info\0"), uaPublic, asPublic), 32);
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
  const key = await subtle.importKey("raw", cek, "AES-GCM", false, ["decrypt"]);
  const plain = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, cipher));
  assert.equal(plain[plain.length - 1], 2, "last-record delimiter");
  return new TextDecoder().decode(plain.slice(0, -1));
}

test("web push: payload encrypted per RFC 8291 decrypts on the browser side", async () => {
  const ua = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const uaPublic = new Uint8Array(await subtle.exportKey("raw", ua.publicKey));
  const auth = crypto.getRandomValues(new Uint8Array(16));
  const msg = JSON.stringify({ title: "Patch Tuesday ottobre 2026", body: "4 zero-day – àèì" });
  const body = await encryptPayload(msg, b64u.encode(uaPublic), b64u.encode(auth));
  assert.equal(await decrypt(body, ua, uaPublic, auth), msg);
  // a fresh key and salt every time: two encryptions never match
  const again = await encryptPayload(msg, b64u.encode(uaPublic), b64u.encode(auth));
  assert.notDeepEqual(body.slice(0, 16), again.slice(0, 16));
});

test("web push: VAPID token is a valid ES256 JWT for the push service origin", async () => {
  const kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await subtle.exportKey("jwk", kp.privateKey);
  const pub = b64u.encode(await subtle.exportKey("raw", kp.publicKey));
  const env = { VAPID_PRIVATE_KEY: JSON.stringify(jwk), VAPID_PUBLIC_KEY: pub, PUBLIC_ORIGIN: "https://mpm.example" };
  const h = await vapidAuth("https://fcm.googleapis.com/fcm/send/abc", env, Date.UTC(2026, 9, 14));
  const m = h.match(/^vapid t=([^.]+)\.([^.]+)\.([^,]+), k=(.+)$/);
  assert.ok(m);
  assert.equal(m[4], pub);
  const claims = JSON.parse(new TextDecoder().decode(b64u.decode(m[2])));
  assert.equal(claims.aud, "https://fcm.googleapis.com");
  assert.equal(claims.sub, "https://mpm.example");
  assert.ok(claims.exp - Date.UTC(2026, 9, 14) / 1000 <= 24 * 3600);
  const ok = await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, kp.publicKey, b64u.decode(m[3]), enc.encode(`${m[1]}.${m[2]}`));
  assert.ok(ok);
});

test("web push: only browser push services, only known topics", () => {
  assert.ok(validEndpoint("https://fcm.googleapis.com/fcm/send/x"));
  assert.ok(validEndpoint("https://updates.push.services.mozilla.com/wpush/v2/x"));
  assert.ok(validEndpoint("https://web.push.apple.com/QK"));
  assert.ok(validEndpoint("https://wns2-db5p.notify.windows.com/w/?token=x"));
  for (const bad of ["http://fcm.googleapis.com/x", "https://evil.example/x", "https://fcm.googleapis.com.evil.example/x",
    "https://user:pw@fcm.googleapis.com/x", "https://fcm.googleapis.com:8443/x", "https://169.254.169.254/x", "javascript:alert(1)", 42]) {
    assert.equal(validEndpoint(bad), false, String(bad));
  }
  assert.deepEqual(cleanTopics(["exploited", "cve:CVE-2026-21345", "kb:KB5070112", "evil", "cve:<x>"]), ["exploited", "cve:CVE-2026-21345", "kb:KB5070112"]);
  assert.equal(cleanTopics(["nope"]), null);
  assert.equal(cleanTopics("exploited"), null);
});

const pushEnv = () => ({ DB: {}, VAPID_PUBLIC_KEY: "B".repeat(87), VAPID_PRIVATE_KEY: "{}" });
const post = (path, body, headers = {}) => new Request(`https://mpm.example${path}`, {
  method: "POST", body: typeof body === "string" ? body : JSON.stringify(body),
  headers: { "Content-Type": "application/json", Origin: "https://mpm.example", "Sec-Fetch-Site": "same-origin", ...headers },
});

test("web push endpoints: cross-site, oversized and malformed requests are refused", async () => {
  const sub = { subscription: { endpoint: "https://evil.example/x", keys: { p256dh: "x", auth: "y" } }, topics: ["all"] };
  let r = await handlePush(post("/api/push/subscribe", sub, { Origin: "https://evil.example" }), pushEnv(), "/api/push/subscribe", "https://mpm.example");
  assert.equal(r.status, 403);
  r = await handlePush(post("/api/push/subscribe", sub, { "Sec-Fetch-Site": "cross-site" }), pushEnv(), "/api/push/subscribe", "https://mpm.example");
  assert.equal(r.status, 403);
  r = await handlePush(post("/api/push/subscribe", sub), pushEnv(), "/api/push/subscribe", "https://mpm.example");
  assert.equal(r.status, 400);
  r = await handlePush(post("/api/push/subscribe", "x".repeat(5000)), pushEnv(), "/api/push/subscribe", "https://mpm.example");
  assert.equal(r.status, 400);
  r = await handlePush(post("/api/push/subscribe", sub, { "Content-Type": "text/plain" }), pushEnv(), "/api/push/subscribe", "https://mpm.example");
  assert.equal(r.status, 400);
  r = await handlePush(post("/api/push/subscribe", sub), {}, "/api/push/subscribe", "https://mpm.example");
  assert.equal(r.status, 503);
  r = await handlePush(new Request("https://mpm.example/api/push/key"), {}, "/api/push/key", "https://mpm.example");
  assert.equal(r.status, 503);
});

test("embed card: escaped text, no script, localized", () => {
  const svg = embedSvg({ generated_at: "2026-10-14T08:00:00Z", latest: { id: "2026-Oct", total: 88, exploited: 4, critical: 6, public_exploit: "<script>" } }, "it", "dark", "mpm.example");
  assert.match(svg, /ottobre 2026/);
  assert.match(svg, />88</);
  assert.doesNotMatch(svg, /<script|on\w+=/i);
  assert.match(svg, />–</);
  assert.equal(monthLabel("2026-Oct\"><x", "en"), "");
  const empty = embedSvg(null, "en", "light", "");
  assert.match(empty, /Patch Tuesday/);
});
