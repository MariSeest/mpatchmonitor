// Generates the VAPID key pair for browser notifications (Web Push).
//   node tools/vapid.mjs
// Put the public key in wrangler.jsonc (vars.VAPID_PUBLIC_KEY) and the private key in a secret:
//   npx wrangler secret put VAPID_PRIVATE_KEY   (paste the JSON line)
// Keep the private key secret; changing it invalidates every existing subscription.
const { subtle } = globalThis.crypto;
const kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const raw = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
const jwk = await subtle.exportKey("jwk", kp.privateKey);
const b64u = (b) => Buffer.from(b).toString("base64url");
console.log("VAPID_PUBLIC_KEY  =", b64u(raw));
console.log("VAPID_PRIVATE_KEY =", JSON.stringify({ kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d }));
