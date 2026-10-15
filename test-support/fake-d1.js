/** In-memory stand-in for Cloudflare D1 (tests only), backed by node:sqlite and the real migration. */
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";

export function fakeD1() {
  const db = new DatabaseSync(":memory:");
  const dir = new URL("../migrations/", import.meta.url);
  for (const f of readdirSync(dir).filter((n) => n.endsWith(".sql")).sort()) db.exec(readFileSync(new URL(f, dir), "utf8"));
  const plain = (r) => (r ? { ...r } : null);
  const stmt = (sql, args = []) => ({
    bind: (...a) => stmt(sql, a),
    async first(col) { const r = plain(db.prepare(sql).get(...args)); return r && col ? r[col] : r; },
    async all() { return { results: db.prepare(sql).all(...args).map(plain) }; },
    async run() { db.prepare(sql).run(...args); return { success: true }; },
    exec() {
      return /^\s*select|returning/i.test(sql)
        ? { results: db.prepare(sql).all(...args).map(plain) }
        : (db.prepare(sql).run(...args), { results: [] });
    },
  });
  return { prepare: (sql) => stmt(sql), batch: async (list) => list.map((s) => s.exec()), raw: db };
}

export function fakeKV(init = {}) {
  const m = new Map(Object.entries(init).map(([k, v]) => [k, typeof v === "string" ? v : JSON.stringify(v)]));
  return {
    writes: 0,
    async get(k, opt) {
      const v = m.get(k);
      if (v == null) return null;
      if (opt?.type === "json") return JSON.parse(v);
      if (opt?.type === "stream") return new Response(v).body;
      return v;
    },
    async put(k, v) { this.writes++; m.set(k, v); },
  };
}

export function ctx() {
  const pending = [];
  return { waitUntil: (p) => pending.push(p), flush: () => Promise.all(pending.splice(0)) };
}
