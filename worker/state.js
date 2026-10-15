/** Small key/value state kept in D1 (cheap writes, no KV quota). */
export async function getState(env, key) {
  const row = await env.DB.prepare("SELECT value FROM state WHERE key = ?").bind(key).first();
  try { return row ? JSON.parse(row.value) : null; } catch { return null; }
}

export async function putState(env, key, value) {
  await env.DB.prepare(`INSERT INTO state (key, value, updated_at) VALUES (?,?,?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`)
    .bind(key, JSON.stringify(value), Date.now()).run();
}
