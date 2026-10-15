/**
 * MPatchMonitor MCP server (Model Context Protocol, Streamable HTTP, JSON responses only).
 * Read-only tools over public data, so any AI assistant (Claude, Copilot, ChatGPT with MCP)
 * can ask "which Microsoft updates are exploited?" without scraping the site.
 *
 * Connect with the URL  https://<site>/mcp  (no authentication: the data is public).
 */
const SERVER = { name: "mpatchmonitor", version: "1.0.0" };
const PROTOCOLS = ["2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_BODY = 65_536;

const TOOLS = [
  { name: "search", description: "Search Microsoft CVEs and security updates (KB) by identifier or words in the title.",
    inputSchema: { type: "object", properties: { query: { type: "string", maxLength: 100 }, limit: { type: "integer", minimum: 1, maximum: 50 } }, required: ["query"] } },
  { name: "get_cve", description: "Details of a Microsoft CVE: priority, risk score, severity, CVSS, EPSS, exploitation, release, fixing updates.",
    inputSchema: { type: "object", properties: { id: { type: "string", pattern: "^CVE-\\d{4}-\\d{4,7}$" } }, required: ["id"] } },
  { name: "get_kb", description: "Details of a Microsoft security update: products, CVEs fixed, exploited count, risk score, superseding update.",
    inputSchema: { type: "object", properties: { kb: { type: "string" } }, required: ["kb"] } },
  { name: "hot_list", description: "Highest-risk items right now, ranked by the MPatchMonitor score.",
    inputSchema: { type: "object", properties: { kind: { type: "string", enum: ["cves", "cvesMs", "cvesNonMs", "kbs"] }, limit: { type: "integer", minimum: 1, maximum: 50 } } } },
  { name: "exploited_recent", description: "Vulnerabilities added to the CISA Known Exploited Vulnerabilities catalog recently, all vendors.",
    inputSchema: { type: "object", properties: { days: { type: "integer", minimum: 1, maximum: 90 } } } },
  { name: "patch_tuesday", description: "Summary of Microsoft Patch Tuesday releases (last 12 months, or one release such as 2026-Oct).",
    inputSchema: { type: "object", properties: { release: { type: "string", pattern: "^\\d{4}-[A-Z][a-z]{2}$" } } } },
  { name: "csirt_italia", description: "Latest CSIRT Italia (ACN) bulletins that mention Microsoft.",
    inputSchema: { type: "object", properties: { limit: { type: "integer", minimum: 1, maximum: 50 } } } },
];

const rpc = (id, result) => ({ jsonrpc: "2.0", id, result });
const rpcError = (id, code, message) => ({ jsonrpc: "2.0", id: id ?? null, error: { code, message } });
const text = (obj) => ({ content: [{ type: "text", text: JSON.stringify(obj, null, 1) }] });
const clamp = (n, lo, hi, d) => Math.min(hi, Math.max(lo, Number.isInteger(n) ? n : d));

let cache = { version: null, data: null };
async function index(env) {
  const v = await env.MPM.get("version", { type: "json", cacheTtl: 60 });
  const ver = v?.hashes?.mcp || v?.version || "none";
  if (cache.version !== ver || !cache.data) {
    cache = { version: ver, data: (await env.MPM.get("mcp", { type: "json", cacheTtl: 60 })) || { cves: {}, kbs: {}, kev_recent: [], months: [] } };
  }
  return cache.data;
}

const cveObj = (id, r, base) => r && { id, title: r[0], priority: r[1], score: r[2], severity: r[3], cvss: r[4], epss: r[5],
  in_cisa_kev: r[6], exploited: r[7], release: r[8], updates: r[9], public_exploit_sources: r[10] || [],
  microsoft_mitigations: r[11] || [], page: `${base}/cve/${id}`,
  microsoft: `https://msrc.microsoft.com/update-guide/vulnerability/${id}` };
const kbObj = (id, r, base) => r && { id, released: r[0], severity: r[1], cves_fixed: r[2], cves_in_kev: r[3], score: r[4],
  products: r[5], cves: r[6], superseded_by: r[7], known_issues: r[8], page: `${base}/kb/${id}`,
  catalog: `https://catalog.update.microsoft.com/Search.aspx?q=${id}` };

async function callTool(env, name, args, base) {
  const a = args && typeof args === "object" ? args : {};
  switch (name) {
    case "search": {
      const q = String(a.query || "").trim().slice(0, 100);
      if (!q) throw new Error("query is required");
      const idx = await index(env);
      const limit = clamp(a.limit, 1, 50, 10);
      const up = q.toUpperCase();
      const words = q.toLowerCase().split(/\s+/).filter(Boolean);
      const out = [];
      if (idx.cves[up]) out.push(cveObj(up, idx.cves[up], base));
      const kb = up.startsWith("KB") ? up : `KB${up}`;
      if (idx.kbs[kb]) out.push(kbObj(kb, idx.kbs[kb], base));
      for (const [id, r] of Object.entries(idx.cves)) {
        if (out.length >= limit) break;
        if (id !== up && words.every((w) => r[0].toLowerCase().includes(w))) out.push(cveObj(id, r, base));
      }
      return text({ results: out.slice(0, limit) });
    }
    case "get_cve": {
      const id = String(a.id || "").toUpperCase();
      const r = (await index(env)).cves[id];
      return text(r ? cveObj(id, r, base) : { error: `${id} is not in the last 12 Microsoft releases` });
    }
    case "get_kb": {
      const id = `KB${String(a.kb || "").toUpperCase().replace(/^KB/, "").replace(/\D/g, "")}`;
      const r = (await index(env)).kbs[id];
      return text(r ? kbObj(id, r, base) : { error: `${id} not found` });
    }
    case "hot_list": {
      const kind = ["cves", "cvesMs", "cvesNonMs", "kbs"].includes(a.kind) ? a.kind : "cves";
      const hot = (await env.MPM.get("hot", { type: "json", cacheTtl: 60 })) || {};
      return text({ kind, items: (hot[kind] || []).slice(0, clamp(a.limit, 1, 50, 15)) });
    }
    case "exploited_recent": {
      const days = clamp(a.days, 1, 90, 7);
      const since = new Date(Date.now() - days * 86_400_000).toISOString().slice(0, 10);
      const rows = (await index(env)).kev_recent.filter((k) => k[3] >= since)
        .map(([cve, vendor, product, added, ransomware, epss, score]) => ({ cve, vendor, product, added, ransomware, epss, score }));
      return text({ days, count: rows.length, items: rows });
    }
    case "patch_tuesday": {
      const months = (await index(env)).months.map(([id, date, total, exploited, kev, critical]) => ({ id, date, total, exploited, kev, critical, page: `${base}/release/${id}` }));
      return text(a.release ? (months.find((m) => m.id === a.release) || { error: "release not found" }) : { releases: months });
    }
    case "csirt_italia": {
      const rows = await env.DB.prepare("SELECT title, link, published, cves FROM acn_items ORDER BY published DESC LIMIT ?")
        .bind(clamp(a.limit, 1, 50, 10)).all();
      return text({ source: "CSIRT Italia (ACN)", items: rows.results.map((r) => ({ ...r, cves: JSON.parse(r.cves || "[]") })) });
    }
    default:
      throw Object.assign(new Error(`Unknown tool ${name}`), { code: -32602 });
  }
}

export async function handleMcp(request, env, base) {
  const headers = { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };
  if (request.method === "GET") return new Response(null, { status: 405, headers: { Allow: "POST" } });
  if (!(request.headers.get("Content-Type") || "").includes("application/json")) {
    return new Response(JSON.stringify(rpcError(null, -32700, "Content-Type must be application/json")), { status: 415, headers });
  }
  const raw = await request.text();
  if (raw.length > MAX_BODY) return new Response(JSON.stringify(rpcError(null, -32600, "Request too large")), { status: 413, headers });
  let msg;
  try { msg = JSON.parse(raw); } catch { return new Response(JSON.stringify(rpcError(null, -32700, "Parse error")), { status: 400, headers }); }
  if (Array.isArray(msg)) return new Response(JSON.stringify(rpcError(null, -32600, "Batches are not supported")), { status: 400, headers });
  if (!msg || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") {
    return new Response(JSON.stringify(rpcError(msg?.id, -32600, "Invalid request")), { status: 400, headers });
  }
  if (msg.id === undefined) return new Response(null, { status: 202 });   // notification

  let out;
  try {
    switch (msg.method) {
      case "initialize": {
        const asked = msg.params?.protocolVersion;
        out = rpc(msg.id, {
          protocolVersion: PROTOCOLS.includes(asked) ? asked : PROTOCOLS[0],
          capabilities: { tools: { listChanged: false } },
          serverInfo: SERVER,
          instructions: "Public Microsoft patch intelligence: CVEs, security updates, exploitation (CISA KEV, EPSS), Patch Tuesday and CSIRT Italia bulletins. Always cite the 'page' or 'microsoft' links.",
        });
        break;
      }
      case "ping": out = rpc(msg.id, {}); break;
      case "tools/list": out = rpc(msg.id, { tools: TOOLS }); break;
      case "tools/call": {
        const name = String(msg.params?.name || "");
        if (!TOOLS.some((t) => t.name === name)) { out = rpcError(msg.id, -32602, `Unknown tool ${name}`); break; }
        try { out = rpc(msg.id, await callTool(env, name, msg.params?.arguments, base)); }
        catch (err) { out = rpc(msg.id, { content: [{ type: "text", text: String(err.message || err).slice(0, 200) }], isError: true }); }
        break;
      }
      default: out = rpcError(msg.id, -32601, "Method not found");
    }
  } catch (err) {
    console.error("mcp error", err);
    out = rpcError(msg.id, -32603, "Internal error");
  }
  return new Response(JSON.stringify(out), { status: 200, headers });
}

export const _tools = TOOLS;
