# MPatchMonitor: security assessment

Vulnerability assessment and penetration test of the public site, its API and the private admin
console, carried out on the code in this repository. Infrastructure details (hostnames, account
identifiers, secrets) are intentionally omitted.

## 1. Summary

| | |
|---|---|
| Result | **No open vulnerabilities known.** 8 issues found and fixed during the assessment. |
| Automated black-box checks | **233 of 233 passed** (`security/pentest.py`), including the trackers, feeds, MCP server, Telegram webhook, language selection, Web Push subscriptions, the embeddable card, sitemap, structured data, preview images, the EPSS history proxy and the new pages |
| DOM XSS with hostile data | **Passed** in English and in Italian on 26 checks (hostile ATT&CK mappings, Sigma links and Windows known issues included): dashboard, CVE and update pages (hostile mitigations and exploit links), Patch Tuesday, every tracker, trends, monthly analysis, glossary, service status, CSIRT Italia, alerts, What changed, My devices with a hostile inventory file, a hostile SBOM and program list, and the report built from them (`security/dom_xss.py`) |
| Nuclei scan | **8,819 templates on 5 targets** (public pages and admin console): **0 vulnerabilities**, 4 informational technology detections (Cloudflare). To be repeated on the new pages after deployment. |
| Unit tests | **62 JavaScript** (including KQL generation, ATT&CK suggestions, remediation scripts, sitemap, JSON-LD and the EPSS proxy) (guard, bans, rate limits, passkeys, CSRF, device matching, software and SBOM matching, rollout plan, CSIRT Italia monitor, Telegram Watch bot, Web Push encryption and VAPID signature, embed card, MCP server, feeds, language selection) and **45 Python** (release health parsing, ATT&CK and Sigma sources, preview images, pipeline, fixes index, revision diffs, KB catalog, risk score, public exploits, mitigations, search index, trackers, translation completeness) |
| Dependencies | `npm audit`: 0 vulnerabilities. `pip-audit`: none. `bandit`: no findings |

## 2. Scope and method

- **Targets:** public Worker (pages, JSON API, RSS feeds and calendar, `/mcp` server, Telegram webhook, Web Push subscription API, embeddable SVG card, service worker, static assets, scheduled MSRC and CSIRT Italia watchers), browser-side processing on *My devices* and the evidence report, admin Worker (passkey authentication, management API), data pipeline and GitHub workflow.
- **Environment:** local Cloudflare runtime (workerd via Wrangler) with D1, KV and Rate Limiting bindings simulated.
- **Method:** OWASP Web Security Testing Guide (WSTG v4.2) for test design, OWASP ASVS 4.0 level 2 as the requirement baseline, plus code review of every security-relevant module.

| WSTG area | Covered by |
|---|---|
| Configuration and deployment (CONF) | security headers, HTTP methods, exposed files, HSTS, CSP |
| Identity and authentication (ATHN) | passkey registration and sign-in, forged and replayed assertions, lockout |
| Authorisation and session (ATHZ, SESS) | API without session, forged and malformed cookies, cookie attributes, logout, global revocation |
| Input validation (INPV) | reflected and DOM XSS, SQL injection, path traversal, template and command injection, SSRF, CRLF, Host header |
| Error handling (ERRH) | unknown routes, malformed JSON, oversized bodies and URLs |
| Client side (CLNT) | Trusted Types, framing, CORS, links to external sources |
| Business logic (BUSL) | rate limiting, automatic blocking, escalation, allowlist, IPv6 /64 rotation |

## 3. Issues found and fixed

| ID | Issue | Severity | Fix |
|---|---|---|---|
| VA-01 | The absolute URLs for social previews were built from the request's Host header, so a forged Host was reflected in the page. Not reachable through Cloudflare routing, but fragile. | Low | Origin pinned in configuration (`PUBLIC_ORIGIN`). |
| VA-02 | The MSRC watcher wrote to KV every five minutes. KV's free write quota is shared by every Worker in the account, so another project could be starved and the site would stop updating. | Medium (availability) | Watcher state moved to D1; KV is now written only by the pipeline. |
| VA-03 | Requests from allowlisted addresses that matched an attack rule were each written to D1; an authorised scan of thousands of requests consumed write quota. | Low | Allowlisted matches are only logged to Workers Logs. |
| VA-04 | Two isolates blocking the same address at the same time could count two offences and escalate the block. | Low | An active block is reused instead of escalated. |
| VA-05 | Chart geometry used inline `style` attributes, which a strict CSP must block; the alternative was weakening the CSP. | Info | Geometry passed as data attributes and applied through the CSSOM; CSP keeps no `unsafe-inline`. |
| VA-06 | Exported CSV cells starting with `=`, `+`, `-` or `@` would be executed as formulas by spreadsheet software. | Low | Such cells are prefixed and every cell is quoted. |
| VA-07 | On the *Hottest* list, item links from the dataset were escaped but not filtered by scheme, so a `javascript:` URL in poisoned data would have produced a clickable link (execution was still blocked by the CSP). | Low | Links pass through the same `https`/same-site filter as every other page. |
| VA-08 | Re-running the local penetration test reused the same test addresses, so a block left by an earlier run made the rate-limit check report a 403 instead of a 429 (test reliability, not a site issue). | Info | Each run starts from a random point of the 198.18.0.0/15 test range. |

## 4. Controls verified

- **Rate limiting:** a burst of 45 requests is limited with HTTP 429; sustained flooding ends in an automatic block (HTTP 403 with `Retry-After`).
- **Automatic blocking:** trap paths (`/.env`, `/.git`, `/wp-login.php`, backups, …), attack payloads and scanner tools are blocked on the first request; other visitors are unaffected; IPv6 blocks cover the /64.
- **Escalation:** first block 1 hour, second 24 hours, then 7 days.
- **Admin console:** reachable only on its own hostname and from allowed countries; every API call needs a passkey session; CSRF refused without the same-origin `Origin`, the custom header and a JSON body; five failed sign-ins lock the address out for 15 minutes; challenges are single use; signature counters must increase; user verification is mandatory.
- **Session cookie:** `__Host-` prefix, `Secure`, `HttpOnly`, `SameSite=Strict`, 8 hours; only a SHA-256 hash of the token is stored.
- **Headers:** CSP `default-src 'self'` without `unsafe-inline` or `unsafe-eval`, Trusted Types, `frame-ancestors 'none'`, HSTS, COOP, COEP, CORP, Referrer-Policy, Permissions-Policy, `nosniff`.
- **Disclosure:** configuration, source, migration and dependency files are not served; errors carry no stack traces; the public site never links to the admin console.
- **Client-side processing:** inventory files are parsed only in the browser (5 MB per file, 500 files, 5,000 devices); unknown formats are ignored; control characters are stripped; every value is escaped; the CSP allows connections only to the site, and `POST` to any page or API is refused, so inventories cannot be sent anywhere; exported CSVs neutralise formulas.
- **Languages:** the language comes only from `lang=en|it`, a cookie with the same two values, or `Accept-Language`; anything else is ignored and never reflected. The cookie is `Secure`, `SameSite=Lax` and carries no identity. Italian HTML comes from a file in the repository, is checked by the tests for scripts and event handlers, and is inserted by the Worker; dynamic text is escaped as before. Pages send `Vary: Cookie, Accept-Language`.
- **MCP server:** read-only tools over public data; JSON bodies only (no form CSRF), 64 KB limit, no batches, arguments validated, unknown tools refused, no CORS.
- **Telegram Watch bot:** the webhook answers only with Telegram's secret token (compared in constant time); only the chat id and topics are stored; the public alert log never contains recipients; delivery is capped per cron run to stay on the free plan.
- **Browser notifications (Web Push):** subscribe and unsubscribe accept only `POST` with a JSON body up to 4 KB, from the site's own `Origin` (and `Sec-Fetch-Site: same-origin` when sent); the push endpoint must be `https` on a known browser push service (Google, Mozilla, Apple, Microsoft), with no credentials or custom port, so the Worker cannot be used to reach other hosts (no SSRF); keys are checked for length and format; topics come from a fixed list or valid CVE/KB identifiers; at most 20,000 subscriptions. Messages are encrypted for each browser (RFC 8291) and signed with VAPID (RFC 8292) using WebCrypto; the private key is a Worker secret. Only the endpoint, its keys, topics and language are stored; expired subscriptions are deleted on the first 404/410; unsubscribing deletes everything. Sending is capped per cron run to stay within the free plan.
- **Service worker and app:** the service worker caches only an offline page and static assets, never data or API responses; notification clicks open only the site or a CSIRT Italia bulletin; it is registered through a Trusted Types policy that accepts only `/sw.js`.
- **Embeddable card:** `image/svg+xml` with `Content-Security-Policy: default-src 'none'`, `nosniff`, `Cross-Origin-Resource-Policy: cross-origin` only on this route; parameters are reduced to fixed values and never reflected; numbers and text are escaped; no script, links or external resources.
- **EPSS history proxy:** the CVE identifier is validated by pattern before any outbound request, which goes only to `api.first.org` with a 5-second timeout; answers are cleaned (dates, numbers in range) and cached for 12 hours, so each CVE costs at most one outbound request a day.
- **Structured data and sitemap:** JSON-LD is built server-side from validated paths and escapes `<`, `>` and `&`, so it can never close its script element; it is a data block, not executed, and the CSP is unchanged. The sitemap lists only identifiers that match the CVE/KB/month patterns. Preview images are served only if the stored value is a real PNG.
- **Remediation scripts:** generated in the browser; device names and KB numbers from inventory files are filtered to safe characters and written as single-quoted PowerShell literals, so a hostile inventory cannot inject commands. The scripts are report-only unless run with `-Install` or `-Apply`.
- **KQL queries:** CVE and KB identifiers are validated and stripped to letters, digits and hyphens before they reach a query.
- **New pages:** trends, monthly analysis, glossary and service status use the same strict CSP; month identifiers are validated by pattern and by month name (otherwise 404); the service status API exposes only check times, results and queue sizes, never tokens, fingerprints or recipients.
- **CSIRT Italia monitor:** only links on `acn.gov.it` or `csirt.gov.it` are kept; titles and summaries are stored as text and escaped on output.
- **Data integrity:** links to Microsoft updates are accepted only for `https` Microsoft hosts; every value is escaped before rendering; hostile data in titles, products, revision notes and links did not execute.

## 5. Residual risks

1. **Request quota.** On a `workers.dev` hostname there is no WAF in front of the Worker. A large distributed flood on dynamic routes could exhaust the free daily request quota; static pages would stay online but data would stop loading until the next day. Cloudflare's always-on DDoS protection reduces this risk; a custom domain would allow a free WAF rate-limiting rule before the Worker.
2. **Distributed attackers.** Per-address limits do not stop an attacker spread over many networks; the Rate Limiting binding is also counted per Cloudflare location and eventually consistent.
3. **Upstream data.** MSRC, CISA, FIRST, NVD, CSIRT Italia, endoflife.date, GitHub (including Metasploit, Nuclei and PoC-in-GitHub, from which only CVE identifiers are read; the CTID ATT&CK mappings; the SigmaHQ file list), Microsoft's release health pages and Have I Been Pwned are trusted sources; their content is escaped and links are filtered, but their accuracy is not verified.
4. **Third-party accounts.** Cloudflare, GitHub and Telegram accounts are outside the application's control and are the most valuable targets; they must use strong, phishing-resistant authentication.

## 6. Limits of this assessment

- Not independent: carried out by the author of the code.
- Local runtime: Telegram and Web Push delivery to real browsers, passkeys on physical devices, the distributed rate limiter and Cloudflare's network protections were not verified in production.
- Automated: no manual exploratory testing of unexpected attack chains.

"No known vulnerabilities" does not mean "no possible vulnerabilities". The tests are repeated after every change and an independent test is recommended.

## 7. How to repeat the tests

```bash
npm test && pytest -q
npm run dev                                   # terminal 1, public site on :8787
npm run dev:admin                             # terminal 2, admin console on :8788
python security/pentest.py --public http://localhost:8787 --admin http://localhost:8788 --report security/reports/pentest.md
```
