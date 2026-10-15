"""
MPatchMonitor - threat intelligence beyond MSRC.

Every source is public and free. Each function is defensive: a source that fails returns
None and the pipeline keeps the previous published data for it.

Sources and terms:
  CISA KEV ............ public domain
  NVD (NIST) .......... public domain, optional free API key (NVD_API_KEY)
  FIRST EPSS .......... free, attribution
  endoflife.date ...... MIT-licensed community data, attribution
  GitHub REST API ..... MicrosoftDocs commits, GitHub Advisory Database (CC-BY 4.0)
  Have I Been Pwned ... breach list, CC-BY 4.0, attribution required
  SEC EDGAR ........... public filings, requires a declared User-Agent (SEC_USER_AGENT)
  RSS feeds ........... headlines and links only, never article text
"""
from __future__ import annotations

import logging
import os
import re
import time
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import quote, urlparse
from xml.sax.saxutils import escape

import requests
from defusedxml import ElementTree as SafeET

log = logging.getLogger("mpatchmonitor.intel")
UA = "MPatchMonitor/1.0 (+https://github.com/MariSeest/mpatchmonitor)"
_session = requests.Session()
_session.headers.update({"User-Agent": UA})
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


def _get(url: str, *, params=None, headers=None, as_json=True, retries=3, timeout=60):
    for attempt in range(1, retries + 1):
        try:
            r = _session.get(url, params=params, headers=headers, timeout=timeout)
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json() if as_json else r.content
        except (requests.RequestException, ValueError) as exc:
            if attempt == retries:
                log.warning("GET %s failed: %s", url, exc)
                return None
            time.sleep(2 ** attempt)


def safe_url(u: str, hosts: tuple[str, ...] | None = None) -> str:
    """Only absolute https links; optionally restricted to given hosts (and their subdomains)."""
    try:
        p = urlparse(str(u or "").strip())
    except ValueError:
        return ""
    if p.scheme != "https" or not p.hostname:
        return ""
    host = p.hostname.lower()
    if hosts and not any(host == h or host.endswith("." + h) for h in hosts):
        return ""
    return p.geturl()


def _days_since(d: str | None, today: date) -> float | None:
    if not d:
        return None
    try:
        return (today - date.fromisoformat(str(d)[:10])).days
    except ValueError:
        return None


# ------------------------------------------------------------------ risk score
TIERS = [(80, "Patch now"), (60, "High"), (40, "Notable"), (0, "Track")]


def risk_score(*, kev: bool, exploited: bool, ransomware: bool, epss: float | None, cvss: float | None,
               last_activity: str | None, today: date, public_exploit: bool = False) -> tuple[int, str]:
    """Transparent 0-100 score. Same inputs, same score for everyone.

      50  exploitation confirmed (CISA KEV, or Microsoft reports exploitation)
      15  known use in ransomware campaigns
      20  EPSS probability, linear up to 50 %
      10  CVSS base score / 10
      10  public exploit code (Metasploit module, Nuclei template or proof of concept on GitHub)
       5  recency: full within 14 days of release or KEV listing, fading to 0 at 60 days
      (capped at 100)

    Tier: by score, except that exploitation confirmed in the last 30 days is always "Patch now".
    """
    s = 0.0
    if kev or exploited:
        s += 50
    if ransomware:
        s += 15
    if epss:
        s += 20 * min(1.0, float(epss) / 0.5)
    if cvss:
        s += float(cvss)
    if public_exploit:
        s += 10
    age = _days_since(last_activity, today)
    if age is not None and age >= 0:
        s += 5 if age <= 14 else max(0.0, 5 * (60 - age) / 46)
    score = int(round(min(100.0, s)))
    tier = next(label for limit, label in TIERS if score >= limit)
    if (kev or exploited) and age is not None and 0 <= age <= 30:
        tier = "Patch now"
    return score, tier


# ------------------------------------------------------------------ CISA KEV (all vendors)
def normalise_kev(raw: dict | None) -> list[dict]:
    out = []
    for k in (raw or {}).get("vulnerabilities", []):
        cve = str(k.get("cveID", "")).upper()
        if not CVE_RE.fullmatch(cve):
            continue
        out.append({
            "cve": cve,
            "vendor": str(k.get("vendorProject", ""))[:80],
            "product": str(k.get("product", ""))[:120],
            "name": str(k.get("vulnerabilityName", ""))[:200],
            "added": str(k.get("dateAdded", ""))[:10],
            "due": str(k.get("dueDate", ""))[:10],
            "ransomware": str(k.get("knownRansomwareCampaignUse", "")).lower() == "known",
            "action": str(k.get("requiredAction", ""))[:400],
            "desc": str(k.get("shortDescription", ""))[:500],
            "cwes": [str(c)[:20] for c in (k.get("cwes") or [])][:5],
        })
    out.sort(key=lambda x: x["added"], reverse=True)
    return out


# ------------------------------------------------------------------ NVD CVSS for KEV entries
def _nvd_metric(metrics: dict) -> tuple[float | None, str | None, str | None]:
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        items = metrics.get(key) or []
        if not items:
            continue
        primary = next((m for m in items if m.get("type") == "Primary"), items[0])
        data = primary.get("cvssData") or {}
        score = data.get("baseScore")
        sev = data.get("baseSeverity") or primary.get("baseSeverity")
        if score is not None:
            return float(score), (str(sev).title() if sev else None), ver
    return None, None, None


def parse_nvd_page(page: dict) -> dict[str, dict]:
    out = {}
    for item in (page or {}).get("vulnerabilities", []):
        cve = (item.get("cve") or {})
        cid = str(cve.get("id", "")).upper()
        if not CVE_RE.fullmatch(cid):
            continue
        score, sev, ver = _nvd_metric(cve.get("metrics") or {})
        out[cid] = {"cvss": score, "severity": sev, "cvss_version": ver}
    return out


def nvd_kev_cvss(api_key: str | None = None, max_pages: int = 5) -> dict[str, dict] | None:
    """All CVEs in KEV with their CVSS, using the NVD 'hasKev' filter (one or two requests)."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": api_key} if api_key else None
    out: dict[str, dict] = {}
    start = 0
    for _ in range(max_pages):
        page = _get(url, params={"hasKev": "", "resultsPerPage": 2000, "startIndex": start}, headers=headers, timeout=120)
        if page is None:
            return out or None
        out.update(parse_nvd_page(page))
        start += int(page.get("resultsPerPage") or 2000)
        if start >= int(page.get("totalResults") or 0):
            break
        time.sleep(1 if api_key else 6)   # NVD rate limit without a key: 5 requests / 30 s
    return out


# ------------------------------------------------------------------ end of life (endoflife.date)
EOL_PRODUCTS = [
    # slug, label, microsoft
    ("windows", "Windows", True), ("windows-server", "Windows Server", True), ("mssqlserver", "SQL Server", True),
    ("office", "Microsoft Office", True), ("msexchange", "Exchange Server", True), ("sharepoint", "SharePoint Server", True),
    ("dotnet", ".NET", True), ("dotnetfx", ".NET Framework", True), ("powershell", "PowerShell", True),
    ("azure-kubernetes-service", "Azure Kubernetes Service", True), ("visual-studio", "Visual Studio", True),
    ("ubuntu", "Ubuntu", False), ("debian", "Debian", False), ("rhel", "Red Hat Enterprise Linux", False),
    ("macos", "macOS", False), ("ios", "iOS", False), ("android", "Android", False),
    ("nodejs", "Node.js", False), ("python", "Python", False), ("php", "PHP", False), ("java", "Java (Oracle)", False),
    ("postgresql", "PostgreSQL", False), ("mysql", "MySQL", False), ("nginx", "nginx", False),
    ("apache-http-server", "Apache HTTP Server", False), ("kubernetes", "Kubernetes", False),
    ("esxi", "VMware ESXi", False), ("vcenter", "VMware vCenter", False), ("fortios", "FortiOS", False),
    ("panos", "PAN-OS", False), ("citrix-vad", "Citrix Virtual Apps and Desktops", False), ("veeam-backup-and-replication", "Veeam Backup & Replication", False),
    ("firefox", "Mozilla Firefox", False), ("libreoffice", "LibreOffice", False),
]


def _eol_date(v: Any) -> tuple[str | None, bool | None]:
    """endoflife.date uses either an ISO date or a boolean."""
    if isinstance(v, bool):
        return None, v
    if isinstance(v, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
        return v, None
    return None, None


def normalise_eol(slug: str, label: str, microsoft: bool, cycles: list | None, today: date) -> list[dict]:
    out = []
    for c in (cycles or [])[:60]:
        if not isinstance(c, dict):
            continue
        eol_d, eol_b = _eol_date(c.get("eol"))
        sup_d, _ = _eol_date(c.get("support"))
        ext_d, _ = _eol_date(c.get("extendedSupport"))
        end = ext_d or eol_d
        if end:
            days = (date.fromisoformat(end) - today).days
            status = "ended" if days < 0 else "ending" if days <= 180 else "supported"
        else:
            status = "ended" if eol_b is True else "supported"
            days = None
        out.append({
            "product": label, "slug": slug, "microsoft": microsoft,
            "cycle": str(c.get("cycle", ""))[:40], "label": str(c.get("releaseLabel") or c.get("cycle") or "")[:60],
            "released": str(c.get("releaseDate", ""))[:10] or None,
            "support_end": sup_d, "eol": eol_d, "extended_end": ext_d,
            "latest": str(c.get("latest", ""))[:40] or None, "lts": bool(c.get("lts")),
            "status": status, "days_left": days,
            "link": f"https://endoflife.date/{slug}",
        })
    return out


def end_of_life(today: date) -> list[dict] | None:
    rows, ok = [], 0
    for slug, label, ms in EOL_PRODUCTS:
        cycles = _get(f"https://endoflife.date/api/{quote(slug)}.json")
        if cycles is None:
            continue
        ok += 1
        rows += normalise_eol(slug, label, ms, cycles, today)
    return rows if ok else None


# ------------------------------------------------------------------ Microsoft docs tracker (GitHub)
DOC_REPOS = [
    ("MicrosoftDocs/entra-docs", "Entra ID"),
    ("MicrosoftDocs/memdocs", "Intune"),
    ("MicrosoftDocs/defender-docs", "Defender"),
    ("microsoftgraph/microsoft-graph-docs-contrib", "Microsoft Graph"),
    ("MicrosoftDocs/windows-itpro-docs", "Windows"),
    ("MicrosoftDocs/windowsserverdocs", "Windows Server"),
    ("MicrosoftDocs/SupportArticles-docs", "Support articles"),
]
_NOISE = re.compile(r"^(merge (pull request|branch)|sync|publish|auto-?merge|update [\w.-]+\.(yml|json)$|bulk|\[automation\])", re.I)


def normalise_commits(repo: str, area: str, commits: list | None) -> list[dict]:
    out = []
    for c in commits or []:
        msg = str(((c.get("commit") or {}).get("message")) or "").split("\n")[0].strip()
        if not msg or _NOISE.search(msg):
            continue
        out.append({
            "repo": repo, "area": area, "message": msg[:200],
            "date": str(((c.get("commit") or {}).get("author") or {}).get("date", ""))[:20],
            "author": str((c.get("author") or {}).get("login") or ((c.get("commit") or {}).get("author") or {}).get("name") or "")[:60],
            "url": safe_url(c.get("html_url", ""), ("github.com",)),
        })
    return out


def docs_tracker(token: str | None, days: int = 14) -> list[dict] | None:
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    rows, ok = [], 0
    for repo, area in DOC_REPOS:
        data = _get(f"https://api.github.com/repos/{repo}/commits", params={"since": since, "per_page": 100}, headers=headers)
        if data is None:
            continue
        ok += 1
        rows += normalise_commits(repo, area, data)
    rows.sort(key=lambda r: r["date"], reverse=True)
    return rows[:600] if ok else None


# ------------------------------------------------------------------ news headlines (RSS / Atom)
NEWS_FEEDS = [
    ("Microsoft Security Response Center", "https://msrc.microsoft.com/blog/feed"),
    ("CSIRT Italia (ACN)", "https://www.acn.gov.it/portale/feedrss/-/journal/rss/20119/723192"),
    ("CISA", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
]
_ATOM = "{http://www.w3.org/2005/Atom}"


def _text(el) -> str:
    return re.sub(r"\s+", " ", "".join(el.itertext())).strip() if el is not None else ""


def _date(s: str) -> str:
    s = (s or "").strip()
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            d = datetime.strptime(s.replace("GMT", "+0000") if "%z" in fmt else s, fmt)
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return ""


def parse_feed(xml: bytes, source: str, limit: int = 25) -> list[dict]:
    """RSS 2.0 or Atom, parsed with defusedxml (no external entities, no entity bombs)."""
    try:
        root = SafeET.fromstring(xml)
    except Exception as exc:   # malformed or hostile XML
        log.warning("feed %s unreadable: %s", source, exc)
        return []
    items = root.findall(".//item") or root.findall(f".//{_ATOM}entry")
    out = []
    for it in items[:limit]:
        title = _text(it.find("title")) or _text(it.find(f"{_ATOM}title"))
        link = _text(it.find("link"))
        if not link:
            le = it.find(f"{_ATOM}link")
            link = le.get("href", "") if le is not None else ""
        when = _text(it.find("pubDate")) or _text(it.find(f"{_ATOM}updated")) or _text(it.find(f"{_ATOM}published")) \
            or _text(it.find("{http://purl.org/dc/elements/1.1/}date"))
        desc = _text(it.find("description")) or _text(it.find(f"{_ATOM}summary")) or _text(it.find(f"{_ATOM}content"))
        desc = re.sub(r"<[^>]+>", " ", desc)
        url = safe_url(link)
        if not title or not url:
            continue
        out.append({
            "source": source, "title": title[:240], "url": url, "date": _date(when),
            "cves": sorted({c.upper() for c in CVE_RE.findall(title + " " + desc)})[:20],
            "microsoft": bool(re.search(r"\bmicrosoft\b", title + " " + desc, re.I)),
        })
    return out


def news(feeds=NEWS_FEEDS) -> list[dict] | None:
    rows, ok = [], 0
    for source, url in feeds:
        xml = _get(url, as_json=False, timeout=30)
        if xml is None:
            continue
        ok += 1
        rows += parse_feed(xml, source)
    rows.sort(key=lambda r: r["date"], reverse=True)
    return rows[:200] if ok else None


# ------------------------------------------------------------------ data breaches
def normalise_hibp(breaches: list | None, limit: int = 60) -> list[dict]:
    rows = []
    for b in breaches or []:
        if not b.get("IsVerified") or b.get("IsSensitive") or b.get("IsSpamList") or b.get("IsRetired") or b.get("IsFabricated"):
            continue
        rows.append({
            "source": "Have I Been Pwned", "name": str(b.get("Title") or b.get("Name"))[:120],
            "domain": str(b.get("Domain") or "")[:120], "breach_date": str(b.get("BreachDate") or "")[:10],
            "added": str(b.get("AddedDate") or "")[:10], "accounts": int(b.get("PwnCount") or 0),
            "data": [str(x)[:40] for x in (b.get("DataClasses") or [])][:12],
            "url": f"https://haveibeenpwned.com/PwnedWebsites#{quote(str(b.get('Name', '')))}",
        })
    rows.sort(key=lambda r: r["added"], reverse=True)
    return rows[:limit]


def normalise_sec(hits: dict | None, limit: int = 40) -> list[dict]:
    rows = []
    for h in ((hits or {}).get("hits") or {}).get("hits", []):
        s = h.get("_source") or {}
        adsh = str(s.get("adsh") or h.get("_id", "").split(":")[0])
        ciks = s.get("ciks") or []
        if not re.fullmatch(r"\d{10}-\d{2}-\d{6}", adsh) or not ciks:
            continue
        cik = str(int(ciks[0]))
        rows.append({
            "source": "SEC 8-K Item 1.05", "company": str((s.get("display_names") or [""])[0])[:160],
            "filed": str(s.get("file_date") or "")[:10], "form": str(s.get("form") or "8-K")[:12],
            "url": f"https://www.sec.gov/Archives/edgar/data/{cik}/{adsh.replace('-', '')}/{adsh}-index.html",
        })
    seen, out = set(), []
    for r in sorted(rows, key=lambda r: r["filed"], reverse=True):
        if r["url"] not in seen:
            seen.add(r["url"])
            out.append(r)
    return out[:limit]


def breaches(sec_user_agent: str | None) -> dict | None:
    hibp = _get("https://haveibeenpwned.com/api/v3/breaches")
    sec = None
    if sec_user_agent:
        end = date.today()
        sec = _get("https://efts.sec.gov/LATEST/search-index", params={
            "q": '"Item 1.05"', "forms": "8-K", "dateRange": "custom",
            "startdt": (end - timedelta(days=365)).isoformat(), "enddt": end.isoformat(),
        }, headers={"User-Agent": sec_user_agent})
    if hibp is None and sec is None:
        return None
    return {"hibp": normalise_hibp(hibp), "sec": normalise_sec(sec)}


# ------------------------------------------------------------------ open source fixes (GitHub Advisory Database)
def normalise_advisory(cve: str, advisories: list | None) -> list[dict]:
    rows = []
    for a in advisories or []:
        for v in a.get("vulnerabilities") or []:
            pkg = v.get("package") or {}
            if not pkg.get("name"):
                continue
            rows.append({
                "cve": cve, "ghsa": str(a.get("ghsa_id") or "")[:30], "ecosystem": str(pkg.get("ecosystem") or "")[:30],
                "package": str(pkg.get("name"))[:120], "affected": str(v.get("vulnerable_version_range") or "")[:120],
                "fixed": str(v.get("first_patched_version") or "")[:60] or None,
                "url": safe_url(a.get("html_url", ""), ("github.com",)),
            })
    return rows[:20]


def open_source(kev_cves: list[str], token: str | None, cache: dict, budget: int = 250) -> dict:
    """Map exploited CVEs to open-source packages and fixed versions. Results are cached
    (including 'no package') so each CVE is looked up once; 'budget' caps lookups per run."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    done = 0
    for cve in kev_cves:
        if cve in cache or done >= budget:
            continue
        data = _get("https://api.github.com/advisories", params={"cve_id": cve, "type": "reviewed", "per_page": 10}, headers=headers)
        done += 1
        if data is None:
            continue
        cache[cve] = normalise_advisory(cve, data)
    return cache


# ------------------------------------------------------------------ public exploit code
EXPLOIT_SOURCES = {
    # bit: (name, raw file that lists the CVEs it covers)
    1: ("metasploit", "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"),
    2: ("nuclei", "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"),
    4: ("poc", "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/README.md"),
}
EXPLOIT_LINKS = {
    "metasploit": "https://github.com/search?q=repo%3Arapid7%2Fmetasploit-framework+{cve}&type=code",
    "nuclei": "https://github.com/search?q=repo%3Aprojectdiscovery%2Fnuclei-templates+{cve}&type=code",
    "poc": "https://github.com/nomi-sec/PoC-in-GitHub/blob/master/{year}/{cve}.json",
}


def cves_in(text: bytes | str | None) -> set[str]:
    if not text:
        return set()
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    return {m.upper() for m in CVE_RE.findall(text)}


def public_exploits(previous: dict | None = None) -> dict[str, int] | None:
    """CVE -> bitmask of sources with public exploit code. Only CVE identifiers are read from
    the files; no exploit code is stored or published. A source that fails keeps its previous bits."""
    previous = previous or {}
    out: dict[str, int] = {}
    ok = False
    for bit, (name, url) in EXPLOIT_SOURCES.items():
        body = _get(url, as_json=False, timeout=180)
        if body is None:
            log.warning("exploit source %s unavailable, keeping previous data", name)
            for cve, mask in previous.items():
                if mask & bit:
                    out[cve] = out.get(cve, 0) | bit
            continue
        ok = True
        for cve in cves_in(body):
            out[cve] = out.get(cve, 0) | bit
    return out if ok else None


def exploit_info(cve: str, mask: int | None) -> dict | None:
    """Public view of the bitmask, with links to where the code can be checked."""
    if not mask:
        return None
    year = cve.split("-")[1] if cve.count("-") >= 2 else ""
    info = {}
    for bit, (name, _) in EXPLOIT_SOURCES.items():
        if mask & bit:
            info[name] = EXPLOIT_LINKS[name].format(cve=cve, year=year)
    return info


# ------------------------------------------------------------------ RSS output
def rss(title: str, link: str, description: str, items: list[dict], self_url: str) -> str:
    """items: {title, link, guid, date (ISO), description}. Every value is XML-escaped."""
    def rfc822(iso: str) -> str:
        try:
            return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%a, %d %b %Y %H:%M:%S +0000")
        except ValueError:
            return ""
    parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom"><channel>',
        f"<title>{escape(title)}</title><link>{escape(link)}</link><description>{escape(description)}</description>",
        f'<atom:link href="{escape(self_url)}" rel="self" type="application/rss+xml"/>',
        "<generator>MPatchMonitor</generator><language>en</language>",
    ]
    for it in items[:60]:
        parts.append(
            f"<item><title>{escape(it['title'])}</title><link>{escape(it['link'])}</link>"
            f"<guid isPermaLink=\"false\">{escape(it['guid'])}</guid>"
            + (f"<pubDate>{rfc822(it['date'])}</pubDate>" if it.get("date") else "")
            + f"<description>{escape(it.get('description', ''))}</description></item>")
    parts.append("</channel></rss>")
    return "".join(parts)


def env(name: str) -> str | None:
    v = os.environ.get(name, "").strip()
    return v or None
