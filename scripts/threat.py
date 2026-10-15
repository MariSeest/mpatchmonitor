"""
MPatchMonitor - detection and context sources (all free, no keys):

  * Windows release health: known issues of Windows updates, from Microsoft's public pages
  * MITRE ATT&CK techniques of exploited CVEs, from the Center for Threat-Informed Defense
    "Mappings Explorer" (KEV mappings, Apache 2.0)
  * Sigma detection rules that target a CVE, from the SigmaHQ repository (DRL 1.1)
  * Social preview images (PNG) for the monthly analysis pages

Every function returns None when its source is unavailable, so the caller keeps the previous data.
"""
from __future__ import annotations

import base64
import io
import logging
import re
from pathlib import Path

import intel

log = logging.getLogger("mpatchmonitor.threat")

# ------------------------------------------------------------------ Windows release health
HEALTH_BASE = "https://learn.microsoft.com/en-us/windows/release-health/"
HEALTH_PAGES = [
    ("status-windows-11-25h2", "Windows 11, version 25H2"),
    ("status-windows-11-24h2", "Windows 11, version 24H2"),
    ("status-windows-11-23h2", "Windows 11, version 23H2"),
    ("status-windows-10-22h2", "Windows 10, version 22H2"),
    ("status-windows-server-2025", "Windows Server 2025"),
    ("status-windows-server-2022", "Windows Server 2022"),
    ("status-windows-10-1809-and-windows-server-2019", "Windows Server 2019"),
    ("status-windows-10-1607-and-windows-server-2016", "Windows Server 2016"),
]
KB_RE = re.compile(r"\bKB\s?(\d{6,8})\b", re.I)
BUILD_RE = re.compile(r"OS Builds?\s+([\d.]+)", re.I)
DATE_RE = re.compile(r"(\d{4}-\d{2}-\d{2})")
STATUSES = ("Confirmed", "Mitigated", "Mitigated: External", "Investigating", "Resolved", "Resolved: External")


def _clean(s: str, n: int = 600) -> str:
    return re.sub(r"\s+", " ", str(s or "")).strip()[:n]


def _status(text: str) -> tuple[str, str]:
    """'Resolved KB5070112' -> ('Resolved', 'KB5070112')."""
    t = _clean(text, 120)
    status = next((s for s in sorted(STATUSES, key=len, reverse=True) if t.lower().startswith(s.lower())), t.split(" ")[0] if t else "")
    kb = KB_RE.search(t)
    return status, f"KB{kb.group(1)}" if kb else ""


def _detail(soup, anchor: str) -> dict:
    """Workaround / resolution text from the issue's detail block, found by its anchor."""
    if not anchor:
        return {}
    target = soup.find(id=anchor) or soup.find(attrs={"name": anchor})
    if target is None:
        return {}
    heading = target if target.name in ("h3", "h4", "h5") else target.find_next(["h3", "h4", "h5"])
    if heading is None:
        return {}
    parts = []
    for el in heading.find_all_next():
        if el is not heading and el.name in ("h2", "h3", "h4"):
            break
        if el.name in ("p", "li"):
            txt = _clean(el.get_text(" "), 900)
            if txt and txt not in parts and not txt.lower().startswith("back to top"):
                parts.append(txt)
    out = {}
    text = " ".join(parts)
    m = re.search(r"(?:Workaround|Mitigation)\s*:?\s*(.+?)(?=(?:Resolution|Next steps|Affected platforms)\s*:|$)", text, re.I)
    if m:
        out["workaround"] = _clean(m.group(1), 700)
    m = re.search(r"(?:Resolution|Next steps)\s*:?\s*(.+?)(?=(?:Workaround|Affected platforms)\s*:|$)", text, re.I)
    if m:
        out["resolution"] = _clean(m.group(1), 500)
    return out


def parse_release_health(html: str | bytes, slug: str, product: str) -> list[dict]:
    """Known issues from one release health page (summary table plus detail blocks)."""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "html.parser")
    out = []
    for table in soup.find_all("table"):
        head = [_clean(th.get_text(" "), 60).lower() for th in table.find_all("th")]
        if not head or "summary" not in head[0] or not any("originating" in h for h in head):
            continue
        for tr in table.find_all("tr"):
            tds = tr.find_all("td")
            if len(tds) < 3:
                continue
            link = tds[0].find("a")
            title = _clean(link.get_text(" ") if link else tds[0].get_text(" "), 240)
            if not title:
                continue
            summary = _clean(tds[0].get_text(" "), 700)
            if summary.startswith(title):
                summary = summary[len(title):].strip(" .:-") or ""
            href = link.get("href", "") if link else ""
            anchor = href[1:] if href.startswith("#") else ""
            orig = _clean(tds[1].get_text(" "), 200)
            kb = KB_RE.search(orig)
            build = BUILD_RE.search(orig)
            date = DATE_RE.search(orig)
            status, resolved_kb = _status(tds[2].get_text(" "))
            updated = DATE_RE.search(tds[3].get_text(" ")) if len(tds) > 3 else None
            issue_id = re.sub(r"[^a-z0-9]+", "-", (anchor or title).lower()).strip("-")[:80]
            out.append({
                "id": f"{slug.replace('status-', '')}:{issue_id}",
                "product": product, "title": title, "summary": summary,
                "kb": f"KB{kb.group(1)}" if kb else "", "build": build.group(1) if build else "",
                "originated": date.group(1) if date else "",
                "status": status, "resolved_kb": resolved_kb if status.startswith("Resolved") else "",
                "updated": updated.group(1) if updated else (date.group(1) if date else ""),
                "url": HEALTH_BASE + slug + (f"#{anchor}" if re.fullmatch(r"[A-Za-z0-9_-]{1,80}", anchor or "") else ""),
                **_detail(soup, anchor),
            })
    return out


def release_health(pages=HEALTH_PAGES, fetch=None) -> list[dict] | None:
    """Known issues of every supported Windows version; the same issue on several versions is merged."""
    fetch = fetch or (lambda url: intel._get(url, as_json=False, timeout=60))
    merged: dict[str, dict] = {}
    ok = False
    for slug, product in pages:
        body = fetch(HEALTH_BASE + slug)
        if not body:
            log.warning("release health page %s unavailable", slug)
            continue
        ok = True
        for it in parse_release_health(body, slug, product):
            key = re.sub(r"[^a-z0-9]+", " ", it["title"].lower()).strip()
            if key in merged:
                m = merged[key]
                if it["product"] not in m["products"]:
                    m["products"].append(it["product"])
                for k in ("kb", "workaround", "resolution", "resolved_kb"):
                    if not m.get(k) and it.get(k):
                        m[k] = it[k]
                m["kbs"] = sorted(set(m["kbs"]) | ({it["kb"]} if it["kb"] else set()))
                m["updated"] = max(m["updated"], it["updated"])
            else:
                merged[key] = {**it, "products": [it.pop("product")], "kbs": [it["kb"]] if it["kb"] else []}
    if not ok:
        return None
    items = list(merged.values())
    items.sort(key=lambda x: (not x["status"].startswith("Resolved"), x["updated"]), reverse=True)
    return items[:300]


# ------------------------------------------------------------------ MITRE ATT&CK (CTID KEV mappings)
CTID_REPO = "center-for-threat-informed-defense/mappings-explorer"
CTID_FALLBACK = "mappings/kev/attack-16.1/kev-07.28.2025/enterprise/kev-07.28.2025_attack-16.1-enterprise.json"
RAW = "https://raw.githubusercontent.com/{repo}/main/{path}"
ATTACK_TYPES = {"exploitation_technique": "exploitation", "primary_impact": "primary", "secondary_impact": "secondary"}
TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _gh_headers(token: str | None) -> dict:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def latest_ctid_file(tree: dict | None) -> str | None:
    """Newest enterprise KEV mapping file in the repository tree (highest ATT&CK version, then date)."""
    best = None
    for item in (tree or {}).get("tree", []):
        p = item.get("path", "")
        m = re.fullmatch(r"mappings/kev/attack-(\d+)\.(\d+)/kev-(\d{2})\.(\d{2})\.(\d{4})/enterprise/[^/]+\.json", p)
        if m:
            key = (int(m.group(1)), int(m.group(2)), m.group(5), m.group(3), m.group(4))
            if best is None or key > best[0]:
                best = (key, p)
    return best[1] if best else None


def parse_attack(doc: dict | None) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for m in (doc or {}).get("mapping_objects", []):
        cve = str(m.get("capability_id", "")).upper()
        tid = str(m.get("attack_object_id", ""))
        if not intel.CVE_RE.fullmatch(cve) or not TECH_RE.match(tid):
            continue
        row = {"id": tid, "name": _clean(m.get("attack_object_name"), 120), "type": ATTACK_TYPES.get(m.get("mapping_type"), "other")}
        if row not in out.setdefault(cve, []):
            out[cve].append(row)
    order = {"exploitation": 0, "primary": 1, "secondary": 2, "other": 3}
    for rows in out.values():
        rows.sort(key=lambda r: (order[r["type"]], r["id"]))
    return out


def attack_mappings(token: str | None = None) -> dict[str, list[dict]] | None:
    tree = intel._get(f"https://api.github.com/repos/{CTID_REPO}/git/trees/main?recursive=1", headers=_gh_headers(token))
    path = latest_ctid_file(tree) or CTID_FALLBACK
    doc = intel._get(RAW.format(repo=CTID_REPO, path=path), timeout=120)
    if not doc:
        return None
    mapped = parse_attack(doc)
    return mapped or None


# ------------------------------------------------------------------ Sigma rules
SIGMA_REPO = "SigmaHQ/sigma"
SIGMA_DIR_RE = re.compile(r"^(rules[^/]*/(?:.+/)?)(CVE-\d{4}-\d{4,7})/[^/]+\.ya?ml$", re.I)


def parse_sigma_tree(tree: dict | None) -> dict[str, dict]:
    """CVE -> {url of the rule folder, number of rules}; only folders named after a CVE."""
    out: dict[str, dict] = {}
    for item in (tree or {}).get("tree", []):
        m = SIGMA_DIR_RE.match(item.get("path", ""))
        if not m or item.get("type") != "blob":
            continue
        cve = m.group(2).upper()
        folder = m.group(1) + m.group(2)
        e = out.setdefault(cve, {"url": f"https://github.com/{SIGMA_REPO}/tree/master/{folder}", "rules": 0})
        e["rules"] += 1
    return out


def sigma_rules(token: str | None = None) -> dict[str, dict] | None:
    tree = intel._get(f"https://api.github.com/repos/{SIGMA_REPO}/git/trees/master?recursive=1", headers=_gh_headers(token), timeout=120)
    if not tree or not tree.get("tree"):
        return None
    return parse_sigma_tree(tree)


# ------------------------------------------------------------------ social preview images
FONT = Path(__file__).resolve().parent.parent / "public" / "fonts" / "archivo.woff2"
IT_MONTHS = ["gennaio", "febbraio", "marzo", "aprile", "maggio", "giugno", "luglio", "agosto", "settembre", "ottobre", "novembre", "dicembre"]
EN_MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
MONTH_IDS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _fonts():
    from fontTools.ttLib import TTFont
    from PIL import ImageFont
    f = TTFont(str(FONT))
    f.flavor = None
    buf = io.BytesIO()
    f.save(buf)
    data = buf.getvalue()

    def make(size, weight):
        font = ImageFont.truetype(io.BytesIO(data), size)
        try:
            font.set_variation_by_axes([weight, 100])
        except (OSError, AttributeError):
            pass
        return font
    return make


def og_image(month: dict, lang: str = "it", host: str = "") -> bytes:
    """1200x630 PNG with the month's figures, for LinkedIn and other link previews."""
    from PIL import Image, ImageDraw
    make = _fonts()
    W, H = 1200, 630
    bg, ink, muted, crit, accent, line = (15, 26, 43), (232, 238, 248), (167, 180, 201), (255, 122, 128), (124, 149, 255), (42, 58, 85)
    img = Image.new("RGB", (W, H), bg)
    d = ImageDraw.Draw(img)
    y, mi = month["id"][:4], MONTH_IDS.index(month["id"][5:])
    title = f"Patch Tuesday {IT_MONTHS[mi]} {y}" if lang == "it" else f"Patch Tuesday {EN_MONTHS[mi]} {y}"
    sub = "L'analisi del mese" if lang == "it" else "The monthly analysis"
    # brand mark
    for i, (dx, dy) in enumerate([(0, 0), (34, 0), (0, 34), (34, 34)]):
        d.rounded_rectangle([72 + dx, 64 + dy, 72 + dx + 28, 64 + dy + 28], radius=5, fill=accent if i == 3 else ink)
    d.text((156, 70), "MPatchMonitor", font=make(40, 700), fill=ink)
    d.text((72, 170), title, font=make(64, 700), fill=ink)
    d.text((72, 250), sub, font=make(34, 450), fill=muted)
    d.rectangle([72, 312, 172, 318], fill=accent)
    labels = (["Vulnerabilità", "Zero-day", "Critiche", "Exploit pubblici"] if lang == "it"
              else ["Vulnerabilities", "Zero-days", "Critical", "Public exploits"])
    values = [month.get("total"), month.get("exploited"), month.get("critical"), month.get("public_exploit")]
    for i, (v, lab) in enumerate(zip(values, labels)):
        x = 72 + i * 270
        d.text((x, 360), str(int(v)) if isinstance(v, (int, float)) else "–", font=make(96, 700), fill=crit if i == 1 else ink)
        d.text((x, 480), lab, font=make(30, 450), fill=muted)
    d.line([72, 552, W - 72, 552], fill=line, width=2)
    d.text((72, 568), host or "mpatchmonitor", font=make(26, 450), fill=muted)
    out = io.BytesIO()
    img.save(out, "PNG", optimize=True)
    return out.getvalue()


def og_images(summary: dict, host: str = "") -> dict[str, str]:
    """KV key -> base64 PNG, for the last three months in both languages (older ones are kept by KV)."""
    out = {}
    for m in (summary.get("months") or [])[-3:]:
        if not re.fullmatch(r"\d{4}-[A-Z][a-z]{2}", str(m.get("id", ""))) or m["id"][5:] not in MONTH_IDS:
            continue
        for lang in ("it", "en"):
            try:
                out[f"og:{m['id']}:{lang}"] = base64.b64encode(og_image(m, lang, host)).decode()
            except Exception as exc:   # image generation never breaks the data refresh
                log.warning("og image %s %s failed: %s", m["id"], lang, exc)
    return out

