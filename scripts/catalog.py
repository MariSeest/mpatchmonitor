"""
MPatchMonitor - derived datasets: KB catalog, hot lists, exploited CVEs of every vendor,
compact index for the MCP endpoint, and RSS feeds. Pure functions: easy to test.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import date

import intel
from intel import TIERS, risk_score, rss

TIER_RANK = {label: i for i, (_, label) in enumerate(TIERS)}   # 0 = most urgent

SEV_RANK = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1, "Unrated": 0}
CATALOG = "https://catalog.update.microsoft.com/Search.aspx?q={kb}"
SUPPORT = "https://support.microsoft.com/help/{num}"


def score_cves(cves: list[dict], release_day: dict[str, str], today: date) -> None:
    for c in cves:
        last = max(filter(None, [(c.get("kev") or {}).get("date_added"), release_day.get(c["release"]), (c.get("revised_at") or "")[:10]]),
                   default=None)
        c["score"], c["tier"] = risk_score(
            kev=bool(c.get("kev")), exploited=bool(c.get("exploited")), ransomware=bool((c.get("kev") or {}).get("ransomware")),
            epss=c.get("epss"), cvss=c.get("cvss"), last_activity=last, today=today, public_exploit=bool(c.get("exploit")))


def build_kb_catalog(cves: list[dict], months: list[dict]) -> list[dict]:
    """One entry per security update (KB) with everything Microsoft says about it."""
    release_day = {m["id"]: m["release_date"] for m in months}
    kbs: dict[str, dict] = {}
    for c in cves:
        for info in c.get("_kbinfo", []):
            k = kbs.setdefault(info["kb"], {
                "kb": info["kb"], "release": c["release"], "date": release_day.get(c["release"], c.get("published")),
                "products": set(), "subtypes": set(), "cves": set(), "supersedes": set(), "known_issues": {},
                "fixed_builds": {}, "restart": set(),
                "severity": "Unrated", "tier": "Track", "cvss": None, "epss": None, "kev": 0, "exploited": 0, "ransomware": False, "score": 0,
                "public_exploit": 0, "mitigations": 0,
            })
            if c["release"] < k["release"]:
                k["release"], k["date"] = c["release"], release_day.get(c["release"], k["date"])
            k["products"].add(info["product"])
            if info["subtype"]:
                k["subtypes"].add(info["subtype"])
            if info["restart"]:
                k["restart"].add(info["restart"])
            k["supersedes"].update(info["supersedes"])
            for ki in info["known_issues"]:
                k["known_issues"][ki["url"]] = ki["label"]
            if info["fixed_build"]:
                k["fixed_builds"][info["product"]] = info["fixed_build"]
            if c["cve"] not in k["cves"]:
                k["cves"].add(c["cve"])
                if SEV_RANK.get(c["severity"], 0) > SEV_RANK.get(k["severity"], 0):
                    k["severity"] = c["severity"]
                k["cvss"] = max(filter(None, [k["cvss"], c.get("cvss")]), default=None)
                k["epss"] = max(filter(None, [k["epss"], c.get("epss")]), default=None)
                k["kev"] += bool(c.get("kev"))
                k["exploited"] += bool(c.get("exploited") or c.get("kev"))
                k["ransomware"] |= bool((c.get("kev") or {}).get("ransomware"))
                k["public_exploit"] += bool(c.get("exploit"))
                k["mitigations"] += bool(c.get("mitigations"))
                k["score"] = max(k["score"], c.get("score", 0))
                if TIER_RANK.get(c.get("tier"), 9) < TIER_RANK[k["tier"]]:
                    k["tier"] = c["tier"]
    superseded_by = defaultdict(set)
    for k in kbs.values():
        for old in k["supersedes"]:
            superseded_by[old].add(k["kb"])
    out = []
    for k in kbs.values():
        num = k["kb"][2:]
        crit = sum(1 for _ in k["cves"])
        score = min(100, k["score"] + (3 if crit >= 10 else 0))
        by_score = next(label for limit, label in TIERS if score >= limit)
        out.append({
            "tier": min(k["tier"], by_score, key=TIER_RANK.get),
            **{x: k[x] for x in ("kb", "release", "date", "severity", "cvss", "epss", "kev", "exploited", "ransomware",
                                 "public_exploit", "mitigations")},
            "score": score,
            "products": sorted(k["products"]), "subtypes": sorted(k["subtypes"]), "restart": sorted(k["restart"]),
            "cves": sorted(k["cves"]), "count": len(k["cves"]),
            "supersedes": sorted(k["supersedes"]), "superseded_by": sorted(superseded_by.get(k["kb"], [])),
            "known_issues": [{"label": v, "url": u} for u, v in sorted(k["known_issues"].items())],
            "fixed_builds": dict(sorted(k["fixed_builds"].items())),
            "catalog_url": CATALOG.format(kb=k["kb"]), "support_url": SUPPORT.format(num=num),
        })
    out.sort(key=lambda x: (x["date"] or "", x["score"]), reverse=True)
    return out


def attach_health(kbs: list[dict], health: list[dict]) -> None:
    """Windows release health issues on the update that caused them and on the one that fixed them."""
    by_kb: dict[str, list[dict]] = defaultdict(list)
    for h in health:
        row = {"id": h["id"], "title": h["title"], "status": h["status"], "url": h["url"], "updated": h.get("updated", "")}
        for kb in h.get("kbs", []):
            by_kb[kb].append({**row, "role": "caused"})
        if h.get("resolved_kb"):
            by_kb[h["resolved_kb"]].append({**row, "role": "fixed"})
    for k in kbs:
        k["health"] = by_kb.get(k["kb"], [])[:12]


def build_kev_dataset(kev: list[dict], epss: dict, nvd: dict, today: date, exploits: dict | None = None,
                      attack: dict | None = None, sigma: dict | None = None) -> list[dict]:
    """Every known exploited CVE, all vendors, with EPSS, CVSS (NVD) and the risk score."""
    out = []
    for k in kev:
        e = epss.get(k["cve"]) or {}
        n = nvd.get(k["cve"]) or {}
        exploit = intel.exploit_info(k["cve"], (exploits or {}).get(k["cve"]))
        score, tier = risk_score(kev=True, exploited=True, ransomware=k["ransomware"], epss=e.get("epss"),
                                 cvss=n.get("cvss"), last_activity=k["added"], today=today, public_exploit=bool(exploit))
        out.append({**k, "microsoft": k["vendor"].lower() == "microsoft", "epss": e.get("epss"), "exploit": exploit,
                    "epss_percentile": e.get("percentile"), "cvss": n.get("cvss"), "cvss_severity": n.get("severity"),
                    "score": score, "tier": tier,
                    "attack": [t["id"] for t in (attack or {}).get(k["cve"], [])][:6] or None,
                    "sigma": ((sigma or {}).get(k["cve"]) or {}).get("url"),
                    "nvd_url": f"https://nvd.nist.gov/vuln/detail/{k['cve']}"})
    return out


def build_hot(cves: list[dict], kev_rows: list[dict], kbs: list[dict], n: int = 100) -> dict:
    def ms_row(c):
        return {"id": c["cve"], "title": c["title"], "score": c["score"], "tier": c["tier"], "severity": c["severity"],
                "kev": bool(c.get("kev")), "exploited": bool(c.get("exploited")), "epss": c.get("epss"), "cvss": c.get("cvss"),
                "public_exploit": bool(c.get("exploit")), "microsoft": True, "link": f"/cve/{c['cve']}"}

    def kev_row(k):
        return {"id": k["cve"], "title": k["name"] or f"{k['vendor']} {k['product']}", "score": k["score"], "tier": k["tier"],
                "severity": k.get("cvss_severity"), "kev": True, "exploited": True, "epss": k.get("epss"), "cvss": k.get("cvss"),
                "public_exploit": bool(k.get("exploit")),
                "vendor": k["vendor"], "microsoft": k["microsoft"], "added": k["added"], "link": k["nvd_url"]}

    ms = sorted((ms_row(c) for c in cves), key=lambda r: (-r["score"], -(r["epss"] or 0)))
    nonms = sorted((kev_row(k) for k in kev_rows if not k["microsoft"]), key=lambda r: (-r["score"], -(r["epss"] or 0)))
    allc = sorted(ms + nonms, key=lambda r: (-r["score"], -(r["epss"] or 0)))
    kb = sorted(({"id": k["kb"], "title": ", ".join(k["products"][:2]) + (" and more" if len(k["products"]) > 2 else ""),
                  "score": k["score"], "tier": k["tier"], "severity": k["severity"], "cves": k["count"], "kev": k["kev"], "date": k["date"],
                  "link": f"/kb/{k['kb']}"} for k in kbs), key=lambda r: (-r["score"], r["date"] or ""))
    return {"cves": allc[:n], "cvesMs": ms[:n], "cvesNonMs": nonms[:n], "kbs": kb[:n]}


def build_mcp_index(cves: list[dict], kbs: list[dict], kev_rows: list[dict], months: list[dict]) -> dict:
    """Small, flat index the Worker can parse within the free plan's CPU budget."""
    return {
        "cves": {c["cve"]: [c["title"], c["priority"], c["score"], c["severity"], c.get("cvss"), c.get("epss"),
                            bool(c.get("kev")), bool(c.get("exploited")), c["release"],
                            [u["kb"] for u in c.get("updates", [])][:6], sorted(c.get("exploit") or {}),
                            [m["text"][:300] for m in c.get("mitigations") or []][:2]] for c in cves},
        "kbs": {k["kb"]: [k["date"], k["severity"], k["count"], k["kev"], k["score"], k["products"][:6], k["cves"][:40],
                          k["superseded_by"][:3], len(k["known_issues"])] for k in kbs},
        "kev_recent": [[k["cve"], k["vendor"], k["product"], k["added"], k["ransomware"], k.get("epss"), k["score"]]
                       for k in kev_rows[:150]],
        "months": [[m["id"], m["release_date"], m["total"], m["exploited"], m["kev"], m["by_severity"].get("Critical", 0)] for m in months],
    }


def build_feeds(base: str, cves: list[dict], kbs: list[dict], kev_rows: list[dict], months: list[dict],
                changes: list[dict], today: date) -> dict[str, str]:
    feeds = {}
    feeds["microsoft-patches"] = rss(
        "MPatchMonitor: Microsoft security updates by risk", f"{base}/kb", "Latest Microsoft security updates ranked by risk.",
        [{"title": f"{k['kb']} ({k['severity']}, score {k['score']}): {', '.join(k['products'][:2])}",
          "link": f"{base}/kb/{k['kb']}", "guid": f"kb:{k['kb']}", "date": f"{k['date']}T00:00:00Z" if k["date"] else "",
          "description": f"Fixes {k['count']} CVEs, {k['kev']} in CISA KEV."} for k in sorted(kbs, key=lambda x: (x["date"] or "", x["score"]), reverse=True)[:60]],
        f"{base}/feed/microsoft-patches.xml")
    recent = [k for k in kev_rows if k["added"] and (today - date.fromisoformat(k["added"])).days <= 30]
    feeds["exploited-this-week"] = rss(
        "MPatchMonitor: exploited vulnerabilities, last 30 days", f"{base}/exploited", "CISA KEV additions, every vendor.",
        [{"title": f"{k['cve']} {k['vendor']} {k['product']}{' (ransomware)' if k['ransomware'] else ''}",
          "link": k["nvd_url"], "guid": f"kev:{k['cve']}", "date": f"{k['added']}T00:00:00Z", "description": k["desc"]} for k in recent],
        f"{base}/feed/exploited-this-week.xml")
    feeds["non-ms-kev"] = rss(
        "MPatchMonitor: exploited vulnerabilities outside Microsoft", f"{base}/exploited?scope=other", "Latest CISA KEV additions for other vendors.",
        [{"title": f"{k['cve']} {k['vendor']} {k['product']}", "link": k["nvd_url"], "guid": f"kev:{k['cve']}",
          "date": f"{k['added']}T00:00:00Z", "description": k["desc"]} for k in kev_rows if not k["microsoft"]][:60],
        f"{base}/feed/non-ms-kev.xml")
    feeds["patch-tuesday"] = rss(
        "MPatchMonitor: Microsoft Patch Tuesday", f"{base}/release", "One item per monthly Microsoft release.",
        [{"title": f"{m.get('title', m['id'])}: {m['total']} CVEs, {m['exploited']} exploited", "link": f"{base}/release/{m['id']}",
          "guid": f"release:{m['id']}", "date": m.get("released_at", ""), "description":
          f"{m['by_severity'].get('Critical', 0)} Critical, {m['kev']} in CISA KEV."} for m in reversed(months)],
        f"{base}/feed/patch-tuesday.xml")
    feeds["changes"] = rss(
        "MPatchMonitor: what Microsoft changed", f"{base}/changes", "Revisions to Microsoft security advisories.",
        [{"title": f"{c.get('cve', '')} {c.get('title', '')}: {c['detail'][:120]}".strip(), "link": f"{base}/cve/{c['cve']}" if c.get("cve") else f"{base}/changes",
          "guid": c["key"], "date": c["ts"], "description": c["detail"]}
         for c in changes if c["kind"] in ("revised", "silent", "published", "exploited", "kev")][:60],
        f"{base}/feed/changes.xml")
    return feeds


def build_search_index(cves: list[dict], kbs: list[dict], kev_rows: list[dict], generated: str) -> dict:
    """Compact index for the search box: [type, id, title, extra]. Loaded by the browser on first use."""
    items = [["cve", c["cve"], c["title"][:140], c["severity"]] for c in cves]
    items += [["kb", k["kb"], ", ".join(k["products"][:3])[:140], k["date"] or ""] for k in kbs]
    seen = {c["cve"] for c in cves}
    items += [["kev", k["cve"], (k.get("name") or f"{k['vendor']} {k['product']}")[:140], k["vendor"][:40]]
              for k in kev_rows if k["cve"] not in seen]
    products = sorted({p for k in kbs for p in k["products"]})
    items += [["product", p, p, ""] for p in products]
    return {"generated_at": generated, "items": items}


def build_summary(months: list[dict], cves: list[dict], generated: str) -> dict:
    """Small dataset for the embeddable card: the Worker never parses the full dashboard."""
    def row(m):
        mc = [c for c in cves if c["release"] == m["id"]]
        return {"id": m["id"], "release_date": m["release_date"], "total": m["total"], "exploited": m["exploited"],
                "kev": m["kev"], "critical": m["by_severity"].get("Critical", 0),
                "p1": sum(1 for c in mc if c["priority"] == "P1"),
                "public_exploit": sum(1 for c in mc if c.get("exploit"))}
    rows = [row(m) for m in months]
    return {"generated_at": generated, "latest": rows[-1] if rows else None, "months": rows}
