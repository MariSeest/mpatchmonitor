#!/usr/bin/env python3
"""
MPatchMonitor - data pipeline.

Pulls Microsoft Security Update Guide data (MSRC CVRF API v3.0), enriches every
CVE with CISA KEV and FIRST EPSS, computes a remediation priority and builds a
change log of everything Microsoft modified (new CVEs, revisions, exploitation
status, severity, CVSS).

Output is a single JSON document stored in Cloudflare KV and served by the Worker.

Usage:
    python scripts/fetch_msrc.py --months 12 --previous prev.json --out out/dashboard.json
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import html
import json
import re
import logging
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

import catalog
import intel
import threat

MSRC_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CVE_URL = "https://msrc.microsoft.com/update-guide/vulnerability/{cve}"

SEVERITY_RANK = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1}
PRIO_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}

# Threat "Type" codes used in MSRC CVRF documents
THREAT_IMPACT = 0
THREAT_EXPLOIT_STATUS = 1
THREAT_SEVERITY = 3

# Suggested remediation windows (days) per priority. Adjust to your policy.
PRIORITY_SLA_DAYS = {"P1": 7, "P2": 14, "P3": 30, "P4": 90}

CHANGELOG_DAYS = 60       # keep this much history in the change feed
CHANGELOG_MAX = 1500
HISTORY_PER_CVE = 5

log = logging.getLogger("mpatchmonitor")
session = requests.Session()
session.headers.update({"Accept": "application/json", "User-Agent": "MPatchMonitor/1.0"})


def get_json(url: str, params: dict | None = None, retries: int = 3) -> Any:
    for attempt in range(1, retries + 1):
        try:
            r = session.get(url, params=params, timeout=90)
            r.raise_for_status()
            return r.json()
        except (requests.RequestException, ValueError) as exc:
            if attempt == retries:
                raise
            wait = 2 ** attempt
            log.warning("GET %s failed (%s), retry in %ss", url, exc, wait)
            time.sleep(wait)


def _val(obj: Any) -> str:
    if isinstance(obj, dict):
        return str(obj.get("Value") or "")
    return str(obj or "")


def _ver(n: str) -> tuple:
    try:
        return tuple(int(p) for p in str(n).split("."))
    except ValueError:
        return (0,)


# --------------------------------------------------------------------------- MSRC
def list_releases(months: int) -> list[dict]:
    data = get_json(f"{MSRC_BASE}/updates")
    releases = [u for u in data.get("value", []) if u.get("InitialReleaseDate")]
    releases.sort(key=lambda u: u["InitialReleaseDate"], reverse=True)
    return releases[:months]


def parse_exploit_status(text: str) -> dict:
    """'Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected'"""
    out: dict[str, str] = {}
    for part in text.split(";"):
        if ":" in part:
            k, v = part.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def parse_revisions(v: dict) -> list[dict]:
    revs = []
    for r in v.get("RevisionHistory") or []:
        if not r.get("Date"):
            continue
        revs.append({
            "n": str(r.get("Number") or "1.0"),
            "date": r["Date"][:19] + "Z",  # MSRC timestamps are UTC
            "desc": _val(r.get("Description")).strip()[:400],
        })
    revs.sort(key=lambda r: (_ver(r["n"]), r["date"]))
    return revs


REMEDIATION_WORKAROUND = 0
REMEDIATION_MITIGATION = 1
REMEDIATION_VENDOR_FIX = 2
MAX_KBS = 12
_NO_MITIGATION = re.compile(r"^(none\.?|n/?a\.?|not applicable\.?)$|has not identified any (mitigating factors|workarounds|mitigations)"
                            r"|no (known )?(mitigating factors|workarounds|mitigations)", re.I)


def parse_mitigations(v: dict) -> list[dict]:
    """Workarounds and mitigations Microsoft publishes for when the update cannot be installed yet."""
    out, seen = [], set()
    for r in v.get("Remediations") or []:
        kind = {REMEDIATION_WORKAROUND: "workaround", REMEDIATION_MITIGATION: "mitigation"}.get(r.get("Type"))
        if not kind:
            continue
        text = clean_text(_val(r.get("Description")), 700)
        if not text or _NO_MITIGATION.search(text) or text.lower() in seen:
            continue
        seen.add(text.lower())
        out.append({"type": kind, "text": text})
        if len(out) >= 4:
            break
    return out


def parse_updates(v: dict) -> list[dict]:
    """Security updates (KB articles) Microsoft lists as the fix, with a safe link."""
    kbs: dict[str, str] = {}
    for r in v.get("Remediations") or []:
        if r.get("Type") != REMEDIATION_VENDOR_FIX:
            continue
        num = _val(r.get("Description")).strip().upper().removeprefix("KB")
        if not num.isdigit() or num in kbs:
            continue
        url = str(r.get("URL") or "")
        host = (urlparse(url).hostname or "").lower()
        if urlparse(url).scheme != "https" or not (host == "microsoft.com" or host.endswith(".microsoft.com")):
            url = f"https://support.microsoft.com/help/{num}"
        kbs[num] = url
        if len(kbs) >= MAX_KBS:
            break
    return [{"kb": f"KB{k}", "url": u} for k, u in kbs.items()]


BUILD_RE = re.compile(r"^\d+(\.\d+){1,4}$")
REINSTALL_RE = re.compile(
    r"re-?install|re-?releas|already (installed|applied)|install (the|this) (updated|new|latest) (update|package|version)"
    r"|need to (take|install) (any )?(further )?action|customers should (re-?)?apply", re.I)


def clean_text(value: str, limit: int = 6000) -> str:
    """Advisory notes are HTML: keep readable sentences only."""
    t = re.sub(r"<(script|style)\b.*?</\1\s*>", " ", str(value or ""), flags=re.I | re.S)
    t = re.sub(r"<(br|/p|/li|/h\d)\s*/?>", "\n", t, flags=re.I)
    t = re.sub(r"<[^>]+>", " ", t)
    t = html.unescape(t).replace("\xa0", " ")
    t = re.sub(r"[ \t\r\f\v]+", " ", t)
    t = re.sub(r"\s*\n\s*", "\n", t).strip()
    return t[:limit]


def note_text(v: dict, title: str) -> str:
    return clean_text("\n".join(_val(n) for n in v.get("Notes") or [] if n.get("Title") == title))


def parse_fixes(v: dict, products: dict[str, str]) -> list[tuple[str, str, str]]:
    """(product name, fixed build, KB) for every vendor fix. Hotpatch packages are skipped:
    their builds follow a different numbering and would hide missing cumulative updates."""
    out = []
    for r in v.get("Remediations") or []:
        if r.get("Type") != REMEDIATION_VENDOR_FIX or "hotpatch" in str(r.get("SubType") or "").lower():
            continue
        kb = _val(r.get("Description")).strip().upper().removeprefix("KB")
        kb = f"KB{kb}" if kb.isdigit() else ""
        fb = r.get("FixedBuild")
        fb = (fb[0] if fb else "") if isinstance(fb, list) else fb
        fb = str(fb or "").strip()
        if not BUILD_RE.match(fb):
            fb = ""
        if not (kb or fb):
            continue
        for pid in r.get("ProductID") or []:
            if pid in products:
                out.append((products[pid], fb, kb))
    return out


REMEDIATION_KNOWN_ISSUE = 5


def parse_kb_details(v: dict, products: dict[str, str]) -> list[dict]:
    """Per-KB details Microsoft publishes with each fix: supersedence, sub type, known issues."""
    rems = v.get("Remediations") or []
    issues = {}
    for r in rems:
        if r.get("Type") != REMEDIATION_KNOWN_ISSUE:
            continue
        label = _val(r.get("Description")).strip()[:120]
        url = str(r.get("URL") or "")
        host = (urlparse(url).hostname or "").lower()
        if urlparse(url).scheme == "https" and (host == "microsoft.com" or host.endswith(".microsoft.com")):
            for pid in r.get("ProductID") or []:
                issues.setdefault(pid, []).append({"label": label or "Known issues", "url": url})
    out = []
    for r in rems:
        if r.get("Type") != REMEDIATION_VENDOR_FIX:
            continue
        kb = _val(r.get("Description")).strip().upper().removeprefix("KB")
        if not kb.isdigit():
            continue
        sup = r.get("Supercedence") or r.get("Supersedence")   # Microsoft spells it "Supercedence"
        sup = sup if isinstance(sup, list) else [sup] if sup else []
        sup = [f"KB{str(x).strip().upper().removeprefix('KB')}" for x in sup if str(x).strip().upper().removeprefix("KB").isdigit()]
        fb = r.get("FixedBuild")
        fb = (fb[0] if fb else "") if isinstance(fb, list) else fb
        fb = str(fb or "").strip()
        restart = _val(r.get("RestartRequired")).strip()
        for pid in r.get("ProductID") or []:
            if pid not in products:
                continue
            out.append({"kb": f"KB{kb}", "product": products[pid], "subtype": str(r.get("SubType") or "")[:40],
                        "fixed_build": fb if BUILD_RE.match(fb) else "", "supersedes": sup[:5],
                        "restart": restart[:20], "known_issues": issues.get(pid, [])[:3]})
    return out


def parse_vulnerability(v: dict, products: dict[str, str], release_id: str) -> dict | None:
    cve = v.get("CVE", "")
    if not cve.startswith("CVE-"):
        return None  # skip advisories (ADV...)

    notes = v.get("Notes") or []
    family = next((n.get("Value") for n in notes if n.get("Title") == "Tag"), None) or "Other"
    cna = next((n.get("Value") for n in notes if n.get("Title") == "CNA"), None) or "Microsoft"

    threats = v.get("Threats") or []
    severities = [_val(t.get("Description")) for t in threats if t.get("Type") == THREAT_SEVERITY]
    severities = [s for s in severities if s in SEVERITY_RANK]
    severity = max(severities, key=SEVERITY_RANK.get) if severities else "Unrated"

    impacts = Counter(_val(t.get("Description")) for t in threats if t.get("Type") == THREAT_IMPACT)
    impacts.pop("", None)
    impact = impacts.most_common(1)[0][0] if impacts else "Unknown"

    exploited = disclosed = False
    assessment = ""
    for t in threats:
        if t.get("Type") != THREAT_EXPLOIT_STATUS:
            continue
        st = parse_exploit_status(_val(t.get("Description")))
        exploited |= st.get("Exploited", "").lower() == "yes"
        disclosed |= st.get("Publicly Disclosed", "").lower() == "yes"
        assessment = assessment or st.get("Latest Software Release", "")

    cvss_sets = v.get("CVSSScoreSets") or []
    best = max(cvss_sets, key=lambda s: s.get("BaseScore") or 0, default={})
    product_ids = {pid for st in v.get("ProductStatuses") or [] for pid in (st.get("ProductID") or [])}
    if not product_ids:
        product_ids = {pid for s in cvss_sets for pid in (s.get("ProductID") or [])}
    if not product_ids:
        product_ids = {pid for t in threats for pid in (t.get("ProductID") or [])}

    revs = parse_revisions(v)
    published = min((r["date"] for r in revs), default="")
    latest = revs[-1] if revs else {"n": "1.0", "date": published, "desc": ""}

    return {
        "cve": cve,
        "title": _val(v.get("Title")),
        "release": release_id,
        "published": published[:10],
        "revision": latest["n"],
        "revised_at": latest["date"],
        "history": revs[-HISTORY_PER_CVE:],
        "family": family,
        "cna": cna,
        "severity": severity,
        "impact": impact,
        "cvss": best.get("BaseScore"),
        "vector": best.get("Vector"),
        "exploited": exploited,
        "disclosed": disclosed,
        "assessment": assessment,
        "products": sorted({products.get(p, p) for p in product_ids})[:25],
        "products_count": len(product_ids),
        "updates": parse_updates(v),
        "mitigations": parse_mitigations(v),
        "action_required": any(n.get("Title") == "Customer Action Required" and _val(n).strip().lower().startswith("yes")
                               for n in v.get("Notes") or []),
        "url": CVE_URL.format(cve=cve),
        # private fields: used to build fixes.json and snapshot.json, removed from dashboard.json
        "_fixes": parse_fixes(v, products),
        "_kbinfo": parse_kb_details(v, products),
        "_text": "\n".join(t for t in (note_text(v, "Description"), note_text(v, "FAQ")) if t),
        "_all_products": sorted({products.get(p, p) for p in product_ids}),
    }


def fetch_release(release: dict) -> tuple[dict, list[dict]]:
    rid = release["ID"]
    doc = get_json(f"{MSRC_BASE}/cvrf/{rid}")
    products = {
        p["ProductID"]: p.get("Value", "")
        for p in (doc.get("ProductTree") or {}).get("FullProductName", [])
        if "ProductID" in p
    }
    cves = [c for v in doc.get("Vulnerability") or [] if (c := parse_vulnerability(v, products, rid))]
    meta = {
        "id": rid,
        "title": _val(doc.get("DocumentTitle")) or release.get("DocumentTitle", rid),
        "release_date": release["InitialReleaseDate"][:10],
        "released_at": release["InitialReleaseDate"],
        "updated_at": release.get("CurrentReleaseDate"),
    }
    log.info("%s: %d CVEs", rid, len(cves))
    return meta, cves


def merge_duplicates(cves: list[dict], month_order: dict[str, int]) -> list[dict]:
    """A CVE can appear in several monthly documents: keep the earliest release,
    but the most recent revision, its text, every fix and the strongest exploitation signals."""
    out: dict[str, dict] = {}
    for c in sorted(cves, key=lambda c: month_order[c["release"]]):
        first = out.get(c["cve"])
        if not first:
            out[c["cve"]] = c
            continue
        if _ver(c["revision"]) > _ver(first["revision"]):
            for k in ("revision", "revised_at", "history", "_text", "action_required"):
                first[k] = c[k]
        first["exploited"] |= c["exploited"]
        first["disclosed"] |= c["disclosed"]
        first["_fixes"] = sorted(set(first["_fixes"]) | set(c["_fixes"]))
        first["_kbinfo"] = first.get("_kbinfo", []) + [k for k in c.get("_kbinfo", []) if k not in first.get("_kbinfo", [])]
        first["_all_products"] = sorted(set(first["_all_products"]) | set(c["_all_products"]))
    return list(out.values())


# --------------------------------------------------------------------- enrichment
def load_kev() -> dict[str, dict]:
    return kev_from_raw(get_json(KEV_URL))


def kev_from_raw(data: dict | None) -> dict[str, dict]:
    data = data or {}
    return {
        k["cveID"]: {
            "date_added": k.get("dateAdded"),
            "due_date": k.get("dueDate"),
            "ransomware": (k.get("knownRansomwareCampaignUse") or "").lower() == "known",
        }
        for k in data.get("vulnerabilities", [])
    }


def load_epss(cves: list[str], batch: int = 80) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for i in range(0, len(cves), batch):
        chunk = cves[i : i + batch]
        try:
            data = get_json(EPSS_URL, params={"cve": ",".join(chunk)})
        except Exception as exc:  # EPSS is best-effort
            log.warning("EPSS batch failed: %s", exc)
            continue
        for row in data.get("data", []):
            out[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
    return out


def priority(c: dict) -> str:
    """Risk-based remediation priority (NIS2 Art. 21(2)(e) - vulnerability handling).
    Public exploit code raises anything below P2 to P2."""
    epss = c.get("epss") or 0
    cvss = c.get("cvss") or 0
    if c["exploited"] or c.get("kev"):
        return "P1"
    if (c["severity"] == "Critical" and cvss >= 9) or epss >= 0.5:
        return "P1"
    if c["severity"] == "Critical" or c["disclosed"] or epss >= 0.1 \
            or c["assessment"] == "Exploitation More Likely" or c.get("exploit"):
        return "P2"
    if c["severity"] == "Important":
        return "P3"
    return "P4"


# ------------------------------------------------------------------- snapshots and diffs
def snapshot_of(c: dict) -> dict:
    """What the pipeline remembers about a CVE to explain the next revision."""
    return {
        "rev": c["revision"],
        "text": c.get("_text", ""),
        "products": c.get("_all_products", []),
        "kbs": sorted({kb for _, _, kb in c.get("_fixes", []) if kb}),
        "builds": sorted({f"{p} {fb}" for p, fb, _ in c.get("_fixes", []) if fb}),
        "cvss": c.get("cvss"),
        "severity": c.get("severity"),
        "exploited": c.get("exploited"),
        "disclosed": c.get("disclosed"),
        "action_required": c.get("action_required"),
    }


def _sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+|\n+", text or "")
    return [p.strip() for p in parts if p.strip()]


def text_diff(before: str, after: str, limit: int = 6000) -> list[list[str]]:
    """Sentence-level diff: [["=", s] | ["-", s] | ["+", s] | ["…", ""]], unchanged runs collapsed."""
    a, b = _sentences(before), _sentences(after)
    ops: list[list[str]] = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
        if tag == "equal":
            same = a[i1:i2]
            if len(same) > 2:
                ops += [["=", same[0]], ["…", ""], ["=", same[-1]]]
            else:
                ops += [["=", x] for x in same]
        else:
            ops += [["-", x] for x in a[i1:i2]] + [["+", x] for x in b[j1:j2]]
    # trim leading/trailing context so the change stands out
    while ops and ops[0][0] in "=…" and len(ops) > 1 and ops[1][0] in "=…":
        ops.pop(0)
    while ops and ops[-1][0] in "=…" and len(ops) > 1 and ops[-2][0] in "=…":
        ops.pop()
    out, size = [], 0
    for op in ops:
        size += len(op[1])
        if size > limit:
            out.append(["…", ""])
            break
        out.append(op)
    return out if any(op[0] in "+-" for op in out) else []


def compute_diff(before: dict, after: dict) -> dict | None:
    d: dict[str, Any] = {"from_rev": before.get("rev"), "to_rev": after.get("rev")}
    fields = []
    labels = {"cvss": "CVSS score", "severity": "Severity", "exploited": "Exploited",
              "disclosed": "Publicly disclosed", "action_required": "Customer action required"}
    for k, label in labels.items():
        if before.get(k) != after.get(k) and before.get(k) is not None:
            fields.append({"field": label, "before": before.get(k), "after": after.get(k)})
    if fields:
        d["fields"] = fields
    for key, name in (("products", "products"), ("kbs", "kbs"), ("builds", "builds")):
        old, new = set(before.get(key) or []), set(after.get(key) or [])
        if new - old:
            d[f"{name}_added"] = sorted(new - old)[:40]
        if old - new:
            d[f"{name}_removed"] = sorted(old - new)[:40]
    t = text_diff(before.get("text", ""), after.get("text", ""))
    if t:
        d["text"] = t
    if len(d) == 2:
        return None
    added_text = " ".join(x for op, x in t if op == "+")
    d["reinstall"] = bool(REINSTALL_RE.search(added_text)) or bool(d.get("builds_added") and d.get("builds_removed"))
    return d


# ------------------------------------------------------------------- change log
def _item(key, ts, kind, c=None, detail="", now="", **extra) -> dict:
    it = {"key": key, "ts": ts, "detected_at": now, "kind": kind, "detail": detail}
    if c:
        it.update(cve=c["cve"], title=c["title"], severity=c["severity"],
                  priority=c["priority"], url=c["url"], release=c["release"])
    it.update(extra)
    return it


def compute_changes(prev: dict, cves: list[dict], months: list[dict], now: datetime,
                    prev_snap: dict | None = None, cur_snap: dict | None = None) -> list[dict]:
    """Merge the previous change log with what changed since the last run.

    Two kinds of signal:
    * Microsoft's own RevisionHistory (authoritative, timestamped by MSRC)
    * differences detected by this pipeline between two runs (exploited, KEV,
      severity, CVSS, priority), timestamped at detection time.
    """
    now_iso = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    cutoff = (now - timedelta(days=CHANGELOG_DAYS)).isoformat()[:19]
    old_log = prev.get("changes") or []
    seen = {c["key"] for c in old_log}
    prev_map = {c["cve"]: c for c in prev.get("cves") or []}
    new: list[dict] = []

    def add(it: dict):
        if it["key"] not in seen:
            seen.add(it["key"])
            new.append(it)

    release_day = {m["id"]: m["release_date"] for m in months}
    for m in months:
        if m.get("released_at", "")[:19] >= cutoff:
            n = sum(1 for c in cves if c["release"] == m["id"])
            add(_item(f"release:{m['id']}", m["released_at"][:19] + "Z", "release",
                      detail=f"{m['title']} - {n} CVEs", now=now_iso, release=m["id"]))

    for c in cves:
        # Microsoft revisions
        for r in c["history"]:
            if r["date"][:19] < cutoff:
                continue
            if _ver(r["n"]) <= (1, 0):
                # Initial publication: Patch Tuesday CVEs are covered by the release
                # item, so only out-of-band / mid-month publications get their own entry.
                if r["date"][:10] == release_day.get(c["release"]):
                    continue
                add(_item(f"{c['cve']}:pub", r["date"], "published", c, r["desc"], now_iso, rev=r["n"]))
            else:
                add(_item(f"{c['cve']}:rev:{r['n']}", r["date"], "revised", c, r["desc"], now_iso, rev=r["n"]))

        # What exactly changed in Microsoft's advisory since the previous run
        before = (prev_snap or {}).get(c["cve"])
        after = (cur_snap or {}).get(c["cve"])
        if before and after:
            diff = compute_diff(before, after)
            if diff:
                key = f"{c['cve']}:rev:{after['rev']}"
                target = next((x for x in new if x["key"] == key), None)
                if target is None and before["rev"] == after["rev"]:
                    # Microsoft changed the advisory without publishing a new version
                    h = hashlib.sha256(json.dumps(after, sort_keys=True).encode()).hexdigest()[:10]
                    target = _item(f"{c['cve']}:silent:{h}", now_iso, "silent", c,
                                   "Microsoft changed the advisory without a new version number", now_iso, rev=after["rev"])
                    add(target)
                    target = next((x for x in new if x["key"] == target["key"]), None)
                if target is not None:
                    target["diff"] = diff
                    if diff["reinstall"] or (diff.get("fields") and any(f["field"] == "Customer action required" and f["after"] for f in diff["fields"])):
                        target["action"] = "reinstall" if diff["reinstall"] else "action"

        # Pipeline-detected differences
        p = prev_map.get(c["cve"])
        if not p:
            continue
        if c["exploited"] and not p.get("exploited"):
            add(_item(f"{c['cve']}:exploited", now_iso, "exploited", c,
                      "Microsoft now reports exploitation detected", now_iso))
        if c.get("kev") and not p.get("kev"):
            add(_item(f"{c['cve']}:kev", now_iso, "kev", c,
                      f"Added to CISA KEV, due {c['kev'].get('due_date')}", now_iso))
        if c["severity"] != p.get("severity") and p.get("severity"):
            add(_item(f"{c['cve']}:sev:{c['severity']}", now_iso, "severity", c,
                      f"Severity {p['severity']} → {c['severity']}", now_iso))
        if c.get("cvss") != p.get("cvss") and p.get("cvss") is not None and c.get("cvss") is not None:
            add(_item(f"{c['cve']}:cvss:{c['cvss']}", now_iso, "cvss", c,
                      f"CVSS {p['cvss']} → {c['cvss']}", now_iso))
        if PRIO_RANK[c["priority"]] < PRIO_RANK.get(p.get("priority", "P4"), 4):
            add(_item(f"{c['cve']}:prio:{c['priority']}", now_iso, "priority", c,
                      f"Priority {p.get('priority')} → {c['priority']}", now_iso))

    merged = new + [c for c in old_log if c["ts"][:19] >= cutoff]
    merged.sort(key=lambda c: c["ts"], reverse=True)
    return merged[:CHANGELOG_MAX]


# --------------------------------------------------------------------------- main
def build(months: int, prev: dict, now: datetime | None = None, prev_snap: dict | None = None,
          kev_raw: dict | None = None, epss_extra: list[str] | None = None,
          exploits: dict[str, int] | None = None) -> tuple[dict, dict, dict]:
    now = now or datetime.now(timezone.utc)
    releases = list_releases(months)
    if not releases:
        raise RuntimeError("No MSRC releases returned")

    month_meta, all_cves = [], []
    for rel in releases:
        meta, cves = fetch_release(rel)
        month_meta.append(meta)
        all_cves.extend(cves)

    order = {m["id"]: i for i, m in enumerate(reversed(month_meta))}
    cves = merge_duplicates(all_cves, order)

    if kev_raw is None:
        try:
            kev_raw = get_json(KEV_URL)
        except Exception as exc:
            log.warning("KEV unavailable: %s", exc)
            kev_raw = {}
    kev = kev_from_raw(kev_raw)
    epss = load_epss(sorted({c["cve"] for c in cves} | set(epss_extra or [])))
    build.last_epss = epss   # reused for non-Microsoft KEV entries

    for c in cves:
        c["kev"] = kev.get(c["cve"])
        c["exploit"] = intel.exploit_info(c["cve"], (exploits or {}).get(c["cve"]))
        e = epss.get(c["cve"])
        c["epss"] = round(e["epss"], 5) if e else None
        c["epss_percentile"] = round(e["percentile"], 4) if e else None
        c["priority"] = priority(c)
        c["sla_days"] = PRIORITY_SLA_DAYS[c["priority"]]

    for m in month_meta:
        mc = [c for c in cves if c["release"] == m["id"]]
        m["total"] = len(mc)
        m["by_severity"] = dict(Counter(c["severity"] for c in mc))
        m["exploited"] = sum(c["exploited"] for c in mc)
        m["kev"] = sum(bool(c["kev"]) for c in mc)
    month_meta.sort(key=lambda m: m["release_date"])

    catalog.score_cves(cves, {m["id"]: m["release_date"] for m in month_meta}, now.date())
    cur_snap = {c["cve"]: snapshot_of(c) for c in cves}
    changes = compute_changes(prev, cves, month_meta, now, prev_snap, cur_snap)
    generated = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    fixes = build_fixes(cves, generated)
    kbs = catalog.build_kb_catalog(cves, month_meta)
    build.last_kbs = kbs
    for c in cves:
        for k in [k for k in c if k.startswith("_")]:
            del c[k]
    dashboard = {
        "generated_at": generated,
        "sources": {"msrc": MSRC_BASE, "kev": KEV_URL, "epss": EPSS_URL},
        "sla_days": PRIORITY_SLA_DAYS,
        "months": month_meta,
        "cves": cves,
        "changes": changes,
    }
    return dashboard, fixes, {"generated_at": generated, "cves": cur_snap}


def build_fixes(cves: list[dict], generated: str) -> dict:
    """Compact index for the 'My devices' page: product -> [cve index, fixed build, KB]."""
    ids = [c["cve"] for c in cves]
    pos = {cid: i for i, cid in enumerate(ids)}
    products: dict[str, int] = {}
    fixes: dict[str, list] = {}
    for c in cves:
        for name, fb, kb in sorted(set(c.get("_fixes", []))):
            pi = products.setdefault(name, len(products))
            fixes.setdefault(str(pi), []).append([pos[c["cve"]], fb, kb])
    return {"version": generated, "cves": ids, "products": list(products), "fixes": fixes}


def load_previous(path: str | None) -> dict:
    if not path or not Path(path).is_file():
        return {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8") or "{}")
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        log.warning("Previous snapshot unreadable, starting fresh")
        return {}


IT_MONTHS = {"Jan": "gennaio", "Feb": "febbraio", "Mar": "marzo", "Apr": "aprile", "May": "maggio", "Jun": "giugno",
             "Jul": "luglio", "Aug": "agosto", "Sep": "settembre", "Oct": "ottobre", "Nov": "novembre", "Dec": "dicembre"}
IT_SEVERITY = {"Critical": "Critica", "Important": "Importante", "Moderate": "Moderata", "Low": "Bassa"}


def month_it(release_id: str) -> str:
    y, _, m = str(release_id).partition("-")
    return f"{IT_MONTHS.get(m, m)} {y}".strip()


def detail_it(detail: str) -> str:
    """Italian version of the change notes written by this pipeline. Microsoft's own revision
    notes are returned unchanged: they are quoted as published."""
    d = detail or ""
    if d == "Microsoft now reports exploitation detected":
        return "Microsoft ora segnala uno sfruttamento rilevato"
    if d == "Microsoft changed the advisory without a new version number":
        return "Microsoft ha modificato il bollettino senza un nuovo numero di versione"
    if m := re.match(r"^Added to CISA KEV, due (\S+)$", d):
        return f"Aggiunta al CISA KEV, scadenza {m[1]}"
    if m := re.match(r"^Severity (\w+) → (\w+)$", d):
        return f"Gravità {IT_SEVERITY.get(m[1], m[1])} → {IT_SEVERITY.get(m[2], m[2])}"
    if m := re.match(r"^CVSS (\S+) → (\S+)$", d):
        return f"CVSS {m[1]} → {m[2]}"
    if m := re.match(r"^Priority (P\d) → (P\d)$", d):
        return f"Priorità {m[1]} → {m[2]}"
    if m := re.match(r"^.* Security Updates - (\d+) CVEs$", d):
        return f"{m[1]} CVE"
    return d


def build_alerts(data: dict, kev_data: list[dict], known_kev: set[str], base: str,
                 health: list[dict] | None = None, known_health: set[str] | None = None) -> dict:
    """Events for the Watch bot: what is new in this run, with the topics that should hear about it."""
    gen = data["generated_at"]
    by_cve = {c["cve"]: c for c in data["cves"]}
    events = []

    def refs(cve: str | None) -> list[str]:
        if not cve:
            return []
        c = by_cve.get(cve) or {}
        return [f"cve:{cve}"] + [f"kb:{u['kb']}" for u in c.get("updates", [])][:6]

    for ch in data["changes"]:
        if ch.get("detected_at") != gen:
            continue
        kind, cve = ch["kind"], ch.get("cve")
        link = f"{base}/cve/{cve}" if cve else f"{base}/release/{ch.get('release', '')}"
        name = ch.get("title", "")
        if kind == "release":
            topics, title = ["patchtuesday"], f"Microsoft Patch Tuesday: {ch['detail']}"
            title_it = f"Patch Tuesday di Microsoft di {month_it(ch.get('release', ''))}: {detail_it(ch['detail'])}"
        elif kind == "published":
            topics, title = ["oob", *refs(cve)], f"New Microsoft CVE outside Patch Tuesday: {cve} {name}"
            title_it = f"Nuova CVE Microsoft fuori dal Patch Tuesday: {cve} {name}"
        elif kind in ("exploited", "kev"):
            topics = ["exploited", *refs(cve)]
            title = f"{'Now exploited' if kind == 'exploited' else 'Added to CISA KEV'}: {cve} {name}"
            title_it = f"{'Ora sfruttata' if kind == 'exploited' else 'Aggiunta al CISA KEV'}: {cve} {name}"
        elif kind in ("revised", "silent"):
            topics = (["reinstall"] if ch.get("action") == "reinstall" else []) + refs(cve)
            title = f"{'Reinstall required' if ch.get('action') == 'reinstall' else 'Microsoft revised'} {cve}: {name}"
            title_it = f"{'Reinstallazione richiesta' if ch.get('action') == 'reinstall' else 'Microsoft ha rivisto'} {cve}: {name}"
        else:
            topics, title = refs(cve), f"{cve}: {ch['detail']}"
            title_it = f"{cve}: {detail_it(ch['detail'])}"
        if topics:
            events.append({"ts": ch["ts"], "topics": topics, "title": title.strip()[:280], "text": ch.get("detail", "")[:500],
                           "title_it": title_it.strip()[:280], "text_it": detail_it(ch.get("detail", ""))[:500],
                           "link": link, "ref": ch["key"]})
    if known_kev:   # first run: nothing is "new"
        for k in kev_data:
            if k["cve"] not in known_kev:
                events.append({"ts": f"{k['added']}T00:00:00Z", "topics": ["kev", f"cve:{k['cve']}"],
                               "title": f"CISA KEV: {k['cve']} {k['vendor']} {k['product']}{' (ransomware)' if k['ransomware'] else ''}"[:280],
                               "title_it": f"Nuova nel CISA KEV: {k['cve']} {k['vendor']} {k['product']}{' (ransomware)' if k['ransomware'] else ''}"[:280],
                               "text": k["desc"][:500], "link": f"{base}/exploited", "ref": f"kev:{k['cve']}"})
    if known_health:   # first run of the release health source: nothing is "new"
        for h in health or []:
            if h["id"] in known_health or h["status"].startswith("Resolved"):
                continue
            kb_topics = [f"kb:{k}" for k in h.get("kbs", [])][:6]
            versions = ", ".join(h.get("products", [])[:3])
            events.append({"ts": f"{h.get('updated') or gen[:10]}T00:00:00Z", "topics": ["issues", *kb_topics],
                           "title": f"Windows known issue: {h['title']}"[:280],
                           "title_it": f"Problema noto di Windows: {h['title']}"[:280],
                           "text": f"{h.get('kb') or ''} {versions}. {h.get('summary', '')}".strip()[:500],
                           "text_it": f"{h.get('kb') or ''} {versions}. {h.get('summary', '')}".strip()[:500],
                           "link": f"{base}/known-issues", "ref": f"health:{h['id']}"[:200]})
    return {"version": gen, "events": events[:200]}


def _sha(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()[:16]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--months", type=int, default=12)
    ap.add_argument("--previous", help="previous dashboard.json (for change detection)")
    ap.add_argument("--previous-snapshot", help="previous snapshot.json (to explain revisions)")
    ap.add_argument("--previous-version", help="previous version.json (to upload only what changed)")
    ap.add_argument("--slow", action="store_true", help="also refresh slow sources (EOL, docs, breaches, open source, NVD)")
    ap.add_argument("--out", default="out/dashboard.json")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    now = datetime.now(timezone.utc)
    today = now.date()
    base = (intel.env("PUBLIC_ORIGIN") or "https://mpatchmonitor.example").rstrip("/")
    prev = load_previous(args.previous)
    prev_snapshot = load_previous(args.previous_snapshot)
    prev_version = load_previous(args.previous_version)

    # caches carried from run to run
    caches = prev_snapshot.get("caches") or {}
    status = dict(caches.get("sources") or {})
    stamp = now.isoformat(timespec="seconds").replace("+00:00", "Z")

    def mark(name: str, ok: bool, count: int | None = None, at: str | None = None):
        prev_s = status.get(name) or {}
        status[name] = {"ok": ok, "checked": stamp, "updated": (at or stamp) if ok else prev_s.get("updated"),
                        "count": count if ok else prev_s.get("count")}

    # public exploit code: refreshed with the slow sources, or once a day
    exploits, exploits_at = caches.get("exploits") or {}, caches.get("exploits_at") or ""
    if args.slow or not exploits or exploits_at[:10] != today.isoformat():
        fresh_x = intel.public_exploits(exploits)
        mark("exploits", fresh_x is not None, len(fresh_x or {}))
        if fresh_x is not None:
            exploits, exploits_at = fresh_x, stamp

    kev_raw = get_json(KEV_URL)
    kev_rows = intel.normalise_kev(kev_raw)
    mark("kev", bool(kev_rows), len(kev_rows))
    data, fixes, snapshot = build(args.months, prev, now, prev_snapshot.get("cves") or {}, kev_raw=kev_raw,
                                  epss_extra=[k["cve"] for k in kev_rows], exploits=exploits)
    mark("msrc", True, len(data["cves"]))
    kbs = build.last_kbs
    epss = build.last_epss
    mark("epss", bool(epss), len(epss))
    nvd, nvd_at = caches.get("nvd") or {}, caches.get("nvd_at") or ""
    if args.slow or not nvd or nvd_at[:10] != today.isoformat():
        fresh = intel.nvd_kev_cvss(intel.env("NVD_API_KEY"))
        mark("nvd", bool(fresh), len(fresh or {}))
        if fresh:
            nvd, nvd_at = fresh, now.isoformat(timespec="seconds")
    oss_cache = caches.get("oss") or {}

    # detection context: ATT&CK techniques (CTID) and Sigma rules, refreshed once a day
    gh_token = intel.env("GITHUB_TOKEN")
    attack, attack_at = caches.get("attack") or {}, caches.get("attack_at") or ""
    if args.slow or not attack or attack_at[:10] != today.isoformat():
        fresh_a = threat.attack_mappings(gh_token)
        mark("attack", fresh_a is not None, len(fresh_a or {}))
        if fresh_a:
            attack, attack_at = fresh_a, stamp
    sigma, sigma_at = caches.get("sigma") or {}, caches.get("sigma_at") or ""
    if args.slow or not sigma or sigma_at[:10] != today.isoformat():
        fresh_s = threat.sigma_rules(gh_token)
        mark("sigma", fresh_s is not None, len(fresh_s or {}))
        if fresh_s is not None:
            sigma, sigma_at = fresh_s, stamp
    for c in data["cves"]:
        if attack.get(c["cve"]):
            c["attack"] = attack[c["cve"]][:8]
        if sigma.get(c["cve"]):
            c["sigma"] = sigma[c["cve"]]

    # Windows release health: known issues of the updates, with the slow sources or every 3 hours
    health, health_at = caches.get("health"), caches.get("health_at") or ""
    known_health = set(caches.get("health_ids") or [])
    if args.slow or health is None or health_at[:19] < (now - timedelta(hours=3)).isoformat(timespec="seconds")[:19]:
        fresh_h = threat.release_health()
        mark("health", fresh_h is not None, len(fresh_h or []))
        if fresh_h is not None:
            health, health_at = fresh_h, stamp
    health = health or []
    catalog.attach_health(kbs, health)

    kev_data = catalog.build_kev_dataset(kev_rows, epss, nvd, today, exploits, attack=attack, sigma=sigma)
    outputs: dict[str, str] = {}
    dump = lambda o: json.dumps(o, ensure_ascii=False, separators=(",", ":"))
    outputs["dashboard"] = dump(data)
    outputs["fixes"] = dump(fixes)
    outputs["kb"] = dump({"generated_at": data["generated_at"], "kbs": kbs})
    outputs["kev"] = dump({"generated_at": data["generated_at"], "kev": kev_data})
    outputs["hot"] = dump({"generated_at": data["generated_at"], **catalog.build_hot(data["cves"], kev_data, kbs)})
    outputs["mcp"] = dump(catalog.build_mcp_index(data["cves"], kbs, kev_data, data["months"]))
    outputs["search"] = dump(catalog.build_search_index(data["cves"], kbs, kev_data, data["generated_at"]))
    summary = catalog.build_summary(data["months"], data["cves"], data["generated_at"])
    outputs["summary"] = dump(summary)
    outputs["health"] = dump({"generated_at": data["generated_at"], "checked": health_at, "items": health})
    for key, png in threat.og_images(summary, base.split("//")[-1]).items():
        outputs[key] = png
    for name, xml in catalog.build_feeds(base, data["cves"], kbs, kev_data, data["months"], data["changes"], today).items():
        outputs[f"feed:{name}"] = xml

    headlines = intel.news()
    mark("news", headlines is not None, len(headlines or []))
    if headlines is not None:
        outputs["news"] = dump({"generated_at": data["generated_at"], "items": headlines})
    if args.slow:
        eol = intel.end_of_life(today)
        mark("eol", eol is not None, len(eol or []))
        if eol is not None:
            outputs["eol"] = dump({"generated_at": data["generated_at"], "items": eol})
        docs = intel.docs_tracker(intel.env("GITHUB_TOKEN"))
        mark("docs", docs is not None, len(docs or []))
        if docs is not None:
            outputs["docs"] = dump({"generated_at": data["generated_at"], "items": docs})
        br = intel.breaches(intel.env("SEC_USER_AGENT"))
        mark("breaches", br is not None, len((br or {}).get('hibp', [])))
        if br is not None:
            outputs["breaches"] = dump({"generated_at": data["generated_at"], **br})
        oss_cache = intel.open_source([k["cve"] for k in kev_data if not k["microsoft"]], intel.env("GITHUB_TOKEN"), oss_cache)
        mark("oss", True, len(oss_cache))
        kev_by_id = {k["cve"]: k for k in kev_data}
        oss_rows = [{**r, "vendor": kev_by_id[c]["vendor"], "added": kev_by_id[c]["added"], "ransomware": kev_by_id[c]["ransomware"],
                     "epss": kev_by_id[c].get("epss"), "score": kev_by_id[c]["score"]}
                    for c, rows in oss_cache.items() if c in kev_by_id for r in rows]
        oss_rows.sort(key=lambda r: (-r["score"], -(r["epss"] or 0)))
        outputs["oss"] = dump({"generated_at": data["generated_at"], "items": oss_rows,
                               "checked": len(oss_cache), "kev_total": sum(1 for k in kev_data if not k["microsoft"])})

    alerts = build_alerts(data, kev_data, set(caches.get("kev_ids") or []), base, health, known_health)
    if alerts["events"]:
        outputs["alerts"] = dump(alerts)
    outputs["sources"] = dump({"generated_at": data["generated_at"], "slow": bool(args.slow), "sources": status})
    snapshot["caches"] = {"nvd": nvd, "nvd_at": nvd_at, "oss": oss_cache, "kev_ids": sorted(k["cve"] for k in kev_data),
                          "exploits": exploits, "exploits_at": exploits_at, "sources": status,
                          "attack": attack, "attack_at": attack_at, "sigma": sigma, "sigma_at": sigma_at,
                          "health": health, "health_at": health_at,
                          "health_ids": sorted(set(known_health) | {h["id"] for h in health})}
    outputs["snapshot"] = dump(snapshot)

    out_dir = Path(args.out).parent
    out_dir.mkdir(parents=True, exist_ok=True)
    old_hashes = prev_version.get("hashes") or {}
    hashes = dict(old_hashes)
    updated = dict(prev_version.get("updated") or {})
    bulk = []
    for key, value in outputs.items():
        h = _sha(value)
        (out_dir / (key.replace(":", "-") + (".xml" if key.startswith("feed:") else ".json"))).write_text(value, encoding="utf-8")
        if old_hashes.get(key) != h or key in ("dashboard", "snapshot"):
            bulk.append({"key": key, "value": value})
            updated[key] = data["generated_at"]
        hashes[key] = h
    (out_dir / "bulk.json").write_text(json.dumps(bulk, ensure_ascii=False), encoding="utf-8")

    new_items = sum(1 for c in data["changes"] if c["detected_at"] == data["generated_at"])
    (out_dir / "version.json").write_text(json.dumps({
        "version": data["generated_at"], "cves": len(data["cves"]), "new_changes": new_items,
        "hashes": hashes, "updated": updated,
    }), encoding="utf-8")
    log.info("Wrote %d datasets, %d changed (%s); %d CVEs, %d changes, %d new", len(outputs), len(bulk),
             ", ".join(b["key"] for b in bulk), len(data["cves"]), len(data["changes"]), new_items)
    return 0


if __name__ == "__main__":
    sys.exit(main())
