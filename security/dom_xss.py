#!/usr/bin/env python3
"""DOM XSS check: loads the dashboard and a CVE page with hostile data and verifies that
nothing executes and no markup is injected. Needs Playwright (pip install playwright;
python -m playwright install chromium) and a local Worker whose KV holds the payload
dataset (see --write-payload)."""
import argparse, json, sys
from pathlib import Path

PAYLOAD = '<img src=x onerror="window.__xss=1">"\'><script>window.__xss=1</script>'

def payload_dataset(src: Path, dst: Path):
    d = json.loads(src.read_text(encoding="utf-8"))
    c = d["cves"][0]
    c.update(title=PAYLOAD, family=PAYLOAD, impact=PAYLOAD, vector="CVSS:3.1/AV:N/" + PAYLOAD,
             products=[PAYLOAD], updates=[{"kb": PAYLOAD, "url": "javascript:window.__xss=1"}])
    c["history"] = [{"n": "1.0", "date": "2026-10-13T07:00:00Z", "desc": PAYLOAD}]
    c["mitigations"] = [{"type": PAYLOAD, "text": PAYLOAD}, {"type": "workaround", "text": PAYLOAD}]
    c["exploit"] = {"metasploit": "javascript:window.__xss=1", PAYLOAD: "javascript:window.__xss=1"}
    c["exploited"] = True
    c["attack"] = [{"id": PAYLOAD, "name": PAYLOAD, "type": PAYLOAD}, {"id": "T1068", "name": PAYLOAD, "type": "primary"}]
    c["sigma"] = {"url": "javascript:window.__xss=1", "rules": PAYLOAD}
    d["changes"].insert(0, {"key": "xss-diff", "ts": "2026-10-14T08:01:00Z", "detected_at": d["generated_at"], "kind": "silent",
                            "detail": PAYLOAD, "cve": c["cve"], "title": PAYLOAD, "priority": "P1", "url": "javascript:x", "release": c["release"], "rev": PAYLOAD,
                            "diff": {"from_rev": PAYLOAD, "to_rev": PAYLOAD, "fields": [{"field": PAYLOAD, "before": PAYLOAD, "after": PAYLOAD}],
                                     "products_added": [PAYLOAD], "kbs_added": [PAYLOAD], "text": [["+", PAYLOAD], ["-", PAYLOAD]], "reinstall": True}})
    d["changes"].insert(0, {"key": "xss", "ts": "2026-10-14T08:00:00Z", "detected_at": d["generated_at"], "kind": "revised",
                            "detail": PAYLOAD, "cve": c["cve"], "title": PAYLOAD, "priority": "P1", "url": "javascript:x", "release": c["release"]})
    dst.write_text(json.dumps(d), encoding="utf-8")
    return c["cve"]

KEEP = {"date", "release", "added", "due", "published", "released", "support_end", "eol", "extended_end", "filed",
        "breach_date", "tier", "status", "severity", "ecosystem"}


def poison(obj, depth=0):
    """Replace every string (except dates and enums) with the payload, and every URL with javascript:."""
    if isinstance(obj, dict):
        return {k: (v if k in KEEP else ("javascript:window.__xss=1" if k in ("url", "link", "nvd_url", "catalog_url", "support_url") and isinstance(v, str)
                                         else poison(v, depth + 1))) for k, v in obj.items()}
    if isinstance(obj, list):
        return [poison(x, depth + 1) for x in obj]
    return PAYLOAD if isinstance(obj, str) else obj


def tracker_payloads(src_dir: Path, out_dir: Path):
    """Hostile copies of the tracker datasets (first rows poisoned) plus SQL for CSIRT Italia items and alerts."""
    out_dir.mkdir(parents=True, exist_ok=True)
    lists = {"kb": ["kbs"], "kev": ["kev"], "hot": ["cves", "cvesMs", "cvesNonMs", "kbs"], "eol": ["items"], "oss": ["items"],
             "breaches": ["hibp", "sec"], "docs": ["items"], "search": ["items"], "health": ["items"]}
    # status sources and Patch Tuesday summary: every string poisoned
    for name in ("sources", "summary"):
        d = json.loads((src_dir / f"x-{name}.json").read_text(encoding="utf-8"))
        if name == "sources":
            d["sources"] = {k: {**poison(v), "ok": v["ok"], "checked": v["checked"], "updated": v["updated"]} for k, v in d["sources"].items()}
            d["sources"][PAYLOAD] = {"ok": False, "checked": PAYLOAD, "updated": PAYLOAD, "count": PAYLOAD}
        else:
            d["latest"] = {**d["latest"], "total": PAYLOAD, "exploited": PAYLOAD}
        (out_dir / f"x-{name}.json").write_text(json.dumps(d), encoding="utf-8")
    for name, keys in lists.items():
        d = json.loads((src_dir / f"x-{name}.json").read_text(encoding="utf-8"))
        for k in keys:
            d[k][:3] = [poison(r) for r in d[k][:3]]
            if name == "kb":
                d[k][0]["kb"] = d[k][1]["kb"] = "KB5079999"
        (out_dir / f"x-{name}.json").write_text(json.dumps(d), encoding="utf-8")
    q = lambda v: "'" + v.replace("'", "''") + "'"
    sql = ["DELETE FROM acn_items;", "DELETE FROM watch_events;",
           f"INSERT INTO acn_items VALUES ('xss',{q(PAYLOAD)},'javascript:window.__xss=1','2026-10-14T08:00:00Z',{q(PAYLOAD)},'Microsoft',{q(json.dumps([PAYLOAD, 'CVE-2999-11090']))},1);",
           f"INSERT INTO watch_events (ts,topics,title,text,link,ref) VALUES (1792000000000,{q('acn,' + PAYLOAD)},{q(PAYLOAD)},{q(PAYLOAD)},'javascript:window.__xss=1','xss');"]
    (out_dir / "xss.sql").write_text("\n".join(sql), encoding="utf-8")


TRACKER_PAGES = ["/kb", "/kb/KB5079999", "/release", "/release/2026-Oct", "/hot", "/exploited", "/open-source", "/end-of-life",
                 "/breaches", "/docs-tracker", "/acn", "/alerts", "/feeds", "/method", "/trends", "/analysis", "/analysis/{release}",
                 "/glossary", "/status", "/known-issues?tab=all"]


def run(base: str, cve: str, lang: str = "en", release: str = "2026-Oct") -> int:
    from playwright.sync_api import sync_playwright
    fails = []
    with sync_playwright() as p:
        b = p.chromium.launch()
        import time
        for path in [f"{p}{'&' if '?' in p else '?'}lang={lang}" for p in ["/", f"/cve/{cve}", "/changes", *[x.format(release=release) for x in TRACKER_PAGES]]]:
            time.sleep(1.2)   # stay under the local rate limit
            pg = b.new_context(service_workers="block").new_page()   # the service worker is tested separately
            pg.add_init_script("localStorage.setItem('mpm-follow', JSON.stringify(['kb:KB5079999', '<img src=x onerror=window.__xss=1>']))")
            dialogs = []
            pg.on("dialog", lambda dlg: (dialogs.append(dlg.message), dlg.dismiss()))
            pg.goto(base + path, wait_until="load"); pg.wait_for_timeout(2500)
            executed = pg.evaluate("window.__xss === 1")
            injected = pg.evaluate("document.querySelectorAll('img[src=x], script:not([src]):not([type$=json])').length")
            js_links = pg.evaluate("[...document.querySelectorAll('a')].filter(a => a.href.startsWith('javascript:')).length")
            visible = PAYLOAD[:20] in pg.inner_text("body")
            ok = not executed and not dialogs and injected == 0 and js_links == 0
            print(f"[{'PASS' if ok else 'FAIL'}] {path}: executed={executed} injected={injected} js_links={js_links} payload_shown_as_text={visible}")
            if not ok: fails.append(path)
            pg.close()
        # hostile inventory file on "My devices", then the report built from it
        import tempfile, os
        inv = {"schema": "mpm-inventory/1", "device": PAYLOAD, "collected_at": PAYLOAD,
               "os": {"caption": PAYLOAD, "build": "26100", "ubr": "1", "installation_type": PAYLOAD, "arch": "AMD64"},
               "edge": {"version": PAYLOAD}, "hotfixes": [PAYLOAD, "KB1"]}
        fd, fpath = tempfile.mkstemp(suffix=".json"); os.write(fd, json.dumps(inv).encode()); os.close(fd)
        ctx = b.new_context(service_workers="block"); pg = ctx.new_page(); dialogs = []
        pg.on("dialog", lambda dlg: (dialogs.append(dlg.message), dlg.dismiss()))
        pg.goto(base + f"/my?lang={lang}", wait_until="load"); pg.wait_for_timeout(2000)
        pg.set_input_files("#files", fpath); pg.wait_for_timeout(800)
        for where in ("/my", "/report"):
            if where == "/report":
                pg.goto(base + "/report", wait_until="load"); pg.wait_for_timeout(2000); pg.wait_for_timeout(600)
                pg.fill("#org", PAYLOAD); pg.fill("#author", PAYLOAD); pg.wait_for_timeout(300)
            executed = pg.evaluate("window.__xss === 1")
            injected = pg.evaluate("document.querySelectorAll('img[src=x], script:not([src]):not([type$=json])').length")
            ok = not executed and not dialogs and injected == 0
            print(f"[{'PASS' if ok else 'FAIL'}] {where} with a hostile inventory file: executed={executed} injected={injected}")
            if not ok: fails.append(where)
        os.unlink(fpath)
        # hostile SBOM and program list in "My software"
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
            {"name": PAYLOAD, "version": PAYLOAD, "purl": "pkg:npm/" + PAYLOAD + "@1.0.0"},
            {"name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]}
        inv2 = {**inv, "device": "PC-01", "software": [{"name": PAYLOAD, "version": PAYLOAD, "publisher": PAYLOAD}, {"name": "Python 3.8.10", "version": "3.8.10", "publisher": PAYLOAD}]}
        paths = []
        for obj in (sbom, inv2):
            fd, fp = tempfile.mkstemp(suffix=".json"); os.write(fd, json.dumps(obj).encode()); os.close(fd); paths.append(fp)
        ctx = b.new_context(service_workers="block"); pg = ctx.new_page(); dialogs = []
        pg.on("dialog", lambda dlg: (dialogs.append(dlg.message), dlg.dismiss()))
        pg.goto(base + f"/my?lang={lang}", wait_until="load"); pg.wait_for_timeout(2000)
        pg.set_input_files("#files", paths); pg.wait_for_timeout(1500)
        executed = pg.evaluate("window.__xss === 1")
        injected = pg.evaluate("document.querySelectorAll('img[src=x], script:not([src]):not([type$=json])').length")
        ok = not executed and not dialogs and injected == 0
        print(f"[{'PASS' if ok else 'FAIL'}] /my with a hostile SBOM and program list: executed={executed} injected={injected}")
        if not ok: fails.append("/my software")
        for fp in paths: os.unlink(fp)
        b.close()
    return 1 if fails else 0

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", default="http://localhost:8787")
    ap.add_argument("--write-payload", nargs=2, metavar=("SOURCE_JSON", "OUT_JSON"))
    ap.add_argument("--write-tracker-payloads", nargs=2, metavar=("DEMO_DIR", "OUT_DIR"))
    ap.add_argument("--cve")
    ap.add_argument("--lang", default="en", choices=["en", "it"])
    ap.add_argument("--release", default="2026-Oct")
    a = ap.parse_args()
    if a.write_payload:
        print(payload_dataset(Path(a.write_payload[0]), Path(a.write_payload[1])))
        sys.exit(0)
    if a.write_tracker_payloads:
        tracker_payloads(Path(a.write_tracker_payloads[0]), Path(a.write_tracker_payloads[1]))
        sys.exit(0)
    sys.exit(run(a.base, a.cve, a.lang, a.release))
