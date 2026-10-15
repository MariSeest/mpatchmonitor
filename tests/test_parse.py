import copy
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import fetch_msrc as fm  # noqa: E402
from fetch_msrc import (  # noqa: E402
    compute_changes, merge_duplicates, parse_exploit_status, parse_vulnerability, priority,
)

PRODUCTS = {"11926": "Windows 11 Version 24H2 for x64-based Systems", "12345": "Windows Server 2025"}
NOW = datetime(2026, 10, 20, 9, 0, tzinfo=timezone.utc)
MONTHS = [{"id": "2026-Oct", "title": "October 2026 Security Updates", "release_date": "2026-10-13",
           "released_at": "2026-10-13T07:00:00Z"}]


def vuln(**over):
    v = {
        "CVE": "CVE-2026-12345",
        "Title": {"Value": "Windows Kernel Elevation of Privilege Vulnerability"},
        "Notes": [{"Title": "Tag", "Type": 7, "Value": "Windows Kernel"},
                  {"Title": "CNA", "Type": 8, "Value": "Microsoft"}],
        "Threats": [
            {"Type": 0, "Description": {"Value": "Elevation of Privilege"}, "ProductID": ["11926"]},
            {"Type": 3, "Description": {"Value": "Important"}, "ProductID": ["11926"]},
            {"Type": 1, "Description": {"Value": "Publicly Disclosed:No;Exploited:Yes;"
                                                 "Latest Software Release:Exploitation Detected"}},
        ],
        "CVSSScoreSets": [{"BaseScore": 7.8, "Vector": "CVSS:3.1/AV:L", "ProductID": ["11926", "12345"]}],
        "RevisionHistory": [
            {"Date": "2026-10-13T07:00:00", "Number": "1.0", "Description": {"Value": "Information published."}},
            {"Date": "2026-10-16T08:00:00", "Number": "1.1", "Description": {"Value": "Updated FAQ."}},
        ],
    }
    v.update(over)
    return v


def enriched(**over):
    c = parse_vulnerability(vuln(**over), PRODUCTS, "2026-Oct")
    c.update(kev=None, epss=0.01)
    c["priority"] = priority(c)
    return c


def test_exploit_status():
    s = parse_exploit_status("Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected")
    assert s["Exploited"] == "Yes" and s["Latest Software Release"] == "Exploitation Detected"


def test_parse_fields():
    c = parse_vulnerability(vuln(), PRODUCTS, "2026-Oct")
    assert c["severity"] == "Important"
    assert c["impact"] == "Elevation of Privilege"
    assert c["family"] == "Windows Kernel"
    assert c["exploited"] is True and c["disclosed"] is False
    assert c["cvss"] == 7.8 and c["products_count"] == 2
    assert c["published"] == "2026-10-13"
    assert c["revision"] == "1.1" and c["revised_at"] == "2026-10-16T08:00:00Z"


def test_skip_advisories():
    assert parse_vulnerability(vuln(CVE="ADV990001"), PRODUCTS, "2026-Oct") is None


def test_priority():
    c = enriched()
    assert c["priority"] == "P1"  # exploited in the wild
    c.update(exploited=False, assessment="")
    assert priority(c) == "P3"
    c.update(epss=0.2)
    assert priority(c) == "P2"


def test_merge_duplicates_keeps_latest_revision():
    a = parse_vulnerability(vuln(), PRODUCTS, "2026-Sep")
    b = parse_vulnerability(vuln(RevisionHistory=[{"Date": "2026-10-18T07:00:00", "Number": "2.0"}]),
                            PRODUCTS, "2026-Oct")
    out = merge_duplicates([b, a], {"2026-Sep": 0, "2026-Oct": 1})
    assert len(out) == 1 and out[0]["release"] == "2026-Sep" and out[0]["revision"] == "2.0"


def test_changes_first_run_uses_microsoft_revisions():
    log = compute_changes({}, [enriched()], MONTHS, NOW)
    kinds = {c["kind"] for c in log}
    assert kinds == {"release", "revised"}          # 1.0 on Patch Tuesday is folded into the release
    assert log[0]["kind"] == "revised" and log[0]["rev"] == "1.1"


def test_changes_detects_new_signals_and_is_idempotent():
    old = enriched(Threats=[{"Type": 3, "Description": {"Value": "Important"}}])
    prev = {"cves": [old], "changes": compute_changes({}, [old], MONTHS, NOW)}
    cur = enriched()
    cur["kev"] = {"date_added": "2026-10-19", "due_date": "2026-11-09", "ransomware": False}
    log = compute_changes(prev, [cur], MONTHS, NOW)
    kinds = [c["kind"] for c in log]
    assert "exploited" in kinds and "kev" in kinds and "priority" in kinds
    again = compute_changes({"cves": [cur], "changes": log}, [copy.deepcopy(cur)], MONTHS, NOW)
    assert len(again) == len(log)


def test_out_of_band_publication_gets_own_entry():
    oob = enriched(CVE="CVE-2026-99999",
                   RevisionHistory=[{"Date": "2026-10-17T18:00:00", "Number": "1.0",
                                     "Description": {"Value": "Information published."}}])
    log = compute_changes({}, [oob], MONTHS, NOW)
    assert any(c["kind"] == "published" and c["cve"] == "CVE-2026-99999" for c in log)


def test_updates_only_safe_microsoft_links():
    c = parse_vulnerability(vuln(Remediations=[
        {"Type": 2, "Description": {"Value": "5044284"}, "URL": "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5044284"},
        {"Type": 2, "Description": {"Value": "5044285"}, "URL": "https://evil.example/kb"},
        {"Type": 2, "Description": {"Value": "5044286"}, "URL": "javascript:alert(1)"},
        {"Type": 1, "Description": {"Value": "Workaround text"}},
    ]), PRODUCTS, "2026-Oct")
    urls = {u["kb"]: u["url"] for u in c["updates"]}
    assert urls["KB5044284"].startswith("https://catalog.update.microsoft.com/")
    assert urls["KB5044285"] == "https://support.microsoft.com/help/5044285"
    assert urls["KB5044286"] == "https://support.microsoft.com/help/5044286"
    assert len(urls) == 3


# ---------------------------------------------------------------- fixes, snapshots and diffs
from fetch_msrc import build_fixes, clean_text, compute_diff, parse_fixes, snapshot_of, text_diff  # noqa: E402


def test_parse_fixes_uses_fixed_build_and_skips_hotpatch():
    v = vuln(Remediations=[
        {"Type": 2, "Description": {"Value": "5044284"}, "FixedBuild": "10.0.26100.2033", "ProductID": ["11926"], "SubType": "Security Update"},
        {"Type": 2, "Description": {"Value": "5044999"}, "FixedBuild": "10.0.26100.1900", "ProductID": ["11926"], "SubType": "Security Hotpatch Update"},
        {"Type": 2, "Description": {"Value": "5044300"}, "FixedBuild": "<script>", "ProductID": ["12345"]},
        {"Type": 5, "Description": {"Value": "Known issue"}, "ProductID": ["11926"]},
    ])
    fixes = parse_fixes(v, PRODUCTS)
    assert ("Windows 11 Version 24H2 for x64-based Systems", "10.0.26100.2033", "KB5044284") in fixes
    assert all(kb != "KB5044999" for _, _, kb in fixes)
    assert ("Windows Server 2025", "", "KB5044300") in fixes


def test_clean_text_strips_html():
    assert clean_text("<p>Hello&nbsp;<b>world</b></p><script>x</script>") == "Hello world"


def test_text_diff_marks_added_and_removed_sentences():
    ops = text_diff("Install the update. Restart the device. No other action.",
                    "Install the update. Restart the device. Customers must reinstall the update.")
    assert ["-", "No other action."] in ops and ["+", "Customers must reinstall the update."] in ops


def snap(**over):
    c = enriched()
    c["_fixes"] = [("Windows 11 Version 24H2 for x64-based Systems", "10.0.26100.2033", "KB5044284")]
    c["_text"] = "The update fixes the issue."
    c["_all_products"] = ["Windows 11 Version 24H2 for x64-based Systems"]
    s = snapshot_of(c)
    s.update(over)
    return s


def test_compute_diff_detects_rerelease():
    before = snap(rev="1.0")
    after = snap(rev="1.1", kbs=["KB5044390"], builds=["Windows 11 Version 24H2 for x64-based Systems 10.0.26100.2100"],
                 products=before["products"] + ["Windows Server 2025"],
                 text="The update fixes the issue. Customers who already installed the update should reinstall it.")
    d = compute_diff(before, after)
    assert d["reinstall"] is True
    assert d["products_added"] == ["Windows Server 2025"]
    assert d["kbs_added"] == ["KB5044390"] and d["kbs_removed"] == ["KB5044284"]


def test_no_diff_when_nothing_changed():
    assert compute_diff(snap(rev="1.0"), snap(rev="1.1")) is None


def test_silent_change_is_reported_with_its_diff():
    c = enriched()
    before, after = snap(rev="1.1"), snap(rev="1.1", cvss=8.8)
    earlier = compute_changes({}, [c], MONTHS, NOW)          # the 1.1 revision was already recorded
    log = compute_changes({"cves": [c], "changes": earlier}, [c], MONTHS, NOW,
                          {c["cve"]: before}, {c["cve"]: after})
    silent = [x for x in log if x["kind"] == "silent"]
    assert silent and silent[0]["diff"]["fields"][0] == {"field": "CVSS score", "before": 7.8, "after": 8.8}


def test_revision_item_gets_diff_and_action():
    c = enriched()
    before = snap(rev="1.0")
    after = snap(rev="1.1", text="The update fixes the issue. Customers should reinstall the updated package.")
    log = compute_changes({"cves": [c], "changes": []}, [c], MONTHS, NOW, {c["cve"]: before}, {c["cve"]: after})
    rev = next(x for x in log if x["kind"] == "revised")
    assert rev["action"] == "reinstall" and rev["diff"]["text"]


def test_build_fixes_index():
    c = enriched()
    c["_fixes"] = [("P1", "10.0.1.5", "KB1"), ("P2", "", "KB2")]
    idx = build_fixes([c], "v1")
    assert idx["products"] == ["P1", "P2"]
    assert idx["fixes"]["0"] == [[0, "10.0.1.5", "KB1"]]


# --------------------------------------------------------------------------- Italian alerts
def test_detail_it_translates_pipeline_notes_and_keeps_microsoft_text():
    assert fm.detail_it("Severity Important → Critical") == "Gravità Importante → Critica"
    assert fm.detail_it("Added to CISA KEV, due 2026-11-03") == "Aggiunta al CISA KEV, scadenza 2026-11-03"
    assert fm.detail_it("Priority P3 → P1") == "Priorità P3 → P1"
    assert fm.detail_it("October 2026 Security Updates - 88 CVEs") == "88 CVE"
    note = "Updated FAQ information. This is an informational change only."
    assert fm.detail_it(note) == note
    assert fm.month_it("2026-Oct") == "ottobre 2026"


def test_build_alerts_has_italian_title_and_text():
    gen = "2026-10-14T08:00:00Z"
    data = {"generated_at": gen, "cves": [{"cve": "CVE-2026-1", "updates": [{"kb": "KB5070001"}]}], "changes": [
        {"key": "k1", "ts": gen, "detected_at": gen, "kind": "exploited", "cve": "CVE-2026-1", "title": "Windows RCE",
         "detail": "Microsoft now reports exploitation detected"},
        {"key": "k2", "ts": gen, "detected_at": gen, "kind": "release", "release": "2026-Oct",
         "detail": "October 2026 Security Updates - 88 CVEs"},
    ]}
    ev = fm.build_alerts(data, [], set(), "https://example.test")["events"]
    assert ev[0]["title_it"] == "Ora sfruttata: CVE-2026-1 Windows RCE"
    assert ev[0]["text_it"] == "Microsoft ora segnala uno sfruttamento rilevato"
    assert "kb:KB5070001" in ev[0]["topics"]
    assert ev[1]["title_it"] == "Patch Tuesday di Microsoft di ottobre 2026: 88 CVE"


# --------------------------------------------------------------------------- mitigations and exploit priority
def test_parse_mitigations_skips_boilerplate_and_duplicates():
    v = {"Remediations": [
        {"Type": 1, "Description": {"Value": "Microsoft has not identified any mitigating factors for this vulnerability."}},
        {"Type": 0, "Description": {"Value": "<p>Block TCP port 445 at the perimeter firewall.</p>"}},
        {"Type": 0, "Description": {"Value": "Block TCP port 445 at the perimeter firewall."}},
        {"Type": 1, "Description": {"Value": "Systems with Hyper-V disabled are not affected."}},
        {"Type": 2, "Description": {"Value": "5070001"}},
        {"Type": 0, "Description": {"Value": "None"}},
    ]}
    out = fm.parse_mitigations(v)
    assert [m["type"] for m in out] == ["workaround", "mitigation"]
    assert out[0]["text"] == "Block TCP port 445 at the perimeter firewall."


def test_public_exploit_raises_priority_to_p2():
    c = {"exploited": False, "kev": None, "severity": "Important", "cvss": 7.0, "epss": 0.01, "disclosed": False,
         "assessment": "Exploitation Less Likely", "exploit": None}
    assert fm.priority(c) == "P3"
    c["exploit"] = {"poc": "https://github.com/x"}
    assert fm.priority(c) == "P2"


def test_search_index_and_summary():
    import catalog
    cves = [{"cve": "CVE-2026-1", "title": "Windows Kernel EoP", "severity": "Important", "release": "2026-Oct", "priority": "P1", "exploit": {"poc": "x"}}]
    kbs = [{"kb": "KB5070001", "products": ["Windows 11"], "date": "2026-10-13"}]
    kev = [{"cve": "CVE-2026-1", "vendor": "Microsoft", "product": "Windows", "name": "x"},
           {"cve": "CVE-2026-9", "vendor": "Ivanti", "product": "EPMM", "name": "Ivanti EPMM RCE"}]
    idx = catalog.build_search_index(cves, kbs, kev, "g")["items"]
    assert ["cve", "CVE-2026-1", "Windows Kernel EoP", "Important"] in idx
    assert ["kev", "CVE-2026-9", "Ivanti EPMM RCE", "Ivanti"] in idx
    assert not any(i[0] == "kev" and i[1] == "CVE-2026-1" for i in idx)
    assert ["product", "Windows 11", "Windows 11", ""] in idx
    months = [{"id": "2026-Oct", "release_date": "2026-10-13", "total": 1, "exploited": 0, "kev": 0, "by_severity": {"Important": 1}}]
    s = catalog.build_summary(months, cves, "g")
    assert s["latest"]["p1"] == 1 and s["latest"]["public_exploit"] == 1 and s["latest"]["critical"] == 0
