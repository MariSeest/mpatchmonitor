import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import catalog  # noqa: E402
import intel  # noqa: E402

TODAY = date(2026, 10, 14)


def test_risk_score_bounds_and_tiers():
    top, tier = intel.risk_score(kev=True, exploited=True, ransomware=True, epss=0.9, cvss=9.8, last_activity="2026-10-13", today=TODAY)
    assert top == 100 and tier == "Patch now"
    low, tier = intel.risk_score(kev=False, exploited=False, ransomware=False, epss=0.001, cvss=5.0, last_activity="2025-01-01", today=TODAY)
    assert low < 40 and tier == "Track"
    mid, _ = intel.risk_score(kev=False, exploited=False, ransomware=False, epss=0.3, cvss=9.8, last_activity="2026-10-13", today=TODAY)
    assert 20 < mid < 40
    fresh, tier = intel.risk_score(kev=True, exploited=True, ransomware=False, epss=0.02, cvss=7.5, last_activity="2026-10-01", today=TODAY)
    assert fresh < 80 and tier == "Patch now"
    old_kev, _ = intel.risk_score(kev=True, exploited=False, ransomware=False, epss=0.02, cvss=7.5, last_activity="2024-01-01", today=TODAY)
    assert 50 <= old_kev < 80


def test_kev_normalisation_and_order():
    rows = intel.normalise_kev({"vulnerabilities": [
        {"cveID": "CVE-2026-1111", "vendorProject": "Fortinet", "product": "FortiOS", "dateAdded": "2026-10-01",
         "dueDate": "2026-10-22", "knownRansomwareCampaignUse": "Known", "requiredAction": "Apply updates."},
        {"cveID": "CVE-2026-2222", "vendorProject": "Microsoft", "product": "Windows", "dateAdded": "2026-10-13"},
        {"cveID": "not-a-cve"},
    ]})
    assert [r["cve"] for r in rows] == ["CVE-2026-2222", "CVE-2026-1111"]
    assert rows[1]["ransomware"] is True


def test_nvd_prefers_newest_cvss():
    page = {"vulnerabilities": [{"cve": {"id": "CVE-2026-1111", "metrics": {
        "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
        "cvssMetricV31": [{"type": "Secondary", "cvssData": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}},
                          {"type": "Primary", "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}}]}
    assert intel.parse_nvd_page(page)["CVE-2026-1111"] == {"cvss": 9.8, "severity": "Critical", "cvss_version": "3.1"}


def test_end_of_life_status():
    rows = intel.normalise_eol("windows", "Windows", True, [
        {"cycle": "10-22h2", "eol": "2025-10-14", "releaseDate": "2022-10-18"},
        {"cycle": "11-24h2-e", "eol": "2027-10-12", "releaseDate": "2024-10-01", "lts": False},
        {"cycle": "11-25h2", "eol": "2027-03-01"},
        {"cycle": "old", "eol": True},
    ], TODAY)
    assert [r["status"] for r in rows] == ["ended", "supported", "ending", "ended"]


def test_commits_filter_noise_and_unsafe_links():
    rows = intel.normalise_commits("MicrosoftDocs/entra-docs", "Entra ID", [
        {"commit": {"message": "Merge pull request #1 from x", "author": {"date": "2026-10-10T00:00:00Z"}}},
        {"commit": {"message": "Update conditional access policy guidance\n\nlong body", "author": {"date": "2026-10-11T00:00:00Z"}},
         "author": {"login": "writer"}, "html_url": "https://github.com/MicrosoftDocs/entra-docs/commit/abc"},
        {"commit": {"message": "Fix typo", "author": {"date": "2026-10-12T00:00:00Z"}}, "html_url": "javascript:alert(1)"},
    ])
    assert [r["message"] for r in rows] == ["Update conditional access policy guidance", "Fix typo"]
    assert rows[1]["url"] == ""


RSS = b"""<?xml version="1.0"?><rss version="2.0"><channel><title>CSIRT</title>
<item><title>Aggiornamenti Mensili Microsoft</title><link>https://www.acn.gov.it/portale/w/aggiornamenti-mensili-microsoft-25</link>
<pubDate>Tue, 13 Oct 2026 20:15:00 GMT</pubDate><description>&lt;p&gt;Microsoft ha rilasciato gli aggiornamenti: CVE-2026-1234&lt;/p&gt;</description></item>
<item><title>Risolte vulnerabilit\xc3\xa0 in prodotti Fortinet</title><link>javascript:alert(1)</link></item>
</channel></rss>"""

ATOM = b"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>x</title>
<entry><title>Patch now</title><link href="https://example.org/a"/><updated>2026-10-12T08:00:00Z</updated><summary>Microsoft Exchange CVE-2026-9999</summary></entry>
</feed>"""

BOMB = b"""<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">]>
<rss><channel><item><title>&lol2;</title><link>https://example.org</link></item></channel></rss>"""

XXE = b"""<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><rss><channel><item><title>&xxe;</title><link>https://example.org</link></item></channel></rss>"""


def test_parse_rss_and_atom():
    rss_items = intel.parse_feed(RSS, "CSIRT Italia (ACN)")
    assert len(rss_items) == 1
    it = rss_items[0]
    assert it["microsoft"] and it["cves"] == ["CVE-2026-1234"] and it["date"] == "2026-10-13T20:15:00Z"
    atom = intel.parse_feed(ATOM, "Example")
    assert atom[0]["url"] == "https://example.org/a" and atom[0]["microsoft"] and atom[0]["cves"] == ["CVE-2026-9999"]


@pytest.mark.parametrize("xml", [BOMB, XXE])
def test_hostile_xml_is_refused(xml):
    assert intel.parse_feed(xml, "evil") == []


def test_hibp_and_sec_normalisation():
    hibp = intel.normalise_hibp([
        {"Name": "Acme", "Title": "Acme", "Domain": "acme.example", "BreachDate": "2026-09-01", "AddedDate": "2026-10-10T00:00:00Z",
         "PwnCount": 1000, "DataClasses": ["Email addresses", "Passwords"], "IsVerified": True},
        {"Name": "Hidden", "IsVerified": True, "IsSensitive": True},
        {"Name": "Fake", "IsVerified": False},
    ])
    assert [h["name"] for h in hibp] == ["Acme"]
    sec = intel.normalise_sec({"hits": {"hits": [
        {"_id": "0001193125-26-123456:d1.htm", "_source": {"ciks": ["0000320193"], "display_names": ["Example Corp (CIK 0000320193)"],
                                                           "file_date": "2026-10-02", "form": "8-K", "adsh": "0001193125-26-123456"}},
        {"_id": "bad", "_source": {"ciks": [], "adsh": "x"}},
    ]}})
    assert sec[0]["url"] == "https://www.sec.gov/Archives/edgar/data/320193/000119312526123456/0001193125-26-123456-index.html"


def test_advisory_normalisation():
    rows = intel.normalise_advisory("CVE-2021-44228", [{"ghsa_id": "GHSA-jfh8-c2jp-5v3q", "html_url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
        "vulnerabilities": [{"package": {"ecosystem": "maven", "name": "org.apache.logging.log4j:log4j-core"},
                             "vulnerable_version_range": ">= 2.0-beta9, < 2.15.0", "first_patched_version": "2.15.0"}]}])
    assert rows[0]["fixed"] == "2.15.0" and rows[0]["ecosystem"] == "maven"


def test_rss_output_is_escaped():
    xml = intel.rss("T", "https://x", "D", [{"title": "<script>&", "link": "https://x/1", "guid": "1", "date": "2026-10-13T00:00:00Z"}], "https://x/feed")
    assert "&lt;script&gt;&amp;" in xml and "<script>" not in xml and "Tue, 13 Oct 2026" in xml


def test_kb_catalog_and_hot_lists():
    cves = [
        {"cve": "CVE-1", "title": "A", "release": "2026-Oct", "severity": "Critical", "cvss": 9.8, "epss": 0.4, "kev": {"date_added": "2026-10-13", "ransomware": True},
         "exploited": True, "priority": "P1", "published": "2026-10-13", "updates": [], "revised_at": "2026-10-13T07:00:00Z",
         "_kbinfo": [{"kb": "KB2", "product": "Windows 11", "subtype": "Security Update", "fixed_build": "10.0.26100.7000",
                      "supersedes": ["KB1"], "restart": "Yes", "known_issues": [{"label": "5070002", "url": "https://support.microsoft.com/help/5070002"}]}]},
        {"cve": "CVE-2", "title": "B", "release": "2026-Sep", "severity": "Important", "cvss": 7.0, "epss": 0.01, "kev": None,
         "exploited": False, "priority": "P3", "published": "2026-09-08", "updates": [], "revised_at": "2026-09-08T07:00:00Z",
         "_kbinfo": [{"kb": "KB1", "product": "Windows 11", "subtype": "Security Update", "fixed_build": "10.0.26100.6900",
                      "supersedes": [], "restart": "", "known_issues": []}]},
    ]
    months = [{"id": "2026-Sep", "release_date": "2026-09-08", "total": 1, "exploited": 0, "kev": 0, "by_severity": {}},
              {"id": "2026-Oct", "release_date": "2026-10-13", "total": 1, "exploited": 1, "kev": 1, "by_severity": {"Critical": 1}}]
    catalog.score_cves(cves, {"2026-Sep": "2026-09-08", "2026-Oct": "2026-10-13"}, TODAY)
    assert cves[0]["score"] > 90 and cves[1]["tier"] == "Track"
    kbs = catalog.build_kb_catalog(cves, months)
    k2 = next(k for k in kbs if k["kb"] == "KB2")
    k1 = next(k for k in kbs if k["kb"] == "KB1")
    assert k2["supersedes"] == ["KB1"] and k1["superseded_by"] == ["KB2"]
    assert k2["known_issues"][0]["url"].startswith("https://support.microsoft.com/")
    assert k2["fixed_builds"] == {"Windows 11": "10.0.26100.7000"} and k2["ransomware"] is True
    kev = catalog.build_kev_dataset(
        [{"cve": "CVE-2026-3333", "vendor": "Ivanti", "product": "EPMM", "name": "Ivanti EPMM", "added": "2026-10-10", "due": "2026-10-31",
          "ransomware": False, "action": "", "desc": "", "cwes": []}], {"CVE-2026-3333": {"epss": 0.7, "percentile": 0.99}}, {}, TODAY)
    hot = catalog.build_hot(cves, kev, kbs)
    assert hot["cves"][0]["id"] == "CVE-1" and hot["cvesNonMs"][0]["id"] == "CVE-2026-3333" and hot["kbs"][0]["id"] == "KB2"
    feeds = catalog.build_feeds("https://site", cves, kbs, kev, months, [], TODAY)
    assert "KB2" in feeds["microsoft-patches"] and "CVE-2026-3333" in feeds["exploited-this-week"]


# --------------------------------------------------------------------------- public exploit code
def test_public_exploit_adds_ten_points_and_is_capped():
    base, _ = intel.risk_score(kev=False, exploited=False, ransomware=False, epss=0.01, cvss=7.5, last_activity="2025-01-01", today=TODAY)
    more, _ = intel.risk_score(kev=False, exploited=False, ransomware=False, epss=0.01, cvss=7.5, last_activity="2025-01-01", today=TODAY,
                               public_exploit=True)
    assert more - base == 10
    top, _ = intel.risk_score(kev=True, exploited=True, ransomware=True, epss=0.9, cvss=9.8, last_activity="2026-10-13", today=TODAY,
                              public_exploit=True)
    assert top == 100


def test_public_exploits_reads_only_cve_ids_and_keeps_previous_on_failure(monkeypatch):
    bodies = {
        "metasploit": b'{"exploit/windows/x": {"references": ["CVE-2026-1111", "URL-https://x"]}}',
        "nuclei": None,   # source down
        "poc": b"## CVE-2026-2222\n- [someone/poc](https://github.com/someone/poc)\n",
    }
    def fake_get(url, **kw):
        name = next(n for _, (n, u) in intel.EXPLOIT_SOURCES.items() if u == url)
        return bodies[name]
    monkeypatch.setattr(intel, "_get", fake_get)
    out = intel.public_exploits({"CVE-2026-3333": 2, "CVE-2026-1111": 2})
    assert out["CVE-2026-1111"] == 1 | 2      # metasploit now + nuclei kept from the previous run
    assert out["CVE-2026-2222"] == 4
    assert out["CVE-2026-3333"] == 2
    info = intel.exploit_info("CVE-2026-2222", 4)
    assert info == {"poc": "https://github.com/nomi-sec/PoC-in-GitHub/blob/master/2026/CVE-2026-2222.json"}
    assert intel.exploit_info("CVE-2026-1", 0) is None


def test_public_exploits_none_when_every_source_fails(monkeypatch):
    monkeypatch.setattr(intel, "_get", lambda url, **kw: None)
    assert intel.public_exploits({}) is None
