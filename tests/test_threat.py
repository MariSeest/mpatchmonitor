import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import catalog  # noqa: E402
import fetch_msrc as fm  # noqa: E402
import threat  # noqa: E402

PAGE = """<html><body>
<h2>Known issues</h2>
<table><thead><tr><th>Summary</th><th>Originating update</th><th>Status</th><th>Last updated</th></tr></thead><tbody>
<tr><td><a href="#3700msgdesc"><b>Apps which require AC-3 audio might close</b></a><br>Some apps might close unexpectedly.</td>
<td>OS Build 26100.9550<br><a href="https://support.microsoft.com/kb/5124010">KB5124010</a><br>2026-09-22</td>
<td>Confirmed</td><td>2026-10-02<br>15:41 PT</td></tr>
<tr><td><a href="#3650msgdesc"><b>Remote Desktop sessions <script>x</script> disconnect</b></a><br>Sessions might disconnect.</td>
<td>OS Build 26100.9445 KB5124008 2026-09-08</td>
<td>Resolved KB5124010</td><td>2026-09-22 10:00 PT</td></tr>
</tbody></table>
<h3>October 2026</h3>
<div id="3700msgdesc"></div><h4>Apps which require AC-3 audio might close</h4>
<p>Following installation of KB5124010 some apps might close.</p>
<p><b>Workaround:</b> Use another audio codec until the fix.</p>
<p><b>Next steps:</b> We are working on a resolution.</p>
<p><b>Affected platforms:</b></p><ul><li>Client: Windows 11, version 24H2</li></ul>
<h4>Another issue</h4><p>Not ours.</p>
</body></html>"""


def test_release_health_parses_summary_and_detail():
    items = threat.parse_release_health(PAGE, "status-windows-11-24h2", "Windows 11, version 24H2")
    assert len(items) == 2
    a, b = items
    assert a["title"] == "Apps which require AC-3 audio might close"
    assert a["kb"] == "KB5124010" and a["build"] == "26100.9550" and a["originated"] == "2026-09-22"
    assert a["status"] == "Confirmed" and a["updated"] == "2026-10-02"
    assert a["url"].endswith("status-windows-11-24h2#3700msgdesc")
    assert a["workaround"].startswith("Use another audio codec")
    assert "Not ours" not in a.get("workaround", "") + a.get("resolution", "")
    assert b["status"] == "Resolved" and b["resolved_kb"] == "KB5124010" and b["kb"] == "KB5124008"


def test_release_health_merges_versions_and_survives_failures():
    pages = [("status-windows-11-24h2", "Windows 11, version 24H2"), ("status-windows-11-25h2", "Windows 11, version 25H2"),
             ("status-windows-10-22h2", "Windows 10, version 22H2")]
    fetch = lambda url: None if url.endswith("22h2") else PAGE  # noqa: E731
    items = threat.release_health(pages, fetch)
    assert len(items) == 2
    assert items[0]["products"] == ["Windows 11, version 24H2", "Windows 11, version 25H2"]
    assert items[0]["status"] == "Confirmed"   # open issues first
    assert threat.release_health(pages, lambda url: None) is None


def test_attack_mapping_parse_and_latest_file():
    tree = {"tree": [{"path": "mappings/kev/attack-15.1/kev-02.13.2025/enterprise/a.json"},
                     {"path": "mappings/kev/attack-16.1/kev-07.28.2025/enterprise/b.json"},
                     {"path": "mappings/kev/attack-16.1/kev-07.28.2025/mobile/c.json"}]}
    assert threat.latest_ctid_file(tree).endswith("/b.json")
    doc = {"mapping_objects": [
        {"capability_id": "CVE-2024-38193", "mapping_type": "primary_impact", "attack_object_id": "T1068", "attack_object_name": "Exploitation for Privilege Escalation"},
        {"capability_id": "CVE-2024-38193", "mapping_type": "exploitation_technique", "attack_object_id": "T1204.002", "attack_object_name": "Malicious File"},
        {"capability_id": "CVE-2024-38193", "mapping_type": "exploitation_technique", "attack_object_id": "T1204.002", "attack_object_name": "Malicious File"},
        {"capability_id": "<script>", "mapping_type": "primary_impact", "attack_object_id": "T1068"},
        {"capability_id": "CVE-2024-1", "mapping_type": "primary_impact", "attack_object_id": "javascript:x"}]}
    m = threat.parse_attack(doc)
    assert list(m) == ["CVE-2024-38193"]
    assert [r["id"] for r in m["CVE-2024-38193"]] == ["T1204.002", "T1068"]


def test_sigma_tree():
    tree = {"tree": [
        {"path": "rules-emerging-threats/2024/Exploits/CVE-2024-1234/proc_creation_win_x.yml", "type": "blob"},
        {"path": "rules-emerging-threats/2024/Exploits/CVE-2024-1234/file_event_win_y.yml", "type": "blob"},
        {"path": "regression_data/rules-emerging-threats/2024/Exploits/CVE-2024-9999/x.json", "type": "blob"},
        {"path": "rules/windows/process_creation/proc_creation_win_z.yml", "type": "blob"}]}
    s = threat.parse_sigma_tree(tree)
    assert s == {"CVE-2024-1234": {"url": "https://github.com/SigmaHQ/sigma/tree/master/rules-emerging-threats/2024/Exploits/CVE-2024-1234", "rules": 2}}


def test_og_images_are_png():
    out = threat.og_images({"months": [{"id": "2026-Sep", "total": 111, "exploited": 3, "critical": 7, "public_exploit": 7},
                                       {"id": "bad<", "total": 1}, {"id": "2026-Oct", "total": 88, "exploited": 4, "critical": 6, "public_exploit": 5}]}, "x.example")
    assert set(out) == {"og:2026-Sep:it", "og:2026-Sep:en", "og:2026-Oct:it", "og:2026-Oct:en"}
    png = base64.b64decode(out["og:2026-Oct:it"])
    assert png[:8] == b"\x89PNG\r\n\x1a\n" and len(png) < 200_000


def test_health_on_kb_and_alerts():
    health = [{"id": "11-24h2:a", "title": "Audio apps close", "status": "Confirmed", "url": "https://learn.microsoft.com/x#a", "kbs": ["KB5124010"],
               "resolved_kb": "", "updated": "2026-10-02", "products": ["Windows 11, version 24H2"], "summary": "Apps close.", "kb": "KB5124010"},
              {"id": "11-24h2:b", "title": "RDP disconnects", "status": "Resolved", "url": "https://learn.microsoft.com/x#b", "kbs": ["KB5124008"],
               "resolved_kb": "KB5124010", "updated": "2026-09-22", "products": ["Windows 11, version 24H2"], "summary": "", "kb": "KB5124008"}]
    kbs = [{"kb": "KB5124010"}, {"kb": "KB5124008"}, {"kb": "KB1"}]
    catalog.attach_health(kbs, health)
    assert [(h["id"], h["role"]) for h in kbs[0]["health"]] == [("11-24h2:a", "caused"), ("11-24h2:b", "fixed")]
    assert kbs[2]["health"] == []
    data = {"generated_at": "2026-10-14T08:00:00Z", "cves": [], "changes": []}
    assert fm.build_alerts(data, [], set(), "https://x", health, set())["events"] == []      # first run: nothing new
    ev = fm.build_alerts(data, [], set(), "https://x", health, {"old"})["events"]
    assert len(ev) == 1 and ev[0]["topics"] == ["issues", "kb:KB5124010"] and ev[0]["title_it"].startswith("Problema noto")
