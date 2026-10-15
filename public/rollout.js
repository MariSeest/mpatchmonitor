"use strict";

/* MPatchMonitor — rollout in waves: pilot workstations, other workstations, servers.
 * Pure functions (also used by the unit tests); labels are added by the page. */

(function (root) {
  // Days from today at which each wave starts, by the most urgent priority still missing.
  const OFFSETS = { P1: [0, 2, 5], P2: [0, 4, 10], P3: [0, 7, 21], P4: [0, 14, 45] };
  const RANK = { P1: 1, P2: 2, P3: 3, P4: 4 };
  const addDays = (iso, n) => { const d = new Date(iso + "T00:00:00Z"); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().slice(0, 10); };

  /**
   * results: analysis results from MPMMatch.analyze; overrides: {deviceName: 1|2|3}.
   * Returns {urgency, waves: [{wave, start, due, late, devices:[{name, missing, p1, due}], updates:[{product, kb, fb}]}]}.
   */
  function plan(results, today, overrides = {}, pilotShare = 0.1) {
    const todo = results.filter((r) => r.status === "missing");
    const urgency = todo.flatMap((r) => r.missing.map((m) => m.priority)).sort((a, b) => RANK[a] - RANK[b])[0] || "P4";
    const work = todo.filter((r) => !r.device.server).sort((a, b) => a.missing.length - b.missing.length || a.device.name.localeCompare(b.device.name));
    const pilotCount = work.length <= 1 ? work.length : Math.max(1, Math.ceil(work.length * pilotShare));
    const waveOf = new Map();
    work.forEach((r, i) => waveOf.set(r.device.name, i < pilotCount ? 1 : 2));
    todo.filter((r) => r.device.server).forEach((r) => waveOf.set(r.device.name, 3));
    for (const [name, w] of Object.entries(overrides || {})) if (waveOf.has(name) && [1, 2, 3].includes(Number(w))) waveOf.set(name, Number(w));

    const off = OFFSETS[urgency];
    const waves = [1, 2, 3].map((wave) => {
      const members = todo.filter((r) => waveOf.get(r.device.name) === wave);
      const updates = new Map();
      members.forEach((r) => r.recommended.forEach((u) => updates.set(`${u.product}|${u.kb || u.fb}`, { product: u.product, kb: u.kb || "", fb: u.fb || u.fixed_build || "" })));
      const due = members.reduce((o, r) => (r.oldest && (!o || r.oldest < o) ? r.oldest : o), null);
      const start = addDays(today, off[wave - 1]);
      return {
        wave, start, due, late: Boolean(due && due < start),
        devices: members.map((r) => ({ name: r.device.name, missing: r.missing.length, p1: r.counts?.P1 || 0, due: r.oldest,
          updates: r.recommended.map((u) => ({ product: u.product, kb: u.kb || "", fb: u.fb || u.fixed_build || "" })) })),
        updates: [...updates.values()],
      };
    });
    return { urgency, waves };
  }

  const icsText = (s) => String(s).replace(/[\\;,]/g, (c) => "\\" + c).replace(/\r?\n/g, "\\n").slice(0, 900);

  /** One all-day event per non-empty wave. labels: {1: "...", 2: "...", 3: "..."} */
  function ics(p, labels, stamp, origin) {
    const lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//MPatchMonitor//Rollout//EN", "CALSCALE:GREGORIAN"];
    for (const w of p.waves) {
      if (!w.devices.length) continue;
      const day = w.start.replace(/-/g, "");
      const next = addDays(w.start, 1).replace(/-/g, "");
      lines.push("BEGIN:VEVENT", `UID:mpm-rollout-${day}-${w.wave}@mpatchmonitor`, `DTSTAMP:${stamp}`,
        `DTSTART;VALUE=DATE:${day}`, `DTEND;VALUE=DATE:${next}`,
        `SUMMARY:${icsText(`MPatchMonitor: ${labels[w.wave]} (${w.devices.length})`)}`,
        `DESCRIPTION:${icsText([w.devices.map((d) => d.name).join(", "), w.updates.map((u) => u.kb || `${u.product} ${u.fb}`).join(", "), origin].join("\n"))}`,
        "END:VEVENT");
    }
    lines.push("END:VCALENDAR");
    return lines.join("\r\n") + "\r\n";
  }

  /* ---------------------------------------------------------------- remediation scripts
   * Everything that comes from an inventory file is filtered to safe characters before it
   * reaches a script, and every string is a single-quoted PowerShell literal. */
  const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
  const SAFE_KB = /^KB\d{6,8}$/;
  const SAFE_BUILD = /^\d{1,5}(\.\d{1,6}){1,3}$/;
  const psq = (s) => `'${String(s).replace(/['\u2018\u2019\u201a\u201b]/g, "''")}'`;
  const cmt = (s) => String(s).replace(/[\r\n#<>]/g, " ").slice(0, 200);

  function waveScope(p, wave) {
    const w = p.waves.find((x) => x.wave === wave) || { devices: [], updates: [] };
    const devices = w.devices.filter((d) => SAFE_NAME.test(d.name)).map((d) => ({
      name: d.name,
      kbs: [...new Set((d.updates || []).map((u) => u.kb).filter((k) => SAFE_KB.test(k)))],
      builds: (d.updates || []).filter((u) => SAFE_KB.test(u.kb) && SAFE_BUILD.test(u.fb) && /^10\./.test(u.fb)).map((u) => [u.kb, u.fb]),
      edge: (d.updates || []).some((u) => /Edge/i.test(u.product)),
      office: (d.updates || []).some((u) => /Microsoft 365 Apps|Office/i.test(u.product)),
    }));
    const kbs = [...new Set(devices.flatMap((d) => d.kbs))].sort();
    return { w, devices, kbs, skipped: w.devices.length - devices.length };
  }

  function header(title, label, stamp, skipped) {
    return [`# MPatchMonitor - ${cmt(title)}: ${cmt(label)}`, `# Generated ${cmt(stamp)} from the analysis in your browser. Review it before running.`,
      ...(skipped ? [`# ${skipped} device name(s) with unusual characters were left out: add them by hand.`] : []), ""];
  }

  /** Runs on each device: reports what is missing; with -Install installs it through Windows Update. */
  function powershell(p, wave, label, stamp) {
    const { devices, skipped } = waveScope(p, wave);
    const rows = devices.map((d) => `  ${psq(d.name)} = @{ KB = @(${d.kbs.map(psq).join(", ")}); Build = @{ ${d.builds.map(([k, b]) => `${psq(k)} = ${psq(b)}`).join("; ")} }; Edge = $${d.edge}; Office = $${d.office} }`);
    return [...header("Windows Update remediation", label, stamp, skipped),
      "# Run on each device of the wave as administrator. Without -Install it only reports.",
      "param([switch]$Install)",
      "$ErrorActionPreference = 'Stop'",
      "$plan = @{", ...rows, "}",
      "$name = $env:COMPUTERNAME",
      "if (-not $plan.ContainsKey($name)) { Write-Host \"$name is not in this wave.\"; exit 0 }",
      "$item = $plan[$name]",
      "$cv = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'",
      "$current = [version](\"10.0.{0}.{1}\" -f $cv.CurrentBuildNumber, $cv.UBR)",
      "$hotfixes = @(Get-HotFix | Select-Object -ExpandProperty HotFixID)",
      "$missing = @($item.KB | Where-Object {",
      "  if ($item.Build.ContainsKey($_)) { $current -lt [version]$item.Build[$_] } else { $hotfixes -notcontains $_ }",
      "})",
      "if ($item.Edge) { Write-Host 'Microsoft Edge: update from edge://settings/help or let Edge update itself.' }",
      "if ($item.Office -and $Install) {",
      "  $c2r = Join-Path $env:CommonProgramFiles 'microsoft shared\\ClickToRun\\OfficeC2RClient.exe'",
      "  if (Test-Path $c2r) { & $c2r /update user displaylevel=false forceappshutdown=false }",
      "}",
      "if (-not $missing) { Write-Host \"$name is up to date (build $current).\"; exit 0 }",
      "Write-Host (\"Missing on {0}: {1}\" -f $name, ($missing -join ', '))",
      "if (-not $Install) { Write-Host 'Report only. Run again with -Install to install.'; exit 1 }",
      "$session = New-Object -ComObject Microsoft.Update.Session",
      "$result = $session.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0')",
      "$todo = New-Object -ComObject Microsoft.Update.UpdateColl",
      "foreach ($u in $result.Updates) {",
      "  foreach ($id in $u.KBArticleIDs) { if ($missing -contains \"KB$id\") { if (-not $u.EulaAccepted) { $u.AcceptEula() }; [void]$todo.Add($u) } }",
      "}",
      "if ($todo.Count -eq 0) { Write-Warning 'Windows Update does not offer these updates here: check WSUS or Intune policies.'; exit 2 }",
      "$downloader = $session.CreateUpdateDownloader(); $downloader.Updates = $todo; [void]$downloader.Download()",
      "$installer = $session.CreateUpdateInstaller(); $installer.Updates = $todo",
      "$r = $installer.Install()",
      "Write-Host (\"Result: {0}. Restart required: {1}\" -f $r.ResultCode, $r.RebootRequired)",
      ""].join("\r\n");
  }

  /** Intune: an expedited quality update profile through Microsoft Graph, assigned to a group. */
  function intune(p, wave, label, stamp, releaseDate) {
    const { devices, skipped } = waveScope(p, wave);
    const day = /^\d{4}-\d{2}-\d{2}$/.test(releaseDate || "") ? releaseDate : new Date().toISOString().slice(0, 10);
    const reboot = p.urgency === "P1" ? 0 : 1;
    return [...header("Intune expedited quality update", label, stamp, skipped),
      "# Needs: Install-Module Microsoft.Graph.Authentication, and the Intune Administrator role.",
      "# Expedite installs the latest Windows quality update released on or after the date below.",
      "param([Parameter(Mandatory)][string]$GroupId)   # object ID of the Entra ID group with the devices of this wave",
      "if ($GroupId -notmatch '^[0-9a-fA-F-]{36}$') { throw 'GroupId must be a group object ID.' }",
      "Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All' -NoWelcome",
      "$body = @{",
      `  displayName = ${psq(`MPatchMonitor - ${cmt(label)} - ${day}`)}`,
      "  description = 'Created from the MPatchMonitor rollout plan'",
      `  expeditedUpdateSettings = @{ qualityUpdateRelease = ${psq(`${day}T00:00:00Z`)}; daysUntilForcedReboot = ${reboot} }`,
      "} | ConvertTo-Json -Depth 4",
      "$uri = 'https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdateProfiles'",
      "$qp = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType 'application/json'",
      "$assign = @{ assignments = @(@{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $GroupId } }) } | ConvertTo-Json -Depth 6",
      "Invoke-MgGraphRequest -Method POST -Uri \"$uri/$($qp.id)/assign\" -Body $assign -ContentType 'application/json'",
      "Write-Host \"Expedite profile $($qp.id) assigned to group $GroupId.\"",
      "",
      "# Devices of this wave (add them to the group):",
      ...devices.map((d) => `#   ${d.name}${d.kbs.length ? ` (${d.kbs.join(", ")})` : ""}`),
      ""].join("\r\n");
  }

  /** WSUS: approve the wave's updates for a computer group named after the wave. */
  function wsus(p, wave, label, stamp) {
    const { devices, kbs, skipped } = waveScope(p, wave);
    return [...header("WSUS approval", label, stamp, skipped),
      "# Run on the WSUS server as administrator (UpdateServices module). Without -Apply it only reports.",
      "param([switch]$Apply)",
      "$ErrorActionPreference = 'Stop'",
      `$group = ${psq(`MPatchMonitor ${cmt(label)}`)}`,
      `$kbs = @(${kbs.map((k) => psq(k.slice(2))).join(", ")})`,
      `$devices = @(${devices.map((d) => psq(d.name)).join(", ")})`,
      "$wsus = Get-WsusServer",
      "$target = $wsus.GetComputerTargetGroups() | Where-Object Name -eq $group",
      "if (-not $target -and $Apply) { $target = $wsus.CreateComputerTargetGroup($group) }",
      "foreach ($n in $devices) {",
      "  $pc = $wsus.SearchComputerTargets($n) | Select-Object -First 1",
      "  if (-not $pc) { Write-Warning \"$n is not registered in WSUS\"; continue }",
      "  if ($Apply) { $target.AddComputerTarget($pc) } else { Write-Host \"Would add $n to '$group'\" }",
      "}",
      "$updates = Get-WsusUpdate -UpdateServer $wsus -Approval AnyExceptDeclined -Status Any |",
      "  Where-Object { @($_.Update.KnowledgebaseArticles | Where-Object { $kbs -contains $_ }).Count -gt 0 }",
      "foreach ($u in $updates) {",
      "  if ($Apply) { $u | Approve-WsusUpdate -Action Install -TargetGroupName $group; Write-Host \"Approved: $($u.Update.Title)\" }",
      "  else { Write-Host \"Would approve: $($u.Update.Title)\" }",
      "}",
      "if (-not $Apply) { Write-Host 'Report only. Run again with -Apply to make the changes.' }",
      ""].join("\r\n");
  }

  root.MPMRollout = { plan, ics, OFFSETS, scripts: { powershell, intune, wsus } };
})(typeof window !== "undefined" ? window : globalThis);
