<#
.SYNOPSIS
  Publishes ONLY the public files of MPatchMonitor to GitHub, without Git.

.DESCRIPTION
  Reads tools\public-files.txt (an allowlist), refuses anything private (wrangler.jsonc,
  .dev.vars, the admin console, reports, node_modules) and any file whose content looks
  like a secret, then uploads each file with the GitHub REST API.
  The token is asked at run time and never written to disk.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\publish-github.ps1 -Owner MariSeest -Repo mpatchmonitor -WhatIf
  powershell -ExecutionPolicy Bypass -File tools\publish-github.ps1 -Owner MariSeest -Repo mpatchmonitor
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Owner,
  [Parameter(Mandatory = $true)][string]$Repo,
  [string]$Branch = "main",
  [switch]$WhatIf
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# Never publish these, whatever the allowlist says.
$blocked = @(
  '^wrangler\.jsonc$', '^admin/', '\.dev\.vars', '^node_modules/', '^\.wrangler/', '^security/reports/',
  '^out/', 'prev\.json$', '\.local\.', '^GUIDA', '\.env$', '\.pem$', '\.key$'
)
# Content that must never leave this computer.
$secretPatterns = @(
  'ghp_[A-Za-z0-9]{30,}', 'github_pat_[A-Za-z0-9_]{40,}', '\b\d{8,10}:[A-Za-z0-9_-]{35}\b',
  'SETUP_TOKEN\s*=\s*"?[^"\s]{8,}', '"database_id"\s*:\s*"[0-9a-f]{8}-', '"id"\s*:\s*"[0-9a-f]{32}"',
  'CLOUDFLARE_API_TOKEN\s*=\s*\S{20,}', '-----BEGIN [A-Z ]*PRIVATE KEY-----'
)

$patterns = Get-Content "tools/public-files.txt" | Where-Object { $_ -and -not $_.StartsWith("#") }
$files = foreach ($p in $patterns) {
  Get-ChildItem -Path $p -File -Force -ErrorAction SilentlyContinue |
    ForEach-Object { $_.FullName.Substring($root.Length + 1).Replace('\', '/') }
}
$files = $files | Sort-Object -Unique

$ok = @()
foreach ($f in $files) {
  if ($blocked | Where-Object { $f -match $_ }) { Write-Host "SKIP (private)  $f" -ForegroundColor Yellow; continue }
  $text = $null
  if ($f -notmatch '\.(png|woff2)$') { $text = Get-Content $f -Raw -ErrorAction SilentlyContinue }
  if ($text) {
    $hit = $secretPatterns | Where-Object { $text -match $_ } | Select-Object -First 1
    if ($hit) { Write-Host "STOP: $f looks like it contains a secret ($hit). Nothing was published." -ForegroundColor Red; exit 1 }
  }
  $ok += $f
}

Write-Host "`n$($ok.Count) public files:" -ForegroundColor Cyan
$ok | ForEach-Object { Write-Host "  $_" }
if ($WhatIf) { Write-Host "`nDry run: nothing uploaded." -ForegroundColor Cyan; exit 0 }

$secure = Read-Host "`nGitHub token (fine-grained, Contents: Read and write on $Owner/$Repo only)" -AsSecureString
$token = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
$headers = @{ Authorization = "Bearer $token"; Accept = "application/vnd.github+json"; "X-GitHub-Api-Version" = "2022-11-28"; "User-Agent" = "mpm-publisher" }

$done = 0
foreach ($f in $ok) {
  $api = "https://api.github.com/repos/$Owner/$Repo/contents/$([Uri]::EscapeDataString($f).Replace('%2F','/'))"
  $sha = $null
  try { $sha = (Invoke-RestMethod -Uri "$api`?ref=$Branch" -Headers $headers -Method Get).sha } catch { }
  $bytes = [IO.File]::ReadAllBytes((Join-Path $root $f))
  $body = @{ message = "Update $f"; content = [Convert]::ToBase64String($bytes); branch = $Branch }
  if ($sha) { $body.sha = $sha }
  try {
    Invoke-RestMethod -Uri $api -Headers $headers -Method Put -Body ($body | ConvertTo-Json) -ContentType "application/json" | Out-Null
    $done++; Write-Host "OK    $f" -ForegroundColor Green
  } catch {
    Write-Host "ERROR $f : $($_.Exception.Message)" -ForegroundColor Red
  }
}
$token = $null
Write-Host "`nPublished $done of $($ok.Count) files to https://github.com/$Owner/$Repo" -ForegroundColor Cyan
