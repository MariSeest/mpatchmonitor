<#
  MPatchMonitor inventory collector  (read-only, no network access, no admin rights needed)

  Writes a small JSON file describing this device's software versions:
  Windows build, Microsoft Edge version, Microsoft 365 Apps version, installed updates and
  the list of installed programs (name, version, publisher) as shown in "Apps & features".
  Use -NoSoftware to leave the program list out.
  Load the file on the "My devices" page: it is analysed in your browser and never uploaded.

  Usage (PowerShell):
    powershell -ExecutionPolicy Bypass -File .\collect.ps1
    powershell -ExecutionPolicy Bypass -File .\collect.ps1 -Anonymize -OutDir C:\Temp
#>
[CmdletBinding()]
param(
  [string]$OutDir = [Environment]::GetFolderPath("Desktop"),
  [switch]$Anonymize,
  [switch]$NoSoftware
)

$ErrorActionPreference = "SilentlyContinue"

function Get-RegValue($Path, $Name) {
  try { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

$cv = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$os = Get-CimInstance -ClassName Win32_OperatingSystem

$name = $env:COMPUTERNAME
if ($Anonymize) {
  $sha = [Security.Cryptography.SHA256]::Create()
  $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($name))
  $name = "device-" + (($hash[0..3] | ForEach-Object { $_.ToString("x2") }) -join "")
}

$arch = $env:PROCESSOR_ARCHITECTURE
if ($env:PROCESSOR_ARCHITEW6432) { $arch = $env:PROCESSOR_ARCHITEW6432 }

# Microsoft Edge (stable channel)
$edge = $null
foreach ($k in @("HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}",
                 "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}")) {
  if (-not $edge) { $edge = Get-RegValue $k "pv" }
}

# Microsoft 365 Apps / Office Click-to-Run
$c2r = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
$office = $null
$officeVersion = Get-RegValue $c2r "VersionToReport"
if ($officeVersion) {
  $office = [ordered]@{
    version     = $officeVersion
    platform    = Get-RegValue $c2r "Platform"
    product_ids = Get-RegValue $c2r "ProductReleaseIds"
    channel     = Get-RegValue $c2r "CDNBaseUrl"
  }
}

# Installed programs (read-only: the same registry keys "Apps & features" reads)
$software = @()
if (-not $NoSoftware) {
  $keys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*")
  $software = @(Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName -and $_.ReleaseType -notmatch "Update|Hotfix" } |
    Sort-Object DisplayName, DisplayVersion -Unique |
    Select-Object -First 1500 |
    ForEach-Object { [ordered]@{ name = [string]$_.DisplayName; version = [string]$_.DisplayVersion; publisher = [string]$_.Publisher } })
}

$inventory = [ordered]@{
  schema       = "mpm-inventory/1"
  collected_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  device       = $name
  os = [ordered]@{
    caption           = $os.Caption
    version           = $os.Version
    build             = Get-RegValue $cv "CurrentBuild"
    ubr               = Get-RegValue $cv "UBR"
    display_version   = Get-RegValue $cv "DisplayVersion"
    edition           = Get-RegValue $cv "EditionID"
    installation_type = Get-RegValue $cv "InstallationType"
    arch              = $arch
  }
  edge     = if ($edge) { [ordered]@{ version = $edge } } else { $null }
  office   = $office
  hotfixes = @(Get-HotFix | Select-Object -ExpandProperty HotFixID | Sort-Object -Unique)
  software = $software
}

$file = Join-Path $OutDir ("mpm-" + $name + ".json")
$inventory | ConvertTo-Json -Depth 5 | Out-File -FilePath $file -Encoding utf8
Write-Host "Inventory saved to $file"
Write-Host "Open the My devices page and load this file. It stays on your computer."
