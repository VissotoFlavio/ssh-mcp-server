[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$ProfileId,
  [Parameter(Mandatory)][string]$TargetHost,
  [Parameter(Mandatory)][ValidateRange(1, 65535)][int]$Port,
  [Parameter(Mandatory)][string]$User,
  [Parameter(Mandatory)][string]$AuthMode,
  [string]$CredentialLocator,
  [Parameter(Mandatory)][string]$ExpectedHostFingerprint,
  [Parameter(Mandatory)][string]$HostKeyLine
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$profileIdPattern = '^[a-z0-9]+(?:-[a-z0-9]+)*$'
$hostPattern = '^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$'
$fingerprintPattern = '^SHA256:[A-Za-z0-9+/]{43}$'
$userPattern = '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
$locatorPattern = '^[a-z0-9][a-z0-9._:-]{0,127}$'
$reservedIds = @('con', 'prn', 'aux', 'nul', 'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9', 'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9', '__proto__', 'constructor', 'prototype')
function Stop-Provisioning([string]$Message) { throw "Provisioning refused: $Message" }
if ($ProfileId.Length -gt 128 -or $ProfileId -cnotmatch $profileIdPattern -or $reservedIds -ccontains $ProfileId) { Stop-Provisioning 'profileId is invalid.' }
if ($TargetHost.Length -gt 253 -or $TargetHost -cnotmatch $hostPattern) { Stop-Provisioning 'host is invalid; IPv6 is not supported by this helper.' }
if ($User -cnotmatch $userPattern -or ($AuthMode -cne 'agent-key' -and $AuthMode -cne 'password') -or $ExpectedHostFingerprint -cnotmatch $fingerprintPattern) { Stop-Provisioning 'profile data is invalid.' }
if ($AuthMode -ceq 'password' -and ([string]::IsNullOrEmpty($CredentialLocator) -or $CredentialLocator -cnotmatch $locatorPattern -or $CredentialLocator.Contains('..') -or $CredentialLocator -cmatch '^(?:password|passphrase|private[ _-]*key|secret|token)(?:[._:-]|$)')) { Stop-Provisioning 'credential locator is invalid.' }
if ($AuthMode -ceq 'agent-key' -and -not [string]::IsNullOrEmpty($CredentialLocator)) { Stop-Provisioning 'credential locator is allowed only for password profiles.' }
$parts = $HostKeyLine -csplit '\s+'
$expectedHostToken = if ($Port -eq 22) { $TargetHost } else { "[$TargetHost]:$Port" }
if ($parts.Count -cne 3 -or $parts[0] -cne $expectedHostToken -or $parts[1] -cnotmatch '^(?:ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp(?:256|384|521))$' -or $parts[2] -cnotmatch '^[A-Za-z0-9+/]+={0,3}$') { Stop-Provisioning 'host-key line is invalid.' }
try {
  $keyBytes = [Convert]::FromBase64String($parts[2])
  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try { $actualFingerprint = 'SHA256:' + [Convert]::ToBase64String($sha256.ComputeHash($keyBytes)).TrimEnd('=') } finally { $sha256.Dispose() }
} catch { Stop-Provisioning 'host-key line is invalid.' }
if ($actualFingerprint -cne $ExpectedHostFingerprint) { Stop-Provisioning 'host-key fingerprint does not match the supplied host-key line.' }
$nodeExe = Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::ProgramFiles, [System.Environment+SpecialFolderOption]::DoNotVerify)) 'nodejs\node.exe'
$bridge = Join-Path $PSScriptRoot 'provision-approved-profile.mjs'
if (-not (Test-Path -LiteralPath $nodeExe -PathType Leaf) -or -not (Test-Path -LiteralPath $bridge -PathType Leaf)) { Stop-Provisioning 'the local provisioning boundary is unavailable.' }
$request = [ordered]@{ profileId = $ProfileId; host = $TargetHost; port = $Port; user = $User; authMode = $AuthMode; expectedHostFingerprint = $ExpectedHostFingerprint; hostKeyLine = $HostKeyLine }
if ($AuthMode -ceq 'password') { $request['credentialLocator'] = $CredentialLocator }
try { $request | ConvertTo-Json -Compress | & $nodeExe $bridge } catch { Stop-Provisioning 'the local provisioning boundary is unavailable.' }
if ($LASTEXITCODE -ne 0) { Stop-Provisioning 'the local provisioning boundary is unavailable.' }
Write-Host 'Provisioning completed without contacting a remote host.'
if ($AuthMode -ceq 'password') { Write-Host "Create the matching Windows Generic Credential in Credential Manager with target Vissoto/ssh-mcp-server/$CredentialLocator. Enter the password only in that UI." }
