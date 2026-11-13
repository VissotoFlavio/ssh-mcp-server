param(
  [Parameter(Mandatory = $true)][ValidateSet('safe', 'unsafe-root', 'unsafe-state-leaf', 'unsafe-known-hosts-leaf', 'unsafe-write-dac-root', 'unsafe-write-dac-state-leaf', 'unsafe-write-dac-known-hosts-leaf', 'reparse-state-root', 'reparse-state-leaf', 'reparse-known-hosts-leaf', 'openssh-chain-reparse', 'openssh-chain-unsafe-dacl', 'openssh-chain-safe', 'unsafe-registry-mutation', 'unsafe-registry-unprotected', 'unsafe-inherited-leaf', 'overlap', 'dot-alias', 'junction', 'unsupported-volume', 'cleanup')][string]$Mode,
  [ValidateSet('SetValue', 'CreateSubKey', 'CreateLink', 'ChangePermissions', 'TakeOwnership', 'Delete', 'WriteKey', 'GenericWrite')][string]$RegistryMutationRight
)

$ErrorActionPreference = 'Stop'
$keyPath = 'Software\Vissoto\ssh-mcp-server'
$root = $env:SSH_MCP_WINDOWS_STORAGE_TEST_ROOT
if ([string]::IsNullOrWhiteSpace($root)) { throw 'Missing test root.' }
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User

function Set-PrivateAcl([string]$Path, [bool]$Directory) {
  $acl = Get-Acl -LiteralPath $Path
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner($sid)
  $inheritance = if ($Directory) { [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [System.Security.AccessControl.InheritanceFlags]::None }
  $acl.SetAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow))
  Set-Acl -LiteralPath $Path -AclObject $acl
}

function Set-Configuration([string]$StateRoot, [string]$KnownHostsRoot) {
  if ([Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($keyPath, $false)) { throw 'Existing per-user configuration prevents an isolated test.' }
  $key = $null
  try {
    $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($keyPath, $true)
    $key.SetValue('TestRoot', $root, [Microsoft.Win32.RegistryValueKind]::String)
    $key.SetValue('StateRoot', $StateRoot, [Microsoft.Win32.RegistryValueKind]::String)
    $key.SetValue('KnownHostsRoot', $KnownHostsRoot, [Microsoft.Win32.RegistryValueKind]::String)
    $acl = [System.Security.AccessControl.RegistrySecurity]::new()
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetAccessRule([System.Security.AccessControl.RegistryAccessRule]::new($sid, [System.Security.AccessControl.RegistryRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow))
    $key.SetAccessControl($acl)
  } catch {
    if ($null -ne $key) { $key.Close(); $key = $null }
    [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($keyPath, $false)
    throw
  } finally { if ($null -ne $key) { $key.Close() } }
}

function Remove-TestConfiguration {
  $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($keyPath, $false)
  if ($null -eq $key) { return }
  try {
    if ($key.GetValue('TestRoot') -eq $root) {
      $key.Close()
      $key = $null
      [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($keyPath, $false)
    }
  } finally { if ($null -ne $key) { $key.Close() } }
}

function Test-FixtureOwnedRoot {
  $marker = Join-Path $root '.ssh-mcp-fixture-owned'
  return (Test-Path -LiteralPath $marker -PathType Leaf) -and ((Get-Content -LiteralPath $marker -Raw -ErrorAction SilentlyContinue).TrimEnd("`r", "`n") -eq $root)
}

function Remove-FixtureRoot {
  if (Test-FixtureOwnedRoot) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
}

if ($Mode -eq 'cleanup') {
  Remove-TestConfiguration
  Remove-FixtureRoot
  exit 0
}

$createdRoot = $false
$fixtureConfigurationCreated = $false
trap {
  if ($fixtureConfigurationCreated) { Remove-TestConfiguration }
  if ($createdRoot) { Remove-FixtureRoot }
  throw
}
if (Test-Path -LiteralPath $root) { throw 'Test root already exists.' }
New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
Set-Content -LiteralPath (Join-Path $root '.ssh-mcp-fixture-owned') -Value $root -Encoding utf8 -NoNewline
$createdRoot = $true
$state = Join-Path $root 'state'
$knownHosts = if ($Mode -eq 'overlap') { $state } elseif ($Mode -eq 'dot-alias') { "$state\." } else { Join-Path $root 'known-hosts' }
$keys = Join-Path $root 'keys'
New-Item -ItemType Directory -Path $state -ErrorAction Stop | Out-Null
New-Item -ItemType Directory -Path $keys -ErrorAction Stop | Out-Null
if ($knownHosts -ne $state -and $Mode -ne 'dot-alias') { New-Item -ItemType Directory -Path $knownHosts -ErrorAction Stop | Out-Null }
Set-PrivateAcl $state $true
Set-PrivateAcl $keys $true
if ($knownHosts -ne $state -and $Mode -ne 'dot-alias') { Set-PrivateAcl $knownHosts $true }
$stateFile = Join-Path $state 'connection-profiles.json'
Set-Content -LiteralPath $stateFile -Value '{"profiles":[]}' -Encoding utf8 -NoNewline
Set-PrivateAcl $stateFile $false
$replacementFile = "$stateFile.replacement"
Set-Content -LiteralPath $replacementFile -Value '{"profiles":[]}' -Encoding utf8 -NoNewline
Set-PrivateAcl $replacementFile $false
$publicKeyFile = Join-Path $keys 'ssh-mcp-agent-ed25519.pub'
Set-Content -LiteralPath $publicKeyFile -Value 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest ssh-mcp-agent' -Encoding utf8 -NoNewline
Set-PrivateAcl $publicKeyFile $false
$knownHostsFile = Join-Path $knownHosts 'production-api.known_hosts'
if ($Mode -ne 'overlap' -and $Mode -ne 'dot-alias') {
  Set-Content -LiteralPath $knownHostsFile -Value 'example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest' -Encoding utf8 -NoNewline
  Set-PrivateAcl $knownHostsFile $false
  $knownHostsReplacement = "$knownHosts.replacement"
  New-Item -ItemType Directory -Path $knownHostsReplacement -ErrorAction Stop | Out-Null
  Set-PrivateAcl $knownHostsReplacement $true
  Set-Content -LiteralPath (Join-Path $knownHostsReplacement 'production-api.known_hosts') -Value 'example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest' -Encoding utf8 -NoNewline
  Set-PrivateAcl (Join-Path $knownHostsReplacement 'production-api.known_hosts') $false
  Set-Content -LiteralPath "$knownHostsFile.replacement" -Value 'example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest' -Encoding utf8 -NoNewline
  Set-PrivateAcl "$knownHostsFile.replacement" $false
}
$stateReplacement = "$state.replacement"
New-Item -ItemType Directory -Path $stateReplacement -ErrorAction Stop | Out-Null
Set-PrivateAcl $stateReplacement $true
Set-Content -LiteralPath (Join-Path $stateReplacement 'connection-profiles.json') -Value '{"profiles":[]}' -Encoding utf8 -NoNewline
Set-PrivateAcl (Join-Path $stateReplacement 'connection-profiles.json') $false
if ($Mode -eq 'unsafe-root') {
  & icacls.exe $state '/grant' '*S-1-1-0:(W)' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Unable to create unsafe ACL fixture.' }
}
if ($Mode -eq 'unsafe-state-leaf') {
  & icacls.exe $stateFile '/grant' '*S-1-1-0:(W)' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Unable to create unsafe leaf ACL fixture.' }
}
if ($Mode -eq 'unsafe-known-hosts-leaf') {
  & icacls.exe $knownHostsFile '/grant' '*S-1-1-0:(W)' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Unable to create unsafe known-hosts ACL fixture.' }
}
if ($Mode -eq 'unsafe-write-dac-root') {
  & icacls.exe $state '/grant' '*S-1-1-0:(WDAC)' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Unable to create WRITE_DAC root fixture.' }
}
if ($Mode -eq 'unsafe-write-dac-state-leaf') {
  & icacls.exe $stateFile '/grant' '*S-1-1-0:(WDAC)' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Unable to create WRITE_DAC state-file fixture.' }
}
if ($Mode -eq 'unsafe-write-dac-known-hosts-leaf') {
  & icacls.exe $knownHostsFile '/grant' '*S-1-1-0:(WDAC)' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Unable to create WRITE_DAC known-hosts fixture.' }
}
if ($Mode -eq 'unsafe-inherited-leaf') {
  & icacls.exe $stateFile '/inheritance:e' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Unable to create inherited ACL fixture.' }
}
if ($Mode -eq 'junction' -or $Mode -eq 'reparse-state-root') {
  $target = Join-Path $root 'target-state'
  New-Item -ItemType Directory -Path $target -ErrorAction Stop | Out-Null
  Set-PrivateAcl $target $true
  Set-Content -LiteralPath (Join-Path $target 'connection-profiles.json') -Value '{"profiles":[]}' -Encoding utf8 -NoNewline
  Set-PrivateAcl (Join-Path $target 'connection-profiles.json') $false
  $link = Join-Path $root 'linked-state'
  & cmd.exe /d /s /c "mklink /J `"$link`" `"$target`"" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Unable to create junction fixture.' }
  $state = $link
}
if ($Mode -eq 'reparse-state-leaf') {
  $target = "$stateFile.reparse-target"
  Set-Content -LiteralPath $target -Value '{"profiles":[]}' -Encoding utf8 -NoNewline
  Set-PrivateAcl $target $false
  Remove-Item -LiteralPath $stateFile -Force
  & cmd.exe /d /s /c "mklink `"$stateFile`" `"$target`"" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Unable to create state-file reparse fixture.' }
}
if ($Mode -eq 'reparse-known-hosts-leaf') {
  $target = "$knownHostsFile.reparse-target"
  Set-Content -LiteralPath $target -Value 'example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest' -Encoding utf8 -NoNewline
  Set-PrivateAcl $target $false
  Remove-Item -LiteralPath $knownHostsFile -Force
  & cmd.exe /d /s /c "mklink `"$knownHostsFile`" `"$target`"" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Unable to create known-hosts reparse fixture.' }
}
if ($Mode -like 'openssh-chain-*') {
  $system = Join-Path $root 'openssh-system'
  New-Item -ItemType Directory -Path $system -ErrorAction Stop | Out-Null
  Set-PrivateAcl $system $true
  $openSsh = Join-Path $system 'OpenSSH'
  if ($Mode -eq 'openssh-chain-reparse') {
    $target = Join-Path $root 'openssh-target'
    New-Item -ItemType Directory -Path $target -ErrorAction Stop | Out-Null
    Set-PrivateAcl $target $true
    Copy-Item -LiteralPath $env:ComSpec -Destination (Join-Path $target 'ssh.exe') -ErrorAction Stop
    Copy-Item -LiteralPath $env:ComSpec -Destination (Join-Path $target 'ssh-add.exe') -ErrorAction Stop
    Set-PrivateAcl (Join-Path $target 'ssh.exe') $false
    Set-PrivateAcl (Join-Path $target 'ssh-add.exe') $false
    & cmd.exe /d /s /c "mklink /J `"$openSsh`" `"$target`"" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Unable to create OpenSSH reparse fixture.' }
  } else {
    New-Item -ItemType Directory -Path $openSsh -ErrorAction Stop | Out-Null
    Set-PrivateAcl $openSsh $true
    Copy-Item -LiteralPath $env:ComSpec -Destination (Join-Path $openSsh 'ssh.exe') -ErrorAction Stop
    Copy-Item -LiteralPath $env:ComSpec -Destination (Join-Path $openSsh 'ssh-add.exe') -ErrorAction Stop
    Set-PrivateAcl (Join-Path $openSsh 'ssh.exe') $false
    Set-PrivateAcl (Join-Path $openSsh 'ssh-add.exe') $false
    if ($Mode -eq 'openssh-chain-unsafe-dacl') {
      & icacls.exe $openSsh '/grant' '*S-1-1-0:(WDAC)' | Out-Null
      if ($LASTEXITCODE -ne 0) { throw 'Unable to create unsafe OpenSSH DACL fixture.' }
    }
  }
}
Set-Configuration $state $knownHosts
$fixtureConfigurationCreated = $true
if ($Mode -eq 'unsupported-volume') {
  $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($keyPath, $true)
  try { $key.SetValue('StateRoot', 'A:\ssh-mcp-unsupported-volume', [Microsoft.Win32.RegistryValueKind]::String) } finally { $key.Close() }
}
if ($Mode -eq 'unsafe-registry-mutation') {
  if ([string]::IsNullOrWhiteSpace($RegistryMutationRight)) { throw 'Missing registry mutation right.' }
  $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($keyPath, $true)
  try {
    $acl = $key.GetAccessControl()
    $everyone = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
    if ($RegistryMutationRight -eq 'GenericWrite') {
      # GW is SDDL's raw GENERIC_WRITE access mask. RegistryAccessRule rejects
      # that undefined enum value, while the native check must MapGenericMask it.
      $sddl = $acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
      $daclStart = $sddl.IndexOf('D:')
      $saclStart = if ($daclStart -lt 0) { -1 } else { $sddl.IndexOf('S:', $daclStart + 2) }
      $rawGenericWriteAce = '(A;;GW;;;WD)'
      $updatedSddl = if ($saclStart -lt 0) { "$sddl$rawGenericWriteAce" } else { $sddl.Insert($saclStart, $rawGenericWriteAce) }
      $acl.SetSecurityDescriptorSddlForm($updatedSddl, [System.Security.AccessControl.AccessControlSections]::All)
    } else {
      $right = [System.Enum]::Parse([System.Security.AccessControl.RegistryRights], $RegistryMutationRight, $false)
      $acl.AddAccessRule([System.Security.AccessControl.RegistryAccessRule]::new($everyone, $right, [System.Security.AccessControl.AccessControlType]::Allow))
    }
    $key.SetAccessControl($acl)
  } finally { $key.Close() }
}
if ($Mode -eq 'unsafe-registry-unprotected') {
  $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($keyPath, $true)
  try {
    $acl = $key.GetAccessControl()
    $acl.SetAccessRuleProtection($false, $true)
    $key.SetAccessControl($acl)
  } finally { $key.Close() }
}
