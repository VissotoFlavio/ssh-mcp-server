param(
  [Parameter(Mandatory = $true)][ValidateSet('safe', 'unsafe-root', 'unsafe-state-leaf', 'unsafe-known-hosts-leaf', 'unsafe-registry-mutation', 'unsafe-registry-unprotected', 'unsafe-inherited-leaf', 'overlap', 'dot-alias', 'junction', 'unsupported-volume', 'cleanup')][string]$Mode,
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

if ($Mode -eq 'cleanup') {
  Remove-TestConfiguration
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
  exit 0
}

$createdRoot = $false
$fixtureConfigurationCreated = $false
trap {
  if ($fixtureConfigurationCreated) { Remove-TestConfiguration }
  if ($createdRoot) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
  throw
}
if (Test-Path -LiteralPath $root) { throw 'Test root already exists.' }
New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
$createdRoot = $true
$state = Join-Path $root 'state'
$knownHosts = if ($Mode -eq 'overlap') { $state } elseif ($Mode -eq 'dot-alias') { "$state\." } else { Join-Path $root 'known-hosts' }
New-Item -ItemType Directory -Path $state -ErrorAction Stop | Out-Null
if ($knownHosts -ne $state -and $Mode -ne 'dot-alias') { New-Item -ItemType Directory -Path $knownHosts -ErrorAction Stop | Out-Null }
Set-PrivateAcl $state $true
if ($knownHosts -ne $state -and $Mode -ne 'dot-alias') { Set-PrivateAcl $knownHosts $true }
$stateFile = Join-Path $state 'connection-profiles.json'
Set-Content -LiteralPath $stateFile -Value '{"profiles":[]}' -Encoding utf8 -NoNewline
Set-PrivateAcl $stateFile $false
$replacementFile = "$stateFile.replacement"
Set-Content -LiteralPath $replacementFile -Value '{"profiles":[]}' -Encoding utf8 -NoNewline
Set-PrivateAcl $replacementFile $false
$knownHostsFile = Join-Path $knownHosts 'production-api.known_hosts'
if ($Mode -ne 'overlap' -and $Mode -ne 'dot-alias') {
  Set-Content -LiteralPath $knownHostsFile -Value 'example.test ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest' -Encoding utf8 -NoNewline
  Set-PrivateAcl $knownHostsFile $false
}
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
if ($Mode -eq 'unsafe-inherited-leaf') {
  & icacls.exe $stateFile '/inheritance:e' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Unable to create inherited ACL fixture.' }
}
if ($Mode -eq 'junction') {
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
