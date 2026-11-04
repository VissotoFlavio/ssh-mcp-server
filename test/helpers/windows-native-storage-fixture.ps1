param([Parameter(Mandatory = $true)][ValidateSet('safe', 'unsafe-root', 'unsafe-leaf', 'unsafe-registry', 'overlap', 'dot-alias', 'junction', 'cleanup')][string]$Mode)

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
  $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($keyPath, $true)
  try {
    $key.SetValue('StateRoot', $StateRoot, [Microsoft.Win32.RegistryValueKind]::String)
    $key.SetValue('KnownHostsRoot', $KnownHostsRoot, [Microsoft.Win32.RegistryValueKind]::String)
    $acl = [System.Security.AccessControl.RegistrySecurity]::new()
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetAccessRule([System.Security.AccessControl.RegistryAccessRule]::new($sid, [System.Security.AccessControl.RegistryRights]::FullControl, [System.Security.AccessControl.AccessControlType]::Allow))
    $key.SetAccessControl($acl)
  } finally { $key.Close() }
}

if ($Mode -eq 'cleanup') {
  [Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($keyPath, $false)
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
  exit 0
}

New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
$state = Join-Path $root 'state'
$knownHosts = if ($Mode -eq 'overlap') { $state } elseif ($Mode -eq 'dot-alias') { "$state\." } else { Join-Path $root 'known-hosts' }
New-Item -ItemType Directory -Path $state -ErrorAction Stop | Out-Null
if ($knownHosts -ne $state -and $Mode -ne 'dot-alias') { New-Item -ItemType Directory -Path $knownHosts -ErrorAction Stop | Out-Null }
Set-PrivateAcl $state $true
if ($knownHosts -ne $state -and $Mode -ne 'dot-alias') { Set-PrivateAcl $knownHosts $true }
$stateFile = Join-Path $state 'connection-profiles.json'
Set-Content -LiteralPath $stateFile -Value '{"profiles":[]}' -Encoding utf8 -NoNewline
Set-PrivateAcl $stateFile $false
if ($Mode -eq 'unsafe-root') {
  & icacls.exe $state '/grant' '*S-1-1-0:(W)' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Unable to create unsafe ACL fixture.' }
}
if ($Mode -eq 'unsafe-leaf') {
  & icacls.exe $stateFile '/grant' '*S-1-1-0:(W)' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Unable to create unsafe leaf ACL fixture.' }
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
if ($Mode -eq 'unsafe-registry') {
  $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($keyPath, $true)
  try {
    $acl = $key.GetAccessControl()
    $everyone = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
    $acl.AddAccessRule([System.Security.AccessControl.RegistryAccessRule]::new($everyone, [System.Security.AccessControl.RegistryRights]::SetValue, [System.Security.AccessControl.AccessControlType]::Allow))
    $key.SetAccessControl($acl)
  } finally { $key.Close() }
}
