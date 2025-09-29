<#
.SYNOPSIS
  Windows 10/11 Security Hardening & Account Enforcement Script

.DESCRIPTION
  -Place on desktop as “script.ps1”
  -Create folder on desktop as “accounts.txt”
	-Paste desired account names into “accounts.txt”
  -Open elevated PowerShell- this can be done with Windows+R, type “powershell” and then ctrl+shift+enter
  -Type these commands:
  -Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
  -cd "C:\Users\ACCOUNTNAME\Desktop"
  -$AdminPW = ConvertTo-SecureString 'Aa1!aaaaaaaaaa' -AsPlainText -Force
  -.\script.ps1 `
  -SpecPath .\accounts.txt `
  -AdminPasswordSecure $AdminPW `
  -DeleteUnlisted `
  -ReportPath .\full_apply.html

.PARAMETERS
  -SpecPath <string>            : path to the account spec text file.
  -AdminPasswordSecure <SecureString> : secure password for all admins in spec.
  -ApplyCategory <string[]>     : subset of categories to run (default: all).
  -Audit                        : read-only.
  -ReportPath <string>          : optional HTML report.
  -Rollback                     : interactive rollback from JSON log.
  -DeleteUnlisted               : delete (instead of disable) unlisted local users.
  -DisableOnly                  : force disable (default behavior for unlisted users).
  -BaselineExport/-BaselineImport: export/import baselines (optional, not needed for basic run).

  Categories:
   Users, AccountSpec, Features, Firewall, Services, Registry, Passwords, AuditPolicy,
   PSLogging, Defender, ASR, ExploitProtection, BitLocker, WindowsUpdate, RDP, SMB, TLS,
   EventLogs, SRP, OSUpdates

.EXAMPLE
  .\script.ps1 -SpecPath .\accounts.txt -AdminPasswordSecure (Read-Host -AsSecureString) -DeleteUnlisted -ReportPath .\full_apply.html
#>

#Requires -RunAsAdministrator
param(
  [switch]$Rollback,
  [string]$LogPath = "C:\SecurityScript\security_log.json",
  [string]$ReportPath,
  [switch]$Audit,
  [string[]]$ApplyCategory,
  [switch]$BaselineExport,
  [string]$BaselineImport,
  [string]$SpecPath,
  [securestring]$AdminPasswordSecure,
  [switch]$DeleteUnlisted,
  [switch]$DisableOnly
)

# ============================= Globals & Helpers =============================
$script:Changes   = @()
$script:Results   = @{ Successful=@(); Failed=@(); Skipped=@(); Audited=@() }
$script:StartTime = Get-Date
$script:Categories = @(
  'Users','AccountSpec','Features','Firewall','Services','Registry','Passwords','AuditPolicy',
  'PSLogging','Defender','ASR','ExploitProtection','BitLocker','WindowsUpdate',
  'RDP','SMB','TLS','EventLogs','SRP','OSUpdates'
)

# Ensure log directory exists
$LogDir = Split-Path $LogPath -Parent
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Test-InScope([string]$Category){
  if(-not $ApplyCategory -or $ApplyCategory.Count -eq 0){ return $true }
  return $ApplyCategory -contains $Category
}

function Write-Result {
  param(
    [string]$Task,
    [string]$Status,  # SUCCESS | FAILED | SKIPPED | AUDIT
    [string]$Details = "",
    [hashtable]$RollbackData = @{}
  )
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $entry = @{ Task=$Task; Status=$Status; Details=$Details; Timestamp=$timestamp; RollbackData=$RollbackData }
  switch($Status){
    'SUCCESS' { $script:Results.Successful += $entry }
    'FAILED'  { $script:Results.Failed     += $entry }
    'SKIPPED' { $script:Results.Skipped    += $entry }
    'AUDIT'   { $script:Results.Audited    += $entry }
  }
  if($RollbackData.Count -gt 0){ $script:Changes += $entry }
  $color = switch($Status){ 'SUCCESS'{'Green'} 'FAILED'{'Red'} 'SKIPPED'{'Yellow'} 'AUDIT'{'Cyan'} }
  Write-Host "[$Status] $Task - $Details" -ForegroundColor $color
}

function Write-ExecutionLog {
  $data = [ordered]@{
    ExecutionStart = $script:StartTime
    ExecutionEnd   = Get-Date
    AuditMode      = [bool]$Audit
    Results        = $script:Results
    Changes        = $script:Changes
  }
  $data | ConvertTo-Json -Depth 10 | Out-File -FilePath $LogPath -Encoding UTF8
  Write-Host "`nLog saved to: $LogPath" -ForegroundColor Cyan
  if($ReportPath){ New-HtmlReport -ReportPath $ReportPath -Data $data }
}

function New-HtmlReport{
  param([string]$ReportPath,[object]$Data)
  $html = @"
<html><head><meta charset='utf-8'>
<style>
  body{font-family:Segoe UI,Arial,sans-serif; margin:24px;}
  h1{margin-bottom:0}
  .meta{color:#666}
  .ok{color:#0a0}
  .fail{color:#c00}
  .skip{color:#a80}
  .audit{color:#07a}
  table{border-collapse:collapse; width:100%; margin:16px 0}
  th,td{border:1px solid #ddd; padding:8px;}
  th{background:#f5f5f5; text-align:left}
  code{background:#f0f0f0; padding:2px 4px}
</style></head><body>
<h1>Windows Security Hardening Report</h1>
<div class='meta'>Start: $($Data.ExecutionStart) · End: $($Data.ExecutionEnd) · Audit mode: $($Data.AuditMode)</div>
<h2>Summary</h2>
<ul>
  <li class='ok'>Successful: $($Data.Results.Successful.Count)</li>
  <li class='fail'>Failed: $($Data.Results.Failed.Count)</li>
  <li class='skip'>Skipped: $($Data.Results.Skipped.Count)</li>
  <li class='audit'>Audited: $($Data.Results.Audited.Count)</li>
</ul>
<h2>Details</h2>
<table><tr><th>Status</th><th>Task</th><th>Details</th><th>Timestamp</th></tr>
"@
  foreach($s in @('Successful','Failed','Skipped','Audited')){
    foreach($r in $Data.Results.$s){
      $cls = switch($r.Status){ 'SUCCESS'{'ok'} 'FAILED'{'fail'} 'SKIPPED'{'skip'} 'AUDIT'{'audit'} }
      $html += "<tr><td class='$cls'>$($r.Status)</td><td><code>$($r.Task)</code></td><td>$($r.Details)</td><td>$($r.Timestamp)</td></tr>"
    }
  }
  $html += "</table></body></html>"
  $dir = Split-Path $ReportPath -Parent
  if(!(Test-Path $dir)){ New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $html | Out-File -FilePath $ReportPath -Encoding UTF8
  Write-Host "HTML report saved to: $ReportPath" -ForegroundColor Cyan
}

function Get-ChangeLog {
  if (Test-Path $LogPath) {
    try { return (Get-Content $LogPath -Raw | ConvertFrom-Json).Changes } catch { Write-Warning "Could not load log file: $_" }
  }
  return @()
}

# ============================ Account Spec Parser ============================
function Get-AccountSpec {
  param([string]$SpecPath)
  if(-not $SpecPath -or -not (Test-Path $SpecPath)){
    return @{ Admins=@(); Users=@(); Raw=$null }
  }

  $raw = Get-Content -Path $SpecPath -Raw

  $adm = [regex]::Match($raw, '(?is)Authorized\s+Administrators:\s*(.+?)(?=Authorized\s+Users:|$)')
  $usr = [regex]::Match($raw, '(?is)Authorized\s+Users:\s*(.+)$')

  $admins = @()
  if($adm.Success){
    $block = [regex]::Replace($adm.Groups[1].Value, '\([^)]*\)', '')
    $block = [regex]::Replace($block, '(?i)password:\s*\S+', '')
    $tokens = $block -split '\s+' | Where-Object { $_ }
    foreach($t in $tokens){
      if($t -match '^[A-Za-z0-9._-]+$' -and $admins -notcontains $t){ $admins += $t }
    }
  }

  $users = @()
  if($usr.Success){
    $users = ($usr.Groups[1].Value -split '\s+' | Where-Object { $_ }) | Select-Object -Unique
  }

  return @{ Admins=$admins; Users=$users; Raw=$raw }
}

# =============================== Categories =================================
function Set-UserAccounts {
  Write-Host "`n=== USER MANAGEMENT (Baseline: disable Guest & built-in Administrator) ===" -ForegroundColor Blue
  try {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guest -and $guest.Enabled -and -not $Audit){
      $oldStatus = $guest.Enabled; Disable-LocalUser -Name "Guest"
      Write-Result "Disable Guest Account" "SUCCESS" "Guest account disabled" @{Type='UserStatus';Username='Guest';OldStatus=$oldStatus}
    } elseif($guest -and $guest.Enabled -and $Audit){
      Write-Result "Guest Account" "AUDIT" "Enabled=TRUE (should be disabled)" @{}
    } else { Write-Result "Disable Guest Account" "SKIPPED" "Already disabled or not present" }
  } catch { Write-Result "Disable Guest Account" "FAILED" $_.Exception.Message }

  try {
    $admin = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
    if ($admin){
      if($admin.Enabled -and -not $Audit){ Disable-LocalUser -Name "Administrator"; Write-Result "Disable Built-in Administrator" "SUCCESS" "Administrator disabled" @{Type='UserStatus';Username='Administrator';OldStatus=$true} }
      elseif($admin.Enabled -and $Audit){ Write-Result "Built-in Administrator" "AUDIT" "Enabled=TRUE (should be disabled)" }
      else{ Write-Result "Disable Built-in Administrator" "SKIPPED" "Already disabled" }
    }
  } catch { Write-Result "Disable Built-in Administrator" "FAILED" $_.Exception.Message }
}

function Set-AccountSpec {
  Write-Host "`n=== ACCOUNT SPEC ENFORCEMENT ===" -ForegroundColor Blue
  if(-not (Test-InScope 'AccountSpec')){ Write-Result 'AccountSpec' 'SKIPPED' 'Category not in scope'; return }
  if(-not $SpecPath){ Write-Result 'AccountSpec' 'FAILED' 'No -SpecPath provided'; return }

  $adminPw = $AdminPasswordSecure
  if(-not $adminPw -and -not $Audit){
    $adminPw = Read-Host -Prompt "Enter ONE secure password for all listed admins" -AsSecureString
  }

  $spec = Get-AccountSpec -SpecPath $SpecPath
  $admins = $spec.Admins
  $users  = $spec.Users
  $safeBuiltins = @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount')

  if(($admins.Count -eq 0) -and ($users.Count -eq 0)){
    Write-Result 'AccountSpec' 'FAILED' "Spec empty or unparsable: $SpecPath"
    return
  }

  foreach($u in $admins){
    try{
      $exists = Get-LocalUser -Name $u -ErrorAction SilentlyContinue
      if($Audit){
        $inAdmins = (Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "^\w*\\$u$" -or $_.Name -eq $u })
        $det = "Exists=$([bool]$exists); InAdministrators=$([bool]$inAdmins)"
        Write-Result "AccountSpec Admin: $u" 'AUDIT' $det
        continue
      }
      if(-not $exists){
        if(-not $adminPw){ throw "No admin password provided for creation."; }
        New-LocalUser -Name $u -Password $adminPw -PasswordNeverExpires:$false -UserMayNotChangePassword:$false -AccountNeverExpires:$true | Out-Null
        Write-Result "Create Admin: $u" 'SUCCESS' 'Created local user' @{Type='UserCreate';Username=$u}
      } else {
        if(-not $exists.Enabled){ Enable-LocalUser -Name $u; Write-Result "Enable Admin: $u" 'SUCCESS' 'Enabled account' @{Type='UserStatus';Username=$u;OldStatus=$false} }
        if($adminPw){
          try{ Set-LocalUser -Name $u -Password $adminPw }catch{ & net user $u ( [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminPw)) ) /Y | Out-Null }
          Write-Result "Set Password: $u" 'SUCCESS' 'Password updated (not logged)'
        }
      }
      $inAdmins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "^\w*\\$u$" -or $_.Name -eq $u }
      if(-not $inAdmins -and -not $Audit){ Add-LocalGroupMember -Group 'Administrators' -Member $u -ErrorAction Stop; Write-Result "Add to Administrators: $u" 'SUCCESS' 'Added to Administrators' @{Type='Group';Group='Administrators';User=$u;Action='Add'} }
    }catch{ Write-Result "AccountSpec Admin: $u" 'FAILED' $_.Exception.Message }
  }

  foreach($u in $users){
    try{
      $exists = Get-LocalUser -Name $u -ErrorAction SilentlyContinue
      if($Audit){
        $inUsers = (Get-LocalGroupMember -Group 'Users' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "^\w*\\$u$" -or $_.Name -eq $u })
        $det = "Exists=$([bool]$exists); InUsers=$([bool]$inUsers)"
        Write-Result "AccountSpec User: $u" 'AUDIT' $det
        continue
      }
      if(-not $exists){
        $temp = [System.Web.Security.Membership]::GeneratePassword(16,3)
        $sec = ConvertTo-SecureString $temp -AsPlainText -Force
        New-LocalUser -Name $u -Password $sec -PasswordNeverExpires:$false -UserMayNotChangePassword:$false -AccountNeverExpires:$true | Out-Null
        Disable-LocalUser -Name $u
        Write-Result "Create User: $u" 'SUCCESS' 'Created (disabled) local user' @{Type='UserCreate';Username=$u}
      }
      $inUsers = Get-LocalGroupMember -Group 'Users' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "^\w*\\$u$" -or $_.Name -eq $u }
      if(-not $inUsers -and -not $Audit){ Add-LocalGroupMember -Group 'Users' -Member $u -ErrorAction Stop; Write-Result "Add to Users: $u" 'SUCCESS' 'Added to Users group' @{Type='Group';Group='Users';User=$u;Action='Add'} }
    }catch{ Write-Result "AccountSpec User: $u" 'FAILED' $_.Exception.Message }
  }

  try{
    $allowed = @($admins + $users + $safeBuiltins) | Select-Object -Unique
    foreach($acct in Get-LocalUser){
      if($allowed -contains $acct.Name){ continue }
      if($Audit){
        Write-Result "Unlisted Account: $($acct.Name)" 'AUDIT' ("Would {0}" -f ($(if($DeleteUnlisted -and -not $DisableOnly){'DELETE'} else {'DISABLE'})))
        continue
      }
      if($DeleteUnlisted -and -not $DisableOnly){
        foreach($g in @('Administrators','Users')){ try{ Remove-LocalGroupMember -Group $g -Member $acct.Name -ErrorAction SilentlyContinue | Out-Null }catch{} }
        try{ Remove-LocalUser -Name $acct.Name -ErrorAction Stop; Write-Result "Delete Unlisted: $($acct.Name)" 'SUCCESS' 'Deleted account' @{Type='UserDelete';Username=$acct.Name} }
        catch{ Write-Result "Delete Unlisted: $($acct.Name)" 'FAILED' $_.Exception.Message }
      } else {
        if($acct.Enabled){ Disable-LocalUser -Name $acct.Name -ErrorAction SilentlyContinue; Write-Result "Disable Unlisted: $($acct.Name)" 'SUCCESS' 'Disabled account' @{Type='UserStatus';Username=$acct.Name;OldStatus=$true} }
        else { Write-Result "Disable Unlisted: $($acct.Name)" 'SKIPPED' 'Already disabled' }
      }
    }
  }catch{ Write-Result "AccountSpec (Unlisted Handling)" 'FAILED' $_.Exception.Message }
}

function Set-WindowsFeatures {
  Write-Host "`n=== WINDOWS FEATURES ===" -ForegroundColor Blue
  if(-not (Test-InScope 'Features')){ Write-Result 'Windows Features' 'SKIPPED' 'Category not in scope'; return }
  $featuresToDisable = @('SMB1Protocol','TelnetClient','TelnetServer','TFTP','SimpleTCP','Internet-Explorer-Optional-amd64')
  foreach ($feature in $featuresToDisable) {
    try {
      $state = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
      if ($state -and $state.State -eq 'Enabled') {
        if($Audit){ Write-Result "Feature $feature" "AUDIT" "Enabled (should be disabled)" }
        else {
          Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart
          Write-Result "Disable $feature" "SUCCESS" "Feature disabled" @{Type='WindowsFeature';FeatureName=$feature;OldState='Enabled'}
        }
      } else { Write-Result "Disable $feature" "SKIPPED" "Not found or already disabled" }
    } catch { Write-Result "Disable $feature" "FAILED" $_.Exception.Message }
  }
}

# --------- CLM-friendly FIREWALL (uses netsh fallback universally for set ops) ----------
function Set-FirewallConfig {
  Write-Host "`n=== FIREWALL CONFIGURATION ===" -ForegroundColor Blue
  if(-not (Test-InScope 'Firewall')){ Write-Result 'Firewall' 'SKIPPED' 'Category not in scope'; return }

  $profiles = @('Domain','Private','Public')
  foreach ($fwProfile in $profiles) {
    $old = $null
    try { $old = Get-NetFirewallProfile -Profile $fwProfile -ErrorAction Stop } catch { $old = $null }

    if($Audit){
      if($old){
        Write-Result "Firewall $fwProfile" "AUDIT" "Enabled=$($old.Enabled); Inbound=$($old.DefaultInboundAction); Outbound=$($old.DefaultOutboundAction)"
      } else {
        Write-Result "Firewall $fwProfile" "AUDIT" "Could not read via NetSecurity; would ensure profile ON via netsh"
      }
      continue
    }

    try {
      & netsh advfirewall set $($fwProfile.ToLower())profile state on | Out-Null
      & netsh advfirewall set $($fwProfile.ToLower())profile firewallpolicy blockinbound,allowoutbound | Out-Null
      Write-Result "Enable Firewall - $fwProfile" "SUCCESS" "Enabled via netsh" @{Type='FirewallProfile';Profile=$fwProfile;OldEnabled=$(if($old){$old.Enabled}else{$null})}
    } catch {
      Write-Result "Enable Firewall - $fwProfile" "FAILED" $_.Exception.Message
    }
  }

  if($Audit){
    Write-Result "Disable Dangerous Firewall Rules" "AUDIT" "Would disable File and Printer Sharing + Remote Assistance groups via netsh"
  } else {
    try {
      & netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=no | Out-Null
      & netsh advfirewall firewall set rule group="Remote Assistance" new enable=no | Out-Null
      Write-Result "Disable Dangerous Firewall Rules" "SUCCESS" "Disabled rule groups via netsh"
    } catch {
      Write-Result "Disable Dangerous Firewall Rules" "FAILED" $_.Exception.Message
    }
  }
}

function Set-ServicesState {
  Write-Host "`n=== SERVICE MANAGEMENT ===" -ForegroundColor Blue
  if(-not (Test-InScope 'Services')){ Write-Result 'Services' 'SKIPPED' 'Category not in scope'; return }
  $services = @('Telnet','TlntSvr','RemoteRegistry','SNMP','SNMPTRAP','NetTcpPortSharing')
  foreach ($svc in $services) {
    try {
      $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
      if ($service) {
        $oldStart = (Get-CimInstance Win32_Service -Filter "Name='$svc'").StartMode
        $oldStatus = $service.Status
        if($Audit){ Write-Result "Service $svc" "AUDIT" "Status=$oldStatus; Start=$oldStart"; continue }
        if ($service.Status -eq 'Running') { Stop-Service -Name $svc -Force }
        Set-Service -Name $svc -StartupType Disabled
        Write-Result "Disable Service: $svc" "SUCCESS" "Service stopped & disabled" @{Type='Service';ServiceName=$svc;OldStartType=$oldStart;OldStatus=$oldStatus}
      } else { Write-Result "Disable Service: $svc" "SKIPPED" "Not found" }
    } catch { Write-Result "Disable Service: $svc" "FAILED" $_.Exception.Message }
  }
}

function Set-RegistrySecurity {
  Write-Host "`n=== REGISTRY SECURITY ===" -ForegroundColor Blue
  if(-not (Test-InScope 'Registry')){ Write-Result 'Registry' 'SKIPPED' 'Category not in scope'; return }
  $reg = @(
    @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='LocalAccountTokenFilterPolicy'; Value=0; Type='DWORD'; Desc='Disable remote token filtering bypass' },
    @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='FilterAdministratorToken'; Value=1; Type='DWORD'; Desc='Admin approval mode' },
    @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableLUA'; Value=1; Type='DWORD'; Desc='Enable UAC' }
  )
  foreach($s in $reg){
    try{
      if(!(Test-Path $s.Path)){ if(-not $Audit){ New-Item -Path $s.Path -Force | Out-Null } }
      $old = (Get-ItemProperty -Path $s.Path -Name $s.Name -ErrorAction SilentlyContinue).$($s.Name)
      if($Audit){ Write-Result "Registry: $($s.Desc)" 'AUDIT' "Current=$old; Target=$($s.Value)"; continue }
      Set-ItemProperty -Path $s.Path -Name $s.Name -Value $s.Value -Type $s.Type
      Write-Result "Registry: $($s.Desc)" 'SUCCESS' "Applied" @{Type='Registry';Path=$s.Path;Name=$s.Name;OldValue=$old;NewValue=$s.Value;ValueType=$s.Type}
    }catch{ Write-Result "Registry: $($s.Desc)" 'FAILED' $_.Exception.Message }
  }
}

function Set-PasswordPolicy {
  Write-Host "`n=== PASSWORD POLICY ===" -ForegroundColor Blue
  if(-not (Test-InScope 'Passwords')){ Write-Result 'Passwords' 'SKIPPED' 'Category not in scope'; return }
  $cfg = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 90
MinimumPasswordLength = 12
PasswordComplexity = 1
PasswordHistorySize = 10
LockoutBadCount = 5
LockoutDuration = 30
ResetLockoutCount = 30
[Privilege Rights]
[Registry Values]
'@
  try{
    if($Audit){ Write-Result 'Password Policy' 'AUDIT' 'Target: MinLen=12, Hist=10, AgeMax=90, Lockout=5/30m' ; return }
    $tmp = Join-Path $env:TEMP 'secpol.cfg'
    $cfg | Out-File -FilePath $tmp -Encoding ASCII
    secedit /configure /db secedit.sdb /cfg $tmp /areas SECURITYPOLICY | Out-Null
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    Write-Result 'Password Policy' 'SUCCESS' 'Applied via secedit'
  }catch{ Write-Result 'Password Policy' 'FAILED' $_.Exception.Message }
}

function Set-AuditPolicy {
  Write-Host "`n=== AUDIT POLICY ===" -ForegroundColor Blue
  if(-not (Test-InScope 'AuditPolicy')){ Write-Result 'AuditPolicy' 'SKIPPED' 'Category not in scope'; return }
  $cats = @('Account Logon','Account Management','Logon/Logoff','Object Access','Policy Change','Privilege Use','Detailed Tracking','System')
  foreach($c in $cats){
    try{
      if($Audit){ Write-Result "Audit $c" 'AUDIT' 'Success+Failure targeted' ; continue }
      auditpol /set /category:"$c" /success:enable /failure:enable | Out-Null
      if($LASTEXITCODE -eq 0){ Write-Result "Audit $c" 'SUCCESS' 'Enabled success+failure' } else { Write-Result "Audit $c" 'FAILED' 'auditpol error' }
    }catch{ Write-Result "Audit $c" 'FAILED' $_.Exception.Message }
  }
}

function Enable-PSLogging {
  Write-Host "`n=== POWERSHELL LOGGING ===" -ForegroundColor Blue
  if(-not (Test-InScope 'PSLogging')){ Write-Result 'PSLogging' 'SKIPPED' 'Category not in scope'; return }
  $k='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
  $paths = @(
    @{Path="$k\ScriptBlockLogging"; Name='EnableScriptBlockLogging'; Value=1; Type='DWord'},
    @{Path="$k\ModuleLogging"; Name='EnableModuleLogging'; Value=1; Type='DWord'},
    @{Path="$k\Transcription"; Name='EnableTranscripting'; Value=1; Type='DWord'},
    @{Path="$k\Transcription"; Name='OutputDirectory'; Value='C:\SecurityScript\Transcripts'; Type='String'}
  )
  foreach($p in $paths){
    try{
      $old = (Get-ItemProperty -Path $p.Path -Name $p.Name -ErrorAction SilentlyContinue).$($p.Name)
      if($Audit){ Write-Result "PSLogging $($p.Name)" 'AUDIT' "Current=$old; Target=$($p.Value)"; continue }
      if(!(Test-Path $p.Path)){ New-Item -Path $p.Path -Force | Out-Null }
      if($p.Name -eq 'OutputDirectory' -and !(Test-Path $p.Value)){ New-Item -ItemType Directory -Path $p.Value -Force | Out-Null }
      New-ItemProperty -Path $p.Path -Name $p.Name -Value $p.Value -PropertyType $p.Type -Force | Out-Null
      Write-Result "PSLogging $($p.Name)" 'SUCCESS' 'Applied' @{Type='Registry';Path=$p.Path;Name=$p.Name;OldValue=$old;NewValue=$p.Value}
    }catch{ Write-Result "PSLogging $($p.Name)" 'FAILED' $_.Exception.Message }
  }
}

# --------- CLM-friendly DEFENDER (registry + MpCmdRun.exe) ----------
function Set-DefenderBaseline {
  Write-Host "`n=== MICROSOFT DEFENDER BASELINE ===" -ForegroundColor Blue
  if(-not (Test-InScope 'Defender')){ Write-Result 'Defender' 'SKIPPED' 'Category not in scope'; return }
  $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
  $sp = Join-Path $k 'Spynet'
  try{
    if($Audit){ Write-Result 'Defender' 'AUDIT' 'Will enable Realtime, PUA, MAPS Advanced, SendSafeSamples via registry/MpCmdRun'; return }

    if(!(Test-Path $k)){ New-Item $k -Force | Out-Null }
    New-ItemProperty -Path $k -Name 'DisableRealtimeMonitoring' -Value 0 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $k -Name 'PUAProtection' -Value 1 -PropertyType DWord -Force | Out-Null
    if(!(Test-Path $sp)){ New-Item $sp -Force | Out-Null }
    New-ItemProperty -Path $sp -Name 'SubmitSamplesConsent' -Value 1 -PropertyType DWord -Force | Out-Null   # SendSafeSamples
    New-ItemProperty -Path $sp -Name 'SpynetReporting' -Value 2 -PropertyType DWord -Force | Out-Null        # MAPS Advanced

    $mp = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
    if(Test-Path $mp){
      & "$mp" -Enable | Out-Null
      & "$mp" -SignatureUpdate | Out-Null
    }
    Write-Result 'Defender Core' 'SUCCESS' 'Enabled via registry + MpCmdRun'
  }catch{ Write-Result 'Defender Core' 'FAILED' $_.Exception.Message }
}

# --------- CLM-friendly ASR (registry) ----------
function Set-ASRRules {
  Write-Host "`n=== DEFENDER ASR RULES ===" -ForegroundColor Blue
  if(-not (Test-InScope 'ASR')){ Write-Result 'ASR' 'SKIPPED' 'Category not in scope'; return }
  $base='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
  $rules = @(
    'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550',
    'D4F940AB-401B-4EFC-AADC-AD5F3C50688A',
    '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC',
    '3B576869-A4EC-4529-8536-B80A7769E899',
    '0177B8DB-6FB3-4F52-8F17-BC4682F3133B',
    '26190899-1602-49E8-8B27-EB1D0A1CE869'
  )
  try{
    if($Audit){ Write-Result 'ASR' 'AUDIT' 'Will enable common ASR rules via registry'; return }
    if(!(Test-Path $base)){ New-Item -Path $base -Force | Out-Null }
    foreach($id in $rules){
      New-ItemProperty -Path $base -Name $id -Value 1 -PropertyType DWord -Force | Out-Null  # 1 = Block/Enabled
    }
    Write-Result 'ASR Rules' 'SUCCESS' 'Enabled via registry (ASR)'
  }catch{ Write-Result 'ASR Rules' 'FAILED' $_.Exception.Message }
}

function Set-ExploitProtection {
  Write-Host "`n=== EXPLOIT PROTECTION ===" -ForegroundColor Blue
  if(-not (Test-InScope 'ExploitProtection')){ Write-Result 'ExploitProtection' 'SKIPPED' 'Category not in scope'; return }
  $xml = @'
<?xml version="1.0" encoding="UTF-8"?>
<MitigationPolicy>
  <SystemConfig>
    <DEP Enable="true" EmulateAtlThunks="true"/>
    <ASLR ForceRelocateImages="true" BottomUp="true" HighEntropy="true"/>
    <SEHOP Enable="true"/>
    <Heap TerminateOnError="true"/>
    <CFG Enable="true"/>
  </SystemConfig>
</MitigationPolicy>
'@
  try{
    if($Audit){ Write-Result 'Exploit Protection' 'AUDIT' 'System-level mitigations targeted' ; return }
    $tmp = Join-Path $env:TEMP 'ep.xml'; $xml | Out-File -FilePath $tmp -Encoding UTF8
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-ProcessMitigation -PolicyFilePath '$tmp'" | Out-Null
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    Write-Result 'Exploit Protection' 'SUCCESS' 'Applied system-level mitigations'
  }catch{ Write-Result 'Exploit Protection' 'FAILED' $_.Exception.Message }
}

function Enable-BitLockerOSDrive {
  Write-Host "`n=== BITLOCKER (OS DRIVE) ===" -ForegroundColor Blue
  if(-not (Test-InScope 'BitLocker')){ Write-Result 'BitLocker' 'SKIPPED' 'Category not in scope'; return }
  try{
    $os = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
    if(-not $os){ Write-Result 'BitLocker' 'SKIPPED' 'BitLocker not available (Home SKU or feature absent)'; return }

    $tpm = $null
    try { $tpm = Get-Tpm -ErrorAction Stop } catch { $tpm = $null }

    if($Audit){
      $tpminfo = if($tpm){ "TPMPresent=$($tpm.TpmPresent); Ready=$($tpm.TpmReady)" } else { "TPMUnknown" }
      Write-Result 'BitLocker' 'AUDIT' ("ProtectionStatus={0}; {1}" -f $os.ProtectionStatus,$tpminfo)
      return
    }

    if($tpm -and $tpm.TpmPresent -and $tpm.TpmReady){
      if($os.ProtectionStatus -ne 'On'){
        Enable-BitLocker -MountPoint $env:SystemDrive -UsedSpaceOnly -TpmProtector -ErrorAction Stop
        Start-Sleep -Seconds 2
      }
      $os = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
      if($os.ProtectionStatus -eq 'On'){ Write-Result 'BitLocker' 'SUCCESS' 'Enabled on OS drive (TPM)' }
      else { Write-Result 'BitLocker' 'FAILED' 'Attempted enable with TPM but status is not On' }
    } else {
      Write-Result 'BitLocker' 'SKIPPED' 'No ready TPM in this VM; not enabling'
    }
  }catch{ Write-Result 'BitLocker' 'FAILED' $_.Exception.Message }
}

function Set-WindowsUpdatePolicy {
  Write-Host "`n=== WINDOWS UPDATE SETTINGS ===" -ForegroundColor Blue
  if(-not (Test-InScope 'WindowsUpdate')){ Write-Result 'WindowsUpdate' 'SKIPPED' 'Category not in scope'; return }
  $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
  $vals = @(
    @{Path=$k; Name='NoAutoRebootWithLoggedOnUsers'; Value=1; Type='DWORD'},
    @{Path=$k; Name='AUOptions'; Value=3; Type='DWORD'} # 3 = Auto download + notify install
  )
  foreach($v in $vals){
    try{
      $old = (Get-ItemProperty -Path $v.Path -Name $v.Name -ErrorAction SilentlyContinue).$($v.Name)
      if($Audit){ Write-Result "WU $($v.Name)" 'AUDIT' "Current=$old; Target=$($v.Value)"; continue }
      if(!(Test-Path $v.Path)){ New-Item -Path $v.Path -Force | Out-Null }
      New-ItemProperty -Path $v.Path -Name $v.Name -Value $v.Value -PropertyType $v.Type -Force | Out-Null
      Write-Result "WU $($v.Name)" 'SUCCESS' 'Applied' @{Type='Registry';Path=$v.Path;Name=$v.Name;OldValue=$old;NewValue=$v.Value}
    }catch{ Write-Result "WU $($v.Name)" 'FAILED' $_.Exception.Message }
  }
}

function Set-RDPSecurity {
  Write-Host "`n=== RDP / NLA HARDENING ===" -ForegroundColor Blue
  if(-not (Test-InScope 'RDP')){ Write-Result 'RDP' 'SKIPPED' 'Category not in scope'; return }
  $tcpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
  try{
    $rdpEnabled = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections -eq 0
    if(-not $rdpEnabled){ Write-Result 'RDP' 'SKIPPED' 'RDP not enabled on host'; return }
    $oldNLA = (Get-ItemProperty -Path $tcpKey -Name 'UserAuthentication' -ErrorAction SilentlyContinue).UserAuthentication
    if($Audit){ Write-Result 'RDP NLA' 'AUDIT' ("UserAuthentication={0} (1 required)" -f $oldNLA); return }
    New-ItemProperty -Path $tcpKey -Name 'UserAuthentication' -Value 1 -PropertyType DWORD -Force | Out-Null
    Write-Result 'RDP NLA' 'SUCCESS' 'Enforced Network Level Authentication' @{Type='Registry';Path=$tcpKey;Name='UserAuthentication';OldValue=$oldNLA;NewValue=1}
    $pol='HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    New-Item -Path $pol -Force | Out-Null
    New-ItemProperty -Path $pol -Name 'fDisableCdm' -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $pol -Name 'fDisableClip' -Value 1 -PropertyType DWORD -Force | Out-Null
    Write-Result 'RDP Redirection' 'SUCCESS' 'Disabled drive + clipboard redirection'
  }catch{ Write-Result 'RDP' 'FAILED' $_.Exception.Message }
}

function Set-SMBHardening {
  Write-Host "`n=== SMB HARDENING ===" -ForegroundColor Blue
  if(-not (Test-InScope 'SMB')){ Write-Result 'SMB' 'SKIPPED' 'Category not in scope'; return }
  try{
    $wk='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    $old = (Get-ItemProperty -Path $wk -Name 'RequireSecuritySignature' -ErrorAction SilentlyContinue).RequireSecuritySignature
    if($Audit){ Write-Result 'SMB Signing' 'AUDIT' "Client RequireSecuritySignature=$old (1 required)"; return }
    New-Item -Path $wk -Force | Out-Null
    New-ItemProperty -Path $wk -Name 'RequireSecuritySignature' -Value 1 -PropertyType DWORD -Force | Out-Null
    Write-Result 'SMB Signing' 'SUCCESS' 'Client signing required' @{Type='Registry';Path=$wk;Name='RequireSecuritySignature';OldValue=$old;NewValue=1}

    $pol='HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
    $old2 = (Get-ItemProperty -Path $pol -Name 'AllowInsecureGuestAuth' -ErrorAction SilentlyContinue).AllowInsecureGuestAuth
    New-Item -Path $pol -Force | Out-Null
    New-ItemProperty -Path $pol -Name 'AllowInsecureGuestAuth' -Value 0 -PropertyType DWORD -Force | Out-Null
    Write-Result 'SMB Guest' 'SUCCESS' 'Insecure guest auth disabled' @{Type='Registry';Path=$pol;Name='AllowInsecureGuestAuth';OldValue=$old2;NewValue=0}
  }catch{ Write-Result 'SMB' 'FAILED' $_.Exception.Message }
}

function Set-TlsSchannel {
  Write-Host "`n=== TLS / SCHANNEL ===" -ForegroundColor Blue
  if(-not (Test-InScope 'TLS')){ Write-Result 'TLS' 'SKIPPED' 'Category not in scope'; return }
  try{
    $base='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    $targets = @(
      @{Proto='SSL 3.0'; Enable=0},@{Proto='TLS 1.0'; Enable=0},@{Proto='TLS 1.1'; Enable=0},@{Proto='TLS 1.2'; Enable=1},@{Proto='TLS 1.3'; Enable=1}
    )
    foreach($t in $targets){
      foreach($role in @('Server','Client')){
        $p = Join-Path $base (Join-Path $t.Proto $role)
        $old = (Get-ItemProperty -Path $p -Name 'Enabled' -ErrorAction SilentlyContinue).Enabled
        if($Audit){ Write-Result "TLS $($t.Proto) $role" 'AUDIT' "Enabled=$old Target=$($t.Enable)"; continue }
        if(!(Test-Path $p)){ New-Item -Path $p -Force | Out-Null }
        New-ItemProperty -Path $p -Name 'Enabled' -Value $t.Enable -PropertyType DWORD -Force | Out-Null
        Write-Result "TLS $($t.Proto) $role" 'SUCCESS' 'Set' @{Type='Registry';Path=$p;Name='Enabled';OldValue=$old;NewValue=$t.Enable}
      }
    }
  }catch{ Write-Result 'TLS' 'FAILED' $_.Exception.Message }
}

# --------- CLM-friendly EVENT LOG SIZING (no method calls) ----------
function Set-EventLogSizing {
  Write-Host "`n=== EVENT LOG SIZING ===" -ForegroundColor Blue
  if(-not (Test-InScope 'EventLogs')){ Write-Result 'EventLogs' 'SKIPPED' 'Category not in scope'; return }
  $targets = @(
    @{Log='Security'; SizeMB=256}, @{Log='System'; SizeMB=128}, @{Log='Application'; SizeMB=128}
  )
  foreach($t in $targets){
    try{
      if($Audit){ Write-Result "EventLog $($t.Log)" 'AUDIT' "TargetMB=$($t.SizeMB)"; continue }
      wevtutil sl $($t.Log) /ms:$([int64]$t.SizeMB*1MB) | Out-Null
      Write-Result "EventLog $($t.Log)" 'SUCCESS' "Sized to $($t.SizeMB)MB"
    }catch{ Write-Result "EventLog $($t.Log)" 'FAILED' $_.Exception.Message }
  }
}

function Set-SoftwareRestrictionPolicy {
  Write-Host "`n=== SOFTWARE RESTRICTION POLICIES (BASIC) ===" -ForegroundColor Blue
  if(-not (Test-InScope 'SRP')){ Write-Result 'SRP' 'SKIPPED' 'Category not in scope'; return }
  $k='HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers'
  try{
    $sku = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
    if($sku -match 'Core'){ Write-Result 'SRP' 'SKIPPED' 'Unsupported on Home/Core'; return }
    if($Audit){ Write-Result 'SRP' 'AUDIT' 'Default=Disallowed; allow Windows & Program Files; block %AppData% exe' ; return }

    New-Item -Path $k -Force | Out-Null
    New-ItemProperty -Path $k -Name 'DefaultLevel' -Value 0x00000000 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $k -Name 'PolicyScope' -Value 0 -PropertyType DWORD -Force | Out-Null

    $paths = @("C:\Windows\*","C:\Program Files\*","C:\Program Files (x86)\*")
    $i=1000
    foreach($p in $paths){
      $rid = "0\x$i"; $i++
      $rp = Join-Path $k "0\Paths\$rid"
      New-Item -Path $rp -Force | Out-Null
      New-ItemProperty -Path $rp -Name 'ItemData' -Value $p -PropertyType String -Force | Out-Null
      New-ItemProperty -Path $rp -Name 'SaferFlags' -Value 0 -PropertyType DWORD -Force | Out-Null
    }

    $blocks = @("%UserProfile%\AppData\Local\*","%UserProfile%\AppData\Roaming\*")
    foreach($p in $blocks){
      $rid = "0\x$i"; $i++
      $rp = Join-Path $k "0\Paths\$rid"
      New-Item -Path $rp -Force | Out-Null
      New-ItemProperty -Path $rp -Name 'ItemData' -Value $p -PropertyType String -Force | Out-Null
      New-ItemProperty -Path $rp -Name 'SaferFlags' -Value 0x00001000 -PropertyType DWORD -Force | Out-Null
    }
    Write-Result 'SRP' 'SUCCESS' 'Basic SRP applied (may require restart)'
  }catch{ Write-Result 'SRP' 'FAILED' $_.Exception.Message }
}

# ================================ OS Updates ================================
function Test-PSWindowsUpdate {
  try {
    Import-Module PSWindowsUpdate -ErrorAction Stop
    Write-Result 'PSWindowsUpdate Import' 'SUCCESS' 'Module imported'
    return $true
  } catch {
    Write-Result 'PSWindowsUpdate Import' 'FAILED' ("{0}" -f $_.Exception.Message)
  }
  try {
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    Install-Module -Name PSWindowsUpdate -Force -Scope AllUsers -AllowClobber -ErrorAction Stop
    Write-Result 'PSWindowsUpdate Install' 'SUCCESS' 'Installed from PSGallery'
    Import-Module PSWindowsUpdate -ErrorAction Stop
    Write-Result 'PSWindowsUpdate Import' 'SUCCESS' 'Module imported after install'
    return $true
  } catch {
    Write-Result 'PSWindowsUpdate Install' 'FAILED' ("{0}" -f $_.Exception.Message)
    return $false
  }
}

function Invoke-WindowsUpdates {
  Write-Host "`n=== WINDOWS UPDATE (OS) ===" -ForegroundColor Blue
  if(-not (Test-InScope 'OSUpdates')){ Write-Result 'OS Updates' 'SKIPPED' 'Category not in scope'; return }

  if($Audit){
    Write-Result 'OS Updates (Plan)' 'AUDIT' 'Would try PSWindowsUpdate; fallback to USOClient; then wuauclt'
    return
  }

  if(Test-PSWindowsUpdate){
    try{
      Get-WindowsUpdate -AcceptAll -Install -AutoReboot -IgnoreUserInput -ErrorAction Stop | Out-Null
      Write-Result 'OS Updates via PSWindowsUpdate' 'SUCCESS' 'Installed updates (system may reboot)'
      return
    }catch{
      Write-Result 'OS Updates via PSWindowsUpdate' 'FAILED' ("{0}" -f $_.Exception.Message)
    }
  }

  try{
    & UsoClient StartScan     | Out-Null
    & UsoClient StartDownload | Out-Null
    & UsoClient StartInstall  | Out-Null
    Write-Result 'OS Updates via USOClient' 'SUCCESS' 'Scan/Download/Install triggered'
    return
  }catch{
    Write-Result 'OS Updates via USOClient' 'FAILED' ("{0}" -f $_.Exception.Message)
  }

  try{
    wuauclt /detectnow | Out-Null
    wuauclt /updatenow | Out-Null
    Write-Result 'OS Updates via wuauclt' 'SUCCESS' 'Legacy trigger invoked'
  }catch{
    Write-Result 'OS Updates via wuauclt' 'FAILED' ("{0}" -f $_.Exception.Message)
  }
}

# ================================ Baselines =================================
function Export-Baseline{
  param([string]$Path = "C:\SecurityScript\baseline.json")
  $obj = [ordered]@{
    Timestamp = Get-Date
    Defender  = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -ErrorAction SilentlyContinue | Select-Object *)
    Firewall  = @('Domain','Private','Public') | ForEach-Object { @{ Profile=$_ } }
    RDP       = @{ NLA = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication }
    SMB       = @{ Signing = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature }
    TLS       = @{ TLS12 = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name Enabled -ErrorAction SilentlyContinue).Enabled }
    EventLogs = @('Security','System','Application')
  }
  $dir = Split-Path $Path -Parent; if(!(Test-Path $dir)){ New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  ($obj | ConvertTo-Json -Depth 6) | Out-File -FilePath $Path -Encoding UTF8
  Write-Host "Baseline exported to: $Path" -ForegroundColor Cyan
}

# ================================ Rollback ==================================
function Invoke-Rollback {
  Write-Host "`n=== ROLLBACK OPERATIONS ===" -ForegroundColor Blue
  $changes = Get-ChangeLog
  if ($changes.Count -eq 0) { Write-Host 'No changes found to rollback.' -ForegroundColor Yellow; return }
  Write-Host ("Found {0} changes that can be rolled back:" -f $changes.Count) -ForegroundColor Yellow
  for ($i=0; $i -lt $changes.Count; $i++) { Write-Host ("[{0}] {1}" -f $i, $changes[$i].Task) -ForegroundColor Cyan }
  $selection = Read-Host "`nEnter change numbers to rollback (comma-separated) or 'all'"
  if ($selection -eq 'all'){ $idx = 0..($changes.Count-1) } else { try { $idx = $selection -split ',' | ForEach-Object { [int]$_.Trim() } } catch { Write-Host 'Invalid selection.' -ForegroundColor Red; return } }
  foreach ($i in $idx) {
    if ($i -lt 0 -or $i -ge $changes.Count) { Write-Host ("Invalid index: {0}" -f $i) -ForegroundColor Red; continue }
    $c = $changes[$i]; $rb = $c.RollbackData
    try{
      switch ($rb.Type) {
        'UserStatus'     { if ($rb.OldStatus) { Enable-LocalUser -Name $rb.Username } else { Disable-LocalUser -Name $rb.Username }; Write-Host ("Rolled back user: {0}" -f $rb.Username) -ForegroundColor Green }
        'UserCreate'     { try { Remove-LocalUser -Name $rb.Username -ErrorAction Stop; Write-Host ("Rolled back created user: {0}" -f $rb.Username) -ForegroundColor Green } catch {} }
        'UserDelete'     { Write-Host ("Cannot auto-restore deleted user: {0}" -f $rb.Username) -ForegroundColor Yellow }
        'Group'          { if($rb.Action -eq 'Add'){ try{ Remove-LocalGroupMember -Group $rb.Group -Member $rb.User -ErrorAction SilentlyContinue | Out-Null }catch{}; Write-Host ("Rolled back group add: {0} <- {1}" -f $rb.Group,$rb.User) -ForegroundColor Green } }
        'Service'        { Set-Service -Name $rb.ServiceName -StartupType $rb.OldStartType; if ($rb.OldStatus -eq 'Running'){ Start-Service -Name $rb.ServiceName }; Write-Host ("Rolled back service: {0}" -f $rb.ServiceName) -ForegroundColor Green }
        'Registry'       { if ($null -ne $rb.OldValue) { Set-ItemProperty -Path $rb.Path -Name $rb.Name -Value $rb.OldValue } else { Remove-ItemProperty -Path $rb.Path -Name $rb.Name -ErrorAction SilentlyContinue }; Write-Host ("Rolled back registry: {0}\{1}" -f $rb.Path,$rb.Name) -ForegroundColor Green }
        'WindowsFeature' { if ($rb.OldState -eq 'Enabled') { Enable-WindowsOptionalFeature -Online -FeatureName $rb.FeatureName -NoRestart }; Write-Host ("Rolled back feature: {0}" -f $rb.FeatureName) -ForegroundColor Green }
        'FirewallProfile'{ try{ & netsh advfirewall set $($rb.Profile.ToLower())profile state $(if($rb.OldEnabled){"on"}else{"off"}) | Out-Null }catch{}; Write-Host ("Rolled back firewall: {0}" -f $rb.Profile) -ForegroundColor Green }
        'FirewallRule'   { if ($rb.OldState -eq 'True') { try{ & netsh advfirewall firewall set rule name="$($rb.RuleName)" new enable=yes | Out-Null }catch{} }; Write-Host ("Rolled back rule: {0}" -f $rb.RuleName) -ForegroundColor Green }
      }
    }catch{ Write-Host ("Failed rollback for {0}: {1}" -f $c.Task,$_.Exception.Message) -ForegroundColor Red }
  }
}

# ================================ Orchestrator ===============================
function Main {
  Write-Host "Windows Security Automation – Final" -ForegroundColor Green
  Write-Host "============================================================`n" -ForegroundColor Green

  if ($Rollback) { Invoke-Rollback; return }

  if($BaselineExport){ Export-Baseline -Path (if($BaselineImport){$BaselineImport}else{"C:\SecurityScript\baseline.json"}) }

  if(-not $Audit){
    $confirm = Read-Host "This will apply security changes. Continue? (y/N)"
    if($confirm -notmatch '^[Yy]'){ Write-Host 'Operation cancelled.' -ForegroundColor Yellow; return }
  } else {
    Write-Host 'Audit-only mode: No changes will be made.' -ForegroundColor Cyan
  }

  # Core
  if(Test-InScope 'Users'){ Set-UserAccounts }
  if(Test-InScope 'AccountSpec'){ Set-AccountSpec }
  if(Test-InScope 'Features'){ Set-WindowsFeatures }
  if(Test-InScope 'Firewall'){ Set-FirewallConfig }
  if(Test-InScope 'Services'){ Set-ServicesState }
  if(Test-InScope 'Registry'){ Set-RegistrySecurity }
  if(Test-InScope 'Passwords'){ Set-PasswordPolicy }
  if(Test-InScope 'AuditPolicy'){ Set-AuditPolicy }

  # Defense
  if(Test-InScope 'PSLogging'){ Enable-PSLogging }
  if(Test-InScope 'Defender'){ Set-DefenderBaseline }
  if(Test-InScope 'ASR'){ Set-ASRRules }
  if(Test-InScope 'ExploitProtection'){ Set-ExploitProtection }

  # Platform
  if(Test-InScope 'BitLocker'){ Enable-BitLockerOSDrive }
  if(Test-InScope 'WindowsUpdate'){ Set-WindowsUpdatePolicy }
  if(Test-InScope 'RDP'){ Set-RDPSecurity }
  if(Test-InScope 'SMB'){ Set-SMBHardening }
  if(Test-InScope 'TLS'){ Set-TlsSchannel }
  if(Test-InScope 'EventLogs'){ Set-EventLogSizing }
  if(Test-InScope 'SRP'){ Set-SoftwareRestrictionPolicy }
  if(Test-InScope 'OSUpdates'){ Invoke-WindowsUpdates }

  # Summary
  Write-Host "`n=== EXECUTION SUMMARY ===" -ForegroundColor Green
  Write-Host ("Successful: {0}" -f $script:Results.Successful.Count) -ForegroundColor Green
  Write-Host ("Failed:     {0}" -f $script:Results.Failed.Count)     -ForegroundColor Red
  Write-Host ("Skipped:    {0}" -f $script:Results.Skipped.Count)    -ForegroundColor Yellow
  Write-Host ("Audited:    {0}" -f $script:Results.Audited.Count)    -ForegroundColor Cyan

  if($script:Results.Failed.Count -gt 0){
    Write-Host "`nFailed Operations:" -ForegroundColor Red
    foreach($f in $script:Results.Failed){
      Write-Host ("  - {0}: {1}" -f $f.Task, $f.Details) -ForegroundColor Red
    }
  }

  Write-ExecutionLog
  if ($script:Changes.Count -gt 0) {
    Write-Host "`nTo rollback changes: .\script.ps1 -Rollback" -ForegroundColor Cyan
  }
  Write-Host "`nDone. Some settings may require a restart." -ForegroundColor Yellow
}

Main
