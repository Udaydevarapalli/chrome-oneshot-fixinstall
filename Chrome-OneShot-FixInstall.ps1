<# Chrome-OneShot-FixInstall.ps1
 - Downloads Chrome Enterprise MSI (x64/x86)
 - Verifies Authenticode signature (Google LLC)
 - Cleans remnants (best-effort), resets Windows Installer, ensures services
 - Installs Chrome silently with full logging (+ retry as repair on common failures)
 - Extracts "Return value 3" snippet if present
 - Writes concise summary + returns useful exit codes
#>

$ErrorActionPreference = 'Stop'
$LogDir  = 'C:\Windows\Temp'
$WorkDir = 'C:\Temp\ChromeFix'
New-Item -ItemType Directory -Force -Path $LogDir, $WorkDir | Out-Null

function Log([string]$m){
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  "$ts  $m" | Tee-Object -FilePath "$LogDir\Chrome_OneShot.log" -Append | Out-Null
}

# --- Admin check ---
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if(-not $IsAdmin){ Write-Error "Run as Administrator."; exit 1 }

Log "==== Start Chrome OneShot ===="

# --- Choose installer URL (official Google) ---
$arch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
if($arch -like '*64*'){
  $url = 'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi'
}else{
  $url = 'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise.msi'
}
$msiPath = Join-Path $WorkDir ([IO.Path]::GetFileName($url))
Log "Selected URL: $url"

# --- Download (BITS -> Invoke-WebRequest fallback) ---
try{
  try{
    Start-BitsTransfer -Source $url -Destination $msiPath -ErrorAction Stop
    Log "Downloaded via BITS -> $msiPath"
  }catch{
    Log "BITS failed ($($_.Exception.Message)), trying Invoke-WebRequest"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $msiPath -UseBasicParsing
    Log "Downloaded via Invoke-WebRequest -> $msiPath"
  }
}catch{
  Write-Error "Failed to download Chrome: $($_.Exception.Message)"
  exit 2
}

# --- Verify Authenticode signature (defense-in-depth) ---
try{
  $sig = Get-AuthenticodeSignature -LiteralPath $msiPath
  if($sig.Status -ne 'Valid' -or ($sig.SignerCertificate.Subject -notmatch 'CN=Google LLC')){
    Write-Error "MSI signature invalid or not from Google LLC. Status=$($sig.Status) Subject=$($sig.SignerCertificate.Subject)"
    exit 3
  }
  Log "Authenticode OK: $($sig.SignerCertificate.Subject)"
}catch{
  Log "Signature check failed: $($_.Exception.Message)"; exit 3
}

# --- Ensure TEMP is writable (fallback to C:\TempAlt) ---
try{
  $testFile = Join-Path ([IO.Path]::GetTempPath()) "msi_write_test_$([guid]::NewGuid().ToString('n')).tmp"
  Set-Content $testFile "ok" -Encoding ASCII -Force; Remove-Item $testFile -Force
  Log "TEMP OK: $([IO.Path]::GetTempPath())"
}catch{
  $alt = 'C:\TempAlt'; New-Item -ItemType Directory -Force -Path $alt | Out-Null
  [Environment]::SetEnvironmentVariable('TEMP',$alt,'Process')
  [Environment]::SetEnvironmentVariable('TMP',$alt,'Process')
  Log "TEMP not writable. Switched to $alt for this process."
}

# --- Kill Chrome/updater processes ---
'chrome','chrome.exe','GoogleUpdate','GoogleCrashHandler','GoogleCrashHandler64' |
  ForEach-Object { Get-Process $_ -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }
Log "Killed Chrome/Google updater processes if present."

# --- Remove common remnants (best-effort) ---
foreach($p in @(
  "$env:ProgramFiles\Google\Chrome",
  "$env:ProgramFiles(x86)\Google\Chrome",
  "$env:LOCALAPPDATA\Google\Chrome",
  "$env:LOCALAPPDATA\Google\Chromium"
)){
  try{ if(Test-Path $p){ Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue; Log "Deleted $p" } }catch{ Log "Could not delete $p" }
}
foreach($rk in @(
  'HKLM:\SOFTWARE\Google\Chrome',
  'HKLM:\SOFTWARE\WOW6432Node\Google\Chrome',
  'HKCU:\SOFTWARE\Google\Chrome'
)){
  try{ if(Test-Path $rk){ Remove-Item $rk -Recurse -Force -ErrorAction SilentlyContinue; Log "Removed $rk" } }catch{ Log "Could not remove $rk" }
}

# --- Reset Windows Installer + ensure services ---
try{
  Start-Process msiexec.exe -ArgumentList '/unregister' -Wait -WindowStyle Hidden
  Start-Process msiexec.exe -ArgumentList '/regserver'  -Wait -WindowStyle Hidden
  Log 'Windows Installer re-registered.'
}catch{ Log "msiexec reset error: $($_.Exception.Message)" }

foreach($svc in 'msiserver','BITS','wuauserv'){
  try{
    $s = Get-Service $svc -ErrorAction SilentlyContinue
    if($s){
      if($s.StartType -eq 'Disabled'){ Set-Service $svc -StartupType Manual; Log "$svc was Disabled -> Manual" }
      if($s.Status -ne 'Running'){ Start-Service $svc -ErrorAction SilentlyContinue; Log "Started $svc" } else { Log "$svc already running" }
    }
  }catch{ Log "Service $svc error: $($_.Exception.Message)" }
}

# --- Pending reboot warning ---
$pending = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
  'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations'
) | Where-Object { Test-Path $_ }
if($pending){ Log 'WARNING: Pending reboot detected. A reboot may be required for success.' }

# --- Install (silent) ---
$stamp  = (Get-Date).ToString('yyyyMMdd_HHmmss')
$msiLog = Join-Path $LogDir "Chrome_MSI_$stamp.log"
# ADD: /qn and force per-machine; suppress launch; suppress "switch to Chrome" UI if any
$msiArgs = @(
  '/i', "`"$msiPath`"",
  '/L*V', "`"$msiLog`"",
  '/qn', '/norestart',
  'ALLUSERS=1', 'MSIINSTALLPERUSER=0', 'REBOOT=ReallySuppress',
  'DO_NOT_LAUNCH=1', 'SUPPRESS_SWITCH_TO_CHROME=1'
) -join ' '

Log "Running: msiexec $msiArgs"
$p = Start-Process msiexec.exe -ArgumentList $msiArgs -PassThru -Wait -WindowStyle Hidden
$code = $p.ExitCode
Log "MSI exit code: $code"

# --- Retry as repair on common transient failures (e.g., 1603) ---
if($code -ne 0){
  Log 'Attempting quick repair retry...'
  $repairArgs = @(
    '/fvamus', "`"$msiPath`"",
    '/L*V', "`"$msiLog`"",
    '/qn', '/norestart',
    'ALLUSERS=1', 'MSIINSTALLPERUSER=0', 'REBOOT=ReallySuppress',
    'DO_NOT_LAUNCH=1', 'SUPPRESS_SWITCH_TO_CHROME=1'
  ) -join ' '
  Log "Running: msiexec $repairArgs"
  $p2 = Start-Process msiexec.exe -ArgumentList $repairArgs -PassThru -Wait -WindowStyle Hidden
  $code = $p2.ExitCode
  Log "Repair exit code: $code"
}

# --- Extract failure snippet (Return value 3) ---
if(Test-Path $msiLog){
  try{
    $lines = Get-Content -LiteralPath $msiLog -ErrorAction SilentlyContinue
    $hit = $lines | Select-String -Pattern 'Return value 3' | Select-Object -First 1
    if($hit){
      $idx = $hit.LineNumber
      $start=[Math]::Max(0,$idx-40); $end=[Math]::Min($lines.Count-1,$idx+10)
      $snippet = $lines[$start..$end]
      $snipPath = "$LogDir\Chrome_Failure_Snippet_$stamp.txt"
      ($snippet -join "`n") | Out-File -FilePath $snipPath -Encoding utf8 -Force
      Log "Failure snippet: $snipPath"
    } else {
      Log "No 'Return value 3' marker found in log."
    }
  }catch{ Log "Snippet extraction error: $($_.Exception.Message)" }
}else{
  Log 'No MSI log produced.'
}

# --- Summary + exit code ---
$summary = @()
$summary += "Installer : $msiPath"
$summary += "MSI Log   : $msiLog"
$summary += "Main Log  : $LogDir\Chrome_OneShot.log"
if($pending){ $summary += "Note     : Pending reboot was detected. If install failed, reboot and try again." }
$summary += "Result    : ExitCode=$code (0=Success)"
$summaryText = ($summary -join [Environment]::NewLine)

Log "==== Done. Logs in $LogDir ===="
Write-Host "`n$summaryText`n"

exit $code
