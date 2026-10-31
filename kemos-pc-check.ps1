# =============================================================================
# made-by-kemo | PC Forensic Check v5.2 (Paged UI & Custom Progress Bars)
# made-by-kemo | Run as Administrator. Output -> $env:USERPROFILE\Desktop\PC-Check
# =============================================================================
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# =============================================================================
# LOGIN & HWID LOCK SYSTEM
# =============================================================================
Clear-Host
Write-Host "`n=== made-by-kemo | Secure Login ===`n" -ForegroundColor Cyan
$user = Read-Host "username"
$securePass = Read-Host "password" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass)
$plainPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

$isValidUser = $false
if ($user -eq 'kemo' -and $plainPass -eq '6gup') { $isValidUser = $true }
elseif ($user -eq 'dieshire' -and $plainPass -eq 'dieshire') { $isValidUser = $true }

if (-not $isValidUser) {
    Write-Host "`nCredentials invalid.`n" -ForegroundColor Red
    return
}

$mGuid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
$cpuId = (Get-CimInstance Win32_Processor).ProcessorId
$currentHwid = "$mGuid-$cpuId"

$authDir = "$env:APPDATA\kemo-check"
$authFile = "$authDir\auth.json"
if (-not (Test-Path $authDir)) { New-Item -ItemType Directory -Path $authDir -Force | Out-Null }

$authData = @{}
if (Test-Path $authFile) {
    $json = Get-Content $authFile -Raw | ConvertFrom-Json
    if ($json) { foreach ($prop in $json.PSObject.Properties) { $authData[$prop.Name] = $prop.Value } }
}

if ($authData.ContainsKey($user)) {
    if ($authData[$user] -ne $currentHwid) {
        Write-Host "`nHWID mismatched.`n" -ForegroundColor Red
        return
    }
} else {
    $authData[$user] = $currentHwid
    $authData | ConvertTo-Json | Out-File $authFile -Force
}
Write-Host "`n[SAFE] Login successful. Bound to HWID." -ForegroundColor Green
Start-Sleep -Seconds 2
Clear-Host

# =============================================================================
# FORENSIC CHECK START
# =============================================================================
$Out = "$env:USERPROFILE\Desktop\PC-Check"
$ReportPath = Join-Path $Out "report.txt"
New-Item -ItemType Directory -Path $Out -Force | Out-Null
"made-by-kemo | v5.2 | started $(Get-Date) | User: $user" | Out-File $ReportPath
$script:failCount = 0; $script:warnCount = 0; $script:safeCount = 0
$script:Buffer = @()

function Show-Progress {
    param([int]$Percent)
    $filled = [math]::Floor($Percent / 10)
    $empty = 10 - $filled
    $bar = ("/" * $filled) + ("-" * $empty)
    Write-Host "`r[$bar] $Percent% " -NoNewline -ForegroundColor Cyan
}

function Add-Result {
    param([string]$Tag, [string]$Message)
    $script:Buffer += [PSCustomObject]@{ Tag = $Tag; Message = $Message }
    Add-Content $ReportPath "[$Tag] $Message"
}

function Flush-Results {
    Write-Host "`n" # Move below progress bar
    $c = @{SAFE='Green'; WARN='Yellow'; FAIL='Red'; INFO='Cyan'}
    foreach ($item in $script:Buffer) {
        Write-Host "[$($item.Tag)] $($item.Message)" -ForegroundColor $c[$item.Tag]
        switch($item.Tag){ SAFE{$script:safeCount++} WARN{$script:warnCount++} FAIL{$script:failCount++} }
    }
    $script:Buffer = @()
}

function Wait-Pager {
    Write-Host "`nPress Enter to Continue." -ForegroundColor DarkGray
    Read-Host | Out-Null
    Clear-Host
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(-not $isAdmin) { Add-Result WARN "Not elevated - results may be limited." }

$trustedSigners = @(
    'Logitech', 'Logitech Inc', 'Logitech Europe S.A.', 'Microsoft', 'Microsoft Corporation', 'Microsoft Windows',
    'NVIDIA', 'NVIDIA Corporation', 'AMD', 'Advanced Micro Devices', 'Advanced Micro Devices, Inc.', 'Intel', 'Intel Corporation',
    'Realtek', 'Realtek Semiconductor', 'Razer', 'Razer Inc', 'Corsair', 'Corsair Memory', 'SteelSeries', 'SteelSeries ApS',
    'Valve', 'Valve Corp', 'Valve Corporation', 'Epic Games', 'Epic Games, Inc.', 'Blizzard', 'Blizzard Entertainment',
    'Riot Games', 'Riot Games, Inc.', 'Google', 'Google LLC', 'Mozilla', 'Mozilla Corporation', 'Discord', 'Discord Inc.',
    'Spotify', 'Spotify AB', 'Dropbox', 'Dropbox, Inc', 'Apple', 'Apple Inc.', 'Adobe', 'Adobe Inc.', 'Adobe Systems',
    'Oracle', 'Oracle America', 'VMware', 'VMware, Inc.', 'Malwarebytes', 'Malwarebytes Corporation', 'Bitdefender', 'Bitdefender SRL',
    'Kaspersky', 'Kaspersky Lab', 'ESET', 'ESET, spol. s r.o.', 'Avast', 'Avast Software', 'AVG', 'AVG Technologies',
    'CCleaner', 'Piriform', 'Java', 'Oracle America, Inc.', 'Python', 'Python Software Foundation', 'GitHub', 'GitHub, Inc.',
    'JetBrains', 'JetBrains s.r.o.', 'Zoom', 'Zoom Video Communications', 'Slack', 'Slack Technologies', 'TeamViewer', 'TeamViewer Germany GmbH',
    'AnyDesk', 'AnyDesk Software GmbH'
)

function Test-TrustedSigner {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return $null }
    if ($FilePath -match 'Logitech|LGHUB') { return 'Logitech (Path Match)' }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        if ($sig.Status -ne 'Valid') { return $null }
        $signer = $sig.SignerCertificate.Subject
        foreach ($t in $trustedSigners) { if ($signer -like "*$t*") { return $signer } }
    } catch {}
    return $null
}

$highSignal = @('severe', 'matcha', 'spectre', 'aimbot', 'triggerbot', 'wallhack', 'silentaim', 'injector', 'fatality', 'gamesense', 'neverlose', 'onetap', 'legendware', 'primordial', 'skeet', 'memesense', 'nixware', 'aimware', 'pandora', 'weave', 'phantom', 'midnight', 'vape', 'entropy', 'sapphire', 'hvh', 'aimassist', 'radarhack', 'xeno', 'madium', 'potassium', 'volt')

# =============================================================================
# STEP 1 - System Info & HWID
# =============================================================================
Write-Host "=== STEP 1 - System Info & HWID ===" -ForegroundColor Cyan
for($i=0; $i -le 100; $i+=10) { Show-Progress $i; Start-Sleep -Milliseconds 30 }
try {
    Get-ComputerInfo | Out-File "$Out\system-info.txt"
    $volSerial = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").VolumeSerialNumber
    $biosSerial = (Get-CimInstance Win32_BIOS).SerialNumber
    $baseboard = (Get-CimInstance Win32_BaseBoard).SerialNumber
    $hwidData = "=== HWID ===`nMachine GUID: $mGuid`nBIOS: $biosSerial`nMotherboard: $baseboard`nCPU ID: $cpuId`nC: Serial: $volSerial"
    $hwidData | Out-File "$Out\hwid.txt" -Force
    Add-Result SAFE "HWID logged to hwid.txt"
} catch { Add-Result WARN "System info failed: $_" }
Flush-Results; Wait-Pager

# =============================================================================
# STEP 2 - Full PC & USB .cfg Inspection
# =============================================================================
Write-Host "=== STEP 2 - Full PC & USB .cfg Inspection ===" -ForegroundColor Cyan
$drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3 OR DriveType=2" | Select-Object -ExpandProperty DeviceID
$cfgFiles = @()
foreach ($d in $drives) {
    $cfgFiles += Get-ChildItem -Path "$d\" -Filter "*.cfg" -File -Recurse -Force -ErrorAction SilentlyContinue
}

if ($cfgFiles.Count -gt 0) {
    $i = 0
    foreach ($cfg in $cfgFiles) {
        $i++
        $pct = [math]::Round(($i / $cfgFiles.Count) * 100)
        Show-Progress $pct
        $content = Get-Content $cfg.FullName -Raw -ErrorAction SilentlyContinue
        $isSusp = $false
        foreach ($k in $highSignal) { if ($content -match "(?i)$k") { $isSusp = $true; break } }
        if ($isSusp) { Add-Result FAIL "Suspicious .cfg: $($cfg.FullName)" } 
        else { Add-Result SAFE "Clean .cfg: $($cfg.FullName)" }
    }
} else {
    for($i=0; $i -le 100; $i+=10) { Show-Progress $i; Start-Sleep -Milliseconds 20 }
    Add-Result SAFE "No .cfg files found on fixed or USB drives."
}
Flush-Results; Wait-Pager

# =============================================================================
# STEP 3 - Running Processes
# =============================================================================
Write-Host "=== STEP 3 - Running Processes ===" -ForegroundColor Cyan
$procs = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
$i = 0
foreach($p in $procs) {
    $i++
    Show-Progress ([math]::Round(($i/$procs.Count)*100))
    if(-not $p.ExecutablePath) { continue }
    if(Test-TrustedSigner -FilePath $p.ExecutablePath) { continue }
    $sig = Get-AuthenticodeSignature -FilePath $p.ExecutablePath -ErrorAction SilentlyContinue
    if ($sig.Status -ne 'Valid') { Add-Result WARN "UNSIGNED Process: $($p.Name) -> $($p.ExecutablePath)" }
}
if ($script:Buffer.Count -eq 0) { Add-Result SAFE "No unsigned or suspicious processes found." }
Flush-Results; Wait-Pager

# =============================================================================
# STEP 4 - USB Executables & Injection Traces
# =============================================================================
Write-Host "=== STEP 4 - USB Executables & Injection Traces ===" -ForegroundColor Cyan
Show-Progress 10
$usbDrives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" | Select-Object -ExpandProperty DeviceID
if ($usbDrives) { Add-Result WARN "Removable USB Drives currently attached: $($usbDrives -join ', ')" }
Show-Progress 30

$pf = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue
foreach ($p in $pf) {
    if ($p.Name -match '^VOLUME_') { Add-Result WARN "USB EXE Executed (Prefetch): $($p.Name) at $($p.LastWriteTime)" }
}
Show-Progress 60

try {
    $since = (Get-Date).AddDays(-7)
    $sec = @(Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688; StartTime=$since } -MaxEvents 1000 -ErrorAction SilentlyContinue)
    $usbEvHits = 0
    foreach ($ev in $sec) {
        if ($ev.Message -match 'New Process Name:\s+([D-Z]:\\.+\.exe)') {
            Add-Result FAIL "EXE Executed from USB (Event 4688): $($matches[1].Trim()) at $($ev.TimeCreated)"
            $usbEvHits++
        }
    }
    if ($usbEvHits -eq 0) { Add-Result SAFE "No USB EXE execution found in Event Logs." }
} catch {}
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# STEP 5 - Keyword File Scan
# =============================================================================
Write-Host "=== STEP 5 - Keyword File Scan ===" -ForegroundColor Cyan
$roots = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "C:\ProgramData")
$allFiles = @()
foreach($root in $roots) { if (Test-Path $root) { $allFiles += Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue } }

if ($allFiles.Count -gt 0) {
    $i = 0
    foreach ($f in $allFiles) {
        $i++
        Show-Progress ([math]::Round(($i/$allFiles.Count)*100))
        foreach($k in $highSignal) { 
            if($f.Name -like "*$k*") { Add-Result FAIL "Keyword file: $($f.FullName)"; break } 
        }
    }
} else {
    for($i=0; $i -le 100; $i+=10) { Show-Progress $i; Start-Sleep -Milliseconds 20 }
}
if ($script:Buffer.Count -eq 0) { Add-Result SAFE "No keyword file matches found." }
Flush-Results; Wait-Pager

# =============================================================================
# STEP 6 - Forensic Tools (ALL Files Listed)
# =============================================================================
Write-Host "=== STEP 6 - Forensic Tools ===" -ForegroundColor Cyan
$tools = @('BAMParser', 'SavedFilesViewer', 'MFTExplorer', 'DeletedFiles', 'PrefetchViewer', 'ProcessExplorer', 'procexp', 'KAPE')
$drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object -ExpandProperty DeviceID
$i = 0
$foundAny = $false
foreach($tn in $tools) {
    $i++
    Show-Progress ([math]::Round(($i / $tools.Count) * 100))
    foreach($d in $drives) {
        $foundFiles = Get-ChildItem -Path "$d\" -Filter "*$tn*" -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.exe', '.dll', '.msi' }
        foreach ($f in $foundFiles) {
            $foundAny = $true
            $trusted = Test-TrustedSigner -FilePath $f.FullName
            if($trusted) { Add-Result SAFE "[$tn] $($f.FullName) (Trusted)" } 
            elseif($lastLogon -and $f.LastWriteTime -gt $lastLogon) { Add-Result FAIL "[$tn] $($f.FullName) (Modified after logon!)" } 
            else { Add-Result WARN "[$tn] $($f.FullName) (Untrusted)" }
        }
    }
}
if (-not $foundAny) { Add-Result SAFE "No forensic tool files found." }
Flush-Results; Wait-Pager

# =============================================================================
# STEP 7 - Amcache & Shimcache
# =============================================================================
Write-Host "=== STEP 7 - Amcache & Shimcache ===" -ForegroundColor Cyan
Show-Progress 50
$amc = "C:\Windows\AppCompat\Programs\Amcache.hve"
if(Test-Path $amc) { Copy-Item $amc "$Out\Amcache.hve" -Force; Add-Result WARN "Amcache exported to output folder." }
Show-Progress 75
try {
    $shim = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -Name AppCompatCache -ErrorAction Stop).AppCompatCache
    $shimStr = -join ($shim | ForEach-Object { [char]$_ })
    $shimExes = [regex]::Matches($shimStr, '[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+\.exe') | ForEach-Object { $_.Value } | Select-Object -Unique
    if ($shimExes) { foreach ($exe in $shimExes) { Add-Result INFO "[Shimcache] $exe" } }
} catch { Add-Result WARN "Shimcache parse failed." }
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# STEP 8 - BAM / DAM
# =============================================================================
Write-Host "=== STEP 8 - BAM / DAM ===" -ForegroundColor Cyan
Show-Progress 20
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$bam = @("SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\$sid", "SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\$sid")
$bE = @()
foreach($bp in $bam) {
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($bp)
        if($k) {
            foreach($vn in $k.GetValueNames()) {
                $d = $k.GetValue($vn)
                if($d -is [byte[]] -and $d.Length -ge 8) {
                    $dt = [DateTime]::FromFileTime([BitConverter]::ToInt64($d, 0))
                    $bE += [PSCustomObject]@{ Path = $vn; LastExec = $dt }
                }
            }
            $k.Close()
        }
    } catch {}
}
Show-Progress 80
if($bE.Count) {
    foreach($b in $bE) {
        if (Test-TrustedSigner -FilePath $b.Path) { Add-Result SAFE "[BAM] $($b.Path) @ $($b.LastExec)" } 
        else {
            $hit = $false
            foreach($k in $highSignal) { if($b.Path -like "*$k*") { $hit = $true; break } }
            if ($hit) { Add-Result FAIL "[BAM] Cheat match: $($b.Path) @ $($b.LastExec)" } 
            else { Add-Result FAIL "[BAM] Untrusted Execution: $($b.Path) @ $($b.LastExec)" }
        }
    }
} else { Add-Result SAFE "BAM/DAM empty or unreadable." }
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# STEP 9 - Defender Detailed
# =============================================================================
Write-Host "=== STEP 9 - Defender Detailed ===" -ForegroundColor Cyan
Show-Progress 25
try {
    $mp = Get-MpComputerStatus
    $off = @()
    if(-not $mp.RealTimeProtectionEnabled) { $off += 'RealTimeProtection' }
    if(-not $mp.AntivirusEnabled) { $off += 'Antivirus' }
    if($off.Count -gt 0) { Add-Result FAIL "Defender DISABLED: $($off -join ', ')" } else { Add-Result SAFE "Defender enabled." }
} catch {}
Show-Progress 50
try {
    $pref = Get-MpPreference
    if($pref.ExclusionPath) { foreach($e in $pref.ExclusionPath) { Add-Result FAIL "Defender Exclusion: $e" } } else { Add-Result SAFE "No Defender exclusions." }
} catch {}
Show-Progress 75
try {
    $threats = @(Get-MpThreatDetection)
    if($threats.Count -gt 0) { foreach($t in $threats) { Add-Result FAIL "Defender Threat: $($t.ThreatID)" } } else { Add-Result SAFE "No Defender threats." }
} catch {}
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# SUMMARY
# =============================================================================
Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "`n SAFE: $($script:safeCount) WARN: $($script:warnCount) FAIL: $($script:failCount)`n" -ForegroundColor Cyan
Write-Host "Report: $ReportPath" -ForegroundColor Cyan
Write-Host "made-by-kemo | v5.2 | finished $(Get-Date)" -ForegroundColor Cyan
Write-Host "`n=== made-by-kemo | done ===`n" -ForegroundColor Cyan
