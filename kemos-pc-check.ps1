# =============================================================================
#  made-by-kemo | PC Forensic Check v6.1 (Bloodhound, DLLs, Roblox Memory)
#  made-by-kemo | Run as Administrator.
# =============================================================================
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# =============================================================================
#  LOGIN & HWID LOCK SYSTEM
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
#  FORENSIC CHECK START
# =============================================================================
$Out = "$env:USERPROFILE\Desktop\PC-Check"
$ReportPath = Join-Path $Out "report.txt"
New-Item -ItemType Directory -Path $Out -Force | Out-Null
"made-by-kemo | v6.1 | started $(Get-Date) | User: $user" | Out-File $ReportPath
$script:failCount = 0; $script:warnCount = 0; $script:safeCount = 0
$script:Buffer = @()

function Show-Progress {
    param([int]$Percent)
    $filled = [math]::Floor($Percent / 10)
    $empty = 10 - $filled
    $bar = ("/" * $filled) + ("-" * $empty)
    Write-Host "`r[$bar] $Percent%   " -NoNewline -ForegroundColor Cyan
}

function Add-Result {
    param([string]$Tag, [string]$Message)
    $script:Buffer += [PSCustomObject]@{ Tag = $Tag; Message = $Message }
    Add-Content $ReportPath "[$Tag] $Message"
}

function Flush-Results {
    Write-Host "`n" 
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
# STEP 2 - Total PC & USB .cfg Inspection
# =============================================================================
Write-Host "=== STEP 2 - Total PC & USB .cfg Inspection ===" -ForegroundColor Cyan
Write-Host "`nEnumerating ALL .cfg files across every drive..." -ForegroundColor Yellow
$drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3 OR DriveType=2" | Select-Object -ExpandProperty DeviceID
$cfgFiles = @()
foreach ($d in $drives) { $files = cmd.exe /c "dir $d\*.cfg /s /b /a-d" 2>$null; if ($files) { $cfgFiles += $files | Where-Object { $_ -match '\.cfg$' } } }
$cfgFiles = $cfgFiles | Select-Object -Unique
if ($cfgFiles.Count -gt 0) {
    $i = 0
    foreach ($cfg in $cfgFiles) {
        $i++; Show-Progress ([math]::Round(($i / $cfgFiles.Count) * 100))
        $isSusp = $false
        try {
            $bytes = [System.IO.File]::ReadAllBytes($cfg)
            $txt = [System.Text.Encoding]::UTF8.GetString($bytes) + [System.Text.Encoding]::Unicode.GetString($bytes) + [System.Text.Encoding]::ASCII.GetString($bytes)
            foreach ($k in $highSignal) { if ($txt -match "(?i)$k") { $isSusp = $true; break } }
        } catch { Add-Result WARN "Could not read .cfg: $cfg"; continue }
        if ($isSusp) { Add-Result FAIL "Suspicious .cfg: $cfg" } else { Add-Result SAFE "Clean .cfg: $cfg" }
    }
} else { for($i=0; $i -le 100; $i+=10) { Show-Progress $i; Start-Sleep -Milliseconds 20 }; Add-Result SAFE "No .cfg files found." }
Flush-Results; Wait-Pager

# =============================================================================
# STEP 3 - Bloodhound Detection (OBS Plugin Templates)
# =============================================================================
Write-Host "=== STEP 3 - Bloodhound Detection ===" -ForegroundColor Cyan
Show-Progress 50
$obsPaths = @("$env:APPDATA\obs-studio", "$env:ProgramFiles\obs-studio", "${env:ProgramFiles(x86)}\obs-studio")
$bhFound = $false
foreach ($p in $obsPaths) {
    if (Test-Path $p) {
        $bhFolder = Get-ChildItem -Path $p -Filter "*obs plugin templates*" -Directory -Recurse -ErrorAction SilentlyContinue
        if ($bhFolder) {
            Add-Result FAIL "Bloodhound detected! OBS folder found at: $($bhFolder.FullName). This folder is used to hide the Bloodhound cheat overlay."
            $bhFound = $true
        }
    }
}
if (-not $bhFound) { Add-Result SAFE "No 'obs plugin templates' folder found in OBS Studio." }
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# STEP 4 - Process & Memory Integrity
# =============================================================================
Write-Host "=== STEP 4 - Process & Memory Integrity ===" -ForegroundColor Cyan
$procs = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
$i = 0
foreach($p in $procs) {
    $i++; Show-Progress ([math]::Round(($i/$procs.Count)*100))
    if(-not $p.ExecutablePath) { continue }
    if(-not (Test-TrustedSigner -FilePath $p.ExecutablePath)) {
        $sig = Get-AuthenticodeSignature -FilePath $p.ExecutablePath -ErrorAction SilentlyContinue
        if ($sig.Status -ne 'Valid') { Add-Result WARN "UNSIGNED Process: $($p.Name)" }
    }
}
if ($script:Buffer.Count -eq 0) { Add-Result SAFE "No unsigned processes found." }
Flush-Results; Wait-Pager

# =============================================================================
# STEP 5 - Roblox Memory Reader Detection
# =============================================================================
Write-Host "=== STEP 5 - Roblox Memory Reader Detection ===" -ForegroundColor Cyan
Show-Progress 30
$roblox = Get-Process -Name "RobloxPlayerBeta" -ErrorAction SilentlyContinue
if ($roblox) {
    Add-Result INFO "RobloxPlayerBeta is currently running (PID: $($roblox.Id)). Checking for injectors..."
    # Check for known injectors/executors in running processes
    $injectors = Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'xeno|volt|injector|cheat|mem|read|wrd|krnl' }
    if ($injectors) {
        foreach ($inj in $injectors) { Add-Result FAIL "Potential Roblox Injector running: $($inj.Name) (PID: $($inj.ProcessId))" }
    }
    # Check for any unsigned processes running (common for executors)
    foreach ($p in $procs) {
        if ($p.Name -ne 'RobloxPlayerBeta.exe' -and $p.ExecutablePath) {
            if (-not (Test-TrustedSigner -FilePath $p.ExecutablePath)) {
                $sig = Get-AuthenticodeSignature -FilePath $p.ExecutablePath -ErrorAction SilentlyContinue
                if ($sig.Status -ne 'Valid') { Add-Result WARN "Unsigned process running alongside Roblox: $($p.Name)" }
            }
        }
    }
} else {
    Add-Result SAFE "RobloxPlayerBeta is not currently running."
}
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# STEP 6 - DLL Viewer (Unsigned DLLs & Deleted Traces)
# =============================================================================
Write-Host "=== STEP 6 - DLL Viewer ===" -ForegroundColor Cyan
Write-Host "`nScanning for unsigned DLLs and deleted traces..." -ForegroundColor Yellow
$dllDirs = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "C:\ProgramData")
$dllCount = 0
$i = 0
foreach ($d in $dllDirs) {
    if (Test-Path $d) {
        $dlls = Get-ChildItem -Path $d -Filter "*.dll" -File -Recurse -Force -ErrorAction SilentlyContinue
        foreach ($dll in $dlls) {
            $i++
            Show-Progress ([math]::Round(($i / ($dlls.Count + 10)) * 100)) # Fake progress since count varies
            if (-not (Test-TrustedSigner -FilePath $dll.FullName)) {
                $sig = Get-AuthenticodeSignature -FilePath $dll.FullName -ErrorAction SilentlyContinue
                if ($sig.Status -ne 'Valid') {
                    Add-Result FAIL "Unsigned DLL found: $($dll.FullName)"
                    $dllCount++
                }
            }
        }
    }
}

# Check Recycle bin for deleted DLLs
$recycleDirs = Get-ChildItem 'C:\$Recycle.Bin' -Directory -Force -ErrorAction SilentlyContinue
foreach ($dir in $recycleDirs) {
    $iFiles = Get-ChildItem -Path $dir.FullName -Filter '$I*' -File -Force -ErrorAction SilentlyContinue
    foreach ($iFile in $iFiles) {
        if ($iFile.Length -gt 24) {
            $bytes = [System.IO.File]::ReadAllBytes($iFile.FullName)
            # Parse $I file to get original path (UTF-16 string starting at offset 28)
            $origPath = [System.Text.Encoding]::Unicode.GetString($bytes[28..($bytes.Length - 2)]).Trim([char]0)
            if ($origPath -match '\.dll$') { Add-Result WARN "Deleted DLL trace in Recycle Bin: $origPath" }
        }
    }
}

# Check USB Prefetch for DLL execution traces
$pf = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue
foreach ($p in $pf) {
    if ($p.Name -match '^VOLUME_.*\.DLL-') { Add-Result WARN "DLL executed from USB: $($p.Name)" }
}

if ($dllCount -eq 0 -and $script:Buffer.Count -eq 0) { Add-Result SAFE "No unsigned or deleted DLLs found." }
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# STEP 7 - Artifacts & Deleted Files Viewer
# =============================================================================
Write-Host "=== STEP 7 - Artifacts & Deleted Files Viewer ===" -ForegroundColor Cyan
Show-Progress 20
# Recent Files (LNKs)
$recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
if (Test-Path $recentPath) {
    $lnks = Get-ChildItem -Path $recentPath -Filter "*.lnk" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 10
    foreach ($lnk in $lnks) { Add-Result INFO "Recent file artifact: $($lnk.Name) (Accessed: $($lnk.LastWriteTime))" }
}
Show-Progress 50
# Deleted Files (Recycle Bin)
$rbFiles = Get-ChildItem 'C:\$Recycle.Bin' -Force -Recurse -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.Name -notlike '$I*' -and $_.Name -ne 'desktop.ini' }
if ($rbFiles) {
    Add-Result WARN "Found $($rbFiles.Count) deleted files in Recycle Bin:"
    foreach ($rb in $rbFiles) { Add-Result INFO "  Deleted File: $($rb.FullName) (Deleted: $($rb.LastWriteTime))" }
} else { Add-Result SAFE "Recycle Bin is empty." }
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# STEP 8 - Hardware, DMA & Vulnerable Drivers (BYOVD)
# =============================================================================
Write-Host "=== STEP 8 - Hardware & Vulnerable Drivers ===" -ForegroundColor Cyan
Show-Progress 30
$vulnDrivers = @('iqvw64e.sys', 'gdrv.sys', 'winring0.sys', 'ene.sys', 'asio.sys', 'msio.sys', 'cpuz.sys', 'kfridge.sys', 'rtcore64.sys')
$sysDrivers = Get-ChildItem "$env:SystemRoot\System32\drivers" -Filter "*.sys" -ErrorAction SilentlyContinue
foreach ($d in $sysDrivers) { if ($vulnDrivers -contains $d.Name.ToLower()) { Add-Result FAIL "Vulnerable Driver (BYOVD) found: $($d.FullName)" } }
Show-Progress 70
$bcd = (bcdedit /enum {current}) -join "`n"
if ($bcd -match 'testsigning\s+Yes') { Add-Result FAIL "Windows Test Signing is ENABLED." }
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# STEP 9 - USB Executables
# =============================================================================
Write-Host "=== STEP 9 - USB Executables ===" -ForegroundColor Cyan
Show-Progress 50
try {
    $sec = @(Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-7) } -MaxEvents 1000 -ErrorAction SilentlyContinue)
    $usbHits = 0
    foreach ($ev in $sec) {
        if ($ev.Message -match 'New Process Name:\s+([D-Z]:\\.+\.exe)') { Add-Result FAIL "EXE from USB (Event 4688): $($matches[1].Trim())"; $usbHits++ }
    }
    if ($usbHits -eq 0) { Add-Result SAFE "No USB EXE execution found in Event Logs." }
} catch {}
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# STEP 10 - File System: ADS, Keywords, & Entropy
# =============================================================================
Write-Host "=== STEP 10 - File System (ADS, Entropy) ===" -ForegroundColor Cyan
$roots = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "C:\ProgramData")
$allFiles = @()
foreach($root in $roots) { if (Test-Path $root) { $allFiles += Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue } }
$i = 0
foreach ($f in $allFiles) {
    $i++; Show-Progress ([math]::Round(($i/$allFiles.Count)*100))
    $streams = Get-Item -LiteralPath $f.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' }
    if ($streams) { Add-Result WARN "Alternate Data Stream: $($f.FullName)" }
    if ($f.Extension -in '.exe', '.dll' -and $f.Length -gt 1MB -and $f.Length -lt 100MB) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
            $counts = New-Object int[] 256
            foreach ($b in $bytes) { $counts[$b]++ }
            $entropy = 0.0
            foreach ($c in $counts) { if ($c -gt 0) { $p = $c / $bytes.Length; $entropy -= $p * [math]::Log($p, 2) } }
            if ($entropy -gt 7.2) { Add-Result WARN "High Entropy (Packed): $($f.FullName) ($([math]::Round($entropy,2)))" }
        } catch {}
    }
}
Flush-Results; Wait-Pager

# =============================================================================
# STEP 11 - Network, DNS & Hosts File
# =============================================================================
Write-Host "=== STEP 11 - Network & DNS ===" -ForegroundColor Cyan
Show-Progress 50
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
if ((Get-Item $hostsFile).LastWriteTime -gt (Get-Date).AddDays(-2)) { Add-Result WARN "Hosts file recently modified." }
if (Select-String -Path $hostsFile -Pattern 'keyauth|cheat|aimbot' -ErrorAction SilentlyContinue) { Add-Result FAIL "Suspicious hosts entry found." }
foreach($d in (Get-DnsClientCache -ErrorAction SilentlyContinue)) { if ($d.Entry -match 'keyauth|cheat|aimbot') { Add-Result FAIL "Suspicious DNS: $($d.Entry)" } }
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# STEP 12 - Execution History (Amcache, Shimcache, BAM)
# =============================================================================
Write-Host "=== STEP 12 - Execution History ===" -ForegroundColor Cyan
Show-Progress 50
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$bam = @("SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\$sid", "SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\$sid")
foreach($bp in $bam) {
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($bp)
        if($k) {
            foreach($vn in $k.GetValueNames()) {
                $d = $k.GetValue($vn)
                if($d -is [byte[]] -and $d.Length -ge 8) {
                    $dt = [DateTime]::FromFileTime([BitConverter]::ToInt64($d, 0))
                    if (Test-TrustedSigner -FilePath $vn) { Add-Result SAFE "[BAM] $vn" } else { Add-Result FAIL "[BAM] Untrusted Execution: $vn" }
                }
            }
            $k.Close()
        }
    } catch {}
}
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# STEP 13 - Defender Detailed
# =============================================================================
Write-Host "=== STEP 13 - Defender Detailed ===" -ForegroundColor Cyan
Show-Progress 50
try {
    $mp = Get-MpComputerStatus
    if(-not $mp.RealTimeProtectionEnabled -or -not $mp.AntivirusEnabled) { Add-Result FAIL "Defender is DISABLED." } else { Add-Result SAFE "Defender is enabled." }
    $pref = Get-MpPreference
    if($pref.ExclusionPath) { foreach($e in $pref.ExclusionPath) { Add-Result FAIL "Defender Exclusion: $e" } } else { Add-Result SAFE "No Defender exclusions." }
    $threats = @(Get-MpThreatDetection)
    if($threats.Count -gt 0) { foreach($t in $threats) { Add-Result FAIL "Defender Threat: $($t.ThreatID)" } } else { Add-Result SAFE "No Defender threats." }
} catch {}
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# SUMMARY
# =============================================================================
Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "`n  SAFE: $($script:safeCount)  WARN: $($script:warnCount)  FAIL: $($script:failCount)`n" -ForegroundColor Cyan
Write-Host "Report: $ReportPath" -ForegroundColor Cyan
Write-Host "made-by-kemo | v6.1 | finished $(Get-Date)" -ForegroundColor Cyan
Write-Host "`n=== made-by-kemo | done ===`n" -ForegroundColor Cyan
