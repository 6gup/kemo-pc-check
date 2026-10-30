# =============================================================================
# made-by-kemo | PC Forensic Check v4.0 (Deep Scan & Log Parsing)
# made-by-kemo | Run as Administrator. Output -> $env:USERPROFILE\Desktop\PC-Check
# =============================================================================
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

Write-Host "`n=== made-by-kemo | PC Forensic Check v4.0 | starting... ===`n" -ForegroundColor Cyan

$Out = "$env:USERPROFILE\Desktop\PC-Check"
$ReportPath = Join-Path $Out "report.txt"
New-Item -ItemType Directory -Path $Out -Force | Out-Null
"made-by-kemo | v4.0 | started $(Get-Date)" | Out-File $ReportPath

$script:failCount = 0; $script:warnCount = 0; $script:safeCount = 0

function Write-Result {
    param([string]$Tag, [string]$Message)
    $c = @{SAFE='Green'; WARN='Yellow'; FAIL='Red'; INFO='Cyan'}
    $l = "[$Tag] $Message"
    Write-Host $l -ForegroundColor $c[$Tag]
    Add-Content $ReportPath $l
    switch($Tag){ SAFE{$script:safeCount++} WARN{$script:warnCount++} FAIL{$script:failCount++} }
}
function Write-Section {
    param([string]$Title)
    $l = "`n=== $Title ==="
    Write-Host $l -ForegroundColor DarkCyan
    Add-Content $ReportPath $l
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if($isAdmin) { Write-Result INFO "Running as Administrator." }
else { Write-Result WARN "Not elevated - results limited." }

$lastLogon = $null
try {
    $lastLogon = Get-CimInstance Win32_LogonSession -Filter "LogonType=2 OR LogonType=10" | Sort-Object StartTime -Descending | Select-Object -First 1 -ExpandProperty StartTime
} catch {}
if(-not $lastLogon) { try { $lastLogon = (Get-Item $env:USERPROFILE).LastWriteTime } catch {} }
if($lastLogon) { Write-Result INFO "Last interactive logon: $lastLogon" }
else { Write-Result WARN "Last logon unknown." }

# --- Trusted Publishers (Expanded to fix G Hub issue) ---
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
    # Fix G Hub Installer issue: If path contains Logitech, consider safe even if unsigned
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
$watchList = @('isabelle', 'ghostify', 'TIWorker')
$lowSignal = @('esp', 'cfg', 'config', 'dx9')
$suspExt = @('.dll', '.exe', '.sys', '.asi', '.cfg', '.lua', '.js', '.py', '.bat', '.cmd', '.ps1', '.vbs')
$suspPathRx = '\\(Temp|Downloads|Public)\\'

# =============================================================================
Write-Section "STEP 1 - System Information & HWID"
try {
    Get-ComputerInfo | Out-File "$Out\system-info.txt"
    $machineGuid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
    $biosSerial = (Get-CimInstance Win32_BIOS).SerialNumber
    $baseboard = (Get-CimInstance Win32_BaseBoard).SerialNumber
    $cpuId = (Get-CimInstance Win32_Processor).ProcessorId
    $volSerial = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").VolumeSerialNumber

    $hwidData = "=== HWID INFORMATION ===`nMachine GUID: $machineGuid`nBIOS Serial: $biosSerial`nMotherboard Serial: $baseboard`nCPU ID: $cpuId`nC: Volume Serial: $volSerial"
    $hwidData | Out-File "$Out\hwid.txt" -Force
    
    Write-Result INFO "Machine GUID: $machineGuid"
    Write-Result INFO "BIOS Serial: $biosSerial"
    Write-Result INFO "Motherboard Serial: $baseboard"
    Write-Result INFO "CPU ID: $cpuId"
    Write-Result SAFE "HWID logged to hwid.txt"
} catch { Write-Result WARN "System info/HWID failed: $_" }

# =============================================================================
Write-Section "STEP 2 - Running Processes (Unsigned Scan)"
$procs = Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
$procs | Export-Csv "$Out\processes.csv" -NoTypeInformation
$s = @()
foreach($p in $procs) {
    if(-not $p.ExecutablePath) { continue }
    $trusted = Test-TrustedSigner -FilePath $p.ExecutablePath
    if($trusted) { continue }
    
    $isSuspicious = $false
    if($p.ExecutablePath -match $suspPathRx) { $isSuspicious = $true }
    foreach($k in $highSignal) { if($p.Name -like "*$k*") { $isSuspicious = $true; break } }
    
    # Check Signature of running process
    $sig = Get-AuthenticodeSignature -FilePath $p.ExecutablePath -ErrorAction SilentlyContinue
    if ($sig.Status -ne 'Valid') {
        Write-Result WARN "UNSIGNED Process: $($p.Name) PID $($p.ProcessId) -> $($p.ExecutablePath)"
        $isSuspicious = $true
    }

    if($isSuspicious) { $s += $p }
}
if($s.Count -eq 0) { Write-Result SAFE "No suspicious or unsigned processes found." }

Write-Section "STEP 2b - Watchlist (TIWorker / Isabelle / Ghostify)"
foreach($w in $watchList) {
    $found = Get-CimInstance Win32_Process | Where-Object { $_.Name -like "*$w*" }
    if($found) {
        foreach($p in $found) {
            $path = $p.ExecutablePath
            if($w -eq 'TIWorker' -and $path -notlike '*\System32\*') { Write-Result FAIL "TIWorker running from unusual path: $path" }
            else {
                $sig = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
                if($sig.Status -ne 'Valid') { Write-Result FAIL "$w process UNSIGNED at: $path" }
                else { Write-Result WARN "$w process running (signed by $($sig.SignerCertificate.Subject))" }
            }
        }
    }
}

# =============================================================================
Write-Section "STEP 3 - Installed Programs"
$inst = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*, HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation
$inst | Export-Csv "$Out\installed-programs.csv" -NoTypeInformation
foreach($i in $inst) {
    if(-not $i.DisplayName) { continue }
    $isTrusted = $false
    foreach($t in $trustedSigners) { if($i.Publisher -like "*$t*") { $isTrusted = $true; break } }
    if($isTrusted) { continue }
    foreach($k in $highSignal) {
        if($i.DisplayName -like "*$k*") { Write-Result FAIL "Susp installed: $($i.DisplayName) [$($i.Publisher)]"; break }
    }
}

# =============================================================================
Write-Section "STEP 4 - Persistence & Services"
$bS = Get-CimInstance Win32_Service | Where-Object { $_.PathName -match $suspPathRx }
foreach($x in $bS) {
    $exe = ($x.PathName -replace '^"([^"]+)".*', '$1') -replace '^(\S+\.exe).*', '$1'
    if(-not (Test-TrustedSigner -FilePath $exe)) { Write-Result FAIL "Svc from bad path: $($x.Name) -> $($x.PathName)" }
}
$bT = Get-ScheduledTask | Where-Object { ($_.Actions.Execute -join ' ') -match $suspPathRx }
foreach($x in $bT) { Write-Result FAIL "Bad task: $($x.TaskPath)$($x.TaskName)" }
if(-not $bS -and -not $bT) { Write-Result SAFE "No suspicious persistence found." }

# =============================================================================
Write-Section "STEP 5 - USB History & Execution"
# 1. Get USB History from Registry
$usbReg = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
$usbDevices = Get-ChildItem -Path $usbReg -ErrorAction SilentlyContinue
if ($usbDevices) {
    Write-Result WARN "USB Insertion History Found (Registry):"
    foreach ($dev in $usbDevices) {
        $friendlyName = (Get-ItemProperty -Path $dev.PSPath -Name FriendlyName -ErrorAction SilentlyContinue).FriendlyName
        if (-not $friendlyName) { $friendlyName = $dev.PSChildName }
        Write-Result INFO " USB Device: $friendlyName"
    }
} else { Write-Result SAFE "No USB history found in registry." }

# 2. Check Prefetch for EXEs run from USB Drives (D:, E:, F:, etc)
$pf = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue
if ($pf) {
    $usbExes = @()
    foreach ($p in $pf) {
        # Prefetch naming convention for USB: VOLUME_{GUID}_{EXENAME}.PF
        if ($p.Name -match '^VOLUME_') {
            $usbExes += $p.Name
            Write-Result WARN "Executable run from external volume: $($p.Name) (Last Write: $($p.LastWriteTime))"
        }
    }
    if ($usbExes.Count -eq 0) { Write-Result SAFE "No external volume execution traces found in Prefetch." }
}

# =============================================================================
Write-Section "STEP 6 - Keyword & Unsigned File Scan"
$roots = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\AppData\Local", "$env:USERPROFILE\AppData\Roaming", "$env:USERPROFILE\AppData\LocalLow", "$env:TEMP", "C:\ProgramData", "C:\Windows\Temp")
$hits = New-Object System.Collections.Generic.List[object]
foreach($root in $roots) {
    Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $suspExt -contains $_.Extension.ToLower() } | ForEach-Object {
        $f = $_
        $sig = $null
        foreach($k in $highSignal) { if($f.Name -like "*$k*") { $sig = 'HIGH'; break } }
        if(-not $sig) { foreach($k in $watchList) { if($f.Name -like "*$k*") { $sig = 'WATCH'; break } } }
        
        # Check if unsigned EXE
        $isUnsigned = $false
        if ($f.Extension -eq '.exe' -or $f.Extension -eq '.dll') {
            $auth = Get-AuthenticodeSignature -FilePath $f.FullName -ErrorAction SilentlyContinue
            if ($auth.Status -ne 'Valid') { $isUnsigned = $true }
        }

        if(($sig -or $isUnsigned) -and -not (Test-TrustedSigner -FilePath $f.FullName)) {
            $hits.Add([PSCustomObject]@{
                Signal = $(if($sig){$sig}else{'UNSIGNED'}); FullName = $f.FullName; Length = $f.Length; LastWriteTime = $f.LastWriteTime
            })
        }
    }
}
$hits | Export-Csv "$Out\keyword-files.csv" -NoTypeInformation
foreach($h in $hits) {
    if ($h.Signal -eq 'HIGH') { Write-Result FAIL "High-signal file: $($h.FullName)" }
    elseif ($h.Signal -eq 'UNSIGNED') { Write-Result WARN "Unsigned Executable: $($h.FullName)" }
    else { Write-Result WARN "Watchlist file: $($h.FullName)" }
}
if($hits.Count -eq 0) { Write-Result SAFE "No suspicious or unsigned files found in common paths." }

# =============================================================================
Write-Section "STEP 7 - Forensic Tools (BAMParser, MFTExplorer, etc.)"
$tools = @('BAMParser', 'SavedFilesViewer', 'MFTExplorer', 'DeletedFiles', 'PrefetchViewer', 'ProcessExplorer', 'procexp')
$tRoots = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents", "$env:PROGRAMFILES", "${env:ProgramFiles(x86)}", "C:\ProgramData", "C:\Tools")
foreach($tn in $tools) {
    $found = $null
    foreach($r in $tRoots) {
        if (Test-Path $r) {
            $found = Get-ChildItem -Path $r -Filter "$tn*" -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.exe', '.dll', '.msi', '.zip' } | Select-Object -First 1
            if($found) { break }
        }
    }
    
    if($found) {
        $trusted = Test-TrustedSigner -FilePath $found.FullName
        if($trusted) { Write-Result SAFE "$tn found and trusted ($trusted)." }
        else {
            $m = $found.LastWriteTime
            if($lastLogon -and $m -gt $lastLogon) { Write-Result FAIL "$tn at $($found.FullName) MODIFIED after last logon ($m)." }
            else { Write-Result WARN "$tn found at $($found.FullName) (Modified: $m). Check its output data!" }
        }
        
        # Attempt to find generated CSVs from these tools
        $csvOut = Get-ChildItem -Path $found.Directory -Filter "*.csv" -ErrorAction SilentlyContinue | Select-Object -First 3
        if ($csvOut) {
            foreach ($csv in $csvOut) { Write-Result INFO " Found output file: $($csv.FullName)" }
        }
    } else { Write-Result SAFE "$tn not found." }
}

# =============================================================================
Write-Section "STEP 8 - Amcache & Shimcache (Extracting File Names)"
# Shimcache Raw Byte Extraction (Extracts readable strings ending in .exe)
try {
    $shim = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -Name AppCompatCache -ErrorAction Stop).AppCompatCache
    $shimStr = -join ($shim | ForEach-Object { [char]$_ })
    $shimExes = [regex]::Matches($shimStr, '[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+\.exe') | ForEach-Object { $_.Value } | Select-Object -Unique
    if ($shimExes) {
        Write-Result WARN "Shimcache contains $($shimExes.Count) EXE traces. Listing all:"
        foreach ($exe in $shimExes) { Write-Result INFO " [Shimcache] $exe" }
    }
} catch { Write-Result WARN "Could not parse Shimcache natively." }

# Amcache Hive (Copy for manual parsing since we can't parse binary natively)
$amc = "C:\Windows\AppCompat\Programs\Amcache.hve"
if(Test-Path $amc) {
    Copy-Item $amc "$Out\Amcache.hve" -Force
    Write-Result WARN "Amcache hive exported to output folder. Use AmcacheParser to view $($amc)."
}

# =============================================================================
Write-Section "STEP 9 - BAM / DAM (All Entries)"
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$bam = @("SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\$sid", "SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\$sid")
$bE = New-Object System.Collections.Generic.List[object]
foreach($bp in $bam) {
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($bp)
        if($k) {
            foreach($vn in $k.GetValueNames()) {
                $d = $k.GetValue($vn)
                if($d -is [byte[]] -and $d.Length -ge 8) {
                    $dt = [DateTime]::FromFileTime([BitConverter]::ToInt64($d, 0))
                    $bE.Add([PSCustomObject]@{ Path = $vn; LastExec = $dt })
                }
            }
            $k.Close()
        }
    } catch {}
}
if($bE.Count) {
    Write-Result INFO "BAM/DAM Parsed $($bE.Count) executed programs. Listing all:"
    foreach($b in $bE) {
        $isTrusted = (Test-TrustedSigner -FilePath $b.Path)
        if ($isTrusted) { Write-Result SAFE " [BAM] $($b.Path) @ $($b.LastExec)" }
        else {
            $hit = $false
            foreach($k in $highSignal) { if($b.Path -like "*$k*") { $hit = $true; break } }
            if ($hit) { Write-Result FAIL " [BAM] Cheat match: $($b.Path) @ $($b.LastExec)" }
            else { Write-Result INFO " [BAM] $($b.Path) @ $($b.LastExec)" }
        }
    }
}

# =============================================================================
Write-Section "STEP 10 - Event Viewer (Unsigned EXE & KeyAuth)"
try {
    $since = (Get-Date).AddDays(-7)
    # Check DNS for KeyAuth
    $dnsHits = @()
    foreach($d in (Get-DnsClientCache -ErrorAction SilentlyContinue)) {
        if ($d.Entry -match 'keyauth|cheat|aimbot') { $dnsHits += "$($d.Entry) -> $($d.Data)" }
    }
    if ($dnsHits) { foreach ($h in $dnsHits) { Write-Result FAIL "Suspicious DNS: $h" } }
    else { Write-Result SAFE "No KeyAuth domains in DNS cache." }

    # Event ID 4688 (Process Creation) - Look for Unsigned EXEs
    $sec = @(Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688; StartTime=$since } -MaxEvents 150 -ErrorAction SilentlyContinue)
    if($sec.Count) {
        Write-Result INFO "Analyzing $($sec.Count) Process Creation events..."
        foreach ($ev in $sec) {
            # Extract EXE path from 4688 Message
            if ($ev.Message -match 'New Process Name:\s+(.+)') {
                $exePath = $matches[1].Trim()
                if (Test-Path $exePath) {
                    $auth = Get-AuthenticodeSignature -FilePath $exePath -ErrorAction SilentlyContinue
                    if ($auth.Status -ne 'Valid' -and -not (Test-TrustedSigner -FilePath $exePath)) {
                        Write-Result WARN "Unsigned EXE ran (Event 4688): $exePath at $($ev.TimeCreated)"
                    }
                }
            }
        }
    } else { Write-Result SAFE "No 4688 events (Auditing is off or empty)." }
} catch { Write-Result WARN "Event log query failed." }

# =============================================================================
Write-Section "STEP 11 - Recycle Bin & Shadows (Full List)"
$rb = Get-ChildItem 'C:\$Recycle.Bin' -Force -Recurse -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.Name -notlike '$I*' -and $_.Name -ne 'desktop.ini' }
if ($rb) {
    Write-Result WARN "Recycle Bin contains $($rb.Count) files:"
    foreach ($r in $rb) { 
        $sz = [math]::Round($r.Length / 1KB, 1)
        Write-Result INFO " $($r.FullName) ($sz KB)" 
    }
} else { Write-Result SAFE "Recycle Bin is empty." }

$vss = (vssadmin list shadows 2>&1) | Out-String
if ($vss -match 'No items found') { Write-Result SAFE "No shadow copies." }
elseif ($vss -match 'Shadow Copy ID') {
    $shadows = [regex]::Matches($vss, 'creation time:\s*(.+)')
    Write-Result WARN "$($shadows.Count) Shadow Copies exist:"
    foreach ($m in $shadows) { Write-Result INFO " Created: $($m.Groups[1].Value.Trim())" }
}

# =============================================================================
Write-Section "STEP 12 - Defender Detailed"
try {
    $mp = Get-MpComputerStatus
    $off = @()
    if(-not $mp.RealTimeProtectionEnabled) { $off += 'RealTimeProtection' }
    if(-not $mp.AntivirusEnabled) { $off += 'Antivirus' }
    if(-not $mp.BehaviorMonitorEnabled) { $off += 'BehaviorMonitor' }
    if(-not $mp.OnAccessProtectionEnabled) { $off += 'OnAccessProtection' }
    if(-not $mp.IsTamperProtected) { $off += 'TamperProtection' }
    if(-not $mp.IoavProtectionEnabled) { $off += 'IOAV' }
    if($off.Count -gt 0) { Write-Result FAIL "Defender protections DISABLED: $($off -join ', ')" }
    else { Write-Result SAFE "No Defender threats."} 
    } catch {}

    # ==========================================================================
Write-Section "SUMMARY"
Write-Host "`n  SAFE: $($script:safeCount)  WARN:  $($script:warnCount)  FAIL: $($script:failCount)`n" -ForegroundColor Cyan
Write-Result INFO "Report: $ReportPath"
Write-Result INFO "made-by-kemo | v4.0 | finished $(Get-Date)"
Write-Host "`n=== made-by-kemo | done ===`n" -ForegroundColor Cyan
