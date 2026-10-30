# =============================================================================
# made-by-kemo | PC Forensic Check v5.1 (Full .cfg Scan, USB EXE, Progress)
# made-by-kemo | Run as Administrator. Output -> $env:USERPROFILE\Desktop\PC-Check
# =============================================================================
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'

# =============================================================================
# LOGIN & HWID LOCK SYSTEM
# =============================================================================
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

# =============================================================================
# FORENSIC CHECK START
# =============================================================================
Write-Host "`n=== made-by-kemo | PC Forensic Check v5.1 | starting... ===`n" -ForegroundColor Cyan
$Out = "$env:USERPROFILE\Desktop\PC-Check"
$ReportPath = Join-Path $Out "report.txt"
New-Item -ItemType Directory -Path $Out -Force | Out-Null
"made-by-kemo | v5.1 | started $(Get-Date) | User: $user" | Out-File $ReportPath
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
if(-not $isAdmin) { Write-Result WARN "Not elevated - results may be limited." }

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
Write-Section "STEP 1 - System Info & HWID"
try {
    Get-ComputerInfo | Out-File "$Out\system-info.txt"
    $volSerial = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").VolumeSerialNumber
    $biosSerial = (Get-CimInstance Win32_BIOS).SerialNumber
    $baseboard = (Get-CimInstance Win32_BaseBoard).SerialNumber
    $hwidData = "=== HWID ===`nMachine GUID: $mGuid`nBIOS: $biosSerial`nMotherboard: $baseboard`nCPU ID: $cpuId`nC: Serial: $volSerial"
    $hwidData | Out-File "$Out\hwid.txt" -Force
    Write-Result SAFE "HWID logged to hwid.txt"
} catch { Write-Result WARN "System info failed: $_" }

# =============================================================================
Write-Section "STEP 2 - Full PC .cfg Inspection"
$drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object -ExpandProperty DeviceID
$cfgFiles = @()
foreach ($d in $drives) {
    $cfgFiles += Get-ChildItem -Path "$d\" -Filter "*.cfg" -File -Recurse -Force -ErrorAction SilentlyContinue
}

if ($cfgFiles.Count -gt 0) {
    Write-Result WARN "Found $($cfgFiles.Count) .cfg files. Scanning contents..."
    $i = 0
    foreach ($cfg in $cfgFiles) {
        $i++
        $pct = [math]::Round(($i / $cfgFiles.Count) * 100)
        Write-Progress -Activity "Scanning .cfg files" -Status "$pct% - $($cfg.FullName)" -PercentComplete $pct
        
        $content = Get-Content $cfg.FullName -Raw -ErrorAction SilentlyContinue
        $isSusp = $false
        foreach ($k in $highSignal) {
            if ($content -match "(?i)$k") { $isSusp = $true; break }
        }
        
        if ($isSusp) {
            Write-Result FAIL "Suspicious .cfg: $($cfg.FullName) (Contains cheat keywords)"
        } else {
            Write-Result SAFE "Clean .cfg: $($cfg.FullName)"
        }
    }
    Write-Progress -Activity "Scanning .cfg files" -Completed
} else {
    Write-Result SAFE "No .cfg files found on this PC."
}

# =============================================================================
Write-Section "STEP 3 - Running Processes"
$procs = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
$i = 0
foreach($p in $procs) {
    $i++
    Write-Progress -Activity "Scanning Processes" -Status "$([math]::Round(($i/$procs.Count)*100))%" -PercentComplete (($i/$procs.Count)*100)
    if(-not $p.ExecutablePath) { continue }
    if(Test-TrustedSigner -FilePath $p.ExecutablePath) { continue }
    
    $sig = Get-AuthenticodeSignature -FilePath $p.ExecutablePath -ErrorAction SilentlyContinue
    if ($sig.Status -ne 'Valid') {
        Write-Result WARN "UNSIGNED Process: $($p.Name) -> $($p.ExecutablePath)"
    }
}
Write-Progress -Activity "Scanning Processes" -Completed

# =============================================================================
Write-Section "STEP 4 - USB Executables & Injection Traces"
$usbDrives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=2" | Select-Object -ExpandProperty DeviceID
if ($usbDrives) {
    Write-Result WARN "Removable USB Drives currently attached: $($usbDrives -join ', ')"
} else {
    Write-Result INFO "No USB drives currently attached."
}

# Check Prefetch for VOLUME_ (USB EXE execution)
$pf = Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue
foreach ($p in $pf) {
    if ($p.Name -match '^VOLUME_') {
        Write-Result WARN "USB EXE Executed (Prefetch): $($p.Name) at $($p.LastWriteTime)"
    }
}

# Check Event Log for process creation from USB drives (D:, E:, etc)
try {
    $since = (Get-Date).AddDays(-7)
    $sec = @(Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688; StartTime=$since } -MaxEvents 1000 -ErrorAction SilentlyContinue)
    $usbEvHits = 0
    foreach ($ev in $sec) {
        if ($ev.Message -match 'New Process Name:\s+([D-Z]:\\.+\.exe)') {
            $exe = $matches[1].Trim()
            Write-Result FAIL "EXE Executed from USB (Event 4688): $exe at $($ev.TimeCreated)"
            $usbEvHits++
        }
    }
    if ($usbEvHits -eq 0) { Write-Result SAFE "No USB EXE execution found in Event Logs." }
} catch {}

# =============================================================================
Write-Section "STEP 5 - Keyword & File Scan"
$roots = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "C:\ProgramData")
foreach($root in $roots) {
    if (Test-Path $root) {
        Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $f = $_
            $sig = $null
            foreach($k in $highSignal) { if($f.Name -like "*$k*") { $sig = 'HIGH'; break } }
            if ($sig) { Write-Result FAIL "Keyword file: $($f.FullName)" }
        }
    }
}
Write-Result SAFE "Keyword scan complete."

# =============================================================================
Write-Section "STEP 6 - Forensic Tools (ALL Files Listed)"
$tools = @('BAMParser', 'SavedFilesViewer', 'MFTExplorer', 'DeletedFiles', 'PrefetchViewer', 'ProcessExplorer', 'procexp', 'KAPE')
$tRoots = @("C:\", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads", "C:\Tools")
$foundAny = $false
foreach($tn in $tools) {
    foreach($r in $tRoots) {
        if (Test-Path $r) {
            $foundFiles = Get-ChildItem -Path $r -Filter "*$tn*" -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.exe', '.dll', '.msi' }
            foreach ($f in $foundFiles) {
                $foundAny = $true
                $trusted = Test-TrustedSigner -FilePath $f.FullName
                if($trusted) { 
                    Write-Result SAFE "[$tn] $($f.FullName) (Trusted)" 
                } elseif($lastLogon -and $f.LastWriteTime -gt $lastLogon) { 
                    Write-Result FAIL "[$tn] $($f.FullName) (Modified after logon!)" 
                } else { 
                    Write-Result WARN "[$tn] $($f.FullName) (Untrusted/Unknown)" 
                }
            }
        }
    }
}
if (-not $foundAny) { Write-Result SAFE "No forensic tool files found." }

# =============================================================================
Write-Section "STEP 7 - Amcache & Shimcache"
$amc = "C:\Windows\AppCompat\Programs\Amcache.hve"
if(Test-Path $amc) { Copy-Item $amc "$Out\Amcache.hve" -Force; Write-Result WARN "Amcache exported to output folder." }

try {
    $shim = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -Name AppCompatCache -ErrorAction Stop).AppCompatCache
    $shimStr = -join ($shim | ForEach-Object { [char]$_ })
    $shimExes = [regex]::Matches($shimStr, '[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+\.exe') | ForEach-Object { $_.Value } | Select-Object -Unique
    if ($shimExes) { foreach ($exe in $shimExes) { Write-Result INFO "[Shimcache] $exe" } }
} catch { Write-Result WARN "Shimcache parse failed." }

# =============================================================================
Write-Section "STEP 8 - BAM / DAM (Red for suspicious)"
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
if($bE.Count) {
    foreach($b in $bE) {
        if (Test-TrustedSigner -FilePath $b.Path) { 
            Write-Result SAFE "[BAM] $($b.Path) @ $($b.LastExec)" 
        } else {
            $hit = $false
            foreach($k in $highSignal) { if($b.Path -like "*$k*") { $hit = $true; break } }
            if ($hit) { 
                Write-Result FAIL "[BAM] Cheat match: $($b.Path) @ $($b.LastExec)" 
            } else { 
                Write-Result FAIL "[BAM] Untrusted Execution: $($b.Path) @ $($b.LastExec)" 
            }
        }
    }
}

# =============================================================================
Write-Section "STEP 9 - Defender Detailed"
try {
    $mp = Get-MpComputerStatus
    $off = @()
    if(-not $mp.RealTimeProtectionEnabled) { $off += 'RealTimeProtection' }
    if(-not $mp.AntivirusEnabled) { $off += 'Antivirus' }
    if($off.Count -gt 0) { Write-Result FAIL "Defender DISABLED: $($off -join ', ')" }
    else { Write-Result SAFE "Defender enabled." }
} catch {}

try {
    $pref = Get-MpPreference
    if($pref.ExclusionPath) { foreach($e in $pref.ExclusionPath) { Write-Result FAIL "Defender Exclusion: $e" } }
    else { Write-Result SAFE "No Defender exclusions." }
} catch {}

try {
    $threats = @(Get-MpThreatDetection)
    if($threats.Count -gt 0) { foreach($t in $threats) { Write-Result FAIL "Defender Threat: $($t.ThreatID) -> $($t.Resources)" } }
    else { Write-Result SAFE "No Defender threats." }
} catch {}

# =============================================================================
Write-Section "SUMMARY"
Write-Host "`n SAFE: $($script:safeCount) WARN: $($script:warnCount) FAIL: $($script:failCount)`n" -ForegroundColor Cyan
Write-Result INFO "Report: $ReportPath"
Write-Result INFO "made-by-kemo | v5.1 | finished $(Get-Date)"
Write-Host "`n=== made-by-kemo | done ===`n" -ForegroundColor Cyan
