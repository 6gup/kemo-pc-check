# =============================================================================
#  made-by-kemo | PC Forensic Check v7.0 (Ultimate Structured Edition)
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
#  CORE VARIABLES & FUNCTIONS
# =============================================================================
$Out = "$env:USERPROFILE\Desktop\PC-Check"
$ReportPath = Join-Path $Out "report.txt"
New-Item -ItemType Directory -Path $Out -Force | Out-Null
"made-by-kemo | v7.0 | started $(Get-Date) | User: $user" | Out-File $ReportPath
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
# STEP 3 - File System: Keywords, ADS & Entropy
# =============================================================================
Write-Host "=== STEP 3 - File System (Keywords, ADS, Entropy) ===" -ForegroundColor Cyan
$csharpEntropy = @"
using System; using System.IO;
public class KemoEntropy {
    public static double GetEntropy(string filePath) {
        byte[] bytes = new byte[1024 * 1024];
        using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite)) {
            int read = fs.Read(bytes, 0, bytes.Length);
            if (read == 0) return 0;
            int[] counts = new int[256];
            for (int i = 0; i < read; i++) counts[bytes[i]]++;
            double entropy = 0;
            for (int i = 0; i < 256; i++) { if (counts[i] > 0) { double p = (double)counts[i] / read; entropy -= p * Math.Log(p, 2); } }
            return entropy;
        }
    }
}
"@
try { Add-Type -TypeDefinition $csharpEntropy -ErrorAction Stop } catch {}

$roots = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "C:\ProgramData")
$allFiles = @()
foreach($root in $roots) { if (Test-Path $root) { $allFiles += Get-ChildItem -LiteralPath $root -Recurse -Force -Include *.exe, *.dll, *.bat, *.cmd, *.ps1, *.vbs -ErrorAction SilentlyContinue } }
$i = 0; $total = [math]::Max(1, $allFiles.Count)
foreach ($f in $allFiles) {
    $i++; Show-Progress ([math]::Round(($i/$total)*100))
    foreach($k in $highSignal) { if($f.Name -like "*$k*") { Add-Result FAIL "Keyword file: $($f.FullName)"; break } }
    $streams = Get-Item -LiteralPath $f.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' }
    if ($streams) { Add-Result WARN "Alternate Data Stream: $($f.FullName)" }
    if ($f.Length -gt 100KB) {
        try { $ent = [KemoEntropy]::GetEntropy($f.FullName); if ($ent -gt 7.2) { Add-Result WARN "High Entropy (Packed): $($f.FullName) ($([math]::Round($ent,2)))" } } catch {}
    }
}
if ($script:Buffer.Count -eq 0) { Add-Result SAFE "No suspicious files, ADS, or packed executables found." }
Flush-Results; Wait-Pager

# =============================================================================
# STEP 4 - Process & Memory Integrity (RWX & DLL Injections)
# =============================================================================
Write-Host "=== STEP 4 - Process & Memory Integrity ===" -ForegroundColor Cyan
$csharpMem = @"
using System; using System.Runtime.InteropServices;
public class MemScan {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] public static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION { public IntPtr BaseAddress; public IntPtr AllocationBase; public uint AllocationProtect; public IntPtr RegionSize; public uint State; public uint Protect; public uint Type; }
    public static int ScanRWX(int pid) {
        IntPtr h = OpenProcess(0x0410, false, pid); if(h == IntPtr.Zero) return -1;
        IntPtr addr = IntPtr.Zero; int count = 0; MEMORY_BASIC_INFORMATION mbi;
        while(VirtualQueryEx(h, addr, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != 0) {
            if(mbi.State == 0x1000 && (mbi.Protect == 0x40 || mbi.Protect == 0x80)) count++;
            addr = new IntPtr(addr.ToInt64() + mbi.RegionSize.ToInt64());
        }
        return count;
    }
}
"@
try { Add-Type -TypeDefinition $csharpMem -ErrorAction Stop } catch {}

$procs = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath
$i = 0
foreach($p in $procs) {
    $i++; Show-Progress ([math]::Round(($i/$procs.Count)*100))
    if(-not $p.ExecutablePath) { continue }
    if(-not (Test-TrustedSigner -FilePath $p.ExecutablePath)) {
        $sig = Get-AuthenticodeSignature -FilePath $p.ExecutablePath -ErrorAction SilentlyContinue
        if ($sig.Status -ne 'Valid') { Add-Result WARN "UNSIGNED Process: $($p.Name)" }
    }
    if (Get-Command MemScan -ErrorAction SilentlyContinue) {
        $rwx = [MemScan]::ScanRWX($p.ProcessId)
        if ($rwx -gt 5) { Add-Result FAIL "Suspicious RWX Memory ($rwx regions) in: $($p.Name)" }
    }
    if ($p.Name -match 'csgo|cs2|valorant|fortnite|r5apex|rust|escapefromtarkov|RobloxPlayerBeta') {
        $proc = Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
        foreach ($mod in $proc.Modules) {
            if (-not (Test-TrustedSigner -FilePath $mod.FileName)) {
                $msig = Get-AuthenticodeSignature -FilePath $mod.FileName -ErrorAction SilentlyContinue
                if ($msig.Status -ne 'Valid') { Add-Result FAIL "Unsigned DLL injected into $($p.Name): $($mod.ModuleName)" }
            }
        }
    }
}
if ($script:Buffer.Count -eq 0) { Add-Result SAFE "No unsigned processes, RWX memory, or injected DLLs found." }
Flush-Results; Wait-Pager

# =============================================================================
# STEP 5 - Roblox Specific Checks
# =============================================================================
Write-Host "=== STEP 5 - Roblox Specific Checks ===" -ForegroundColor Cyan
Show-Progress 25
$roblox = Get-Process -Name "RobloxPlayerBeta" -ErrorAction SilentlyContinue
if ($roblox) {
    $injectors = Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'xeno|volt|injector|cheat|mem|read|wrd|krnl' }
    if ($injectors) { foreach ($inj in $injectors) { Add-Result FAIL "Potential Roblox Injector running: $($inj.Name)" } }
} else { Add-Result SAFE "Roblox is not currently running." }

Show-Progress 50
$rbxVersions = "$env:LOCALAPPDATA\Roblox\Versions"
if (Test-Path $rbxVersions) {
    $settings = Get-ChildItem -Path $rbxVersions -Filter "ClientAppSettings.json" -File -Recurse -ErrorAction SilentlyContinue
    foreach ($s in $settings) {
        Add-Result WARN "Roblox ClientAppSettings.json found (Potential FPS Unlock/ESP): $($s.FullName)"
        if ((Get-Content $s.FullName -Raw) -match 'DFIntTaskSchedulerTargetFps|FpsCap|DisableAAC') { Add-Result FAIL "Roblox settings tampered (FPS Unlock / AAC Bypass)" }
    }
}
Show-Progress 75
$rbxDirs = @("$env:LOCALAPPDATA\Roblox", "$env:LOCALAPPDATA\Temp", "$env:USERPROFILE\Downloads")
foreach ($dir in $rbxDirs) {
    if (Test-Path $dir) {
        $scripts = Get-ChildItem -Path $dir -Recurse -Include *.lua, *.asi, *.dll -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'inject|execut|krnl|xeno|fluxus|synapse|script' }
        foreach ($s in $scripts) { Add-Result FAIL "Potential Roblox Executor file found: $($s.FullName)" }
    }
}
Show-Progress 100
if ($script:Buffer.Count -eq 0) { Add-Result SAFE "No Roblox executor files or tampering found." }
Flush-Results; Wait-Pager

# =============================================================================
# STEP 6 - DLL Viewer & Deleted Traces
# =============================================================================
Write-Host "=== STEP 6 - DLL Viewer & Deleted Traces ===" -ForegroundColor Cyan
$dllDirs = @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP", "C:\ProgramData")
$i = 0; $foundDll = $false
foreach ($d in $dllDirs) {
    if (Test-Path $d) {
        $dlls = Get-ChildItem -Path $d -Filter "*.dll" -File -Recurse -Force -ErrorAction SilentlyContinue
        foreach ($dll in $dlls) {
            $i++; Show-Progress ([math]::Round(($i / ($dlls.Count + 20)) * 100))
            if (-not (Test-TrustedSigner -FilePath $dll.FullName)) {
                if ((Get-AuthenticodeSignature -FilePath $dll.FullName).Status -ne 'Valid') { Add-Result FAIL "Unsigned DLL: $($dll.FullName)"; $foundDll = $true }
            }
        }
    }
}
$recycleDirs = Get-ChildItem 'C:\$Recycle.Bin' -Directory -Force -ErrorAction SilentlyContinue
foreach ($dir in $recycleDirs) {
    $iFiles = Get-ChildItem -Path $dir.FullName -Filter '$I*' -File -Force -ErrorAction SilentlyContinue
    foreach ($iFile in $iFiles) {
        if ($iFile.Length -gt 24) {
            $bytes = [System.IO.File]::ReadAllBytes($iFile.FullName)
            $origPath = [System.Text.Encoding]::Unicode.GetString($bytes[28..($bytes.Length - 2)]).Trim([char]0)
            if ($origPath -match '\.dll$') { Add-Result WARN "Deleted DLL trace: $origPath"; $foundDll = $true }
        }
    }
}
if (-not $foundDll) { Add-Result SAFE "No unsigned or deleted DLLs found." }
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# STEP 7 - Execution History (Amcache, Shimcache, BAM, UserAssist)
# =============================================================================
Write-Host "=== STEP 7 - Execution History ===" -ForegroundColor Cyan
Show-Progress 20
$amc = "C:\Windows\AppCompat\Programs\Amcache.hve"
if(Test-Path $amc) { Copy-Item $amc "$Out\Amcache.hve" -Force; Add-Result WARN "Amcache exported to output folder." }
Show-Progress 40
try {
    $shim = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -Name AppCompatCache -ErrorAction Stop).AppCompatCache
    $shimExes = [regex]::Matches((-join ($shim | ForEach-Object { [char]$_ })), '[a-zA-Z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+\.exe') | ForEach-Object { $_.Value } | Select-Object -Unique
    foreach ($exe in $shimExes) { Add-Result INFO "[Shimcache] $exe" }
} catch {}
Show-Progress 60
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$bam = @("SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\$sid", "SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\$sid")
foreach($bp in $bam) {
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($bp)
        if($k) {
            foreach($vn in $k.GetValueNames()) {
                $d = $k.GetValue($vn)
                if($d -is [byte[]] -and $d.Length -ge 8) {
                    if (Test-TrustedSigner -FilePath $vn) { Add-Result SAFE "[BAM] $vn" } else { Add-Result FAIL "[BAM] Untrusted Execution: $vn" }
                }
            }
            $k.Close()
        }
    } catch {}
}
Show-Progress 80
function Decode-Rot13($str) { $chars = $str.ToCharArray(); for ($i = 0; $i -lt $chars.Length; $i++) { $c = $chars[$i]; if ($c -match '[a-z]') { $chars[$i] = [char]((([int]$c - 97 + 13) % 26) + 97) } elseif ($c -match '[A-Z]') { $chars[$i] = [char]((([int]$c - 65 + 13) % 26) + 65) } }; return -join $chars }
$uaPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
foreach ($guid in (Get-ChildItem $uaPath -ErrorAction SilentlyContinue)) {
    $countKey = "$($guid.PSPath)\Count"
    if (Test-Path $countKey) {
        $props = Get-ItemProperty $countKey -ErrorAction SilentlyContinue
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -notmatch '^PS') {
                $decoded = Decode-Rot13 $p.Name
                if ($decoded -match '\.exe|\.cfg') {
                    foreach ($k in $highSignal) { if ($decoded -match "(?i)$k") { Add-Result FAIL "Deleted/Executed Cheat Trace (UserAssist): $decoded" } }
                }
            }
        }
    }
}
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# STEP 8 - Jump Lists & Recent Artifacts
# =============================================================================
Write-Host "=== STEP 8 - Jump Lists & Recent Files ===" -ForegroundColor Cyan
Show-Progress 50
$foundAny = $false
$recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
if (Test-Path $recentPath) {
    $lnks = Get-ChildItem -Path $recentPath -Filter "*.lnk" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 10
    foreach ($lnk in $lnks) { Add-Result INFO "Recent file: $($lnk.Name) (Accessed: $($lnk.LastWriteTime))"; $foundAny = $true }
}
$jumpListPath = "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
if (Test-Path $jumpListPath) {
    foreach ($jl in (Get-ChildItem -Path $jumpListPath -File -ErrorAction SilentlyContinue)) {
        $txt = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($jl.FullName)) + [System.Text.Encoding]::Unicode.GetString([System.IO.File]::ReadAllBytes($jl.FullName))
        foreach ($exe in ([regex]::Matches($txt, '[a-zA-Z0-9_\-\. ]+\.exe') | Select-Object -ExpandProperty Value | Select-Object -Unique)) { if ($exe.Length -gt 5) { Add-Result INFO "Recent EXE opened: $exe"; $foundAny = $true } }
        foreach ($cfg in ([regex]::Matches($txt, '[a-zA-Z0-9_\-\. ]+\.cfg') | Select-Object -ExpandProperty Value | Select-Object -Unique)) { 
            if ($cfg.Length -gt 5) { $foundAny = $true; if ($cfg -match '(?i)aimbot|esp') { Add-Result FAIL "Recent CFG with keyword: $cfg" } else { Add-Result INFO "Recent CFG opened: $cfg" } }
        }
    }
}
if (-not $foundAny) { Add-Result SAFE "No recent artifacts found." }
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# STEP 9 - Network, DNS & KeyAuth History
# =============================================================================
Write-Host "=== STEP 9 - Network, DNS & KeyAuth History ===" -ForegroundColor Cyan
Show-Progress 20
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
if ((Get-Item $hostsFile).LastWriteTime -gt (Get-Date).AddDays(-2)) { Add-Result WARN "Hosts file recently modified." }
if (Select-String -Path $hostsFile -Pattern 'keyauth|cheat|aimbot' -ErrorAction SilentlyContinue) { Add-Result FAIL "Suspicious hosts entry found." }
Show-Progress 40
$dnsHits = @()
foreach($d in (Get-DnsClientCache -ErrorAction SilentlyContinue)) { 
    if ($d.Entry -match 'keyauth|auth\.keyauth|keyauth\.win|cheat|aimbot') { Add-Result FAIL "Suspicious DNS Cache: $($d.Entry) -> $($d.Data)"; $dnsHits += $d.Entry } 
}
Show-Progress 60
$psHist = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $psHist) {
    $histHits = Select-String -Path $psHist -Pattern 'keyauth|aimbot|esp|inject' -ErrorAction SilentlyContinue
    foreach ($h in $histHits) { Add-Result FAIL "PowerShell History KeyAuth Trace: $($h.Line.Trim())" }
}
Show-Progress 80
$rules = Get-NetFirewallRule -Direction Outbound -Action Allow -Enabled True -ErrorAction SilentlyContinue | Get-NetFirewallApplicationFilter
foreach ($r in $rules) {
    if ($r.Program -match 'Temp|AppData|Downloads|Public' -and $r.Program -match '\.exe') { Add-Result WARN "Suspicious Outbound Firewall Rule: $($r.Program)" }
}
Show-Progress 100
if ($script:Buffer.Count -eq 0) { Add-Result SAFE "No suspicious network, DNS, or KeyAuth traces found." }
Flush-Results; Wait-Pager

# =============================================================================
# STEP 10 - Hardware, DMA & Vulnerable Drivers (BYOVD)
# =============================================================================
Write-Host "=== STEP 10 - Hardware & Vulnerable Drivers ===" -ForegroundColor Cyan
Show-Progress 30
$vulnDrivers = @('iqvw64e.sys', 'gdrv.sys', 'winring0.sys', 'ene.sys', 'asio.sys', 'msio.sys', 'cpuz.sys', 'kfridge.sys', 'rtcore64.sys')
foreach ($d in (Get-ChildItem "$env:SystemRoot\System32\drivers" -Filter "*.sys" -ErrorAction SilentlyContinue)) { if ($vulnDrivers -contains $d.Name.ToLower()) { Add-Result FAIL "Vulnerable Driver (BYOVD) found: $($d.FullName)" } }
Show-Progress 70
$bcd = (bcdedit /enum {current}) -join "`n"
if ($bcd -match 'testsigning\s+Yes') { Add-Result FAIL "Windows Test Signing is ENABLED." }
Show-Progress 100
if ($script:Buffer.Count -eq 0) { Add-Result SAFE "No vulnerable drivers or Test Signing found." }
Flush-Results; Wait-Pager

# =============================================================================
# STEP 11 - Unsigned System Drivers
# =============================================================================
Write-Host "=== STEP 11 - Unsigned System Drivers ===" -ForegroundColor Cyan
$sysDrivers = Get-ChildItem "$env:SystemRoot\System32\drivers" -Filter "*.sys" -ErrorAction SilentlyContinue
$i = 0; $unsignedCount = 0
foreach ($d in $sysDrivers) {
    $i++; Show-Progress ([math]::Round(($i / $sysDrivers.Count) * 100))
    if ((Get-AuthenticodeSignature -FilePath $d.FullName -ErrorAction SilentlyContinue).Status -ne 'Valid') { Add-Result FAIL "UNSIGNED Driver: $($d.Name)"; $unsignedCount++ }
}
if ($unsignedCount -eq 0) { Add-Result SAFE "All System32 drivers are properly signed." }
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# STEP 12 - USB Executables & Prefetch Integrity
# =============================================================================
Write-Host "=== STEP 12 - USB Executables & Prefetch ===" -ForegroundColor Cyan
Show-Progress 30
try {
    $sec = @(Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-7) } -MaxEvents 1000 -ErrorAction SilentlyContinue)
    foreach ($ev in $sec) { if ($ev.Message -match 'New Process Name:\s+([D-Z]:\\.+\.exe)') { Add-Result FAIL "EXE from USB (Event 4688): $($matches[1].Trim())" } }
} catch {}
Show-Progress 70
$pfReg = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -ErrorAction SilentlyContinue).EnablePrefetcher
if ($pfReg -eq 0) { Add-Result FAIL "Prefetch is DISABLED! (Hiding traces)." } 
elseif ((Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf").Count -eq 0) { Add-Result WARN "Prefetch is enabled but empty. Traces may have been wiped." } 
else { Add-Result SAFE "Prefetch is enabled and contains data." }
Show-Progress 100
if ($script:Buffer.Count -eq 0) { Add-Result SAFE "No USB executables found." }
Flush-Results; Wait-Pager

# =============================================================================
# STEP 13 - Persistence (Tasks, Startup, Services, WMI)
# =============================================================================
Write-Host "=== STEP 13 - Persistence Mechanisms ===" -ForegroundColor Cyan
Show-Progress 25
foreach ($t in (Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' -and $_.State -ne 'Disabled' })) {
    if (($t.Actions.Execute -join ' ') -match 'Temp|AppData|Public|ProgramData') { Add-Result FAIL "Suspicious Task: $($t.TaskName)" }
}
Show-Progress 50
foreach ($key in @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")) {
    if (Test-Path $key) { foreach ($p in (Get-ItemProperty -Path $key).PSObject.Properties) { if ($p.Name -notmatch 'PS' -and $p.Value -match 'Temp|AppData|Public') { Add-Result FAIL "Suspicious Startup: $($p.Name)" } } }
}
Show-Progress 75
try {
    $svcEvents = @(Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddDays(-7)} -MaxEvents 50 -ErrorAction SilentlyContinue)
    foreach ($ev in $svcEvents) { if ($ev.Message -match 'Service Name:\s+(.+)' -and $ev.Message -match 'Service File Name:\s+(.+)') { if ($matches[2].Trim() -match 'Temp|AppData|Public') { Add-Result FAIL "Suspicious Service Installed: $($matches[1].Trim())" } } }
} catch {}
Show-Progress 90
$wmiConsumers = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue
if ($wmiConsumers) { foreach ($c in $wmiConsumers) { Add-Result FAIL "WMI Persistence: $($c.Name)" } }
Show-Progress 100
if ($script:Buffer.Count -eq 0) { Add-Result SAFE "No suspicious persistence found." }
Flush-Results; Wait-Pager

# =============================================================================
# STEP 14 - Bloodhound & Anti-Cheat Status
# =============================================================================
Write-Host "=== STEP 14 - Bloodhound & Anti-Cheat Status ===" -ForegroundColor Cyan
Show-Progress 30
$obsPaths = @("$env:APPDATA\obs-studio", "$env:ProgramFiles\obs-studio", "${env:ProgramFiles(x86)}\obs-studio")
foreach ($p in $obsPaths) { if (Test-Path $p) { $bh = Get-ChildItem -Path $p -Filter "*obs plugin templates*" -Directory -Recurse -ErrorAction SilentlyContinue; if ($bh) { Add-Result FAIL "Bloodhound detected! OBS folder found at: $($bh.FullName)" } } }
Show-Progress 70
$rbx = Get-Process -Name "RobloxPlayerBeta" -ErrorAction SilentlyContinue
if ($rbx) {
    if (($rbx.Modules | Select-Object -ExpandProperty ModuleName) -match "RobloxPlayerBeta.dll|Hyperion|Byfron") { Add-Result SAFE "Roblox Anti-Cheat (Hyperion) is active." }
    else { Add-Result FAIL "Roblox is running, but Anti-Cheat DLL is MISSING (Bypassed)." }
} else { Add-Result SAFE "Roblox is not currently running." }
Show-Progress 100
if ($script:Buffer.Count -eq 0) { Add-Result SAFE "No Bloodhound or Anti-Cheat bypasses found." }
Flush-Results; Wait-Pager

# =============================================================================
# STEP 15 - Zone.Identifier (Download Sources)
# =============================================================================
Write-Host "=== STEP 15 - Download Sources ===" -ForegroundColor Cyan
$i = 0; $foundZ = $false
foreach ($d in @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop", "$env:TEMP")) {
    if (Test-Path $d) {
        foreach ($f in (Get-ChildItem -Path $d -Include *.exe, *.dll, *.zip, *.cfg -File -Recurse -ErrorAction SilentlyContinue)) {
            $i++; Show-Progress ([math]::Min(99, [math]::Round(($i / 50) * 100)))
            if (Get-Item -LiteralPath $f.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue) {
                $url = ((Get-Content -LiteralPath $f.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue) | Select-String 'HostUrl=').Line
                if ($url) { Add-Result INFO "Downloaded: $($f.Name) [URL: $($url.Replace('HostUrl=',''))]"; $foundZ = $true }
            }
        }
    }
}
if (-not $foundZ) { Add-Result SAFE "No internet-downloaded executables found." }
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# STEP 16 - Macro & Script Executors
# =============================================================================
Write-Host "=== STEP 16 - Macro & Script Executors ===" -ForegroundColor Cyan
Show-Progress 50
$macroProcs = Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'AutoHotkey|Razer|Synapse|Logitech|GHUB|Macro' }
if ($macroProcs) { foreach ($m in $macroProcs) { Add-Result WARN "Macro Software running: $($m.Name)" } }
else { Add-Result SAFE "No macro software currently running." }
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# STEP 17 - Defender Detailed
# =============================================================================
Write-Host "=== STEP 17 - Defender Detailed ===" -ForegroundColor Cyan
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
# STEP 18 - Suspicious Parent Processes
# =============================================================================
Write-Host "=== STEP 18 - Suspicious Parent Processes ===" -ForegroundColor Cyan
Show-Progress 50
$procs = Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'RobloxPlayerBeta|csgo|cs2|valorant|r5apex' }
foreach ($p in $procs) {
    $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.ParentProcessId)" -ErrorAction SilentlyContinue
    if ($parent -and $parent.ExecutablePath -and ($parent.ExecutablePath -match 'Temp|AppData|Downloads') -and $parent.Name -notmatch 'explorer|Roblox|Steam|Epic') {
        Add-Result FAIL "Game ($($p.Name)) launched by suspicious parent: $($parent.Name) -> $($parent.ExecutablePath)"
    }
}
if ($script:Buffer.Count -eq 0) { Add-Result SAFE "No games launched by suspicious parent processes." }
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# SUMMARY
# =============================================================================
Write-Host "=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "`n  SAFE: $($script:safeCount)  WARN: $($script:warnCount)  FAIL: $($script:failCount)`n" -ForegroundColor Cyan
Write-Host "Report: $ReportPath" -ForegroundColor Cyan
Write-Host "made-by-kemo | v7.0 | finished $(Get-Date)" -ForegroundColor Cyan
Write-Host "`n=== made-by-kemo | done ===`n" -ForegroundColor Cyan
