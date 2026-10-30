Nig
kxpacts<kxpacts@gmail.com>
You
# =============================================================================
# made-by-kemo | PC Forensic Check v3.1 (trusted publisher whitelist)
# made-by-kemo | Run as Administrator. Output -> $env:USERPROFILE\Desktop\PC-Check
# made-by-kemo | Safe: green | Warn: yellow | Fail: red | Info: cyan
# =============================================================================
$ErrorActionPreference='SilentlyContinue'; $ProgressPreference='SilentlyContinue'
Write-Host "`n=== made-by-kemo | PC Forensic Check v3.1 | starting... ===`n" -ForegroundColor Cyan
$Out="$env:USERPROFILE\Desktop\PC-Check"; $ReportPath=Join-Path $Out "report.txt"
New-Item -ItemType Directory -Path $Out -Force | Out-Null
"made-by-kemo | v3.1 | started $(Get-Date)" | Out-File $ReportPath
$script:failCount=0;$script:warnCount=0;$script:safeCount=0

function Write-Result {
    param([string]$Tag,[string]$Message)
    $c=@{SAFE='Green';WARN='Yellow';FAIL='Red';INFO='Cyan'}
    $l="[$Tag] $Message"
    Write-Host $l -ForegroundColor $c[$Tag]
    Add-Content $ReportPath $l
    switch($Tag){SAFE{$script:safeCount++}WARN{$script:warnCount++}FAIL{$script:failCount++}}
}
function Write-Section {
    param([string]$Title)
    $l="`n=== $Title ==="
    Write-Host $l -ForegroundColor DarkCyan
    Add-Content $ReportPath $l
}

$isAdmin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if($isAdmin){Write-Result INFO "Running as Administrator."}else{Write-Result WARN "Not elevated - results limited."}

$lastLogon=$null
try{$lastLogon=Get-CimInstance Win32_LogonSession -Filter "LogonType=2 OR LogonType=10"|Sort-Object StartTime -Descending|Select-Object -First 1 -ExpandProperty StartTime}catch{}
if(-not $lastLogon){try{$lastLogon=(Get-Item $env:USERPROFILE).LastWriteTime}catch{}}
if($lastLogon){Write-Result INFO "Last interactive logon: $lastLogon"}else{Write-Result WARN "Last logon unknown."}

# ============================================================================
# TRUSTED PUBLISHERS — anything signed by these is treated as SAFE
# ============================================================================
$trustedSigners=@(
    'Logitech','Logitech Inc','Logitech Europe S.A.',
    'Microsoft','Microsoft Corporation','Microsoft Windows',
    'NVIDIA','NVIDIA Corporation',
    'AMD','Advanced Micro Devices','Advanced Micro Devices, Inc.',
    'Intel','Intel Corporation',
    'Realtek','Realtek Semiconductor',
    'Razer','Razer Inc',
    'Corsair','Corsair Memory',
    'SteelSeries','SteelSeries ApS',
    'Valve','Valve Corp','Valve Corporation',
    'Epic Games','Epic Games, Inc.',
    'Blizzard','Blizzard Entertainment',
    'Riot Games','Riot Games, Inc.',
    'Google','Google LLC',
    'Mozilla','Mozilla Corporation',
    'Discord','Discord Inc.',
    'Spotify','Spotify AB',
    'Dropbox','Dropbox, Inc',
    'Apple','Apple Inc.',
    'Adobe','Adobe Inc.','Adobe Systems',
    'Oracle','Oracle America',
    'VMware','VMware, Inc.',
    'Malwarebytes','Malwarebytes Corporation',
    'Bitdefender','Bitdefender SRL',
    'Kaspersky','Kaspersky Lab',
    'ESET','ESET, spol. s r.o.',
    'Avast','Avast Software',
    'AVG','AVG Technologies',
    'CCleaner','Piriform',
    'Java','Oracle America, Inc.',
    'Python','Python Software Foundation',
    'GitHub','GitHub, Inc.',
    'JetBrains','JetBrains s.r.o.',
    'Zoom','Zoom Video Communications',
    'Slack','Slack Technologies',
    'TeamViewer','TeamViewer Germany GmbH',
    'AnyDesk','AnyDesk Software GmbH'
)

function Test-TrustedSigner {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return $null }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        if ($sig.Status -ne 'Valid') { return $null }
        $signer = $sig.SignerCertificate.Subject
        foreach ($t in $trustedSigners) {
            if ($signer -like "*$t*") { return $signer }
        }
    } catch {}
    return $null
}

$highSignal=@(
    'severe','matcha','spectre','aimbot','triggerbot','wallhack','silentaim','injector',
    'fatality','gamesense','neverlose','onetap','legendware','primordial','skeet',
    'memesense','nixware','aimware','pandora','weave','phantom','midnight','vape',
    'entropy','sapphire','hvh','aimassist','radarhack',
    'xeno','madium','potassium','volt'
)
$watchList=@('isabelle','ghostify','TIWorker')
$lowSignal=@('esp','cfg','config','dx9')
$suspExt=@('.dll','.exe','.sys','.asi','.cfg','.lua','.js','.py','.bat','.cmd','.ps1','.vbs')
$suspPathRx='\\(Temp|Downloads|Public)\\'

Write-Section "STEP 1 - System Information"
try{
    Get-ComputerInfo|Out-File "$Out\system-info.txt"
    $cv=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    Write-Result INFO "OS: $($cv.ProductName) build $($cv.CurrentBuild)"
    Get-Volume|Select DriveLetter,FileSystem,FileSystemLabel,Size,SizeRemaining|Export-Csv "$Out\volumes.csv" -NoTypeInformation
    Write-Result SAFE "System info collected."
}catch{Write-Result WARN "System info failed: $_"}

Write-Section "STEP 2 - Running Processes"
$procs=Get-CimInstance Win32_Process|Select ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate
$procs|Export-Csv "$Out\processes.csv" -NoTypeInformation
$s=@()
foreach($p in $procs){
    if(-not $p.ExecutablePath){continue}
    # FIRST: if signed by a trusted publisher, skip entirely
    $trusted=Test-TrustedSigner -FilePath $p.ExecutablePath
    if($trusted){
        Write-Result SAFE "Trusted process: $($p.Name) (signed: $trusted)"
        continue
    }
    $h=$false
    if($p.ExecutablePath -match $suspPathRx){$h=$true}
    foreach($k in $highSignal){if($p.Name -like "*$k*"){$h=$true;break}}
    if($p.CommandLine -match '-(enc|encodedcommand)\b|FromBase64String|DownloadString'){$h=$true}
    if($h){$s+=$p}
}
if($s.Count){foreach($p in $s){Write-Result FAIL "Susp proc: $($p.Name) PID $($p.ProcessId) -> $($p.ExecutablePath)"}}
else{Write-Result SAFE "No suspicious processes (trusted publishers excluded)."}

Write-Section "STEP 2b - Watchlist (TIWorker / Isabelle / Ghostify)"
foreach($w in $watchList){
    $found=Get-CimInstance Win32_Process|Where-Object{$_.Name -like "*$w*"}
    if($found){
        foreach($p in $found){
            $path=$p.ExecutablePath
            if(-not $path){$path='(unknown)'}
            if($w -eq 'TIWorker' -and $path -notlike '*\System32\*'){
                Write-Result FAIL "TIWorker running from unusual path: $path (expected System32)"
            }else{
                if(Test-Path $path){
                    $sig=Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
                    if($sig.Status -ne 'Valid'){
                        Write-Result FAIL "$w process UNSIGNED at: $path"
                    }else{
                        Write-Result WARN "$w process running (signed by $($sig.SignerCertificate.Subject)) at: $path"
                    }
                }else{
                    Write-Result WARN "$w process running, path: $path"
                }
            }
        }
    }
}

Write-Section "STEP 3 - Installed Programs"
$inst=Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*|Select DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation
$inst|Export-Csv "$Out\installed-programs.csv" -NoTypeInformation
$sI=@()
foreach($i in $inst){
    if(-not $i.DisplayName){continue}
    # skip if publisher is trusted
    $isTrusted=$false
    foreach($t in $trustedSigners){if($i.Publisher -like "*$t*"){$isTrusted=$true;break}}
    if($isTrusted){continue}
    foreach($k in $highSignal){if($i.DisplayName -like "*$k*"){$sI+=$i;break}}
}
if($sI.Count){foreach($x in $sI){Write-Result FAIL "Susp installed: $($x.DisplayName) [$($x.Publisher)]"}}
else{Write-Result SAFE "No installed apps matched cheat names (trusted publishers excluded)."}

Write-Section "STEP 4 - Persistence"
Get-CimInstance Win32_Service|Select Name,State,StartMode,PathName|Export-Csv "$Out\services.csv" -NoTypeInformation
Get-ScheduledTask|Select TaskPath,TaskName,State|Export-Csv "$Out\scheduled-tasks.csv" -NoTypeInformation
Get-CimInstance Win32_StartupCommand|Select Name,Command,Location,User|Export-Csv "$Out\startup.csv" -NoTypeInformation
$bS=Get-CimInstance Win32_Service|Where{$_.PathName -match $suspPathRx}
if($bS){foreach($x in $bS){
    $exe=($x.PathName -replace '^"([^"]+)".*','$1') -replace '^(\S+\.exe).*','$1'
    if(Test-TrustedSigner -FilePath $exe){Write-Result SAFE "Trusted service from drop path: $($x.Name)";continue}
    Write-Result FAIL "Svc from bad path: $($x.Name) -> $($x.PathName)"
}}else{Write-Result SAFE "No services from bad paths."}
$bT=Get-ScheduledTask|Where{($_.Actions.Execute -join ' ') -match $suspPathRx}
if($bT){foreach($x in $bT){Write-Result FAIL "Bad task: $($x.TaskPath)$($x.TaskName)"}}else{Write-Result SAFE "No bad scheduled tasks."}
$bU=Get-CimInstance Win32_StartupCommand|Where{$_.Command -match $suspPathRx}
if($bU){foreach($x in $bU){Write-Result FAIL "Bad startup: $($x.Name) -> $($x.Command)"}}else{Write-Result SAFE "No bad startup entries."}

Write-Section "STEP 5 - USB Devices"
Get-PnpDevice -PresentOnly|Select Class,FriendlyName,InstanceId,Status|Export-Csv "$Out\present-devices.csv" -NoTypeInformation
$u=Get-PnpDevice -PresentOnly|Where{$_.InstanceId -like 'USBSTOR*' -or $_.FriendlyName -match 'USB.*(Storage|Mass|Flash)'}
if($u){foreach($x in $u){Write-Result WARN "USB storage: $($x.FriendlyName) ($($x.InstanceId))"}}else{Write-Result SAFE "No USB storage attached."}

Write-Section "STEP 6 - Keyword Filename Scan (trusted signers excluded)"
$roots=@("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:USERPROFILE\AppData\Local","$env:USERPROFILE\AppData\Roaming","$env:USERPROFILE\AppData\LocalLow","$env:TEMP","C:\ProgramData","C:\Windows\Temp")|Where{Test-Path $_}
$hits=New-Object System.Collections.Generic.List[object]
foreach($root in $roots){
    Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue|ForEach-Object{
        $f=$_;$sig=$null
        foreach($k in $highSignal){if($f.Name -like "*$k*"){$sig='HIGH';break}}
        if(-not $sig){foreach($k in $watchList){if($f.Name -like "*$k*"){$sig='WATCH';break}}}
        if(-not $sig){foreach($k in $lowSignal){if($f.Name -like "*$k*"){$sig='LOW';break}}}
        if($sig -and ($suspExt -contains $f.Extension.ToLower())){
            $trusted=Test-TrustedSigner -FilePath $f.FullName
            if($trusted){
                Write-Result SAFE "Trusted file with keyword in name: $($f.Name) (signed: $trusted)"
                return
            }
            $hits.Add([PSCustomObject]@{Signal=$sig;FullName=$f.FullName;Length=$f.Length;CreationTime=$f.CreationTime;LastWriteTime=$f.LastWriteTime})
        }
    }
}
$hits|Export-Csv "$Out\keyword-files.csv" -NoTypeInformation
$hH=@($hits|Where{$_.Signal -eq 'HIGH'});$wH=@($hits|Where{$_.Signal -eq 'WATCH'});$lH=@($hits|Where{$_.Signal -eq 'LOW'})
if($hH.Count){foreach($h in $hH){Write-Result FAIL "High-signal file: $($h.FullName) ($($h.LastWriteTime))"}}
if($wH.Count){foreach($h in $wH){Write-Result WARN "Watchlist file: $($h.FullName)"}}
if($lH.Count){foreach($h in $lH){Write-Result WARN "Low-signal file: $($h.FullName)"}}
if($hits.Count -eq 0){Write-Result SAFE "No keyword file matches (trusted signers excluded)."}

Write-Section "STEP 7 - Signature & Publisher Check (all suspicious files)"
$toCheck=@()
$toCheck+=$hits|Select-Object -ExpandProperty FullName
$toCheck+=$s|ForEach-Object{$_.ExecutablePath}|Where-Object{$_}
$toCheck=$toCheck|Sort-Object -Unique|Where-Object{Test-Path $_}
$sigR=@()
foreach($file in $toCheck){
    try{
        $sg=Get-AuthenticodeSignature -FilePath $file -ErrorAction Stop
        $hh=(Get-FileHash $file -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        $signer=if($sg.SignerCertificate){$sg.SignerCertificate.Subject}else{'(none)'}
        $sigR+=[PSCustomObject]@{File=$file;SigStatus=$sg.Status;Signer=$signer;SHA256=$hh}
    }catch{
        $sigR+=[PSCustomObject]@{File=$file;SigStatus='Error';Signer='(unreadable)';SHA256=''}
    }
}
$sigR|Export-Csv "$Out\signatures.csv" -NoTypeInformation
if($sigR.Count -eq 0){
    Write-Result INFO "No suspicious files to sign-check."
}else{
    $bad=@()
    foreach($x in $sigR){
        $isWindows=$x.Signer -match 'Microsoft'
        $isValid=($x.SigStatus -eq 'Valid')
        $isTrusted=$false
        foreach($t in $trustedSigners){if($x.Signer -like "*$t*"){$isTrusted=$true;break}}
        if($isTrusted){Write-Result SAFE "Trusted signer: $($x.File) — $($x.Signer)"}
        elseif(-not $isValid){$bad+=$x}
        elseif(-not $isWindows){Write-Result WARN "Third-party signed (not Microsoft): $($x.File) — signer: $($x.Signer)"}
    }
    if($bad.Count -gt 0){foreach($b in $bad){Write-Result FAIL "Unsigned/Invalid: $($b.File) [$($b.SigStatus)] — signer: $($b.Signer)"}}
    elseif($sigR.Count -gt 0){Write-Result SAFE "All checked files were either trusted or valid."}
    foreach($g in ($sigR|Where-Object{$_.SigStatus -eq 'Valid' -and $_.Signer -match 'Microsoft'})){Write-Result INFO "Microsoft-signed: $($g.File)"}
}

Write-Section "STEP 8 - Prefetch"
$pf=Get-ChildItem "C:\Windows\Prefetch" -Filter "*.pf" -ErrorAction SilentlyContinue
$pf|Select Name,Length,CreationTime,LastWriteTime|Sort LastWriteTime -Descending|Export-Csv "$Out\prefetch.csv" -NoTypeInformation
$sP=@()
foreach($x in $pf){foreach($k in $highSignal){if($x.Name -like "*$k*"){$sP+=$x;break}}}
if($sP.Count){foreach($x in $sP){Write-Result FAIL "Susp prefetch: $($x.Name) (last write $($x.LastWriteTime))"}}
elseif($pf.Count -eq 0){Write-Result WARN "Prefetch empty/disabled."}
else{Write-Result SAFE "$($pf.Count) prefetch entries; no cheat-name matches."}
if($lastLogon -and $pf.Count){
    $rP=@($pf|Where{$_.LastWriteTime -gt $lastLogon})
    if($rP.Count){
        Write-Result WARN "$($rP.Count) prefetch entries newer than last logon — listing:"
        foreach($x in ($rP|Select-Object -First 20)){Write-Result INFO " $($x.Name) ($($x.LastWriteTime))"}
    }else{Write-Result SAFE "No prefetch newer than last logon."}
}

Write-Section "STEP 9 - Forensic Tools (BAMParser/SavedFilesViewer/MFTExplorer/DeletedFiles/PrefetchViewer)"
$tools=@('BAMParser','SavedFilesViewer','MFTExplorer','DeletedFiles','PrefetchViewer')
$tRoots=@("$env:USERPROFILE\Desktop","$env:USERPROFILE\Downloads","$env:USERPROFILE\Documents","$env:PROGRAMFILES","${env:ProgramFiles(x86)}","C:\ProgramData","C:\Tools")|Where{Test-Path $_}
foreach($tn in $tools){
    $found=$null
    foreach($r in $tRoots){
        $found=Get-ChildItem -Path $r -Filter "$tn*" -File -Recurse -ErrorAction SilentlyContinue|Where{$_.Extension -in '.exe','.dll','.msi','.zip'}|Select -First 1
        if($found){break}
    }
    if($found){
        $trusted=Test-TrustedSigner -FilePath $found.FullName
        if($trusted){Write-Result SAFE "$tn present but signed by trusted publisher ($trusted) — likely a bundled copy.";continue}
        $m=$found.LastWriteTime
        if($lastLogon -and $m -gt $lastLogon){Write-Result FAIL "$tn at $($found.FullName) MODIFIED after last logon ($m)."}
        else{Write-Result WARN "$tn found at $($found.FullName) (last modified $m)."}
    }else{Write-Result SAFE "$tn not found."}
}

Write-Section "STEP 10 - BAM / DAM"
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$bam=@("SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\$sid","SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\$sid")
$bE=New-Object System.Collections.Generic.List[object]
foreach($bp in $bam){
    try{
        $k=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($bp)
        if(-not $k){Write-Result WARN "BAM path not accessible: $bp";continue}
        foreach($vn in $k.GetValueNames()){
            $d=$k.GetValue($vn)
            if($d -is [byte[]] -and $d.Length -ge 8){
                $dt=[DateTime]::FromFileTime([BitConverter]::ToInt64($d,0))
                $bE.Add([PSCustomObject]@{Path=$vn;LastExec=$dt})
            }
        }
        $k.Close()
    }catch{Write-Result WARN "BAM read failed (SYSTEM-only): $bp"}
}
$bE|Export-Csv "$Out\bam-entries.csv" -NoTypeInformation
if($bE.Count){
    Write-Result SAFE "$($bE.Count) BAM/DAM entries parsed."
    $sB=@()
    foreach($b in $bE){
        # skip trusted-publisher executables from BAM too
        if(Test-Path $b.Path){
            $trusted=Test-TrustedSigner -FilePath $b.Path
            if($trusted){continue}
        }
        foreach($k in $highSignal){if($b.Path -like "*$k*"){$sB+=$b;break}}
    }
    if($sB.Count){foreach($b in $sB){Write-Result FAIL "BAM matches cheat: $($b.Path) @ $($b.LastExec)"}}
    else{Write-Result SAFE "No BAM entries matched cheat names (trusted signers excluded)."}
}else{Write-Result WARN "BAM/DAM unreadable."}

Write-Section "STEP 11 - USN Journal (C:)"
$usn=(fsutil usn queryjournal C: 2>&1)|Out-String
Add-Content $ReportPath $usn
if($usn -match 'Usn Journal ID'){Write-Result SAFE "USN journal active."}else{Write-Result WARN "USN journal unreadable/off."}

Write-Section "STEP 11b - DNS Cache (KeyAuth / Cheat Infrastructure)"
try{
    $dns=Get-DnsClientCache -ErrorAction Stop
    $dnsBad=@('keyauth','keyauth.win','auth.keyauth','keyauth.cc')
    $dnsHits=@()
    foreach($d in $dns){
        foreach($b in $dnsBad){
            if($d.Entry -like "*$b*" -or $d.RecordName -like "*$b*"){
                $dnsHits+=[PSCustomObject]@{Entry=$d.Entry;RecordName=$d.RecordName;Data=$d.Data;TimeToLive=$d.TimeToLive}
                break
            }
        }
    }
    $dnsHits|Export-Csv "$Out\dns-keyauth.csv" -NoTypeInformation
    if($dnsHits.Count -gt 0){
        foreach($h in $dnsHits){Write-Result FAIL "KeyAuth domain in DNS cache: $($h.Entry) -> $($h.Data)"}
    }else{Write-Result SAFE "No KeyAuth domains in DNS cache."}
}catch{Write-Result WARN "DNS cache query failed: $_"}

$hostsFile="$env:SystemRoot\System32\drivers\etc\hosts"
if(Test-Path $hostsFile){
    $hostsHit=Select-String -Path $hostsFile -Pattern 'keyauth|cheat|aimbot' -ErrorAction SilentlyContinue
    if($hostsHit){foreach($h in $hostsHit){Write-Result FAIL "Suspicious hosts entry: $($h.Line.Trim())"}}
    else{Write-Result SAFE "Hosts file clean."}
}

Write-Section "STEP 12 - Amcache / Shimcache"
$amc="C:\Windows\AppCompat\Programs\Amcache.hve"
if(Test-Path $amc){
    $am=Get-Item $amc
    Write-Result WARN "Amcache present (last write $($am.LastWriteTime))."
    try{Copy-Item $amc "$Out\Amcache.hve" -Force}catch{Write-Result WARN "Amcache copy failed."}
}else{Write-Result SAFE "Amcache absent."}
try{
    $sh=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache' -Name AppCompatCache -ErrorAction Stop
    if($sh.AppCompatCache){Write-Result WARN "Shimcache present."}
}catch{Write-Result WARN "Shimcache not readable."}

Write-Section "STEP 13 - Recycle Bin (Detailed)"
$rb=@()
Get-ChildItem 'C:\$Recycle.Bin' -Force -Recurse -ErrorAction SilentlyContinue|Where{-not $_.PSIsContainer -and $_.Name -notlike '$I*' -and $_.Name -ne 'desktop.ini'}|ForEach-Object{
    $rb+=[PSCustomObject]@{FullName=$_.FullName;Length=$_.Length;LastWrite=$_.LastWriteTime}
}
$rb|Export-Csv "$Out\recycle-bin.csv" -NoTypeInformation
if($rb.Count -eq 0){
    Write-Result SAFE "Recycle Bin empty."
}else{
    Write-Result WARN "$($rb.Count) Recycle Bin item(s) — listing all:"
    foreach($r in $rb){
        $susp=$false
        foreach($k in $highSignal){if($r.FullName -like "*$k*"){$susp=$true;break}}
        if($susp){Write-Result FAIL " [CHEAT-NAME] $($r.FullName) ($([math]::Round($r.Length/1KB,1)) KB, $($r.LastWrite))"}
        else{Write-Result INFO " $($r.FullName) ($([math]::Round($r.Length/1KB,1)) KB, $($r.