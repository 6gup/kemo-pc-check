# =============================================================================
# made-by-kemo | PC Forensic Check v3.0 (detect.ac-style triage)
# made-by-kemo | Run as Administrator. Output -> $env:USERPROFILE\Desktop\PC-Check
# made-by-kemo | Safe: green | Warn: yellow | Fail: red | Info: cyan
# =============================================================================
$ErrorActionPreference='SilentlyContinue'; $ProgressPreference='SilentlyContinue'
Write-Host "`n=== made-by-kemo | PC Forensic Check v3.0 | starting... ===`n" -ForegroundColor Cyan
$Out="$env:USERPROFILE\Desktop\PC-Check"; $ReportPath=Join-Path $Out "report.txt"
New-Item -ItemType Directory -Path $Out -Force | Out-Null
"made-by-kemo | v3.0 | started $(Get-Date)" | Out-File $ReportPath
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
    $h=$false
    if($p.ExecutablePath -match $suspPathRx){$h=$true}
    foreach($k in $highSignal){if($p.Name -like "*$k*"){$h=$true;break}}
    if($p.CommandLine -match '-(enc|encodedcommand)\b|FromBase64String|DownloadString'){$h=$true}
    if($h){$s+=$p}
}
if($s.Count){foreach($p in $s){Write-Result FAIL "Susp proc: $($p.Name) PID $($p.ProcessId) -> $($p.ExecutablePath)"}}
else{Write-Result SAFE "No suspicious processes."}

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
    foreach($k in $highSignal){if($i.DisplayName -like "*$k*"){$sI+=$i;break}}
}
if($sI.Count){foreach($x in $sI){Write-Result FAIL "Susp installed: $($x.DisplayName) [$($x.Publisher)]"}}
else{Write-Result SAFE "No installed apps matched cheat names."}

Write-Section "STEP 4 - Persistence"
Get-CimInstance Win32_Service|Select Name,State,StartMode,PathName|Export-Csv "$Out\services.csv" -NoTypeInformation
Get-ScheduledTask|Select TaskPath,TaskName,State|Export-Csv "$Out\scheduled-tasks.csv" -NoTypeInformation
Get-CimInstance Win32_StartupCommand|Select Name,Command,Location,User|Export-Csv "$Out\startup.csv" -NoTypeInformation
$bS=Get-CimInstance Win32_Service|Where{$_.PathName -match $suspPathRx}
if($bS){foreach($x in $bS){Write-Result FAIL "Svc from bad path: $($x.Name) -> $($x.PathName)"}}else{Write-Result SAFE "No services from bad paths."}
$bT=Get-ScheduledTask|Where{($_.Actions.Execute -join ' ') -match $suspPathRx}
if($bT){foreach($x in $bT){Write-Result FAIL "Bad task: $($x.TaskPath)$($x.TaskName)"}}else{Write-Result SAFE "No bad scheduled tasks."}
$bU=Get-CimInstance Win32_StartupCommand|Where{$_.Command -match $suspPathRx}
if($bU){foreach($x in $bU){Write-Result FAIL "Bad startup: $($x.Name) -> $($x.Command)"}}else{Write-Result SAFE "No bad startup entries."}

Write-Section "STEP 5 - USB Devices"
Get-PnpDevice -PresentOnly|Select Class,FriendlyName,InstanceId,Status|Export-Csv "$Out\present-devices.csv" -NoTypeInformation
$u=Get-PnpDevice -PresentOnly|Where{$_.InstanceId -like 'USBSTOR*' -or $_.FriendlyName -match 'USB.*(Storage|Mass|Flash)'}
if($u){foreach($x in $u){Write-Result WARN "USB storage: $($x.FriendlyName) ($($x.InstanceId))"}}else{Write-Result SAFE "No USB storage attached."}

Write-Section "STEP 6 - Keyword Filename Scan"
$roots=@("$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:USERPROFILE\AppData\Local","$env:USERPROFILE\AppData\Roaming","$env:USERPROFILE\AppData\LocalLow","$env:TEMP","C:\ProgramData","C:\Windows\Temp")|Where{Test-Path $_}
$hits=New-Object System.Collections.Generic.List[object]
foreach($root in $roots){
    Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue|ForEach-Object{
        $f=$_;$sig=$null
        foreach($k in $highSignal){if($f.Name -like "*$k*"){$sig='HIGH';break}}
        if(-not $sig){foreach($k in $watchList){if($f.Name -like "*$k*"){$sig='WATCH';break}}}
        if(-not $sig){foreach($k in $lowSignal){if($f.Name -like "*$k*"){$sig='LOW';break}}}
        if($sig -and ($suspExt -contains $f.Extension.ToLower())){
            $hits.Add([PSCustomObject]@{Signal=$sig;FullName=$f.FullName;Length=$f.Length;CreationTime=$f.CreationTime;LastWriteTime=$f.LastWriteTime})
        }
    }
}
$hits|Export-Csv "$Out\keyword-files.csv" -NoTypeInformation
$hH=@($hits|Where{$_.Signal -eq 'HIGH'});$wH=@($hits|Where{$_.Signal -eq 'WATCH'});$lH=@($hits|Where{$_.Signal -eq 'LOW'})
if($hH.Count){foreach($h in $hH){Write-Result FAIL "High-signal file: $($h.FullName) ($($h.LastWriteTime))"}}
if($wH.Count){foreach($h in $wH){Write-Result WARN "Watchlist file: $($h.FullName)"}}
if($lH.Count){foreach($h in $lH){Write-Result WARN "Low-signal file: $($h.FullName)"}}
if($hits.Count -eq 0){Write-Result SAFE "No keyword file matches."}

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
        if(-not $isValid){$bad+=$x}
        elseif(-not $isWindows){Write-Result WARN "Third-party signed (not Microsoft): $($x.File) — signer: $($x.Signer)"}
    }
    if($bad.Count -gt 0){foreach($b in $bad){Write-Result FAIL "Unsigned/Invalid: $($b.File) [$($b.SigStatus)] — signer: $($b.Signer)"}}
    else{Write-Result SAFE "All checked files had valid signatures."}
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
    foreach($b in $bE){foreach($k in $highSignal){if($b.Path -like "*$k*"){$sB+=$b;break}}}
    if($sB.Count){foreach($b in $sB){Write-Result FAIL "BAM matches cheat: $($b.Path) @ $($b.LastExec)"}}
    else{Write-Result SAFE "No BAM entries matched cheat names."}
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
        else{Write-Result INFO " $($r.FullName) ($([math]::Round($r.Length/1KB,1)) KB, $($r.LastWrite))"}
    }
}

Write-Section "STEP 14 - Volume Shadow Copies (Detailed)"
$vssOut=(vssadmin list shadows 2>&1)|Out-String
Add-Content $ReportPath $vssOut
if($vssOut -match 'No items found'){
    Write-Result SAFE "No shadow copies present."
}elseif($vssOut -match 'Shadow Copy ID'){
    $creationMatches=[regex]::Matches($vssOut,'creation time:\s*(.+)')
    $count=$creationMatches.Count
    Write-Result WARN "$count shadow copy/copies present — possible old file versions:"
    $i=1
    foreach($m in $creationMatches){Write-Result INFO " Shadow #$i created: $($m.Groups[1].Value.Trim())";$i++}
    $vssOut|Out-File "$Out\vss-raw.txt"
}else{Write-Result WARN "VSS query returned unexpected output (admin required)."}

Write-Section "STEP 15 - Defender (Detailed)"

try{
    $mp=Get-MpComputerStatus
    $off=@()
    if(-not $mp.RealTimeProtectionEnabled){$off+='RealTimeProtection'}
    if(-not $mp.AntivirusEnabled){$off+='Antivirus'}
    if(-not $mp.BehaviorMonitorEnabled){$off+='BehaviorMonitor'}
    if(-not $mp.OnAccessProtectionEnabled){$off+='OnAccessProtection'}
    if(-not $mp.IsTamperProtected){$off+='TamperProtection'}
    if(-not $mp.IoavProtectionEnabled){$off+='IOAV'}
    if($off.Count -gt 0){Write-Result FAIL "Defender protections DISABLED: $($off -join ', ')"}
    else{Write-Result SAFE "All Defender real-time protections enabled."}
    $mp|Format-List|Out-File "$Out\defender-status.txt"
}catch{Write-Result WARN "Get-MpComputerStatus failed: $_"}

try{
    $pref=Get-MpPreference
    $exPaths=@($pref.ExclusionPath)
    $exProcs=@($pref.ExclusionProcess)
    $exExts=@($pref.ExclusionExtension)
    $exIps=@($pref.ExclusionIpAddress)
    $totalEx=$exPaths.Count+$exProcs.Count+$exExts.Count+$exIps.Count
    if($totalEx -gt 0){
        Write-Result FAIL "Defender has $totalEx exclusion(s) configured:"
        foreach($e in $exPaths){Write-Result FAIL " [Path] $e"}
        foreach($e in $exProcs){Write-Result FAIL " [Process] $e"}
        foreach($e in $exExts){Write-Result FAIL " [Extension] $e"}
        foreach($e in $exIps){Write-Result FAIL " [IP] $e"}
    }else{Write-Result SAFE "No Defender exclusions configured."}
    $pref|Format-List|Out-File "$Out\defender-preferences.txt"
}catch{Write-Result WARN "Get-MpPreference failed (SYSTEM/admin required): $_"}

try{
    $threats=@(Get-MpThreatDetection)
    if($threats.Count -gt 0){
        $threats|Select ThreatID,ThreatStatusID,InitialDetectionTime,LastThreatStatusChangeTime,Resources|Export-Csv "$Out\defender-threats.csv" -NoTypeInformation
        foreach($t in $threats){
            $status=if($t.ThreatStatusID -eq 3){'ALLOWED/ACTIVE'}else{"status $($t.ThreatStatusID)"}
            Write-Result FAIL "Threat [$status]: $($t.ThreatID) -> $($t.Resources)"
        }
    }else{Write-Result SAFE "No Defender threat detections."}
}catch{Write-Result WARN "Get-MpThreatDetection failed: $_"}

try{
    $protHist=@(Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-Windows Defender/Operational';
        Id=1116,1117,1118,1119,5001,5007
    } -MaxEvents 100 -ErrorAction SilentlyContinue)
    if($protHist.Count -gt 0){
        $protHist|Select TimeCreated,Id,Message|Export-Csv "$Out\defender-history.csv" -NoTypeInformation
        Write-Result WARN "$($protHist.Count) Defender history events (detections/config changes) exported:"
        foreach($e in ($protHist|Select -First 5)){
            Write-Result INFO " History: ID $($e.Id) at $($e.TimeCreated) — $($e.Message.Split("`n")[0])"
        }
    }else{Write-Result SAFE "No recent Defender detection/config-change events."}
}catch{Write-Result WARN "Defender event log query failed: $_"}

Wri
