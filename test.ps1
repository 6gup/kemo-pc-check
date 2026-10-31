# =============================================================================
# STEP 42 - Discord Account Detection (Credential Manager)
# =============================================================================
Write-Host "=== STEP 42 - Discord Account Detection ===" -ForegroundColor Cyan
Show-Progress 30

$discordFound = $false

# 1. Check Windows Credential Manager for Discord tokens
$creds = cmdkey /list | Out-String
if ($creds -match 'discord') {
    Add-Result FAIL "Discord authentication token found in Windows Credential Manager (Account logged in)."
    $discordFound = $true
}

# 2. Check Discord Local State for User IDs
$localStatePath = "$env:APPDATA\discord\Local State"
if (Test-Path $localStatePath) {
    $json = Get-Content $localStatePath -Raw | ConvertFrom-Json
    if ($json.os_crypt.encrypted_key) {
        Add-Result INFO "Discord Local State encryption key found."
    }
}

# 3. Scan LevelDB for raw User IDs (17-19 digits)
$discordPath = "$env:APPDATA\discord\Local Storage\leveldb"
if (Test-Path $discordPath) {
    $dbFiles = Get-ChildItem -Path $discordPath -Include *.ldb, *.log -File -ErrorAction SilentlyContinue
    $foundIds = @()
    
    foreach ($file in $dbFiles) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            $txt = [System.Text.Encoding]::UTF8.GetString($bytes)
            
            # Extract ID patterns, ignoring random numbers by checking for standard Discord ID lengths
            $idMatches = [regex]::Matches($txt, '\b\d{17,19}\b')
            foreach ($m in $idMatches) { $foundIds += $m.Value }
        } catch {}
    }
    
    $uniqueIds = $foundIds | Sort-Object -Unique | Select-Object -First 5
    if ($uniqueIds.Count -gt 0) {
        Add-Result INFO "Discord User IDs found in cache:"
        foreach ($id in $uniqueIds) { Add-Result WARN "  [Discord ID] $id" }
        $discordFound = $true
    }
}

if (-not $discordFound) { Add-Result SAFE "No Discord account traces found." }
Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# STEP 43 - Roblox Account Detection (Registry & Logs)
# =============================================================================
Write-Host "=== STEP 43 - Roblox Account Detection ===" -ForegroundColor Cyan
Show-Progress 30

$robloxFound = $false

# 1. Check Roblox Player Registry (Exact Username location)
$playerRegPath = "HKCU:\Software\Roblox\RobloxPlayer"
if (Test-Path $playerRegPath) {
    $playerProps = Get-ItemProperty -Path $playerRegPath -ErrorAction SilentlyContinue
    if ($playerProps.PlayerName) {
        Add-Result FAIL "Roblox Username found in Registry: $($playerProps.PlayerName)"
        $robloxFound = $true
    }
}

# 2. Check Roblox Studio Registry (Exact Username location)
$studioRegPath = "HKCU:\Software\Roblox\RobloxStudioBrowser\roblox.com"
if (Test-Path $studioRegPath) {
    $studioProps = Get-ItemProperty -Path $studioRegPath -ErrorAction SilentlyContinue
    if ($studioProps.DisplayName) {
        Add-Result FAIL "Roblox Studio Username found in Registry: $($studioProps.DisplayName)"
        $robloxFound = $true
    }
}

# 3. Check Roblox Logs for exact JSON Authentication line
$robloxLogs = Get-ChildItem -Path "$env:LOCALAPPDATA\Roblox\logs" -Filter "*.log" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 2
foreach ($log in $robloxLogs) {
    try {
        $content = Get-Content $log.FullName -Raw -ErrorAction SilentlyContinue
        # Roblox logs print "DisplayName":"Username"
        $userMatches = [regex]::Matches($content, '"DisplayName":"([^"]+)"')
        foreach ($m in $userMatches) {
            Add-Result FAIL "Roblox Username found in Logs: $($m.Groups[1].Value)"
            $robloxFound = $true
        }
    } catch {}
}

if (-not $robloxFound) { Add-Result SAFE "No Roblox account traces found." }
Show-Progress 100
Flush-Results; Wait-Pager
