# =============================================================================
# STEP 42 - Discord Account Detection (Fixed)
# =============================================================================
Write-Host "=== STEP 42 - Discord Account Detection ===" -ForegroundColor Cyan
Show-Progress 30

$discordPath = "$env:APPDATA\discord\Local Storage\leveldb"
$foundIds = @()
$foundUsers = @()

if (Test-Path $discordPath) {
    $dbFiles = Get-ChildItem -Path $discordPath -Include *.ldb, *.log -File -ErrorAction SilentlyContinue
    
    foreach ($file in $dbFiles) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            $txt = [System.Text.Encoding]::UTF8.GetString($bytes)
            
            # 1. Find Discord IDs (17-19 digit numbers)
            $idMatches = [regex]::Matches($txt, '\d{17,19}')
            foreach ($m in $idMatches) { $foundIds += $m.Value }
            
            # 2. Find Username patterns (Discord usernames are lowercase, 2-32 chars)
            # We look for strings that commonly precede a username in the cache
            $userMatches = [regex]::Matches($txt, '(?i)(?:username|global_name|display_name|tag)"?\s*:\s*"([a-zA-Z0-9_.]{2,32})"')
            foreach ($m in $userMatches) { $foundUsers += $m.Groups[1].Value }
            
            # 3. Check for the Token prefix (Proves active login)
            if ($txt -match 'dQw4w9WgXcQ:') {
                Add-Result WARN "Discord authentication token found in cache (Account active)."
            }
        } catch {}
    }
    
    $uniqueIds = $foundIds | Sort-Object -Unique | Select-Object -First 10
    $uniqueUsers = $foundUsers | Sort-Object -Unique | Select-Object -First 10
    
    if ($uniqueIds.Count -gt 0 -or $uniqueUsers.Count -gt 0) {
        Add-Result INFO "Discord Cache extracted:"
        foreach ($id in $uniqueIds) { Add-Result WARN "  [Discord ID] $id" }
        foreach ($user in $uniqueUsers) { Add-Result WARN "  [Discord Username] $user" }
        
        if ($uniqueIds.Count -gt 1 -or $uniqueUsers.Count -gt 1) {
            Add-Result FAIL "Multiple Discord identities found in cache (Alt accounts)."
        }
    } else {
        Add-Result SAFE "No Discord identities found in cache."
    }
} else {
    Add-Result SAFE "Discord local storage not found."
}

Show-Progress 100
Flush-Results; Wait-Pager

# =============================================================================
# STEP 43 - Roblox Account Detection (Fixed)
# =============================================================================
Write-Host "=== STEP 43 - Roblox Account Detection ===" -ForegroundColor Cyan
Show-Progress 30

$robloxAccounts = @()

# 1. Check the exact Registry key Roblox uses for the Auth Cookie
$robloxRegPath = "HKCU:\Software\Roblox\RobloxStudioBrowser\roblox.com"
if (Test-Path $robloxRegPath) {
    $regProps = Get-ItemProperty -Path $robloxRegPath -ErrorAction SilentlyContinue
    if ($regProps.ROBLOSECURITY) {
        Add-Result FAIL "Roblox .ROBLOSECURITY cookie found in registry (Account is logged in)."
    }
} else {
    Add-Result INFO "Roblox Studio registry key not found (User might only have the Player installed)."
}

# 2. Check the Player Registry key for the exact Username
$playerRegPath = "HKCU:\Software\Roblox\RobloxPlayer"
if (Test-Path $playerRegPath) {
    $playerProps = Get-ItemProperty -Path $playerRegPath -ErrorAction SilentlyContinue
    if ($playerProps.PlayerName) {
        Add-Result FAIL "Roblox Username found in registry: $($playerProps.PlayerName)"
        $robloxAccounts += $playerProps.PlayerName
    }
}

# 3. Check Roblox Logs for exact JSON Authentication lines
$robloxLogs = Get-ChildItem -Path "$env:LOCALAPPDATA\Roblox\logs" -Filter "*.log" -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 3
foreach ($log in $robloxLogs) {
    try {
        $content = Get-Content $log.FullName -Raw -ErrorAction SilentlyContinue
        # Roblox logs print exact JSON when authenticating
        $userMatches = [regex]::Matches($content, '"DisplayName":"([^"]+)"')
        foreach ($m in $userMatches) { $robloxAccounts += $m.Groups[1].Value }
    } catch {}
}

$uniqueRoblox = $robloxAccounts | Sort-Object -Unique | Where-Object { $_ -notmatch '^(User|Data|Account|Personal|Game)$' }
if ($uniqueRoblox.Count -gt 0) {
    Add-Result INFO "Roblox Usernames found:"
    foreach ($user in $uniqueRoblox) {
        Add-Result WARN "  [Roblox] Username: $user"
    }
} else {
    Add-Result SAFE "No Roblox usernames found in logs."
}

Show-Progress 100
Flush-Results; Wait-Pager