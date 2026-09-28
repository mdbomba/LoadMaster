# Interim WhatsUp Gold PowerShell action for a REST-only LoadMaster backup.
# Replace placeholders only in WUG's protected action configuration. Do not
# commit credentials or API keys to this file.

$ErrorActionPreference = "Stop"
$loadMaster = "10.0.0.90"
$apiKey = "<LOADMASTER_API_KEY>"
$wugUser = "<WUG_USER>"
$wugPassword = "<WUG_PASSWORD>"
$wugDeviceId = 60
$root = "C:\ProgramData\Ipswitch\WhatsUp\LoadMasterBackups\10.0.0.90"
$stamp = [DateTime]::UtcNow.ToString("yyyyMMddTHHmmssZ")
$archiveStamp = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss")
$generation = Join-Path $root $stamp
$backupPath = Join-Path $generation "LoadMaster-10.0.0.90-$stamp.backup"
$tarPath = Join-Path $generation "LoadMaster-10.0.0.90-$stamp.tar"
$extractPath = Join-Path $generation "extracted"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    New-Item -ItemType Directory -Path $extractPath -Force | Out-Null

    $body = @{ apikey = $apiKey; cmd = "backup" } | ConvertTo-Json -Compress
    $response = Invoke-RestMethod -Uri "https://$loadMaster/accessv2" -Method Post `
        -ContentType "application/json" -Body $body -TimeoutSec 120
    if ($response.code -ne 200 -or $response.status -ne "ok" -or !$response.data) {
        throw "LoadMaster backup API failed: $($response.message)"
    }

    [byte[]]$backup = [Convert]::FromBase64String($response.data)
    if ($backup.Length -lt 2 -or $backup[0] -ne 0x1f -or $backup[1] -ne 0x8b) {
        throw "LoadMaster backup is not gzip data"
    }
    [IO.File]::WriteAllBytes($backupPath, $backup)

    $inputStream = [IO.File]::OpenRead($backupPath)
    try {
        $gzip = New-Object IO.Compression.GZipStream(
            $inputStream,
            [IO.Compression.CompressionMode]::Decompress
        )
        try {
            $tar = [IO.File]::Create($tarPath)
            try { $gzip.CopyTo($tar) } finally { $tar.Dispose() }
        } finally { $gzip.Dispose() }
    } finally { $inputStream.Dispose() }

    if (!(Get-Command tar.exe -ErrorAction SilentlyContinue)) {
        throw "tar.exe is required to extract the LoadMaster backup"
    }
    & tar.exe -xf $tarPath -C $extractPath
    if ($LASTEXITCODE -ne 0) { throw "tar.exe extraction failed" }

    $hash = (Get-FileHash -Algorithm SHA256 -Path $backupPath).Hash.ToLowerInvariant()
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add("# Progress LoadMaster configuration backup")
    $lines.Add("# Source: $loadMaster")
    $lines.Add("# Captured UTC: $stamp")
    $lines.Add("# Restore bundle: $backupPath")
    $lines.Add("# Restore bundle SHA-256: $hash")
    $lines.Add("# Uncompressed tar: $tarPath")
    $lines.Add("# Extracted directory: $extractPath")
    $lines.Add("# Binary files are represented by metadata; use the .backup file for restore.")
    $lines.Add("")
    $utf8 = New-Object Text.UTF8Encoding($false, $true)
    foreach ($file in Get-ChildItem $extractPath -File -Recurse | Sort-Object FullName) {
        $relative = $file.FullName.Substring($extractPath.Length).TrimStart('\')
        [byte[]]$raw = [IO.File]::ReadAllBytes($file.FullName)
        $lines.Add("===== FILE: $relative =====")
        if ($raw -contains 0) {
            $fileHash = (Get-FileHash -Algorithm SHA256 -Path $file.FullName).Hash.ToLowerInvariant()
            $lines.Add("[binary file: $($raw.Length) bytes, sha256=$fileHash]")
        } else {
            try {
                $text = $utf8.GetString($raw).TrimEnd("`r", "`n")
                $lines.Add($text)
            } catch {
                $fileHash = (Get-FileHash -Algorithm SHA256 -Path $file.FullName).Hash.ToLowerInvariant()
                $lines.Add("[non-UTF8 file: $($raw.Length) bytes, sha256=$fileHash]")
            }
        }
        $lines.Add("")
    }
    $configText = $lines -join "`n"
    [IO.File]::WriteAllText((Join-Path $generation "configuration.txt"), $configText)

    # This creates a custom CM archive, not a task-produced backup record.
    $wugSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $login = Invoke-RestMethod -Uri "https://localhost/NmConsole/User/LoginAjax" `
        -Method Post -WebSession $wugSession -ContentType "application/x-www-form-urlencoded" `
        -Body @{ username = $wugUser; password = $wugPassword } -TimeoutSec 30
    if (!$login.authenticated) { throw "Local WUG authentication failed" }
    $archive = @{
        Key = "loadmaster-rest-backup"
        Description = "LoadMaster REST backup extracted as uncompressed text"
        ConfigText = $configText
        Retain = $false
        DeviceID = $wugDeviceId
        Timestamp = $archiveStamp
        Custom = $true
    }
    $envelope = @{
        Operation = "saveArchive"
        Json = ($archive | ConvertTo-Json -Compress)
    } | ConvertTo-Json -Compress
    Invoke-RestMethod -Uri "https://localhost/NmConsole/api/Core/CMArchive" `
        -Method Post -WebSession $wugSession -ContentType "application/json" `
        -Body $envelope -TimeoutSec 30 | Out-Null

    $manifest = @(
        "LoadMaster REST backup and WUG custom archive completed"
        "Source: $loadMaster"
        "Captured UTC: $stamp"
        "Restore bundle: $backupPath"
        "Restore bundle SHA-256: $hash"
        "Uncompressed tar: $tarPath"
        "Extracted directory: $extractPath"
        "Extracted files: $((Get-ChildItem $extractPath -File -Recurse).Count)"
        "WUG custom archive key: loadmaster-rest-backup"
    ) -join "`r`n"
    [IO.File]::WriteAllText((Join-Path $generation "manifest.txt"), $manifest)
    [IO.File]::WriteAllText((Join-Path $root "latest.txt"), $manifest)
    Get-ChildItem $root -Directory | Sort-Object Name -Descending | Select-Object -Skip 30 |
        Remove-Item -Recurse -Force
    $Context.SetResult(0, $manifest)
} catch {
    if (Test-Path $generation) { Remove-Item $generation -Recurse -Force }
    $Context.SetResult(1, "LoadMaster backup failed: $($_.Exception.Message)")
}
