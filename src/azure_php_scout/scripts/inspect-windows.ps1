# Fixed, bounded PHP inventory. Reads version metadata; never executes php.exe.
# Run Command executes this as SYSTEM and records its own agent logs.
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$script:Budget = 0
$script:Limited = $false
$script:ReadErrors = 0
$candidates = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
function Encode([string] $Value) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Value)) }
function Emit([string] $Line) {
    if (($script:Budget + $Line.Length + 1) -le 3200) {
        Write-Output $Line
        $script:Budget += $Line.Length + 1
    } else { $script:Limited = $true }
}
function Add-Candidate([string] $Path) {
    # Never follow UNC/network paths while running as SYSTEM.
    if ($Path -match '^[A-Za-z]:[\\/]') { [void] $candidates.Add($Path) }
    elseif ($Path) { $script:ReadErrors++ }
}
Write-Output 'SCOUT_GUEST_BEGIN_V1'
Write-Output 'OS|Windows'
$processes = @(Get-CimInstance Win32_Process -Filter "Name='php.exe' OR Name='php-cgi.exe' OR Name='php-fpm.exe'" -Property ExecutablePath -ErrorVariable processError)
$processState = 'unknown'
if (-not $processError) {
    $processState = 'no'
    if ($processes.Count -gt 0) { $processState = 'yes' }
}
foreach ($item in $processes) { if ($item.ExecutablePath) { Add-Candidate $item.ExecutablePath } }
# Read IIS FastCGI mappings without changing IIS or printing configuration.
$iis = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
if ($iis -match '^[A-Za-z]:[\\/]' -and (Test-Path -LiteralPath $iis)) {
    try {
        $document = New-Object System.Xml.XmlDocument
        $document.XmlResolver = $null
        $document.Load($iis)
        foreach ($application in $document.SelectNodes('/configuration/system.webServer/fastCgi/application')) {
            $candidate = [Environment]::ExpandEnvironmentVariables([string]$application.fullPath)
            if ([IO.Path]::GetFileName($candidate) -match '^php(-cgi)?\.exe$') { Add-Candidate $candidate }
        }
    } catch { $script:ReadErrors++ }
}
$patterns = @('C:\PHP*\php.exe', 'C:\PHP*\php-cgi.exe', 'C:\xampp\php\php.exe',
    'C:\wamp64\bin\php\php*\php.exe', 'C:\wamp\bin\php\php*\php.exe',
    "$env:ProgramFiles\PHP*\php.exe", "${env:ProgramFiles(x86)}\PHP*\php.exe")
foreach ($pattern in $patterns) {
    if ($pattern -notmatch '^[A-Za-z]:[\\/]') { continue }
    foreach ($file in @(Get-Item -Path $pattern)) {
        if (-not $file.PSIsContainer) { Add-Candidate $file.FullName }
    }
}
foreach ($directory in ($env:PATH -split ';')) {
    if ($directory -match '^[A-Za-z]:[\\/]') {
        Add-Candidate (Join-Path $directory 'php.exe')
        Add-Candidate (Join-Path $directory 'php-cgi.exe')
    }
}
$count = 0
foreach ($candidate in $candidates) {
    if ($count -ge 8) { $script:Limited = $true; break }
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
    $count++
    try {
        $versionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($candidate)
        $version = [string]$versionInfo.ProductVersion
        if ($version -notmatch '^\d+\.\d+\.\d+') { $version = [string]$versionInfo.FileVersion }
        if ($version -match '^(\d+\.\d+\.\d+)\.(\d+)$') {
            $version = $matches[1] + '+file.' + $matches[2]
        }
        if ($version -match '^\d+\.\d+\.\d+' -and $version.Length -le 64 -and [Text.Encoding]::UTF8.GetByteCount($candidate) -le 160) {
            Emit ('RUNTIME|' + $version + '|' + (Encode $candidate) + '|file_metadata')
        } else { $script:ReadErrors++ }
    } catch { $script:ReadErrors++ }
}
Write-Output ('PROCESS|' + $processState)
Write-Output 'PACKAGES|not_checked'
Write-Output ('BINARY_ERRORS|' + $script:ReadErrors)
$limit = 'no'
if ($script:Limited) { $limit = 'yes' }
Write-Output ('LIMIT|' + $limit)
Write-Output 'SCOUT_GUEST_END_V1'
