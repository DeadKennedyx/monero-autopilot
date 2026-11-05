param(
    [switch]$Headless,
    [switch]$NoBrowser,
    [ValidateSet('Release','Debug')][string]$Configuration = 'Release',
    [string]$DataDirectory
)
$ErrorActionPreference = 'Stop'
# Windows command-line parsing needs trailing backslashes doubled inside quotes.
function ConvertTo-ProcessArgument([string]$Value) { '"' + ($Value -replace '(\\+)$','$1$1') + '"' }
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$executable = Join-Path $projectRoot ('src-tauri\target\{0}\monero-autopilot.exe' -f $Configuration.ToLowerInvariant())
$readyPath = Join-Path $projectRoot '.runtime\app-ready.json'
$version = (Get-Content -LiteralPath (Join-Path $projectRoot 'src-tauri\tauri.conf.json') -Raw | ConvertFrom-Json).version
$customProfile = $PSBoundParameters.ContainsKey('DataDirectory')
if (-not $customProfile) {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA) -or $env:LOCALAPPDATA -notmatch '^(?:[A-Za-z]:[\\/]|\\\\)') { throw 'Windows local app data must be an absolute path.' }
    $DataDirectory = Join-Path $env:LOCALAPPDATA 'MoneroAutoPilot\mainnet-prototype'
}
if ([string]::IsNullOrWhiteSpace($DataDirectory) -or $DataDirectory -notmatch '^(?:[A-Za-z]:[\\/]|\\\\)' -or $DataDirectory -match '[\r\n"]') { throw 'DataDirectory must be an absolute path without quotes or newlines.' }
$DataDirectory = [IO.Path]::GetFullPath($DataDirectory)
if ($customProfile) {
    $pathHash = [Security.Cryptography.SHA256]::Create()
    try { $profileId = ([BitConverter]::ToString($pathHash.ComputeHash([Text.Encoding]::UTF8.GetBytes($DataDirectory.ToLowerInvariant())))).Replace('-','').Substring(0,16) } finally { $pathHash.Dispose() }
    $readyPath = Join-Path $projectRoot ('.runtime\app-mainnet-{0}-ready.json' -f $profileId)
}
if (-not (Test-Path -LiteralPath $executable)) { throw "Build the $Configuration app first with scripts\build-app.ps1 -Configuration $Configuration." }
$binaryVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($executable).ProductVersion
if ($binaryVersion -ne $version) { throw "The $Configuration executable is version $binaryVersion; build mainnet version $version with scripts\build-app.ps1 before launching it." }
New-Item -ItemType Directory -Path (Join-Path $projectRoot '.runtime') -Force | Out-Null
if (Test-Path -LiteralPath $readyPath) {
    $active = $null
    try {
        $previous = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json
        $running = Get-Process -Id $previous.pid -ErrorAction Stop
        if ($running.ProcessName -eq 'monero-autopilot') { $active = $running }
    } catch { }
    if ($null -ne $active) {
        if ($active.Path -ne $executable -or $previous.mode -ne 'desktop' -or $previous.network -ne 'mainnet' -or $previous.version -ne $version) {
            throw 'Another desktop build is open. Save and quit that app before starting this mainnet build. No running wallet was stopped.'
        }
        if ($previous.url -match '^http://127\.0\.0\.1:\d+/$') {
            $response = $null
            try { $response = Invoke-WebRequest -Uri $previous.url -UseBasicParsing -TimeoutSec 3 } catch { }
            if ($response.StatusCode -eq 200) {
                Write-Output "Monero AutoPilot $version (mainnet) is running: $($previous.url)"
                if (-not $NoBrowser -and -not $previous.desktop) { Start-Process -FilePath $previous.url }
                return
            }
        }
        throw 'The running desktop app has not responded yet. Wait for it or close it normally before starting another.'
    }
    Remove-Item -LiteralPath $readyPath
}
$arguments = '--project-root {0} --ready-file {1} --data-dir {2}' -f (ConvertTo-ProcessArgument $projectRoot),(ConvertTo-ProcessArgument $readyPath),(ConvertTo-ProcessArgument $DataDirectory)
if ($Headless) { $arguments += ' --headless' }
# Start in the current user's environment, and always pass the resolved profile.
# WMI/CIM process creation can inherit a provider environment with different
# app-data variables even when the new process has the correct user identity.
$created = Start-Process -FilePath $executable -ArgumentList $arguments -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
$ready = $null
for ($attempt=0; $attempt -lt 150; $attempt++) {
    if (Test-Path -LiteralPath $readyPath) {
        $candidate = $null
        try { $candidate = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json } catch { }
        if ($null -ne $candidate) {
            if ($candidate.pid -ne $created.Id) { throw 'Another desktop launch owns the readiness file. Review the open app; no running wallet was stopped.' }
            $ready = $candidate
            break
        }
    }
    if ($null -eq (Get-Process -Id $created.Id -ErrorAction SilentlyContinue)) { throw 'AutoPilot could not open the wallet. Close other wallet applications and try again.' }
    Start-Sleep -Milliseconds 100
}
if ($null -eq $ready) { throw 'AutoPilot did not report readiness.' }
if ($ready.url -notmatch '^http://127\.0\.0\.1:\d+/$') { throw 'Unexpected app address.' }
if ($ready.mode -ne 'desktop' -or $ready.network -ne 'mainnet' -or $ready.version -ne $version) { throw 'The executable does not match this mainnet desktop release. Rebuild the selected configuration; no wallet data was reset.' }
Write-Output "Monero AutoPilot $version (mainnet): $($ready.url)"
if ($ready.startupBlocked) { Write-Output 'Startup needs attention. Review the app message; an already-open wallet must be closed normally before handover.' }
if ($Headless -and -not $NoBrowser) { Start-Process -FilePath $ready.url }
