param([Parameter(Mandatory)][ValidatePattern('^[a-z0-9][a-z0-9_-]{0,39}$')][string]$RunId)
$ErrorActionPreference = 'Stop'
$qaAppRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$qaRunRoot = Join-Path $qaAppRoot ".runtime\native-fault\$RunId"
$qaBuild = Get-Content -LiteralPath (Join-Path $qaRunRoot 'build.json') -Raw | ConvertFrom-Json
$qaBuildRoot = Join-Path $qaRunRoot 'source\app'
$qaExecutable = Join-Path $qaBuildRoot 'src-tauri\target\release\monero-autopilot-qa.exe'
if ($qaBuild.executable -ne $qaExecutable -or (Get-FileHash -LiteralPath $qaExecutable -Algorithm SHA256).Hash.ToLowerInvariant() -ne $qaBuild.sha256 -or (Get-FileHash -LiteralPath (Join-Path $qaRunRoot 'overlay.json') -Algorithm SHA256).Hash.ToLowerInvariant() -ne $qaBuild.overlaySha256) { throw 'QA build identity does not match the recorded snapshot.' }
$qaReady = Join-Path $qaRunRoot 'app-ready.json'
if (Test-Path -LiteralPath $qaReady) { throw 'A readiness record already exists. Close/review the prior QA app; do not start another.' }
$qaProfile = Join-Path $qaRunRoot 'profile'
$qaProfileMarker = Join-Path $qaRunRoot 'qa-profile.json'
if (Test-Path -LiteralPath $qaProfile) {
    if ((Get-Item -LiteralPath $qaProfile).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'QA profile must not be a link or junction.' }
    if (-not (Test-Path -LiteralPath $qaProfileMarker)) { throw 'An unmarked profile already exists. Refusing to adopt or copy another wallet.' }
}
if (Test-Path -LiteralPath $qaProfileMarker) {
    $qaProfileRecord = Get-Content -LiteralPath $qaProfileMarker -Raw | ConvertFrom-Json
    if ($qaProfileRecord.run -ne $RunId -or $qaProfileRecord.path -ne $qaProfile) { throw 'QA profile ownership marker does not match this run.' }
} else {
    @{run=$RunId;path=$qaProfile} | ConvertTo-Json | Set-Content -LiteralPath $qaProfileMarker -Encoding utf8
}
function Quote-QAArgument([string]$Value) { '"' + ($Value -replace '(\\+)$','$1$1') + '"' }
# There is intentionally no user-supplied profile path or fallback to LOCALAPPDATA.
$qaArguments = '--project-root {0} --data-dir {1} --ready-file {2}' -f (Quote-QAArgument $qaBuildRoot),(Quote-QAArgument $qaProfile),(Quote-QAArgument $qaReady)
Start-Process -FilePath $qaExecutable -ArgumentList $qaArguments -WorkingDirectory $qaBuildRoot -WindowStyle Hidden | Out-Null
Write-Output "Opened the separate QA desktop for $RunId. Use only this run's controlled wallet."
