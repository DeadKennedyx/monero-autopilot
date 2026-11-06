param([Parameter(Mandatory)][ValidatePattern('^[a-z0-9][a-z0-9_-]{0,39}$')][string]$RunId)
$ErrorActionPreference = 'Stop'
$qaAppRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$qaRunRoot = Join-Path $qaAppRoot ".runtime\native-fault\$RunId"
$qaOverlay = Get-Content -LiteralPath (Join-Path $qaRunRoot 'overlay.json') -Raw | ConvertFrom-Json
$qaExpectedSource = Join-Path $qaRunRoot 'source'
if ($qaOverlay.source -ne $qaExpectedSource) { throw 'Overlay path does not match its isolated run.' }
$qaBuildRoot = Join-Path $qaExpectedSource 'app'
foreach ($qaFile in $qaOverlay.overlayHashes.PSObject.Properties) {
    $qaSourceFile = [IO.Path]::GetFullPath((Join-Path $qaExpectedSource $qaFile.Name))
    if (-not $qaSourceFile.StartsWith($qaExpectedSource.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected overlay source path.' }
    if ((Get-FileHash -LiteralPath $qaSourceFile -Algorithm SHA256).Hash.ToLowerInvariant() -ne $qaFile.Value) { throw 'Overlay sources changed after snapshot. Prepare a new reviewed run.' }
}
$qaSavedTarget = $env:CARGO_TARGET_DIR
try {
    $env:CARGO_TARGET_DIR = Join-Path $qaBuildRoot 'src-tauri\target'
    & (Join-Path $qaBuildRoot 'scripts\build-app.ps1') -Configuration Release
    if ($LASTEXITCODE -ne 0) { throw 'QA desktop build failed.' }
    $qaExecutable = Join-Path $qaBuildRoot 'src-tauri\target\release\monero-autopilot-qa.exe'
    Copy-Item -LiteralPath (Join-Path $qaBuildRoot 'src-tauri\target\release\monero-autopilot.exe') -Destination $qaExecutable -Force
    @{schema=1;executable=$qaExecutable;sha256=(Get-FileHash -LiteralPath $qaExecutable -Algorithm SHA256).Hash.ToLowerInvariant();overlaySha256=(Get-FileHash -LiteralPath (Join-Path $qaRunRoot 'overlay.json') -Algorithm SHA256).Hash.ToLowerInvariant()} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $qaRunRoot 'build.json') -Encoding utf8
    Write-Output 'QA desktop built and hashed. No wallet was launched.'
} finally { $env:CARGO_TARGET_DIR = $qaSavedTarget }
