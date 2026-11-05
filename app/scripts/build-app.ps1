param([ValidateSet('Release','Debug')][string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$appProjectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location $appProjectRoot
try {
    . (Join-Path $PSScriptRoot 'workspace-env.ps1')
    pnpm build:app
    if ($LASTEXITCODE -ne 0) { throw 'Desktop frontend build failed.' }
    node scripts/prepare-installer.mjs
    if ($LASTEXITCODE -ne 0) { throw 'Runtime resource verification failed.' }
    $cargoArguments = @('build','--manifest-path','src-tauri/Cargo.toml','--locked')
    if ($Configuration -eq 'Release') { $cargoArguments += '--release' }
    & cargo @cargoArguments
    if ($LASTEXITCODE -ne 0) { throw 'Native desktop build failed.' }
} finally { Pop-Location }
