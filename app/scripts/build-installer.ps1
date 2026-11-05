$ErrorActionPreference = 'Stop'
$installerRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Push-Location $installerRoot
try {
    . (Join-Path $PSScriptRoot 'workspace-env.ps1')
    node scripts/prepare-installer.mjs
    if ($LASTEXITCODE -ne 0) { throw 'Installer resource verification failed.' }
    pnpm build:app
    if ($LASTEXITCODE -ne 0) { throw 'Desktop frontend build failed.' }
    pnpm exec tauri build --ci --bundles nsis -- --locked
    if ($LASTEXITCODE -ne 0) { throw 'Windows installer build failed.' }
} finally { Pop-Location }
