# Dot-source this file to use the project-local toolchain, when present.
$appRoot = Split-Path -Parent $PSScriptRoot
$appCargo = Join-Path $appRoot '.tools\rust\cargo'
$appRustup = Join-Path $appRoot '.tools\rust\rustup'
if (Test-Path -LiteralPath (Join-Path $appCargo 'bin\cargo.exe')) {
    $env:CARGO_HOME = $appCargo
    $env:RUSTUP_HOME = $appRustup
    $env:Path = "$(Join-Path $appCargo 'bin');$env:Path"
    Write-Output 'Project-local Rust toolchain enabled for this PowerShell session.'
} else {
    Write-Output 'No project-local Rust toolchain found. Using tools already on PATH.'
}
