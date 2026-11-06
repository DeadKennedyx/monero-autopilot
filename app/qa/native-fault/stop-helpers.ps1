param([Parameter(Mandatory)][ValidatePattern('^[a-z0-9][a-z0-9_-]{0,39}$')][string]$RunId)
$ErrorActionPreference = 'Stop'
$qaAppRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$qaRunRoot = Join-Path $qaAppRoot ".runtime\native-fault\$RunId"
$qaHelpers = Get-Content -LiteralPath (Join-Path $qaRunRoot 'helpers.json') -Raw | ConvertFrom-Json
foreach ($qaHelper in @($qaHelpers.proxy,$qaHelpers.tor)) {
    $qaProcess = Get-Process -Id $qaHelper.pid -ErrorAction SilentlyContinue
    if ($null -eq $qaProcess) { continue }
    if ($qaProcess.Path -ne $qaHelper.path -or $qaProcess.StartTime.ToUniversalTime().Ticks -ne $qaHelper.started) { throw 'Helper process identity changed; refusing to stop another process.' }
    Stop-Process -Id $qaProcess.Id -ErrorAction Stop
}
Write-Output 'Only the recorded QA helper processes were stopped. Run files and evidence were preserved.'
