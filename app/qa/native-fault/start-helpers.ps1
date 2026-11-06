param([Parameter(Mandatory)][ValidatePattern('^[a-z0-9][a-z0-9_-]{0,39}$')][string]$RunId)
$ErrorActionPreference = 'Stop'
$qaAppRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$qaRunRoot = Join-Path $qaAppRoot ".runtime\native-fault\$RunId"
$qaConfiguration = Get-Content -LiteralPath (Join-Path $qaRunRoot 'run.json') -Raw | ConvertFrom-Json
if ($qaConfiguration.root -ne $qaRunRoot -or $qaConfiguration.id -ne $RunId) { throw 'Invalid QA run directory.' }
if (Test-Path -LiteralPath (Join-Path $qaRunRoot 'helpers.json')) { throw 'Existing helper evidence found. Stop/review those helpers before starting a fresh run.' }
$qaTorBinary = Join-Path $qaAppRoot '.tools\tor\release\tor\tor.exe'
$qaTorSource = Get-Content -LiteralPath (Join-Path $qaAppRoot 'crates\wallet-rpc\src\tor.rs') -Raw
$qaTorHash = [regex]::Match($qaTorSource, 'pub const TOR_SHA256: &str = "([a-f0-9]{64})";').Groups[1].Value
if ($qaTorHash.Length -ne 64 -or (Get-FileHash -LiteralPath $qaTorBinary -Algorithm SHA256).Hash.ToLowerInvariant() -ne $qaTorHash) { throw 'QA Tor binary does not match the product pin.' }
$qaNodeBinary = (Get-Command node -ErrorAction Stop).Source
$qaNodeVersion = & $qaNodeBinary -p 'Number(process.versions.node.split(".")[0])'
if ([int]$qaNodeVersion -lt 24) { throw 'Node 24 or later is required.' }
# The service key and control files belong only to this Windows user and SYSTEM.
$qaUserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
& icacls $qaRunRoot /inheritance:r /grant:r "*$($qaUserSid):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not protect the isolated QA directory.' }
function Quote-QAArgument([string]$Value) { '"' + ($Value -replace '(\\+)$','$1$1') + '"' }
$qaTorArgs = '--defaults-torrc {0} -f {1}' -f (Quote-QAArgument (Join-Path $qaRunRoot 'tor.defaults')),(Quote-QAArgument (Join-Path $qaRunRoot 'torrc'))
$qaTorProcess = Start-Process -FilePath $qaTorBinary -ArgumentList $qaTorArgs -WorkingDirectory $qaRunRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $qaRunRoot 'tor.stdout.log') -RedirectStandardError (Join-Path $qaRunRoot 'tor.stderr.log')
try {
    $qaProxyArgs = '{0} {1}' -f (Quote-QAArgument (Join-Path $PSScriptRoot 'server.mjs')),$RunId
    $qaProxyProcess = Start-Process -FilePath $qaNodeBinary -ArgumentList $qaProxyArgs -WorkingDirectory $qaAppRoot -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $qaRunRoot 'proxy.log') -RedirectStandardError (Join-Path $qaRunRoot 'proxy.stderr.log')
    @{tor=@{pid=$qaTorProcess.Id;path=$qaTorBinary;started=$qaTorProcess.StartTime.ToUniversalTime().Ticks};proxy=@{pid=$qaProxyProcess.Id;path=$qaNodeBinary;started=$qaProxyProcess.StartTime.ToUniversalTime().Ticks}} | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $qaRunRoot 'helpers.json') -Encoding utf8
    Write-Output "QA helper processes started for $RunId. No wallet or transfer was started."
} catch { if (-not $qaTorProcess.HasExited) { $qaTorProcess.Kill() }; throw }
