$ErrorActionPreference = 'Stop'
$torProjectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$torVersion = '16.0'
$archiveName = "tor-expert-bundle-windows-x86_64-$torVersion.tar.gz"
$archiveHash = '2ee123e9167318a3742778ff704e75f01d4780f05a14522d451fe011011077c4'
$releaseUrl = "https://dist.torproject.org/torbrowser/$torVersion/$archiveName"
$keyUrl = 'https://openpgpkey.torproject.org/.well-known/openpgpkey/torproject.org/hu/kounek7zrdx745qydx6p59t9mqjpuhdf'
$torCache = Join-Path $torProjectRoot '.tools\tor'
$stageParent = Join-Path $torProjectRoot '.runtime\tor-setup'
$stageRoot = Join-Path $stageParent ([Guid]::NewGuid().ToString('N'))
$stageCache = Join-Path $stageRoot '.tools\tor'
$verified = $false
if (-not (Test-Path -LiteralPath (Join-Path $torProjectRoot 'node_modules\openpgp'))) { throw 'Run pnpm install --frozen-lockfile before preparing Tor.' }
$null = Get-Command node -ErrorAction Stop
$null = Get-Command tar -ErrorAction Stop
New-Item -ItemType Directory -Path (Join-Path $stageCache 'verification') -Force | Out-Null
try {
    # Reuse cached public release inputs, but verify them on every invocation.
    # Nothing in the existing runtime is replaced before all checks pass.
    foreach ($downloadSpec in @(
        @{Relative=$archiveName; Url=$releaseUrl},
        @{Relative='verification\bundle.asc'; Url="$releaseUrl.asc"},
        @{Relative='verification\tor.key'; Url=$keyUrl}
    )) {
        $cached = Join-Path $torCache $downloadSpec.Relative
        $staged = Join-Path $stageCache $downloadSpec.Relative
        if (Test-Path -LiteralPath $cached) { Copy-Item -LiteralPath $cached -Destination $staged }
        else { Invoke-WebRequest -Uri $downloadSpec.Url -OutFile $staged -UseBasicParsing }
    }
    $archivePath = Join-Path $stageCache $archiveName
    if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $archiveHash) { throw 'Tor archive does not match the pinned release checksum. Existing runtime was preserved.' }
    Push-Location $stageRoot
    try {
        # Existing verifier checks the complete bundle signature and pinned
        # Tor Browser Developers key fingerprint before any extraction.
        & node (Join-Path $torProjectRoot 'scripts\verify-tor.mjs')
        if ($LASTEXITCODE -ne 0) { throw 'Tor signature verification failed. Existing runtime was preserved.' }
    } finally { Pop-Location }
    $allowed = @('tor/tor.exe','docs/tor.txt','docs/openssl.txt','docs/libevent.txt','docs/zlib.txt')
    $entries = @(& tar -tzf $archivePath)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect the verified Tor bundle.' }
    foreach ($relative in $allowed) {
        if (@($entries | Where-Object { $_ -ceq $relative }).Count -ne 1) { throw "Expected one bundle entry: $relative" }
    }
    $stageRelease = Join-Path $stageRoot 'release'
    New-Item -ItemType Directory -Path $stageRelease -Force | Out-Null
    & tar -xzf $archivePath -C $stageRelease -- @allowed
    if ($LASTEXITCODE -ne 0) { throw 'Cannot extract the allowlisted Tor runtime files.' }
    foreach ($relative in $allowed) {
        $entry = Get-Item -LiteralPath (Join-Path $stageRelease $relative)
        if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Tor runtime entries must be regular files.' }
    }
    $nativeSource = Get-Content -LiteralPath (Join-Path $torProjectRoot 'crates\wallet-rpc\src\tor.rs') -Raw
    $expectedRuntime = [regex]::Match($nativeSource, 'pub const TOR_SHA256: &str = "([a-f0-9]{64})";').Groups[1].Value
    if ($expectedRuntime.Length -ne 64 -or (Get-FileHash -LiteralPath (Join-Path $stageRelease 'tor\tor.exe') -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedRuntime) { throw 'Tor executable does not match the native app pin. Existing runtime was preserved.' }
    foreach ($relative in $allowed) {
        $destination = Join-Path (Join-Path $torCache 'release') $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $stageRelease $relative) -Destination $destination -Force
    }
    New-Item -ItemType Directory -Path (Join-Path $torCache 'verification') -Force | Out-Null
    foreach ($relative in @($archiveName,'verification\bundle.asc','verification\tor.key')) {
        Copy-Item -LiteralPath (Join-Path $stageCache $relative) -Destination (Join-Path $torCache $relative) -Force
    }
    Copy-Item -LiteralPath (Join-Path $stageCache 'verification\verified.json') -Destination (Join-Path $torCache 'verification\verified.json') -Force
    $verified = $true
    Write-Output "Verified Tor Expert Bundle $torVersion is ready for compilation. No executable was started."
} finally {
    # Delete only this invocation's resolved staging directory, never the cache.
    if ($verified -and (Test-Path -LiteralPath $stageRoot)) {
        $resolvedStage = (Resolve-Path -LiteralPath $stageRoot).Path
        $resolvedParent = (Resolve-Path -LiteralPath $stageParent).Path.TrimEnd('\') + '\'
        if (-not $resolvedStage.StartsWith($resolvedParent,[StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing cleanup outside the Tor setup staging directory.' }
        Remove-Item -LiteralPath $resolvedStage -Recurse -Force
    }
}
