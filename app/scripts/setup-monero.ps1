$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$downloadDirectory = Join-Path $projectRoot '.tools\monero'
$verificationDirectory = Join-Path $downloadDirectory 'verification'
New-Item -ItemType Directory -Path $verificationDirectory -Force | Out-Null
$archivePath = Join-Path $downloadDirectory 'monero-win-x64-v0.18.5.4.zip'
Invoke-WebRequest -Uri 'https://www.getmonero.org/downloads/hashes.txt' -OutFile (Join-Path $verificationDirectory 'hashes.txt')
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/monero-project/monero/v0.18.5.4/utils/gpg_keys/binaryfate.asc' -OutFile (Join-Path $verificationDirectory 'binaryfate.asc')
if (-not (Test-Path -LiteralPath $archivePath)) {
    Invoke-WebRequest -Uri 'https://downloads.getmonero.org/cli/monero-win-x64-v0.18.5.4.zip' -OutFile $archivePath
}
Push-Location $projectRoot
try {
    node scripts/verify-monero.mjs
    if ($LASTEXITCODE -ne 0) { throw 'Release signature or checksum verification failed. Nothing will be extracted.' }
} finally { Pop-Location }
# Extract only the two required upstream executables and their license.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$binaryDirectory = Join-Path $downloadDirectory 'release\monero-x86_64-w64-mingw32-v0.18.5.4'
New-Item -ItemType Directory -Path $binaryDirectory -Force | Out-Null
$archive = [System.IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    foreach ($name in @('monerod.exe','monero-wallet-rpc.exe','LICENSE')) {
        $entries = @($archive.Entries | Where-Object { $_.Name -eq $name })
        if ($entries.Count -ne 1) { throw "Unexpected archive contents for $name" }
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entries[0], (Join-Path $binaryDirectory $name), $true)
    }
} finally { $archive.Dispose() }
Write-Output 'Verified Monero 0.18.5.4 tools are ready. Windows Security decisions are left to the user.'
