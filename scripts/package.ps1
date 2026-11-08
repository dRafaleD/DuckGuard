param([string]$OutputDirectory = (Join-Path $PSScriptRoot '..\dist'))
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Push-Location $root
try {
    cargo build --release --locked
    if ($LASTEXITCODE -ne 0) { throw 'Release build failed.' }
    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
    $stage = Join-Path $OutputDirectory 'DuckGuard-windows-x86_64'
    New-Item -ItemType Directory -Force -Path $stage | Out-Null
    Copy-Item 'target\release\duckguard.exe' (Join-Path $stage 'DuckGuard.exe') -Force
    Copy-Item 'scripts\install.ps1', 'README.md', 'LICENSE' $stage -Force
    $archive = Join-Path $OutputDirectory 'DuckGuard-windows-x86_64.zip'
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive -Force
    Get-FileHash -Algorithm SHA256 -LiteralPath $archive | Format-List
} finally { Pop-Location }

