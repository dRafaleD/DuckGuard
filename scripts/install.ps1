$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot 'DuckGuard.exe'
if (!(Test-Path -LiteralPath $source)) { throw 'Extract the ZIP first, then run install.ps1 next to DuckGuard.exe.' }
$destination = Join-Path $env:LOCALAPPDATA 'Programs\DuckGuard'
New-Item -ItemType Directory -Force -Path $destination | Out-Null
Copy-Item -LiteralPath $source -Destination (Join-Path $destination 'DuckGuard.exe') -Force
$currentPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$entries = @($currentPath -split ';' | Where-Object { $_ })
if ($entries -notcontains $destination) {
    [Environment]::SetEnvironmentVariable('Path', (($entries + $destination) -join ';'), 'User')
}
if (($env:Path -split ';') -notcontains $destination) { $env:Path += ";$destination" }
Write-Host "Installed: $destination\DuckGuard.exe"
Write-Host 'Run: DuckGuard --help (open a new terminal if needed).'

