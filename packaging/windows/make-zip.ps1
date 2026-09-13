param(
    [ValidateSet('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')]
    [string]$Target = 'x86_64-pc-windows-msvc',
    [switch]$SkipBuild,
    [string]$BinaryDirectory
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Push-Location $repoRoot
try {
    $metadataJson = & cargo metadata --no-deps --format-version 1
    if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed' }
    $metadata = $metadataJson | ConvertFrom-Json
    $package = $metadata.packages | Where-Object { $_.name -eq 'sniper' }
    $arch = if ($Target.StartsWith('aarch64')) { 'arm64' } else { 'x64' }
    $name = "Sniper-$($package.version)-windows-$arch"
    $dist = Join-Path $repoRoot 'dist'
    $stage = Join-Path $dist $name
    if (Test-Path -LiteralPath $stage) {
        throw "Package directory already exists: $stage. Move it aside before packaging again."
    }
    if (-not $SkipBuild) {
        & cargo build --locked --release --bins --target $Target
        if ($LASTEXITCODE -ne 0) { throw 'Windows release build failed' }
    }
    $binaries = Join-Path $metadata.target_directory "$Target/release"
    if ($BinaryDirectory) {
        if (-not $SkipBuild) { throw '-BinaryDirectory requires -SkipBuild' }
        $binaries = (Resolve-Path -LiteralPath $BinaryDirectory).Path
    }
    foreach ($binary in @('sniper-desktop.exe', 'sniper.exe', 'sniper-cli.exe')) {
        if (-not (Test-Path -LiteralPath (Join-Path $binaries $binary))) {
            throw "Missing binary: $binary. Build the $Target release first."
        }
        $bytes = [System.IO.File]::ReadAllBytes((Join-Path $binaries $binary))
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
        $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
        $expectedMachine = if ($arch -eq 'arm64') { 0xaa64 } else { 0x8664 }
        if ($machine -ne $expectedMachine) { throw "$binary does not match $Target" }
    }
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    foreach ($binary in @('sniper-desktop.exe', 'sniper.exe', 'sniper-cli.exe')) {
        Copy-Item -LiteralPath (Join-Path $binaries $binary) -Destination $stage
    }
    foreach ($license in @('LICENSE', 'LICENSE.md', 'COPYING')) {
        $licensePath = Join-Path $repoRoot $license
        if (Test-Path -LiteralPath $licensePath) {
            Copy-Item -LiteralPath $licensePath -Destination $stage
        }
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'README.md') -Destination $stage
    $archive = Join-Path $dist "$name.zip"
    if (Test-Path -LiteralPath $archive) { throw "Archive already exists: $archive" }
    Compress-Archive -LiteralPath $stage -DestinationPath $archive
    $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $name.zip" | Set-Content -LiteralPath "$archive.sha256" -Encoding ascii
    Write-Host "Created $archive"
}
finally {
    Pop-Location
}
