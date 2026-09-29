param(
    [ValidateSet('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')]
    [string]$Target = 'x86_64-pc-windows-msvc',
    [switch]$SkipBuild,
    [string]$BinaryDirectory,
    [string]$Compiler
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Push-Location $repoRoot
try {
    if (-not $Compiler) {
        $command = Get-Command ISCC.exe -ErrorAction SilentlyContinue
        if ($command) { $Compiler = $command.Source }
        foreach ($candidate in @(
            "${env:ProgramFiles(x86)}/Inno Setup 6/ISCC.exe",
            "$env:LOCALAPPDATA/Programs/Inno Setup 6/ISCC.exe"
        )) {
            if (-not $Compiler -and (Test-Path -LiteralPath $candidate)) { $Compiler = $candidate }
        }
    }
    if (-not $Compiler -or -not (Test-Path -LiteralPath $Compiler)) {
        throw 'Install Inno Setup 6.3+ from https://jrsoftware.org/isdl.php or pass -Compiler <path to ISCC.exe>.'
    }
    if ($BinaryDirectory -and -not $SkipBuild) { throw '-BinaryDirectory requires -SkipBuild' }
    $metadataJson = & cargo metadata --no-deps --format-version 1
    if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed' }
    $metadata = $metadataJson | ConvertFrom-Json
    $package = $metadata.packages | Where-Object { $_.name -eq 'sniper' }
    $arch = if ($Target.StartsWith('aarch64')) { 'arm64' } else { 'x64' }
    if (-not $SkipBuild) {
        & cargo build --locked --release --bins --target $Target
        if ($LASTEXITCODE -ne 0) { throw 'Windows release build failed' }
    }
    $binaries = Join-Path $metadata.target_directory "$Target/release"
    if ($BinaryDirectory) { $binaries = (Resolve-Path -LiteralPath $BinaryDirectory).Path }
    foreach ($binary in @('sniper-desktop.exe', 'sniper.exe', 'sniper-cli.exe')) {
        $path = Join-Path $binaries $binary
        if (-not (Test-Path -LiteralPath $path)) { throw "Missing binary: $binary" }
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
        $machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
        $expectedMachine = if ($arch -eq 'arm64') { 0xaa64 } else { 0x8664 }
        if ($machine -ne $expectedMachine) { throw "$binary does not match $Target" }
    }
    $dist = Join-Path $repoRoot 'dist'
    New-Item -ItemType Directory -Path $dist -Force | Out-Null
    $name = "Sniper-$($package.version)-windows-$arch-setup.exe"
    $installer = Join-Path $dist $name
    if (Test-Path -LiteralPath $installer) { throw "Installer already exists: $installer" }
    & $Compiler "/DAppVersion=$($package.version)" "/DAppArch=$arch" "/DBinaryDirectory=$binaries" "/DOutputDirectory=$dist" (Join-Path $PSScriptRoot 'sniper.iss')
    if ($LASTEXITCODE -ne 0) { throw 'Inno Setup compilation failed' }
    $hash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $name" | Set-Content -LiteralPath "$installer.sha256" -Encoding ascii
    Write-Host "Created $installer"
}
finally { Pop-Location }
