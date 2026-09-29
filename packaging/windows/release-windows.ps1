<#
.SYNOPSIS
  Build release-ready Windows artifacts, with the same provenance gates as
  packaging/macos/release-macos.sh.

.DESCRIPTION
  make-zip.ps1 packages whatever is in the working tree. This wraps it with the
  checks that decide whether the result is fit to publish: the version matches
  Cargo.toml, the tree is clean, HEAD is origin/main, and the tag is not already
  taken. Without them it is easy to ship an archive built from a dirty tree, or
  to overwrite a published version.

  Set ALLOW_ADHOC_RELEASE=1 (or pass -AllowAdhocRelease) for local or CI builds
  that are not going to be published. That skips every provenance gate and keeps
  only the packaging and the artifact verification, which is what CI runs on
  every push so this script cannot rot unnoticed.

.EXAMPLE
  ./packaging/windows/release-windows.ps1

.EXAMPLE
  $env:ALLOW_ADHOC_RELEASE = '1'
  ./packaging/windows/release-windows.ps1 -Target aarch64-pc-windows-msvc
#>
param(
    [ValidateSet('x86_64-pc-windows-msvc', 'aarch64-pc-windows-msvc')]
    [string]$Target = 'x86_64-pc-windows-msvc',
    [switch]$AllowAdhocRelease,
    [string]$ReleaseRepo
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$allowAdhoc = $AllowAdhocRelease.IsPresent -or $env:ALLOW_ADHOC_RELEASE -eq '1'
if (-not $ReleaseRepo) {
    $ReleaseRepo = if ($env:GITHUB_RELEASE_REPO) { $env:GITHUB_RELEASE_REPO }
                   elseif ($env:GITHUB_REPOSITORY) { $env:GITHUB_REPOSITORY }
                   else { 'sm1ee/Sniper' }
}

function Invoke-Git {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    $output = & git @Arguments 2>$null
    return @{ Ok = ($LASTEXITCODE -eq 0); Output = ($output -join "`n").Trim() }
}

function Get-CanonicalRepo {
    param([string]$Value)
    if (-not $Value) { return '' }
    $v = $Value.Trim()
    foreach ($prefix in @('git@github.com:', 'ssh://git@github.com/', 'https://github.com/', 'http://github.com/')) {
        if ($v.StartsWith($prefix)) { $v = $v.Substring($prefix.Length) }
    }
    return $v.TrimEnd('/').TrimEnd('.git').ToLowerInvariant()
}

Push-Location $repoRoot
try {
    # --- version ---------------------------------------------------------
    $cargoVersion = (Select-String -Path (Join-Path $repoRoot 'Cargo.toml') -Pattern '^version = "(.+)"' |
        Select-Object -First 1).Matches[0].Groups[1].Value
    $version = if ($env:VERSION) { $env:VERSION } else { $cargoVersion }
    if ($version -ne $cargoVersion) {
        throw "VERSION=$version does not match Cargo.toml version $cargoVersion"
    }
    $releaseTag = "v$version"
    $arch = if ($Target.StartsWith('aarch64')) { 'arm64' } else { 'x64' }
    $name = "Sniper-$version-windows-$arch"

    # --- provenance ------------------------------------------------------
    if ($allowAdhoc) {
        Write-Host 'ALLOW_ADHOC_RELEASE=1: skipping provenance checks. Not fit to publish.'
    }
    else {
        if (-not (Invoke-Git rev-parse --is-inside-work-tree).Ok) {
            throw 'Release artifacts must be built from a git worktree so origin/main and tag provenance can be verified. Set ALLOW_ADHOC_RELEASE=1 for local-only testing.'
        }

        $origin = Get-CanonicalRepo (Invoke-Git remote get-url origin).Output
        $expected = Get-CanonicalRepo $ReleaseRepo
        if (-not $origin -or $origin -ne $expected) {
            throw "Release artifacts must be built with origin pointing at $ReleaseRepo; origin is $(if ($origin) { $origin } else { 'unavailable' })."
        }

        $dirty = (Invoke-Git status --porcelain --untracked-files=no).Output
        if ($dirty) { throw "Release artifacts require a clean worktree:`n$dirty" }

        $branch = (Invoke-Git symbolic-ref --quiet --short HEAD).Output
        if ($branch -and $branch -ne 'main') {
            throw "Release artifacts must be built from main or detached origin/main; current branch is $branch."
        }

        $remoteMain = (Invoke-Git ls-remote origin refs/heads/main)
        if (-not $remoteMain.Ok -or -not $remoteMain.Output) {
            throw 'Unable to verify origin/main before building release artifacts.'
        }
        $remoteMainCommit = ($remoteMain.Output -split '\s+')[0]
        $headCommit = (Invoke-Git rev-parse HEAD).Output
        if ($headCommit -ne $remoteMainCommit) {
            throw "Release artifacts must be built from origin/main ($remoteMainCommit), not $headCommit."
        }

        if ((Invoke-Git rev-parse -q --verify "refs/tags/$releaseTag^{commit}").Ok) {
            throw "$releaseTag already exists locally. Bump Cargo.toml before building artifacts for a new version."
        }
        $remoteTag = Invoke-Git ls-remote --tags origin $releaseTag
        if (-not $remoteTag.Ok) {
            if ($env:ALLOW_EXISTING_RELEASE_VERSION -eq '1') {
                Write-Warning "Unable to check whether $releaseTag exists on origin; continuing because ALLOW_EXISTING_RELEASE_VERSION=1."
            }
            else {
                throw "Unable to verify whether $releaseTag exists on origin. Set ALLOW_EXISTING_RELEASE_VERSION=1 to override only this check."
            }
        }
        elseif ($remoteTag.Output) {
            throw "$releaseTag already exists on origin. Bump Cargo.toml before building artifacts for a published version."
        }

        if (Get-Command gh -ErrorAction SilentlyContinue) {
            & gh release view $releaseTag --repo $ReleaseRepo *> $null
            if ($LASTEXITCODE -eq 0) {
                throw "GitHub release $releaseTag already exists in $ReleaseRepo."
            }
        }
    }

    # --- package ---------------------------------------------------------
    $dist = Join-Path $repoRoot 'dist'
    $archive = Join-Path $dist "$name.zip"
    $stage = Join-Path $dist $name
    # make-zip.ps1 refuses to overwrite, which is right for a one-shot package
    # but wrong for a script meant to be re-run.
    foreach ($path in @($archive, "$archive.sha256", $stage)) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
    }
    & (Join-Path $PSScriptRoot 'make-zip.ps1') -Target $Target
    if ($LASTEXITCODE -ne 0) { throw 'make-zip.ps1 failed' }

    # --- verify ----------------------------------------------------------
    foreach ($path in @($archive, "$archive.sha256")) {
        if (-not (Test-Path -LiteralPath $path)) { throw "Expected artifact missing: $path" }
    }
    $recorded = ((Get-Content -LiteralPath "$archive.sha256" -Raw).Trim() -split '\s+')[0]
    $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($recorded -ne $actual) {
        throw "Checksum mismatch for $name.zip: recorded $recorded, actual $actual"
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($archive)
    try {
        $entries = $zip.Entries | ForEach-Object { Split-Path $_.FullName -Leaf }
        foreach ($required in @('sniper-desktop.exe', 'sniper.exe', 'sniper-cli.exe')) {
            if ($entries -notcontains $required) { throw "$name.zip is missing $required" }
        }
    }
    finally { $zip.Dispose() }

    Write-Host "Windows release artifacts ready in $dist"
    Write-Host "  $name.zip"
    Write-Host "  $name.zip.sha256  ($actual)"
}
finally {
    Pop-Location
}
