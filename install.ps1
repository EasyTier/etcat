$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repository = "EasyTier/etcat"
$installDir = if ($env:ETCAT_INSTALL_DIR) {
    $env:ETCAT_INSTALL_DIR
} else {
    Join-Path $env:LOCALAPPDATA "Programs\etcat"
}

if ($env:OS -ne "Windows_NT") {
    throw "etcat installer: Windows is required"
}

$processorArchitecture = if ($env:PROCESSOR_ARCHITEW6432) {
    $env:PROCESSOR_ARCHITEW6432
} else {
    $env:PROCESSOR_ARCHITECTURE
}

$target = switch ($processorArchitecture.ToUpperInvariant()) {
    "AMD64" { "x86_64-pc-windows-msvc" }
    "ARM64" { "aarch64-pc-windows-msvc" }
    default { throw "etcat installer: unsupported architecture: $processorArchitecture" }
}

$version = $env:ETCAT_VERSION
if ([string]::IsNullOrWhiteSpace($version)) {
    $release = Invoke-RestMethod `
        -Headers @{ "User-Agent" = "etcat-installer" } `
        -Uri "https://api.github.com/repos/$repository/releases/latest"
    $version = $release.tag_name
} elseif (-not $version.StartsWith("v")) {
    $version = "v$version"
}

if ($version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$') {
    throw "etcat installer: invalid release version: $version"
}

$packageName = "etcat-$version-$target"
$archiveName = "$packageName.zip"
$releaseUrl = "https://github.com/$repository/releases/download/$version"
$tempDir = Join-Path ([System.IO.Path]::GetTempPath()) (
    "etcat-install-" + [System.Guid]::NewGuid().ToString("N")
)

try {
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    $archivePath = Join-Path $tempDir $archiveName
    $checksumPath = Join-Path $tempDir "SHA256SUMS"

    Invoke-WebRequest -Uri "$releaseUrl/$archiveName" -OutFile $archivePath
    Invoke-WebRequest -Uri "$releaseUrl/SHA256SUMS" -OutFile $checksumPath

    $escapedArchiveName = [regex]::Escape($archiveName)
    $checksumEntry = Get-Content -LiteralPath $checksumPath |
        Where-Object { $_ -match "^([0-9A-Fa-f]{64})\s+\*?$escapedArchiveName$" } |
        Select-Object -First 1
    if (-not $checksumEntry) {
        throw "etcat installer: checksum not found for $archiveName"
    }

    $expectedChecksum = ($checksumEntry -split '\s+')[0].ToLowerInvariant()
    $actualChecksum = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath
    ).Hash.ToLowerInvariant()
    if ($actualChecksum -ne $expectedChecksum) {
        throw "etcat installer: checksum verification failed for $archiveName"
    }

    Expand-Archive -LiteralPath $archivePath -DestinationPath $tempDir
    $sourceBinary = Join-Path $tempDir "$packageName\etcat.exe"
    if (-not (Test-Path -LiteralPath $sourceBinary -PathType Leaf)) {
        throw "etcat installer: release archive does not contain etcat.exe"
    }

    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    Copy-Item -LiteralPath $sourceBinary -Destination (
        Join-Path $installDir "etcat.exe"
    ) -Force
} finally {
    if (Test-Path -LiteralPath $tempDir) {
        Remove-Item -LiteralPath $tempDir -Recurse -Force
    }
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$userPathEntries = @($userPath -split ';' | Where-Object { $_ })
if ($userPathEntries -notcontains $installDir) {
    $newUserPath = if ([string]::IsNullOrWhiteSpace($userPath)) {
        $installDir
    } else {
        "$userPath;$installDir"
    }
    [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
}

$processPathEntries = @($env:Path -split ';' | Where-Object { $_ })
if ($processPathEntries -notcontains $installDir) {
    $env:Path = "$installDir;$env:Path"
}

Write-Host "Installed etcat $version to $installDir\etcat.exe"
Write-Host "Open a new terminal if 'etcat' is not yet on PATH."
