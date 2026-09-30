param(
    [Parameter(Mandatory = $true)] [string] $OldInstaller,
    [Parameter(Mandatory = $true)] [string] $NewInstaller
)

$ErrorActionPreference = 'Stop'
$expectedOldHash = 'A386DB9ABC7DDFFE8EB0E11154E31E0E4E870D3188B02F86E957A1CD2C4C55D8'
$oldPath = (Resolve-Path -LiteralPath $OldInstaller).Path
$newPath = (Resolve-Path -LiteralPath $NewInstaller).Path
$actualOldHash = (Get-FileHash -LiteralPath $oldPath -Algorithm SHA256).Hash
if ($actualOldHash -ne $expectedOldHash) {
    throw "The 0.3.6 installer hash does not match the pinned release asset."
}

$installRoot = Join-Path $env:RUNNER_TEMP 'CipherNestUpgradeSmoke'
$appDataRoot = Join-Path $env:APPDATA 'com.ciphernest.vault'
if ((Test-Path -LiteralPath $installRoot) -or (Test-Path -LiteralPath $appDataRoot)) {
    throw 'Upgrade smoke test requires a clean Windows runner.'
}

function Install-CipherNest([string] $installer) {
    $arguments = @('/S', "/D=$installRoot")
    $process = Start-Process -FilePath $installer -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -ne 0) {
        throw "Installer failed with exit code $($process.ExitCode)."
    }
}

Install-CipherNest $oldPath
$installedExecutable = Join-Path $installRoot 'ciphernest.exe'
if (-not (Test-Path -LiteralPath $installedExecutable -PathType Leaf)) {
    throw 'The 0.3.6 executable was not installed in the expected directory.'
}
$oldExecutableHash = (Get-FileHash -LiteralPath $installedExecutable -Algorithm SHA256).Hash

$backupDirectory = Join-Path $appDataRoot 'backups'
New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
$sentinels = @(
    (Join-Path $appDataRoot 'vault.cnvault'),
    (Join-Path $appDataRoot 'vault.cnvault.sync'),
    (Join-Path $appDataRoot 'vault.cnvault.webdav-backup'),
    (Join-Path $backupDirectory 'auto-upgrade-smoke.cnvault')
)
$before = @{}
foreach ($path in $sentinels) {
    [System.IO.File]::WriteAllBytes($path, [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(256))
    $before[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
}

Install-CipherNest $newPath
if (-not (Test-Path -LiteralPath $installedExecutable -PathType Leaf)) {
    throw 'The 0.3.7 executable is missing after overwrite installation.'
}
$newExecutableHash = (Get-FileHash -LiteralPath $installedExecutable -Algorithm SHA256).Hash
if ($newExecutableHash -eq $oldExecutableHash) {
    throw 'The installed executable did not change during overwrite installation.'
}
foreach ($path in $sentinels) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Application data was removed: $path"
    }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $before[$path]) {
        throw "Application data changed during overwrite installation: $path"
    }
}

Write-Output 'Windows 0.3.6 to 0.3.7 overwrite installation preserved the vault, sync and WebDAV backup sidecars, and backup bytes.'
