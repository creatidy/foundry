param(
    [Parameter(Mandatory=$true)][string]$Distribution,
    [Parameter(Mandatory=$true)][string]$Project,
    [Parameter(Mandatory=$true)][string]$ImageId,
    [Parameter(Mandatory=$true)][string]$TlsDirectory,
    [Parameter(Mandatory=$true)][string]$TlsFingerprint,
    [string]$AdoptProject = '-'
)

$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Write-Error 'This entrypoint requires native Windows PowerShell.'
    exit 1
}

# Restrict native argument spelling rather than relying on Windows/WSL quoting.
if ($Distribution -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$' -or
    $Project -cnotmatch '^[a-z0-9][a-z0-9_-]*$' -or
    $ImageId -cnotmatch '^sha256:[a-f0-9]{64}$' -or
    $TlsFingerprint -cnotmatch '^[a-f0-9]{64}$' -or
    ($AdoptProject -cne '-' -and $AdoptProject -cne $Project) -or
    $TlsDirectory -cnotmatch '^/[A-Za-z0-9_./-]+$' -or
    $PSScriptRoot -notmatch '^[A-Za-z]:\\[A-Za-z0-9_ .\\-]+$') {
    Write-Error 'Unsafe argument or non-local Windows script path; see README.'
    exit 1
}

if ($env:DOCKER_HOST -or $env:DOCKER_CONTEXT) {
    Write-Error 'Docker host/context environment overrides are not accepted.'
    exit 1
}

# Explicit Windows pipe: do not use the configured Windows Docker context.
$engine = & docker.exe --host 'npipe:////./pipe/dockerDesktopLinuxEngine' info --format '{{json .}}' 2>$null
if ($LASTEXITCODE -ne 0 -or $engine -isnot [string]) {
    Write-Error 'Docker Desktop Linux engine is unavailable on its fixed Windows pipe.'
    exit 1
}
try { $info = $engine | ConvertFrom-Json } catch { Write-Error 'Invalid engine response.'; exit 1 }
if ($info.OSType -ne 'linux' -or $info.ID -cnotmatch '^[A-Za-z0-9:_-]+$') {
    Write-Error 'The fixed Docker Desktop pipe did not identify a Linux engine.'
    exit 1
}

$wsl = Join-Path $env:SystemRoot 'System32\wsl.exe'
$script = Join-Path $PSScriptRoot 'windows_first_run.py'
$linuxScript = & $wsl --distribution $Distribution --exec wslpath -a $script
if ($LASTEXITCODE -ne 0 -or $linuxScript -isnot [string] -or
    $linuxScript -cnotmatch '^/mnt/[a-z]/[A-Za-z0-9_ ./-]+$') {
    Write-Error 'Cannot resolve the Windows-local entrypoint in the selected WSL distribution.'
    exit 1
}
& $wsl --distribution $Distribution --exec python3 "$linuxScript" $Project $ImageId $TlsDirectory $TlsFingerprint $info.ID $AdoptProject $Distribution
exit $LASTEXITCODE
