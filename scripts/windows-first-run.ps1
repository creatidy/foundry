param(
    [Parameter(Mandatory=$true)][string]$Distribution,
    [Parameter(Mandatory=$true)][string]$Project,
    [Parameter(Mandatory=$true)][string]$ImageId,
    [string]$TlsDirectory = '-',
    [string]$TlsFingerprint = '-',
    [string]$AdoptProject = '-',
    [switch]$ManagedTls,
    [switch]$ManagedBootstrap
)

$ErrorActionPreference = 'Stop'

function Read-BootstrapFrame {
    param([System.IO.StreamReader]$Reader)
    $buffer = New-Object char[] 1
    $line = New-Object System.Text.StringBuilder
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    while ($line.Length -le 8192) {
        $read = $Reader.ReadAsync($buffer, 0, 1)
        $remaining = 120000 - [int]$timer.ElapsedMilliseconds
        if ($remaining -le 0 -or -not $read.Wait($remaining) -or $read.Result -ne 1) { throw 'protocol' }
        if ($buffer[0] -eq "`n") {
            return ($line.ToString() | ConvertFrom-Json)
        }
        if ([int]$buffer[0] -lt 32 -or [int]$buffer[0] -gt 126) { throw 'protocol' }
        [void]$line.Append($buffer[0])
    }
    throw 'protocol'
}

function Invoke-ManagedBootstrap {
    param([string]$Wsl, [string]$LinuxScript, [string]$Engine)
    # Independent exact implementation review is required before enabling.
    $enabled = $false
    if (-not $enabled) { return 'disabled' }
    if ([Console]::IsInputRedirected -or [Console]::IsOutputRedirected) { return 'console-required' }
    $first = $null
    $second = $null
    $firstPtr = [IntPtr]::Zero
    $secondPtr = [IntPtr]::Zero
    $payload = $null
    $bytes = $null
    $process = $null
    try {
        $start = New-Object System.Diagnostics.ProcessStartInfo
        $start.FileName = $Wsl
        $start.Arguments = '--distribution ' + $Distribution + ' --exec python3 "' + $LinuxScript + '" managed-protocol ' + $Project + ' ' + $ImageId + ' ' + $Engine + ' ' + $Distribution
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardInput = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.StandardOutputEncoding = New-Object System.Text.UTF8Encoding($false, $true)
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $start
        if (-not $process.Start()) { return 'recovery-required' }
        $discardErrors = $process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
        $frame = Read-BootstrapFrame $process.StandardOutput
        if (@($frame.PSObject.Properties).Count -ne 4 -or $frame.type -cne 'certificate' -or $frame.project -cne $Project -or
            $frame.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
            $frame.certificate -cnotmatch '\A-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n?\z') { throw 'protocol' }
        Write-Host 'Public certificate obtained from the verified local Docker volume:'
        Write-Host $frame.certificate
        Write-Host ('SHA256: ' + $frame.sha256)
        if ((Read-Host 'Confirm this certificate and project for this session? Type YES') -cne 'YES') { return 'declined' }
        $yes = [Text.Encoding]::ASCII.GetBytes("YES`n")
        $process.StandardInput.BaseStream.Write($yes, 0, $yes.Length)
        $process.StandardInput.BaseStream.Flush()
        $frame = Read-BootstrapFrame $process.StandardOutput
        if (@($frame.PSObject.Properties).Count -eq 2 -and $frame.type -ceq 'result' -and $frame.outcome -ceq 'already-configured') {
            if (-not $process.WaitForExit(120000) -or $process.ExitCode -ne 0) { throw 'protocol' }
            return 'already-configured'
        }
        if (@($frame.PSObject.Properties).Count -ne 1 -or $frame.type -cne 'credentials') { throw 'protocol' }
        Write-Host 'No administrator was observed. Confirm authorization and a private local console; recording and transcription are not automatically detected. Do not disable or bypass organizational monitoring.'
        if ((Read-Host 'Create the initial administrator? Type YES to consent') -cne 'YES') { return 'declined' }
        $first = Read-Host 'Administrator password' -AsSecureString
        $second = Read-Host 'Confirm administrator password' -AsSecureString
        if ($null -eq $first -or $null -eq $second) { return 'invalid-input' }
        $firstPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($first)
        $secondPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($second)
        $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($firstPtr)
        $confirmation = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($secondPtr)
        if ([string]::IsNullOrEmpty($password) -or $password -cne $confirmation -or
            $password.Length -gt 256) {
            return 'invalid-input'
        }
        $payload = @{ password = $password; confirmation = $confirmation } | ConvertTo-Json -Compress
        $bytes = (New-Object System.Text.UTF8Encoding($false, $true)).GetBytes($payload)
        if ($bytes.Length -gt 4096) { return 'invalid-input' }

        $process.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
        $process.StandardInput.Close() # EOF frames the single JSON object.
        $frame = Read-BootstrapFrame $process.StandardOutput
        if (@($frame.PSObject.Properties).Count -ne 2 -or $frame.type -cne 'result' -or $frame.outcome -cnotin @('submitted', 'invalid-input', 'recovery-required', 'configured-recovery-required', 'not-configured-recovery-required')) { throw 'protocol' }
        if (-not $process.WaitForExit(120000)) { throw 'protocol' }
        if (($frame.outcome -ceq 'submitted') -ne ($process.ExitCode -eq 0)) { throw 'protocol' }
        return $frame.outcome
    } catch {
        return 'recovery-required'
    } finally {
        if ($null -ne $process) {
            try { $process.StandardInput.Close() } catch { }
            try { if (-not $process.HasExited) { $process.Kill(); [void]$process.WaitForExit(5000) } } catch { }
            $process.Dispose()
        }
        if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        if ($firstPtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($firstPtr) }
        if ($secondPtr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secondPtr) }
        if ($null -ne $first) { $first.Dispose() }
        if ($null -ne $second) { $second.Dispose() }
        # Managed strings cannot be reliably zeroed by PowerShell/.NET.
        $password = $null
        $confirmation = $null
        $payload = $null
    }
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Write-Error 'This entrypoint requires native Windows PowerShell.'
    exit 1
}

# Restrict native argument spelling rather than relying on Windows/WSL quoting.
if ($Distribution -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$' -or
    $Project -cnotmatch '^[a-z0-9][a-z0-9_-]*$' -or
    $ImageId -cnotmatch '^sha256:[a-f0-9]{64}$' -or
    ($TlsFingerprint -cne '-' -and $TlsFingerprint -cnotmatch '^[a-f0-9]{64}$') -or
    ($AdoptProject -cne '-' -and $AdoptProject -cne $Project) -or
    ($TlsDirectory -ceq '-' -and ($PSBoundParameters.ContainsKey('TlsDirectory') -or
        $PSBoundParameters.ContainsKey('TlsFingerprint') -or $PSBoundParameters.ContainsKey('AdoptProject'))) -or
    ($TlsDirectory -cne '-' -and ($ManagedTls -or $ManagedBootstrap -or $TlsDirectory -cnotmatch '^/[A-Za-z0-9_./-]+$' -or $TlsFingerprint -ceq '-')) -or
    ($TlsDirectory -ceq '-' -and ($TlsFingerprint -cne '-' -or $AdoptProject -cne '-')) -or
    $PSScriptRoot -notmatch '^[A-Za-z]:\\[A-Za-z0-9_ .\\-]+$') {
    Write-Error 'Unsafe argument or non-local Windows script path; see README.'
    exit 1
}

if ($env:DOCKER_HOST -or $env:DOCKER_CONTEXT) {
    Write-Error 'Docker host/context environment overrides are not accepted.'
    exit 1
}

# Explicit Windows pipe: do not use the configured Windows Docker context.
try {
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $engine = & docker.exe --host 'npipe:////./pipe/dockerDesktopLinuxEngine' info --format '{{json .}}' 2>$null
} catch {
    $engine = $null
} finally {
    $ErrorActionPreference = $previousPreference
}
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
if ($TlsDirectory -ceq '-') {
    if ($ManagedBootstrap) {
        $outcome = Invoke-ManagedBootstrap $wsl $linuxScript $info.ID
        Write-Host ('Managed onboarding: ' + $outcome + '.')
        if ($outcome -ceq 'submitted' -or $outcome -ceq 'already-configured') {
            Write-Host 'Open https://127.0.0.1:8787/admin/login only in a browser that trusts the confirmed certificate, and sign in to verify the administrator. Authenticated readiness remains unverified until then.'
        } elseif ($outcome -ne 'disabled') {
            Write-Host 'Do not retry. First establish that the prior WSL worker and any in-container claim-issuer exec have stopped; a Windows timeout or cancellation does not prove this. Inspect administrator state and the retained foundry-bootstrap reservation on the verified Docker engine. Remove a reservation only after quiescence and manual recovery; a prior POST may have completed.'
        }
        if ($outcome -ceq 'submitted' -or $outcome -ceq 'already-configured') { exit 0 }
        exit 1
    }
    & $wsl --distribution $Distribution --exec python3 "$linuxScript" managed $Project $ImageId $info.ID $Distribution
} else {
    & $wsl --distribution $Distribution --exec python3 "$linuxScript" $Project $ImageId $TlsDirectory $TlsFingerprint $info.ID $AdoptProject $Distribution
}
exit $LASTEXITCODE
