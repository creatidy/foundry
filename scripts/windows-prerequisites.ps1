# Read-only prerequisites diagnostic, not an installer or startup command.
$ErrorActionPreference = 'Stop'

function Invoke-BoundedProbe {
    param([string]$Program, [string]$Arguments)
    $process = $null
    try {
        $info = New-Object System.Diagnostics.ProcessStartInfo
        $info.FileName = $Program
        $info.Arguments = $Arguments
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $info
        if (-not $process.Start()) { return $false }
        # Drain both streams concurrently without displaying potentially sensitive diagnostics.
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(10000)) {
            try { $process.Kill() } catch { }
            return $false
        }
        return ($process.ExitCode -eq 0)
    } catch {
        return $false
    } finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}

function Start-PrerequisiteCheck {
    if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
        Write-Host 'This diagnostic requires native Windows PowerShell or PowerShell on Windows.'
        return 1
    }

    Write-Host 'Foundry prerequisite diagnostic only: this does not install, start, or establish readiness.'
    $failed = $false
    $wsl = Join-Path $env:SystemRoot 'System32\wsl.exe'
    if (Invoke-BoundedProbe $wsl '--status') {
        Write-Host 'WSL status command succeeded. This does not verify a working WSL 2 distribution.'
    } else {
        Write-Host 'WSL status unavailable or timed out. Check Windows WSL installation and status manually.'
        $failed = $true
    }
    if (Invoke-BoundedProbe $wsl '--version') {
        Write-Host 'WSL version command succeeded; version output was not inspected.'
    } else {
        Write-Host 'WSL version unavailable or timed out. Check the installed WSL version manually; older WSL may not support --version.'
        $failed = $true
    }
    if (Invoke-BoundedProbe 'docker.exe' 'version --format {{.Server.Os}}') {
        Write-Host 'Docker engine responded to the configured Docker CLI context. Engine OS and Docker Desktop identity were not verified.'
    } else {
        Write-Host 'Docker engine unavailable or timed out. Check Docker Desktop, the selected Docker context, and engine access manually.'
        $failed = $true
    }
    if (Invoke-BoundedProbe 'docker.exe' 'compose version') {
        Write-Host 'Docker Compose version command succeeded.'
    } else {
        Write-Host 'Docker Compose unavailable or timed out. Check Docker Desktop and its Compose installation manually.'
        $failed = $true
    }
    Write-Host 'No certificate trust, image provenance, Linux integration, admin onboarding, or product functionality was verified. See README for the advanced workflow.'
    if ($failed) { return 1 }
    return 0
}

exit (Start-PrerequisiteCheck)
