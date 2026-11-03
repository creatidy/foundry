param(
    [Parameter(Mandatory=$true)][string]$CertificatePath,
    [Parameter(Mandatory=$true)][string]$Fingerprint
)

$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Write-Error 'This command requires native Windows PowerShell.'
    exit 1
}
if ($Fingerprint -cnotmatch '^[a-f0-9]{64}$') {
    Write-Error 'Supply the lowercase SHA-256 fingerprint printed by the verified managed first run.'
    exit 1
}

$store = $null
$certificate = $null
try {
    $pem = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $CertificatePath).ProviderPath)
    if ($pem.Length -gt 1048576 -or $pem -cnotmatch '\A\s*-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\r\n]+)\s*-----END CERTIFICATE-----\s*\z') {
        throw 'Expected exactly one PEM public certificate.'
    }
    $der = [Convert]::FromBase64String($Matches[1])
    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $der)
    $encoded = [Convert]::ToBase64String($certificate.RawData)
    if ([Convert]::ToBase64String($der) -cne $encoded) {
        throw 'Certificate encoding is not exactly one DER certificate.'
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $actual = ([BitConverter]::ToString($sha.ComputeHash($certificate.RawData))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    if ($actual -cne $Fingerprint) { throw 'Certificate fingerprint mismatch; no trust was changed.' }
    Write-Host "Certificate SHA-256: $actual"

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    foreach ($existing in $store.Certificates) {
        if ([Convert]::ToBase64String($existing.RawData) -ceq $encoded) {
            Write-Host 'This certificate is present in the current-user Root view; browser trust is unverified. No change was made and Foundry claims no ownership.'
            exit 0
        }
    }
    Write-Host 'This adds the certificate to Windows CurrentUser Root, not only to Foundry or 127.0.0.1.'
    Write-Host 'Other applications using Windows trust may be affected. Browsers may use different stores or reject this leaf.'
    Write-Host 'Trust depends on the verified local engine, image, host and the fingerprint you compared. Do not bypass browser warnings.'
    Write-Host 'Foundry will not automatically remove this shared trust. Coordinate other users of this certificate.'
    if ((Read-Host 'To add this certificate to CurrentUser Root, type TRUST') -cne 'TRUST') {
        throw 'Trust was not authorized; no trust was changed.'
    }
    # Recheck after the prompt. Store operations are not atomic with other actors.
    $store.Close()
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    foreach ($existing in $store.Certificates) {
        if ([Convert]::ToBase64String($existing.RawData) -ceq $encoded) {
            Write-Host 'This certificate appeared in the current-user Root view during confirmation; browser trust is unverified. No change was made and Foundry claims no ownership.'
            exit 0
        }
    }
    $store.Add($certificate)
    Write-Host 'Added to CurrentUser Root. This does not verify browser compatibility or authenticated readiness.'
} catch {
    Write-Error ('Browser trust stopped: ' + $_.Exception.Message + ' Inspect CurrentUser Root before retrying; an interrupted store operation may have changed it.')
    exit 1
} finally {
    if ($null -ne $store) { $store.Close() }
    if ($null -ne $certificate) { $certificate.Dispose() }
}
