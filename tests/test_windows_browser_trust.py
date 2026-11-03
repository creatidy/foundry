"""Static guards and PowerShell tests with an exclusively in-memory fake store."""

import base64
import hashlib
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "scripts/windows-browser-trust.ps1").read_text(encoding="utf-8")
POWERSHELL = shutil.which("powershell.exe")
OPENSSL = shutil.which("openssl")


class BrowserTrustSourceTests(unittest.TestCase):
    def test_current_user_root_only_and_no_removal(self):
        self.assertIn("X509Store('Root', 'CurrentUser')", SOURCE)
        self.assertNotIn("LocalMachine", SOURCE)
        self.assertNotIn("$store.Remove", SOURCE)
        self.assertEqual(SOURCE.count("$store.Add($certificate)"), 1)

    def test_fingerprint_and_consent_precede_add(self):
        mismatch = SOURCE.index("if ($actual -cne $Fingerprint)")
        consent = SOURCE.index("Read-Host 'To add this certificate")
        addition = SOURCE.index("$store.Add($certificate)")
        self.assertLess(mismatch, consent)
        self.assertLess(consent, addition)
        self.assertIn("-cne 'TRUST'", SOURCE)
        self.assertIn("$sha.ComputeHash($certificate.RawData)", SOURCE)

    def test_existing_certificate_checked_before_and_after_consent(self):
        self.assertEqual(SOURCE.count("foreach ($existing in $store.Certificates)"), 2)
        self.assertEqual(SOURCE.count("[Convert]::ToBase64String($existing.RawData) -ceq $encoded"), 2)
        self.assertIn("$store.Close()\n    $store.Open", SOURCE)
        self.assertIn("Foundry claims no ownership", SOURCE)

    def test_single_certificate_and_no_shell_bypass(self):
        self.assertIn("Expected exactly one PEM public certificate", SOURCE)
        self.assertIn("Certificate encoding is not exactly one DER certificate", SOURCE)
        self.assertNotIn("Invoke-Expression", SOURCE)
        self.assertNotIn("-ExecutionPolicy", SOURCE)


@unittest.skipUnless(POWERSHELL and OPENSSL, "PowerShell and OpenSSL are required for fake-store tests")
class BrowserTrustBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as directory:
            cert = Path(directory) / "cert.pem"
            key = Path(directory) / "key.pem"
            subprocess.run([OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-days", "1",
                            "-subj", "/CN=fixture"], check=True, capture_output=True, timeout=30)
            cls.pem = cert.read_text(encoding="ascii")
        cls.der = ssl.PEM_cert_to_DER_cert(cls.pem)
        cls.fingerprint = hashlib.sha256(cls.der).hexdigest()

    def run_scenario(self, scenario, *, pem=None, fingerprint=None):
        source = SOURCE
        store = "$store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')"
        load = "$pem = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $CertificatePath).ProviderPath)"
        # Refuse to execute if substitution ceases to match: native store access is never permitted.
        self.assertEqual(source.count(store), 1)
        self.assertEqual(source.count(load), 1)
        source = source.replace(store, "$store = $script:fakeStore")
        source = source.replace(load, "$pem = $script:testPem")
        self.assertNotIn("X509Store", source)
        source64 = base64.b64encode(source.encode("utf-8")).decode("ascii")
        pem64 = base64.b64encode((self.pem if pem is None else pem).encode("utf-8")).decode("ascii")
        der64 = base64.b64encode(self.der).decode("ascii")
        harness = r"""
$script:scenario = 'SCENARIO'
$script:testPem = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('PEM'))
$script:fixture = [pscustomobject]@{ RawData = [Convert]::FromBase64String('DER') }
$script:fakeStore = [pscustomobject]@{ Certificates = @(); Opens = 0 }
if ($script:scenario -eq 'duplicate') { $script:fakeStore.Certificates = @($script:fixture) }
$script:fakeStore | Add-Member ScriptMethod Open {
    param($flags)
    $this.Opens++
    Write-Host "FAKE_OPEN:$($this.Opens):$flags"
    if ($script:scenario -eq 'open-failure' -or
        ($script:scenario -eq 'reopen-failure' -and $this.Opens -eq 2)) { throw 'fake open failure' }
}
$script:fakeStore | Add-Member ScriptMethod Close { Write-Host 'FAKE_CLOSE' }
$script:fakeStore | Add-Member ScriptMethod Add {
    param($cert)
    if ($script:scenario -eq 'add-failure') { throw 'fake add failure' }
    Write-Host ('FAKE_ADD:' + [Convert]::ToBase64String($cert.RawData))
}
function Read-Host {
    param($prompt)
    Write-Host 'FAKE_PROMPT'
    if ($script:scenario -eq 'appeared') { $script:fakeStore.Certificates = @($script:fixture) }
    if ($script:scenario -eq 'refusal') { return 'NO' }
    return 'TRUST'
}
$text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('SOURCE'))
& ([scriptblock]::Create($text)) -CertificatePath 'unused' -Fingerprint 'FINGERPRINT'
"""
        for old, new in (("SCENARIO", scenario), ("PEM", pem64), ("DER", der64),
                         ("SOURCE", source64), ("FINGERPRINT", fingerprint or self.fingerprint)):
            harness = harness.replace(old, new)
        encoded = base64.b64encode(harness.encode("utf-16le")).decode("ascii")
        return subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                              capture_output=True, text=True, timeout=30)

    def test_adds_exact_checked_bytes_only_after_consent_and_recheck(self):
        result = self.run_scenario("add")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Certificate SHA-256: " + self.fingerprint, result.stdout)
        self.assertLess(result.stdout.index("FAKE_PROMPT"), result.stdout.index("FAKE_OPEN:2"))
        self.assertLess(result.stdout.index("FAKE_OPEN:2"), result.stdout.index("FAKE_ADD:"))
        self.assertEqual(result.stdout.count("FAKE_ADD:"), 1)
        self.assertIn("FAKE_ADD:" + base64.b64encode(self.der).decode("ascii"), result.stdout)

    def test_duplicate_and_appeared_are_not_claimed_as_browser_trusted(self):
        for scenario in ("duplicate", "appeared"):
            with self.subTest(scenario=scenario):
                result = self.run_scenario(scenario)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Certificate SHA-256: " + self.fingerprint, result.stdout)
                self.assertIn("browser trust is unverified", result.stdout)
                self.assertIn("Foundry claims no ownership", result.stdout)
                self.assertNotIn("FAKE_ADD:", result.stdout)
                self.assertEqual("FAKE_PROMPT" in result.stdout, scenario == "appeared")

    def test_invalid_and_declined_never_add(self):
        for scenario, kwargs in (("mismatch", {"fingerprint": "0" * 64}),
                                 ("malformed", {"pem": "not a certificate"}),
                                 ("refusal", {})):
            with self.subTest(scenario=scenario):
                result = self.run_scenario(scenario, **kwargs)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("FAKE_ADD:", result.stdout)
                self.assertEqual("FAKE_OPEN:" in result.stdout, scenario == "refusal")

    def test_store_failures_never_report_success(self):
        for scenario in ("open-failure", "reopen-failure", "add-failure"):
            with self.subTest(scenario=scenario):
                result = self.run_scenario(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("FAKE_ADD:", result.stdout)
                self.assertNotIn("Added to CurrentUser Root", result.stdout)


if __name__ == "__main__":
    unittest.main()
