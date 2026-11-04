"""Static guards only; native trust behavior requires separate acceptance.

These checks cannot establish store behavior, safe removal, failure handling,
or browser trust. No certificate store or PowerShell process is accessed.
"""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "scripts/windows-browser-trust.ps1").read_text(encoding="utf-8")


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


if __name__ == "__main__":
    unittest.main()
