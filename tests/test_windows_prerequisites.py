"""Contract checks and mocked PowerShell tests for the Windows diagnostic."""

from pathlib import Path
import base64
import os
import shutil
import subprocess
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "windows-prerequisites.ps1"
POWERSHELL = shutil.which("pwsh") or shutil.which("powershell") or shutil.which("powershell.exe")


class WindowsPrerequisiteContractTests(unittest.TestCase):
    def test_probe_allowlist_and_no_raw_output(self):
        text = SCRIPT.read_text(encoding="utf-8")
        probes = [line.strip() for line in text.splitlines() if line.strip().startswith("if (Invoke-BoundedProbe")]
        self.assertEqual(probes, [
            "if (Invoke-BoundedProbe $wsl '--status') {",
            "if (Invoke-BoundedProbe $wsl '--version') {",
            "if (Invoke-BoundedProbe 'docker.exe' 'version --format {{.Server.Os}}') {",
            "if (Invoke-BoundedProbe 'docker.exe' 'compose version') {",
        ])
        self.assertIn("WaitForExit(10000)", text)
        self.assertNotIn("$stdout.Result", text)
        self.assertNotIn("$stderr.Result", text)
        self.assertIn("does not install, start, or establish readiness", text)


@unittest.skipUnless(POWERSHELL, "PowerShell is not installed")
class MockedPowerShellTests(unittest.TestCase):
    def run_scenario(self, failure=None, windows=True):
        source = SCRIPT.read_text(encoding="utf-8")
        start = source.index("function Invoke-BoundedProbe {")
        end = source.index("function Start-PrerequisiteCheck {")
        mock = """function Invoke-BoundedProbe {
    param([string]$Program, [string]$Arguments)
    if ($Arguments -eq '%s') { return $false }
    return $true
}
""" % (failure or "never")
        source = source[:start] + mock + source[end:]
        source = source.replace(
            "[System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT",
            "$false" if windows else "$true",
        )
        # Test-only source is passed in-process, not as a policy-blocked WSL file.
        # This does not test or change the policy for the documented -File path.
        encoded = base64.b64encode(source.encode("utf-16le")).decode("ascii")
        return subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True, text=True, timeout=30,
        )

    def test_success_is_not_readiness(self):
        result = self.run_scenario()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("does not install, start, or establish readiness", result.stdout, result.stderr)
        self.assertIn("No certificate trust", result.stdout)

    def test_each_probe_failure_is_reported(self):
        for argument, message in [
            ("--status", "WSL status unavailable"),
            ("--version", "WSL version unavailable"),
            ("version --format {{.Server.Os}}", "Docker engine unavailable"),
            ("compose version", "Docker Compose unavailable"),
        ]:
            with self.subTest(argument=argument):
                result = self.run_scenario(argument)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stdout)

    def test_non_windows_refused(self):
        result = self.run_scenario(windows=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires native Windows", result.stdout)


@unittest.skipUnless(POWERSHELL and os.environ.get("FOUNDRY_WINDOWS_LIVE_TEST") == "1",
                     "native live diagnostic is opt-in")
class NativeWindowsDiagnosticTests(unittest.TestCase):
    def test_read_only_diagnostic(self):
        encoded = base64.b64encode(SCRIPT.read_text(encoding="utf-8").encode("utf-16le")).decode("ascii")
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True, text=True, timeout=60,
        )
        self.assertIn("does not install, start, or establish readiness", result.stdout)
        self.assertIn("No certificate trust", result.stdout)
        self.assertIn(result.returncode, (0, 1))
        print("Native diagnostic exit:", result.returncode, "\n" + result.stdout)


if __name__ == "__main__":
    unittest.main()
