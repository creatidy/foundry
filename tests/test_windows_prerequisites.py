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
        self.assertIn("$TimeoutMilliseconds = 10000", text)
        self.assertNotIn("$stdout.Result", text)
        self.assertNotIn("$stderr.Result", text)
        self.assertIn("does not install, start, or establish readiness", text)


@unittest.skipUnless(POWERSHELL, "PowerShell is not installed")
class MockedPowerShellTests(unittest.TestCase):
    def run_scenario(self, failure=None, windows=True, check_engine=False):
        source = SCRIPT.read_text(encoding="utf-8")
        source = source.replace("param([switch]$CheckEngine)",
                                "$CheckEngine = $true" if check_engine else "$CheckEngine = $false", 1)
        start = source.index("function Invoke-BoundedProbe {")
        end = source.index("function Start-PrerequisiteCheck {")
        mock = """function Invoke-BoundedProbe {
    param([string]$Program, [string]$Arguments)
    if ($Program -eq 'docker.exe' -and $Arguments -ne 'compose version' -and
        (-not $CheckEngine -or $Arguments -ne 'version --format {{.Server.Os}}')) { throw 'unexpected Docker probe' }
    if ($Arguments -eq 'version --format {{.Server.Os}}') { Write-Host 'MOCK_ENGINE_PROBE' }
    if ($Arguments -eq '%s') { return $false }
    return $true
}
""" % (failure or "never")
        source = source[:start] + mock + "$env:DOCKER_HOST = 'tcp://SECRET_MARKER:2376'\n" + source[end:]
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
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("does not install, start, or establish readiness", result.stdout, result.stderr)
        self.assertIn("No certificate trust", result.stdout)
        self.assertIn("Docker engine probe skipped", result.stdout)

    def test_each_probe_failure_is_reported(self):
        for argument, message in [
            ("--status", "WSL status unavailable"),
            ("--version", "WSL version unavailable"),
            ("version --format {{.Server.Os}}", "Docker engine unavailable"),
            ("compose version", "Docker Compose unavailable"),
        ]:
            with self.subTest(argument=argument):
                result = self.run_scenario(argument, check_engine=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stdout)

    def test_opt_in_success_and_warning_order(self):
        result = self.run_scenario(check_engine=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(result.stdout.index("its selected context may be remote"),
                        result.stdout.index("MOCK_ENGINE_PROBE"))
        self.assertNotIn("SECRET_MARKER", result.stdout + result.stderr)
        self.assertIn("No certificate trust", result.stdout)

    def test_switch_binding(self):
        source = SCRIPT.read_text(encoding="utf-8")
        start = source.index("function Invoke-BoundedProbe {")
        end = source.index("function Start-PrerequisiteCheck {")
        source = source[:start] + "function Invoke-BoundedProbe { return $true }\n" + source[end:]
        source = source.replace(
            "[System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT", "$false"
        )
        payload = base64.b64encode(source.encode("utf-8")).decode("ascii")
        command = ("$s = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + payload +
                   "')); & ([scriptblock]::Create($s)) -CheckEngine")
        encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
        result = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Configured Docker engine responded", result.stdout)

    def test_non_windows_refused(self):
        result = self.run_scenario(windows=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires native Windows", result.stdout)

    def test_remote_environment_is_not_disclosed_or_probed(self):
        source = SCRIPT.read_text(encoding="utf-8")
        source = source.replace("param([switch]$CheckEngine)", "$CheckEngine = $false", 1)
        start = source.index("function Invoke-BoundedProbe {")
        end = source.index("function Start-PrerequisiteCheck {")
        mock = """function Invoke-BoundedProbe {
    param([string]$Program, [string]$Arguments)
    if ($Program -eq 'docker.exe' -and $Arguments -ne 'compose version') { throw 'unexpected Docker probe' }
    return $true
}
$env:DOCKER_HOST = 'tcp://SECRET_MARKER:2376'
"""
        source = source[:start] + mock + source[end:]
        source = source.replace(
            "[System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT", "$false"
        )
        encoded = base64.b64encode(source.encode("utf-16le")).decode("ascii")
        result = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("Docker engine probe skipped", result.stdout)
        self.assertNotIn("SECRET_MARKER", result.stdout + result.stderr)


@unittest.skipUnless(POWERSHELL, "PowerShell is not installed")
class RealProbeTests(unittest.TestCase):
    def test_child_processes(self):
        source = SCRIPT.read_text(encoding="utf-8")
        functions = source[:source.index("function Start-PrerequisiteCheck {")]
        harness = r"""
$exe = (Get-Process -Id $PID).Path
function Child([string]$code, [int]$timeout = 10000) {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
    Invoke-BoundedProbe $exe "-NoProfile -NonInteractive -EncodedCommand $encoded" $timeout
}
if (-not (Child 'exit 0')) { exit 11 }
if (Child 'exit 3') { exit 12 }
if (Invoke-BoundedProbe 'foundry-no-such-executable-917263.exe' '') { exit 13 }
if (-not (Child '[Console]::Out.Write("O" * 1000000); [Console]::Error.Write("E" * 1000000); exit 0')) { exit 14 }
if (Child 'Start-Sleep -Seconds 8; exit 0' 300) { exit 15 }
Write-Host 'probe cases passed'
exit 0
"""
        encoded = base64.b64encode((functions + harness).encode("utf-16le")).decode("ascii")
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("probe cases passed", result.stdout)
        self.assertNotIn("O" * 100, result.stdout + result.stderr)
        self.assertNotIn("E" * 100, result.stdout + result.stderr)


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
