"""Static contracts only; native Windows behavioral coverage is unavailable.

These checks do not execute PowerShell or verify switch binding, exit codes,
probe failures, timeouts, stream handling, endpoint disclosure, or host effects.
Native acceptance requires a separately authorized, isolated test plan.
"""

from pathlib import Path
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "windows-prerequisites.ps1"


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

    def test_engine_probe_switch_and_warning_source_order(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("param([switch]$CheckEngine)", text)
        self.assertIn("if ($CheckEngine) {", text)
        self.assertLess(text.index("if ($CheckEngine) {"),
                        text.index("its selected context may be remote"))
        self.assertLess(text.index("its selected context may be remote"),
                        text.index("if (Invoke-BoundedProbe 'docker.exe' 'version --format {{.Server.Os}}')"))
        self.assertIn("Docker engine probe skipped", text)
        self.assertIn("no endpoint is displayed", text)
        engine = text[text.index("if ($CheckEngine) {"):text.index("Write-Host 'Checking the local Docker Compose CLI")]
        self.assertEqual(engine.count("Invoke-BoundedProbe 'docker.exe' 'version --format {{.Server.Os}}'"), 1)
        self.assertIn("} else {\n        Write-Host 'Docker engine probe skipped", engine)
        self.assertNotIn("$env:DOCKER_HOST", text)
        self.assertNotIn("$env:DOCKER_CONTEXT", text)

    def test_probe_failure_handling_source(self):
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("if (-not $process.WaitForExit($TimeoutMilliseconds)) {", text)
        self.assertIn("$process.Kill()", text)
        self.assertIn("return ($process.ExitCode -eq 0)", text)
        self.assertIn("$process.StandardOutput.ReadToEndAsync()", text)
        self.assertIn("$process.StandardError.ReadToEndAsync()", text)
        self.assertIn("if ($failed) { return 1 }", text)
        self.assertGreaterEqual(text.count("$failed = $true"), 5)

    def test_diagnostic_limitations_and_failure_messages_are_present(self):
        text = SCRIPT.read_text(encoding="utf-8")
        for message in (
            "requires native Windows",
            "WSL status unavailable",
            "WSL version unavailable",
            "Docker engine unavailable",
            "Docker Compose unavailable",
            "No certificate trust",
        ):
            with self.subTest(message=message):
                self.assertIn(message, text)


if __name__ == "__main__":
    unittest.main()
