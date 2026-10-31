"""Integration tests for the TLS preflight using the real Compose CLI.

Run with: python3 -m unittest discover -s tests -v
Requires Docker Compose and an accessible Docker daemon.
"""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]


class TLSPreflightIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="foundry-tls-test-")
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name)
        for name in ("Makefile", "compose.yaml", "scripts/tls_preflight.py"):
            destination = self.project / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, destination)

        self.project_name = "foundry-test-" + uuid.uuid4().hex
        self.env = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("FOUNDRY_", "COMPOSE_"))
        }
        self.env["COMPOSE_PROJECT_NAME"] = self.project_name
        self.secret = "DO_NOT_DISCLOSE_test_secret_72f94c"
        compose = self.project / "compose.yaml"
        compose.write_text(compose.read_text().replace(
            "    environment:\n", "    environment:\n      TEST_SECRET: ${FOUNDRY_TEST_SECRET}\n", 1
        ))
        self.tls = self.project / "tls"
        self.tls.mkdir()
        (self.tls / "server.crt").write_text("certificate placeholder\n")
        (self.tls / "server.key").write_text(self.secret + "\n")
        self.write_env(str(self.tls))
        self.addCleanup(self.assert_no_resources)

    def write_env(self, tls_dir):
        (self.project / ".env").write_text(
            "FOUNDRY_ROUTER_IMAGE=foundry-test-placeholder:never-pull\n"
            "FOUNDRY_ROUTER_HOST=example.test\n"
            f"FOUNDRY_TLS_DIR={tls_dir}\n"
            f"FOUNDRY_TEST_SECRET={self.secret}\n"
        )

    def run_command(self, *command, extra_env=None):
        env = self.env.copy()
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            command, cwd=self.project, env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )

    def assert_no_resources(self):
        for kind in ("container", "network", "volume"):
            result = self.run_command(
                "docker", kind, "ls", "-q", *(["-a"] if kind == "container" else []), "--filter",
                f"label=com.docker.compose.project={self.project_name}",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "", f"Unexpected {kind}: {result.stdout}")

    def assert_no_secret(self, result):
        self.assertNotIn(self.secret, result.stdout + result.stderr)

    def assert_make_fails(self, extra_env=None):
        result = self.run_command("make", "up", extra_env=extra_env)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("TLS preflight failed", result.stdout + result.stderr)
        self.assert_no_secret(result)
        self.assert_no_resources()

    def assert_preflight_succeeds(self, extra_env=None):
        result = self.run_command("python3", "scripts/tls_preflight.py", extra_env=extra_env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_no_secret(result)
        self.assert_no_resources()

    def test_missing_directory(self):
        missing = self.project / "does-not-exist"
        self.write_env(str(missing))
        self.assert_make_fails()
        self.assertFalse(missing.exists())

    def test_relative_directory_even_if_it_exists(self):
        self.write_env("tls")
        self.assert_make_fails()

    def test_empty_directory_setting(self):
        self.write_env("")
        self.assert_make_fails()

    def test_existing_empty_directory(self):
        empty = self.project / "empty"
        empty.mkdir()
        self.write_env(str(empty))
        self.assert_make_fails()

    def test_missing_certificate(self):
        (self.tls / "server.crt").unlink()
        self.assert_make_fails()

    def test_missing_key(self):
        (self.tls / "server.key").unlink()
        self.assert_make_fails()

    def test_valid_directory(self):
        self.assert_preflight_succeeds()

    def test_environment_overrides_env_file(self):
        self.write_env(str(self.project / "missing"))
        self.assert_preflight_succeeds({"FOUNDRY_TLS_DIR": str(self.tls)})
        self.write_env(str(self.tls))
        self.assert_make_fails({"FOUNDRY_TLS_DIR": str(self.project / "missing")})

    def test_quoted_directory_with_spaces(self):
        spaced = self.project / "tls with spaces"
        self.tls.rename(spaced)
        self.write_env(f'"{spaced}"')
        self.assert_preflight_succeeds()


if __name__ == "__main__":
    unittest.main()
