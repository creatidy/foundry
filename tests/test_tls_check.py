"""Offline TLS verification tests; requires the openssl command."""

import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import tls_check


@unittest.skipUnless(shutil.which("openssl"), "openssl required")
class TLSCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.temp.name)
        cls.addClassCleanup(cls.temp.cleanup)

        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=cls.directory, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)

        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key",
                "-out", "ca.crt", "-days", "1", "-subj", "/CN=Test CA")
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key",
                "-out", "server.csr", "-subj", "/CN=example.test",
                "-addext", "subjectAltName=DNS:example.test")
        openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
                "-CAcreateserial", "-out", "server.crt", "-days", "1", "-copy_extensions", "copy")
        openssl("genpkey", "-algorithm", "RSA", "-out", "other.key",
                "-pkeyopt", "rsa_keygen_bits:2048")
        openssl("pkey", "-in", "server.key", "-aes-256-cbc", "-passout", "pass:test",
                "-out", "encrypted.key")

    def setUp(self):
        self.temp_case = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_case.cleanup)
        self.path = Path(self.temp_case.name)
        for name in ("server.crt", "server.key"):
            shutil.copyfile(self.directory / name, self.path / name)
        self.context = ssl.create_default_context(cafile=str(self.directory / "ca.crt"))

    def test_valid(self):
        tls_check.verify(self.path, "example.test", self.context)

    def test_untrusted_and_wrong_hostname(self):
        with self.assertRaises(ssl.SSLError):
            tls_check.verify(self.path, "example.test", ssl.create_default_context())
        with self.assertRaises(ssl.SSLError):
            tls_check.verify(self.path, "wrong.test", self.context)

    def test_invalid_keys_and_certificate(self):
        for filename in ("other.key", "encrypted.key"):
            shutil.copyfile(self.directory / filename, self.path / "server.key")
            with self.subTest(filename=filename), self.assertRaises((ssl.SSLError, ValueError)):
                tls_check.verify(self.path, "example.test", self.context)
        (self.path / "server.crt").write_text("malformed")
        with self.assertRaises(ssl.SSLError):
            tls_check.verify(self.path, "example.test", self.context)

    def test_model_and_ambiguities(self):
        router = {"volumes": [{"type": "bind", "source": str(self.path), "target": "/run/foundry/tls"}],
                  "command": ["--tls-reload-hostname=example.test",
                              "--tls-certfile=/run/foundry/tls/server.crt",
                              "--tls-keyfile=/run/foundry/tls/server.key"]}
        config = {"services": {"router": router}}
        self.assertEqual(tls_check.router_identity(config), (self.path, "example.test"))
        router["command"].append("--tls-reload-hostname=other.test")
        with self.assertRaises(ValueError):
            tls_check.router_identity(config)
        router["command"].pop()
        router["volumes"].append(router["volumes"][0])
        with self.assertRaises(ValueError):
            tls_check.router_identity(config)

    def test_generic_failure_does_not_leak(self):
        secret = "PRIVATE_KEY_SECRET_123"
        result = subprocess.CompletedProcess([], 0, stdout=json.dumps({"secret": secret}).encode(),
                                             stderr=secret.encode())
        output = io.StringIO()
        with mock.patch.object(tls_check.subprocess, "run", return_value=result), \
                contextlib.redirect_stderr(output), contextlib.redirect_stdout(output):
            self.assertEqual(tls_check.main(), 1)
        self.assertIn("TLS check failed", output.getvalue())
        self.assertNotIn(secret, output.getvalue())

    def test_make_uses_default_trust_and_does_not_leak_key(self):
        project = self.path / "project"
        project.mkdir()
        (project / "scripts").mkdir()
        for name in ("Makefile", "compose.yaml", "scripts/tls_check.py"):
            shutil.copyfile(ROOT / name, project / name)
        (project / ".env").write_text(
            "FOUNDRY_ROUTER_IMAGE=unused:latest\nFOUNDRY_ROUTER_HOST=example.test\n"
            f"FOUNDRY_TLS_DIR={self.path}\n")
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("FOUNDRY_", "COMPOSE_"))}
        env["SSL_CERT_FILE"] = str(self.directory / "ca.crt")
        result = subprocess.run(["make", "tls-check"], cwd=project, env=env,
                                capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TLS check failed", result.stdout + result.stderr)
        self.assertNotIn((self.path / "server.key").read_text(), result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
