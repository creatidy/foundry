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
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_FILES = ("Makefile", "compose.yaml", "scripts/tls_check.py",
                 "scripts/local_tls_up.py", "scripts/local_tls_init.py",
                 "scripts/docker_socket_validation.py")


class TLSFixtureImports(unittest.TestCase):
    def test_isolated_helper_dependency_closure(self):
        import test_tls_preflight

        for module, files in (("tls_check", FIXTURE_FILES),
                              ("tls_preflight", test_tls_preflight.FIXTURE_FILES)):
            with self.subTest(module=module), tempfile.TemporaryDirectory() as tmp:
                project = Path(tmp)
                for name in files:
                    destination = project / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(ROOT / name, destination)
                result = subprocess.run(
                    [sys.executable, "-I", "-B", "-c",
                     "import importlib,sys; sys.path.insert(0,sys.argv[1]); "
                     "print(importlib.import_module(sys.argv[2]).__file__)",
                     str(project / "scripts"), module],
                    env={"PATH": os.defpath}, capture_output=True, text=True,
                    check=False, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), str(project / "scripts" / (module + ".py")))
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
        (cls.directory / "ca-dir").mkdir()
        shutil.copyfile(cls.directory / "ca.crt", cls.directory / "ca-dir" / "ca.crt")
        openssl("rehash", "ca-dir")

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
                  "command": ["--host=0.0.0.0", "--port=8787", "--data-dir=/data",
                              "--tls-reload-hostname=example.test",
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

    def test_rejects_argparse_aliases_and_ambiguous_commands(self):
        base = ["--host=0.0.0.0", "--port=8787", "--data-dir=/data",
                "--tls-reload-hostname=example.test", "--tls-certfile=/run/foundry/tls/server.crt",
                "--tls-keyfile=/run/foundry/tls/server.key"]
        config = {"services": {"router": {"volumes": [{"type": "bind", "source": str(self.path),
                                                       "target": "/run/foundry/tls"}],
                                          "command": base}}}
        for option, value in (("--tls-reload-host", "wrong.test"),
                              ("--tls-cert", "/other.crt"), ("--tls-key", "/other.key"),
                              ("--tls", "other"), ("--tls-reload-hostname", "wrong.test"),
                              ("--host", "127.0.0.1")):
            for extra in ([option + "=" + value], [option, value]):
                with self.subTest(extra=extra):
                    config["services"]["router"]["command"] = base + extra
                    with self.assertRaises(ValueError):
                        tls_check.router_identity(config)
        for command in (base + ["--", "--tls-key=other"],
                        base + ["--unknown=anything"],
                        base[:-1] + ["--tls-keyfile", "/run/foundry/tls/server.key"],
                        base[:-1], base + ["positional"]):
            with self.subTest(command=command):
                config["services"]["router"]["command"] = command
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
            for name in FIXTURE_FILES:
            shutil.copyfile(ROOT / name, project / name)
        (project / ".env").write_text(
            "FOUNDRY_ROUTER_IMAGE=unused:latest\nFOUNDRY_ROUTER_HOST=example.test\n"
            f"FOUNDRY_TLS_DIR={self.path}\n")
        env = {key: value for key, value in os.environ.items()
               if not key.startswith(("FOUNDRY_", "COMPOSE_"))}
        env.pop("SSL_CERT_FILE", None)
        env.pop("SSL_CERT_DIR", None)
        render = subprocess.run(["docker", "compose", "--env-file", ".env", "-f", "compose.yaml",
                                 "config", "--format", "json", "--no-path-resolution"],
                                cwd=project, env=env, capture_output=True, timeout=30, check=True)
        self.assertEqual(tls_check.router_identity(json.loads(render.stdout)), (self.path, "example.test"))
        tls_check.verify(self.path, "example.test", self.context)
        # Test-only mutation control: restore the override immediately before
        # default-context creation, simulating removal of the protection.
        control = (
            "import os,sys; sys.path.insert(0,'scripts'); import tls_check; "
            "original=tls_check.ssl.create_default_context; "
            "key=sys.argv[1]; value=sys.argv[2]; "
            "exec('def context(*a, **kw):\\n os.environ[key]=value\\n return original(*a, **kw)'); "
            "tls_check.ssl.create_default_context=context; sys.exit(tls_check.main())"
        )
        for key, value in (("SSL_CERT_FILE", self.directory / "ca.crt"),
                           ("SSL_CERT_DIR", self.directory / "ca-dir")):
            with self.subTest(override=key):
                override_env = dict(env, **{key: str(value)})
                positive = subprocess.run([sys.executable, "-c", control, key, str(value)],
                                          cwd=project, env=override_env, capture_output=True,
                                          text=True, timeout=30)
                self.assertEqual(positive.returncode, 0, positive.stdout + positive.stderr)
                self.assertIn("TLS check passed", positive.stdout)
                instrument = (
                    "import sys,ssl; sys.path.insert(0,'scripts'); import tls_check; "
                    "original=tls_check.verify; "
                    "exec('def checked(*a):\\n try:\\n  original(*a)\\n except ssl.SSLCertVerificationError:\\n  print(\"VERIFY_REJECTED\"); raise'); "
                    "tls_check.verify=checked; sys.exit(tls_check.main())"
                )
                rejected = subprocess.run([sys.executable, "-c", instrument], cwd=project,
                                          env=override_env, capture_output=True, text=True, timeout=30)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn("VERIFY_REJECTED", rejected.stdout)
                result = subprocess.run(["make", "tls-check"], cwd=project, env=override_env,
                                        capture_output=True, text=True, timeout=30)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("TLS check failed", result.stdout + result.stderr)
                self.assertNotIn((self.path / "server.key").read_text(), result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
