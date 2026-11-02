"""Dormant managed flow tests: no custody gate is lifted."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import uuid
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import windows_first_run as first_run


class ManagedIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.project = "isolated-test"
        self.image = "sha256:" + "a" * 64
        self.nonce = "b" * 32
        self.volume = "foundry-tls-" + self.nonce
        self.fingerprint = hashlib.sha256(b"der").hexdigest()
        self.cid = "c" * 64

    def test_gate_blocks_managed_flow(self):
        result = [json.dumps([{"Endpoints": {"docker": {"Host": first_run.SOCKET}}}]),
                  json.dumps({"OSType": "linux", "ID": "engine"}), json.dumps([{"Id": self.image}])]
        with patch.dict(first_run.os.environ, {}, clear=True), \
             patch.object(first_run.platform, "system", return_value="Linux"), \
             patch.object(first_run.platform, "release", return_value="microsoft-standard-WSL2"), \
             patch.object(first_run, "run", side_effect=result), \
             patch.object(first_run, "managed_flow") as flow:
            self.assertEqual(first_run.managed_main([self.project, self.image, "-", "-", "-", "engine", "-", "Ubuntu"]), 1)
            flow.assert_not_called()

    def test_stopped_resume_checks_fingerprint_before_start(self):
        events = []
        config = {"name": self.project, "services": {"router": {"image": self.image}}}
        def command(*args):
            if "config" in args:
                return json.dumps(config)
            if args[:3] == ("docker", "container", "ls"):
                return self.cid
            if args[:3] == ("docker", "image", "inspect"):
                return json.dumps([{"Id": self.image, "Config": {"User": "scarcity"}}])
            if args[:2] == ("docker", "run"):
                return "10001:10001"
            if args[:2] == ("docker", "inspect"):
                return json.dumps([{"State": {"Running": False}}])
            if args[:2] == ("docker", "start"):
                events.append("start")
                return self.cid
            raise AssertionError(args)
        def volume(*args, **kwargs):
            events.append("volume")
            return "certificate"
        with patch.dict(first_run.os.environ, {}, clear=True), \
             patch.object(first_run.os, "chdir"), patch.object(first_run, "run", side_effect=command), \
             patch.object(first_run, "verify_project", return_value=self.cid), \
             patch.object(first_run.managed_tls, "verify_tls_volume", side_effect=volume), \
             patch.object(first_run.ssl, "PEM_cert_to_DER_cert", return_value=b"der"), \
             patch.object(first_run, "request", side_effect=[(200, None, b'{"status":"ok"}'), (303, "/admin/login", b"")]):
            self.assertEqual(first_run.managed_flow(self.project, self.image, self.fingerprint, self.volume,
                                                    self.nonce, self.project, "Ubuntu"), 0)
        self.assertEqual(events, ["volume", "start"])
        events.clear()
        with patch.dict(first_run.os.environ, {}, clear=True), \
             patch.object(first_run.os, "chdir"), patch.object(first_run, "run", side_effect=command), \
             patch.object(first_run, "verify_project", return_value=self.cid), \
             patch.object(first_run.managed_tls, "verify_tls_volume", side_effect=volume), \
             patch.object(first_run.ssl, "PEM_cert_to_DER_cert", return_value=b"der"):
            with self.assertRaises(ValueError):
                first_run.managed_flow(self.project, self.image, "0" * 64, self.volume,
                                       self.nonce, self.project, "Ubuntu")
        self.assertEqual(events, ["volume"])

    def test_existing_project_never_initializes_a_new_volume(self):
        config = {"name": self.project, "services": {"router": {"image": self.image}}}
        results = [json.dumps(config), json.dumps([{"Id": self.image, "Config": {"User": "scarcity"}}]), "10001:10001"]
        with patch.dict(first_run.os.environ, {}, clear=True), \
             patch.object(first_run.os, "chdir"), patch.object(first_run, "run", side_effect=results), \
             patch.object(first_run, "check_project", return_value=True), \
             patch.object(first_run.managed_tls, "initialize_tls_volume") as initialize:
            with self.assertRaises(ValueError):
                first_run.managed_flow(self.project, self.image, "-", "-", "-", "-", "Ubuntu")
            initialize.assert_not_called()

    @unittest.skipUnless(shutil.which("docker") and subprocess.run(
        ["docker", "compose", "version"], stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL).returncode == 0, "Docker Compose unavailable")
    def test_real_compose_merge_contains_no_host_tls_bind(self):
        original = first_run.run
        config_calls = []
        def command(*args):
            if args[:2] == ("docker", "compose") and "config" in args:
                result = original(*args)
                config_calls.append(json.loads(result))
                return result
            if args[:3] == ("docker", "container", "ls"):
                return ""
            if args[:3] == ("docker", "image", "inspect"):
                return json.dumps([{"Id": self.image, "Config": {"User": "scarcity"}}])
            if args[:2] == ("docker", "run"):
                return "10001:10001"
            if args[:2] == ("docker", "compose") and "up" in args:
                return ""
            raise AssertionError(args)
        with patch.dict(first_run.os.environ, {}, clear=True), \
             patch.object(first_run, "run", side_effect=command), \
             patch.object(first_run, "check_project", return_value=False), \
             patch.object(first_run, "verify_project", return_value=self.cid), \
             patch.object(first_run.managed_tls, "_inspect"), \
             patch.object(first_run.managed_tls, "verify_tls_volume", return_value="certificate"), \
             patch.object(first_run.ssl, "PEM_cert_to_DER_cert", return_value=b"der"), \
             patch.object(first_run, "request", side_effect=[(200, None, b'{"status":"ok"}'), (303, "/admin/login", b"")]):
            self.assertEqual(first_run.managed_flow(self.project, self.image, self.fingerprint, self.volume,
                                                    self.nonce, self.project, "Ubuntu"), 0)
        tls = [m for m in config_calls[-1]["services"]["router"]["volumes"] if m["target"] == "/run/foundry/tls"]
        self.assertEqual(len(tls), 1)
        self.assertEqual(tls[0]["type"], "volume")
        self.assertTrue(tls[0]["read_only"])

    @unittest.skipUnless(os.environ.get("FOUNDRY_TEST_MANAGED_TLS_IMAGE"), "requires explicit isolated Docker test image")
    def test_isolated_real_start_and_stopped_recovery(self):
        image = os.environ["FOUNDRY_TEST_MANAGED_TLS_IMAGE"]
        project = "foundry-managed-test-" + uuid.uuid4().hex[:12]
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", 8787))
            except OSError:
                self.skipTest("loopback test port is occupied")
        volume, nonce, cert = first_run.managed_tls.initialize_tls_volume(project, image)
        fingerprint = hashlib.sha256(first_run.ssl.PEM_cert_to_DER_cert(cert)).hexdigest()
        label = "label=com.docker.compose.project=" + project
        try:
            self.assertEqual(first_run.managed_flow(project, image, fingerprint, volume, nonce, project, "Ubuntu"), 1)
            ids = first_run.run("docker", "container", "ls", "--all", "--filter", label, "--quiet").splitlines()
            self.assertEqual(len(ids), 1)
            before = json.loads(first_run.run("docker", "inspect", ids[0]))[0]
            first_run.run("docker", "stop", ids[0])
            self.assertEqual(first_run.managed_flow(project, image, fingerprint, volume, nonce, project, "Ubuntu"), 1)
            after = json.loads(first_run.run("docker", "inspect", ids[0]))[0]
            self.assertEqual(before["Id"], after["Id"])
            self.assertTrue(after["State"]["Running"])
        finally:
            # Only names scoped to this random project and the created TLS volume are removed.
            ids = first_run.run("docker", "container", "ls", "--all", "--filter", label, "--quiet").splitlines()
            for cid in ids:
                subprocess.run(["docker", "rm", "-f", cid], check=True, stdout=subprocess.DEVNULL)
            for kind in ("network", "volume"):
                names = first_run.run("docker", kind, "ls", "--filter", label, "--format", "{{.Name}}").splitlines()
                for name in names:
                    subprocess.run(["docker", kind, "rm", name], check=True, stdout=subprocess.DEVNULL)
            first_run.managed_tls._inspect(project, image, volume, nonce)
            subprocess.run(["docker", "volume", "rm", volume], check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()
