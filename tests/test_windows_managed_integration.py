"""Managed proposal checks; activation requires independent review."""

import json
import contextlib
import io
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import unittest
import uuid
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import windows_first_run as first_run
import windows_managed_tls as managed


class ManagedIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.project = "isolated-test"
        self.image = "sha256:" + "a" * 64
        self.nonce = "b" * 32
        self.volume = managed.volume_name(self.project)
        self.cid = "c" * 64
        self.config = {"name": self.project, "services": {"router": {"image": self.image}}}

    def test_separate_gate_blocks_managed_flow(self):
        result = [json.dumps([{"Endpoints": {"docker": {"Host": first_run.SOCKET}}}]),
                  json.dumps({"OSType": "linux", "ID": "engine"}), json.dumps([{"Id": self.image}])]
        with patch.dict(first_run.os.environ, {}, clear=True), \
             patch.object(first_run.platform, "system", return_value="Linux"), \
             patch.object(first_run.platform, "release", return_value="microsoft-standard-WSL2"), \
             patch.object(first_run, "MANAGED_ACTIVATED", False), \
             patch.object(first_run, "run", side_effect=result), \
             patch.object(first_run, "managed_flow") as flow:
            self.assertEqual(first_run.managed_main([self.project, self.image, "engine", "Ubuntu"]), 1)
            flow.assert_not_called()

    def command(self, *args):
        if "config" in args:
            return json.dumps(self.config)
        if args[:3] == ("docker", "image", "inspect"):
            return json.dumps([{"Id": self.image, "Config": {"User": "scarcity"}}])
        if args[:2] == ("docker", "run"):
            return "10001:10001"
        if args[:3] == ("docker", "container", "ls"):
            return self.cid
        if args[:2] == ("docker", "inspect"):
            return json.dumps([{"State": {"Running": False}}])
        if args[:2] == ("docker", "start"):
            return self.cid
        raise AssertionError(args)

    def test_stopped_recovery_requires_consent_and_reverification(self):
        events = []
        def command(*args):
            if args[:2] == ("docker", "start"):
                events.append("start")
            return self.command(*args)
        def verify(*args, **kwargs):
            events.append("volume")
            return "certificate"
        with patch.dict(first_run.os.environ, {}, clear=True), \
             patch.object(first_run.os, "chdir"), patch.object(first_run, "foreground_terminal", return_value=False), \
             patch.object(first_run, "run", side_effect=command), \
             patch.object(managed, "discover_tls_volume", return_value=(self.volume, self.nonce)), \
             patch.object(managed, "verify_tls_volume", side_effect=verify), \
             patch.object(first_run, "verify_project", return_value=self.cid), \
             patch.object(first_run.ssl, "PEM_cert_to_DER_cert", return_value=b"der"), \
             patch("builtins.input", return_value="YES"), \
             patch.object(first_run, "request", side_effect=[(200, None, b'{"status":"ok"}'), (303, "/admin/login", b"")]):
            self.assertEqual(first_run.managed_flow(self.project, self.image, "Ubuntu"), 0)
        self.assertEqual(events, ["volume", "volume", "start"])

    def test_non_terminal_starts_but_does_not_issue_claim_when_onboarding_needed(self):
        output = io.StringIO()
        with patch.dict(first_run.os.environ, {}, clear=True), patch.object(first_run.os, "chdir"), \
             patch.object(first_run, "foreground_terminal", return_value=False), \
             patch.object(first_run, "run", side_effect=self.command) as docker, \
             patch.object(managed, "discover_tls_volume", return_value=(self.volume, self.nonce)), \
             patch.object(managed, "verify_tls_volume", return_value="certificate"), \
             patch.object(first_run, "verify_project", return_value=self.cid), \
             patch.object(first_run.ssl, "PEM_cert_to_DER_cert", return_value=b"der"), \
             patch("builtins.input", return_value="YES") as prompt, \
             patch.object(first_run, "request", side_effect=[(200, None, b'{"status":"ok"}'),
                 (303, "/admin/onboarding", b"")]), \
             patch.object(first_run.subprocess, "run", side_effect=AssertionError("claim attempted")), \
             contextlib.redirect_stdout(output):
            self.assertEqual(first_run.managed_flow(self.project, self.image, "Ubuntu"), 2)
        self.assertEqual(prompt.call_count, 1)
        self.assertIn("SERVER_RUNNING — ADMIN_ONBOARDING_INCOMPLETE", output.getvalue())
        self.assertIn("does not issue a claim", output.getvalue())
        self.assertTrue(any(call.args[:2] == ("docker", "start") for call in docker.call_args_list))
        self.assertFalse(any("rm" in call.args for call in docker.call_args_list))

    def test_foreground_affirmative_cannot_issue_claim(self):
        output = io.StringIO()
        with patch.dict(first_run.os.environ, {}, clear=True), patch.object(first_run.os, "chdir"), \
             patch.object(first_run.os, "isatty", return_value=True), \
             patch.object(first_run.os, "ttyname", return_value="/dev/pts/1"), \
             patch.object(first_run.os, "tcgetpgrp", return_value=12), patch.object(first_run.os, "getpgrp", return_value=12), \
             patch.object(first_run.sys.stdin, "isatty", return_value=True), \
             patch.object(output, "isatty", return_value=True), \
             patch.object(first_run.sys.stderr, "isatty", return_value=True), \
             patch.object(first_run, "run", side_effect=self.command), \
             patch.object(managed, "discover_tls_volume", return_value=(self.volume, self.nonce)), \
             patch.object(managed, "verify_tls_volume", return_value="certificate"), \
             patch.object(first_run, "verify_project", return_value=self.cid), \
             patch.object(first_run.ssl, "PEM_cert_to_DER_cert", return_value=b"der"), \
             patch.object(first_run, "request", side_effect=[(200, None, b'{"status":"ok"}'),
                 (303, "/admin/onboarding", b"")]), \
             patch("builtins.input", side_effect=["YES", "YES", "I ATTEST"]) as prompt, \
             patch.object(first_run, "attest_claim_terminal", return_value="/dev/pts/1") as attestation, \
             patch.object(first_run.subprocess, "run", side_effect=AssertionError("claim attempted")) as process, \
             contextlib.redirect_stdout(output):
            self.assertEqual(first_run.managed_flow(self.project, self.image, "Ubuntu"), 2)
        self.assertEqual(prompt.call_count, 1)
        attestation.assert_not_called()
        self.assertIn("experimental mode does not issue", output.getvalue())
        process.assert_not_called()

    def test_confirmation_refusal_and_certificate_change_never_start(self):
        for choice, certificates in (("NO", ["certificate"]), (EOFError(), ["certificate"]), ("YES", ["certificate", "changed"])):
            with self.subTest(choice=choice), patch.dict(first_run.os.environ, {}, clear=True), \
                 patch.object(first_run.os, "chdir"), \
                 patch.object(first_run, "run", side_effect=self.command) as docker, \
                 patch.object(managed, "discover_tls_volume", return_value=(self.volume, self.nonce)), \
                 patch.object(managed, "verify_tls_volume", side_effect=certificates), \
                 patch.object(first_run, "verify_project", return_value=self.cid), \
                 patch.object(first_run.ssl, "PEM_cert_to_DER_cert", return_value=b"der"), \
                 patch("builtins.input", side_effect=choice if isinstance(choice, Exception) else None, return_value=choice):
                with self.assertRaises((ValueError, EOFError)):
                    first_run.managed_flow(self.project, self.image, "Ubuntu")
                self.assertFalse(any(call.args[:2] == ("docker", "start") for call in docker.call_args_list))

    def test_unattached_volume_is_not_adopted(self):
        def command(*args):
            if args[:3] == ("docker", "container", "ls"):
                return ""
            return self.command(*args)
        with patch.dict(first_run.os.environ, {}, clear=True), \
             patch.object(first_run.os, "chdir"), \
             patch.object(first_run, "run", side_effect=command), \
             patch.object(managed, "discover_tls_volume", return_value=(self.volume, self.nonce)), \
             patch.object(managed, "verify_tls_volume") as verify:
            with self.assertRaises(ValueError):
                first_run.managed_flow(self.project, self.image, "Ubuntu")
            verify.assert_not_called()

    def test_attestation_refusal_unknown_recording_eof_and_non_tty(self):
        for response in ("NO", "UNKNOWN", "RECORDING REQUIRED", "", EOFError()):
            with self.subTest(response=response), patch.object(first_run, "foreground_terminal", return_value=True), \
                 patch.object(first_run.os, "ttyname", return_value="/dev/pts/1"), \
                 patch("builtins.input", side_effect=response if isinstance(response, Exception) else None,
                       return_value=response):
                self.assertFalse(first_run.attest_claim_terminal())
        with patch.object(first_run, "foreground_terminal", return_value=False), \
             patch("builtins.input") as prompt:
            self.assertFalse(first_run.attest_claim_terminal())
            prompt.assert_not_called()
        with patch.object(first_run, "foreground_terminal", side_effect=[True, False]), \
             patch.object(first_run.os, "ttyname", return_value="/dev/pts/1"), \
             patch("builtins.input", return_value="I ATTEST"):
            self.assertFalse(first_run.attest_claim_terminal())
        with patch.object(first_run, "foreground_terminal", return_value=True), \
             patch.object(first_run.os, "ttyname", side_effect=["/dev/pts/1", "/dev/pts/2"]), \
             patch("builtins.input", return_value="I ATTEST"):
            self.assertFalse(first_run.attest_claim_terminal())

    def test_admin_status_is_not_confused_with_onboarding(self):
        for status, location, expected in ((303, "/admin/login", 0), (303, "/admin/onboarding", 2),
                                           (200, None, None), (303, "/other", None),
                                           (500, "/admin/onboarding", None)):
            output = io.StringIO()
            with self.subTest(status=status, location=location), patch.dict(first_run.os.environ, {}, clear=True), \
                 patch.object(first_run.os, "chdir"), \
                 patch.object(first_run, "run", side_effect=self.command), \
                 patch.object(managed, "discover_tls_volume", return_value=(self.volume, self.nonce)), \
                 patch.object(managed, "verify_tls_volume", return_value="certificate"), \
                 patch.object(first_run, "verify_project", return_value=self.cid), \
                 patch.object(first_run.ssl, "PEM_cert_to_DER_cert", return_value=b"der"), \
                 patch.object(first_run, "request", side_effect=[(200, None, b'{"status":"ok"}'),
                     (status, location, b"")]), \
                 patch("builtins.input", return_value="YES") as prompt, \
                 patch.object(first_run.subprocess, "run", side_effect=AssertionError("claim attempted")), \
                 contextlib.redirect_stdout(output):
                if expected is None:
                    with self.assertRaisesRegex(ValueError, "administrator state unknown"):
                        first_run.managed_flow(self.project, self.image, "Ubuntu")
                else:
                    self.assertEqual(first_run.managed_flow(self.project, self.image, "Ubuntu"), expected)
                self.assertEqual(prompt.call_count, 1)
                self.assertEqual("ADMIN_ONBOARDING_INCOMPLETE" in output.getvalue(), expected == 2)
                self.assertEqual("Administrator configured" in output.getvalue(), expected == 0)

    @unittest.skipUnless(shutil.which("docker") and subprocess.run(
        ["docker", "compose", "version"], stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL).returncode == 0, "Docker Compose unavailable")
    def test_compose_uses_empty_explicit_env_file(self):
        original = first_run.run
        def command(*args):
            if args[:2] == ("docker", "compose") and "config" in args:
                self.assertNotEqual(args[args.index("--env-file") + 1], ".env")
                return original(*args)
            if args[:3] == ("docker", "container", "ls"):
                return ""
            return self.command(*args)
        with patch.dict(first_run.os.environ, {"FOUNDRY_ROUTER_IMAGE": "unsafe"}, clear=True), \
             patch.object(managed, "discover_tls_volume", side_effect=ValueError("stop after config")), \
             patch.object(first_run, "run", side_effect=command):
            with self.assertRaisesRegex(ValueError, "stop after config"):
                first_run.managed_flow(self.project, self.image, "Ubuntu")

    @unittest.skipUnless(shutil.which("docker") and subprocess.run(
        ["docker", "compose", "version"], stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL).returncode == 0, "Docker Compose unavailable")
    def test_real_compose_override_has_readonly_volume_not_bind(self):
        original = first_run.run
        configs = []
        def command(*args):
            if args[:2] == ("docker", "compose") and "config" in args:
                result = original(*args)
                configs.append(json.loads(result))
                return result
            if args[:3] == ("docker", "container", "ls"):
                return ""
            if args[:2] == ("docker", "compose") and "up" in args:
                return ""
            return self.command(*args)
        with patch.dict(first_run.os.environ, {}, clear=True), \
             patch.object(first_run.os, "isatty", return_value=True), \
             patch.object(first_run.os, "ttyname", return_value="/dev/pts/1"), \
             patch.object(first_run.os, "tcgetpgrp", return_value=12), patch.object(first_run.os, "getpgrp", return_value=12), \
             patch.object(first_run, "run", side_effect=command), \
             patch.object(first_run, "check_project", return_value=False), \
             patch.object(first_run, "verify_project", return_value=self.cid), \
             patch.object(managed, "discover_tls_volume", return_value=None), \
             patch.object(managed, "initialize_tls_volume", return_value=(self.volume, self.nonce, "certificate")), \
             patch.object(managed, "verify_tls_volume", return_value="certificate"), \
             patch.object(managed, "_inspect"), \
             patch.object(first_run.ssl, "PEM_cert_to_DER_cert", return_value=b"der"), \
             patch("builtins.input", return_value="YES"), \
             patch.object(first_run, "request", side_effect=[(200, None, b'{"status":"ok"}'), (303, "/admin/login", b"")]):
            self.assertEqual(first_run.managed_flow(self.project, self.image, "Ubuntu"), 0)
        tls = [m for m in configs[-1]["services"]["router"]["volumes"] if m["target"] == "/run/foundry/tls"]
        self.assertEqual(len(tls), 1)
        self.assertEqual(tls[0]["type"], "volume")
        self.assertTrue(tls[0]["read_only"])

    def test_discovery_refuses_conflicts_and_unexpected_project_volumes(self):
        for outputs in ([self.volume, ""], ["", "other"], [self.volume + "\nother", self.volume + "\nother"]):
            with self.subTest(outputs=outputs), patch.object(managed, "_run", side_effect=outputs):
                with self.assertRaises(ValueError):
                    managed.discover_tls_volume(self.project, self.image)

    def test_timeout_never_deletes_resources(self):
        with patch.object(managed, "_run", side_effect=subprocess.TimeoutExpired("docker", 1)) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                managed.discover_tls_volume(self.project, self.image)
        self.assertFalse(any("rm" in call.args[0] for call in run.call_args_list))

    @unittest.skipUnless(os.environ.get("FOUNDRY_TEST_MANAGED_TLS_IMAGE") ==
                         "sha256:adcba8a8c65ceb23103c6de7629948ef0b54cd80bcabd4d41f9f9db1fa6fee97",
                         "requires explicit prepared Docker Desktop test image")
    def test_real_docker_fresh_conflicts_and_stopped_recovery(self):
        # Direct internal API test only: the production entrypoint guard is not changed.
        image = os.environ["FOUNDRY_TEST_MANAGED_TLS_IMAGE"]
        project = "foundry-managed-test-" + uuid.uuid4().hex
        name = managed.volume_name(project)
        extra = name + "-conflict"
        consumer = project + "-consumer"
        label = "label=com.docker.compose.project=" + project
        env = {k: v for k, v in os.environ.items() if not k.startswith(("COMPOSE_", "FOUNDRY_", "DOCKER_"))}
        env["DOCKER_HOST"] = first_run.SOCKET
        with socket.socket() as port:
            try:
                port.bind(("127.0.0.1", 8787))
            except OSError:
                self.skipTest("loopback test port is occupied")
        def docker(*args):
            return subprocess.run(["docker", *args], check=True, text=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, timeout=120).stdout.strip()
        with patch.dict(os.environ, env, clear=True):
            info = json.loads(docker("info", "--format", "{{json .}}"))
            self.assertEqual((info.get("OSType"), info.get("Name")), ("linux", "docker-desktop"))
            self.assertEqual(json.loads(docker("image", "inspect", image))[0]["Id"], image)
            for kind in ("container", "network", "volume"):
                args = [kind, "ls"] + (["--all"] if kind == "container" else [])
                self.assertFalse(docker(*args, "--filter", label, "--quiet"))
            self.assertNotIn(name, docker("volume", "ls", "--quiet").splitlines())
            self.assertNotIn(extra, docker("volume", "ls", "--quiet").splitlines())
            try:
                def flow():
                    output = io.StringIO()
                    with patch.object(os, "isatty", return_value=True), \
                         patch.object(os, "ttyname", return_value="/dev/pts/test"), \
                         patch.object(os, "tcgetpgrp", return_value=42), patch.object(os, "getpgrp", return_value=42), \
                         patch.object(sys.stdin, "isatty", return_value=True), patch.object(output, "isatty", return_value=True), \
                         patch.object(sys.stderr, "isatty", return_value=False), \
                         patch("builtins.input", return_value="YES") as consent, \
                         contextlib.redirect_stdout(output):
                        result = first_run.managed_flow(project, image, "Ubuntu")
                    self.assertEqual(consent.call_count, 1)
                    self.assertNotIn("PRIVATE KEY", output.getvalue())
                    self.assertIn("SERVER_RUNNING — ADMIN_ONBOARDING_INCOMPLETE", output.getvalue())
                    return result
                self.assertEqual(flow(), 2)
                ids = docker("container", "ls", "--all", "--filter", label, "--quiet").splitlines()
                self.assertEqual(len(ids), 1)
                cid = ids[0]
                before = json.loads(docker("inspect", cid))[0]
                self.assertEqual(before["Image"], image)
                mounts = before["Mounts"]
                tls = [m for m in mounts if m["Destination"] == "/run/foundry/tls"]
                self.assertEqual(len(tls), 1)
                self.assertEqual((tls[0]["Type"], tls[0]["Name"], tls[0]["RW"]), ("volume", name, False))
                self.assertFalse(any(m["Type"] == "bind" for m in mounts))
                self.assertTrue(before["State"]["Running"])
                docker("stop", cid)
                # A stopped foreign consumer must also block recovery.
                docker("create", "--name", consumer, "--label", "foundry.test.owner=" + project,
                       "--network", "none", "--tmpfs", "/data:rw,noexec,nosuid,size=1m",
                       "--mount", "type=volume,src=" + name + ",dst=/tls,readonly,volume-nocopy",
                       "--entrypoint", "python", image, "-c", "pass")
                with self.assertRaises(ValueError):
                    flow()
                self.assertFalse(json.loads(docker("inspect", cid))[0]["State"]["Running"])
                docker("rm", consumer)
                docker("volume", "create", "--label", managed._LABEL + ".project=" + project, extra)
                with self.assertRaises(ValueError):
                    flow()
                self.assertFalse(json.loads(docker("inspect", cid))[0]["State"]["Running"])
                docker("volume", "rm", extra)
                self.assertEqual(flow(), 2)
                after = json.loads(docker("inspect", cid))[0]
                self.assertEqual(before["Id"], after["Id"])
                self.assertTrue(after["State"]["Running"])
                self.assertEqual(managed.discover_tls_volume(project, image)[0], name)
            finally:
                # The random, pre-checked project and labels scope cleanup to this test.
                consumers = docker("container", "ls", "--all", "--filter", "label=foundry.test.owner=" + project,
                                   "--quiet").splitlines()
                for item in consumers:
                    docker("rm", "-f", item)
                for item in docker("container", "ls", "--all", "--filter", label, "--quiet").splitlines():
                    docker("rm", "-f", item)
                for kind in ("network", "volume"):
                    for item in docker(kind, "ls", "--filter", label, "--quiet").splitlines():
                        docker(kind, "rm", item)
                names = docker("volume", "ls", "--quiet").splitlines()
                for item in (extra, name):
                    if item in names:
                        data = json.loads(docker("volume", "inspect", item))[0]
                        self.assertEqual(data.get("Labels", {}).get(managed._LABEL + ".project"), project)
                        docker("volume", "rm", item)
                for kind in ("container", "network", "volume"):
                    args = [kind, "ls"] + (["--all"] if kind == "container" else [])
                    self.assertFalse(docker(*args, "--filter", label, "--quiet"))
                self.assertFalse(set((extra, name)) & set(docker("volume", "ls", "--quiet").splitlines()))


if __name__ == "__main__":
    unittest.main()
