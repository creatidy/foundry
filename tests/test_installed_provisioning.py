"""Pure local checks; these do not start a service or contact Docker."""

import errno
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import installed_provisioning as provisioning
import docker_socket_validation
import local_tls_up


class TestMountGroupTests(unittest.TestCase):
    def test_non_rootless_retains_operator_group(self):
        with mock.patch.object(local_tls_up.os, "getegid", return_value=1001):
            self.assertEqual("1001", local_tls_up.test_mount_group({"SecurityOptions": ["name=seccomp"]}))

    def test_rootless_requires_verified_peer_and_mapping(self):
        peer = mock.MagicMock()
        peer.__enter__.return_value.getsockopt.return_value = struct.pack("3i", 123, 1001, 1001)
        response = mock.MagicMock(status=200)
        response.read.return_value = json.dumps({"ID": "test-engine-id", "SecurityOptions": ["name=rootless"]}).encode()
        with mock.patch.dict(os.environ, {"FOUNDRY_TEST_DOCKER_HOST": "unix:///run/user/1001/docker.sock",
                                        "FOUNDRY_TEST_ENGINE_ID": "test-engine-id"}), \
             mock.patch("socket.socket", return_value=peer), \
             mock.patch("http.client.HTTPResponse", return_value=response), \
             mock.patch.object(local_tls_up.os, "geteuid", return_value=1001), \
             mock.patch.object(local_tls_up.os, "getegid", return_value=1001):
            with mock.patch("builtins.open", return_value=io.StringIO("0 1001 1\n1 165536 65536\n")):
                self.assertEqual("0", local_tls_up.test_mount_group({"SecurityOptions": ["name=rootless"]}))
            with mock.patch("builtins.open", return_value=io.StringIO("0 2000 1\n")):
                with self.assertRaises(local_tls_up.TestEngineRefusal):
                    local_tls_up.test_mount_group({"SecurityOptions": ["name=rootless"]})
            peer.__enter__.return_value.getsockopt.return_value = struct.pack("3i", 123, 0, 0)
            with self.assertRaises(local_tls_up.TestEngineRefusal):
                local_tls_up.test_mount_group({"SecurityOptions": ["name=rootless"]})

    def test_rootless_rejects_changed_engine_and_socket_errors(self):
        peer = mock.MagicMock()
        peer.__enter__.return_value.getsockopt.return_value = struct.pack("3i", 123, 1001, 1001)
        response = mock.MagicMock(status=200)
        response.read.return_value = b'{"ID":"other","SecurityOptions":["name=rootless"]}'
        with mock.patch.dict(os.environ, {"FOUNDRY_TEST_DOCKER_HOST": "unix:///run/user/1001/docker.sock",
                                        "FOUNDRY_TEST_ENGINE_ID": "expected"}), \
             mock.patch("socket.socket", return_value=peer), \
             mock.patch("http.client.HTTPResponse", return_value=response), \
             mock.patch.object(local_tls_up.os, "geteuid", return_value=1001):
            with self.assertRaises(local_tls_up.TestEngineRefusal):
                local_tls_up.test_mount_group({"SecurityOptions": ["name=rootless"]})
            peer.__enter__.return_value.connect.side_effect = TimeoutError("socket timeout")
            with self.assertRaises(local_tls_up.TestEngineRefusal):
                local_tls_up.test_mount_group({"SecurityOptions": ["name=rootless"]})

    def test_missing_security_options_fail_closed(self):
        with self.assertRaises(local_tls_up.TestEngineRefusal):
            local_tls_up.test_mount_group({})

    def test_changed_mapping_refuses_before_compose_up(self):
        token = "a" * 32
        project = "foundry-test-" + token
        config = {"name": project, "services": {"router": {
            "volumes": [{"type": "bind", "source": "/tls", "target": "/run/foundry/tls", "read_only": True}],
            "environment": {"SR_HEALTHCHECK_URL": "https://127.0.0.1:8787/healthz"},
            "command": ["--tls-reload-hostname=127.0.0.1"]}}}
        env = {"LOCAL_TLS_PROJECT": project, "TLS_DEST": "/tls", "FOUNDRY_TEST_RUN_ID": token,
               "FOUNDRY_TEST_AUTHORIZATION": "disposable-linux-engine-approved"}
        result = subprocess.CompletedProcess([], 0, stdout=json.dumps(config).encode())
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(local_tls_up, "validate"), \
             mock.patch.object(local_tls_up, "check_project", return_value=False), \
             mock.patch.object(local_tls_up, "verify_test_engine", return_value={}), \
             mock.patch.object(local_tls_up, "test_proxy_image"), \
             mock.patch.object(local_tls_up, "test_mount_group", side_effect=["0", "1001"]), \
             mock.patch.dict(os.environ, {"FOUNDRY_TEST_PROXY_IMAGE_ID": "sha256:" + "a" * 64}), \
             mock.patch.object(local_tls_up.subprocess, "run", return_value=result) as run:
            self.assertEqual(70, local_tls_up.main())
            self.assertEqual(2, run.call_count)
            self.assertIn("config", run.call_args.args[0])


class FixturePreparationTests(unittest.TestCase):
    def test_prepare_refuses_missing_cut_before_side_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "inputs"
            with self.assertRaisesRegex(ValueError, "independently pinned"):
                provisioning.prepare_mi(destination, None)
            self.assertFalse(destination.exists())

    def test_protected_inputs_and_no_reuse(self):
        payload = b"synthetic test payload"
        digest = hashlib.sha256(payload).hexdigest()

        trust = json.dumps({"publication": "/run/foundry/mi/publication.json", "reference": {"sha256": digest}}).encode()
        cut = (payload, trust)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(provisioning.fixture, "EXPECTED_SHA256", digest), \
             mock.patch.dict(provisioning.fixture.TRUST_SHA256, {"fresh": hashlib.sha256(trust).hexdigest()}):
            destination = Path(tmp) / "inputs"
            self.assertEqual(digest, provisioning.prepare_mi(destination, cut))
            self.assertEqual(0o750, stat.S_IMODE(destination.stat().st_mode))
            for name in ("trust.json", "publication.json"):
                info = (destination / name).stat()
                self.assertEqual((0o640, os.geteuid(), os.getegid(), 1),
                                 (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid, info.st_nlink))
            self.assertEqual(payload, (destination / "publication.json").read_bytes())
            self.assertEqual(digest, json.loads((destination / "trust.json").read_text())["reference"]["sha256"])
            local_tls_up.validate_mi(str(destination), digest)
            with self.assertRaises(FileExistsError):
                provisioning.prepare_mi(destination, cut)
            self.assertEqual(payload, (destination / "publication.json").read_bytes())

    def test_bad_digest_and_reference_fail_before_creating_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "inputs"
            with mock.patch.object(provisioning.fixture, "EXPECTED_SHA256", hashlib.sha256(b"good").hexdigest()):
                with self.assertRaisesRegex(ValueError, "reference mismatch"):
                    provisioning.prepare_mi(destination, (b"bad", b"{}"))
                with self.assertRaisesRegex(ValueError, "reference mismatch"):
                    provisioning.prepare_mi(destination, (b"good", b"{}"))
            self.assertEqual([], list(Path(tmp).iterdir()))


class ProxyRelayTests(unittest.IsolatedAsyncioTestCase):
    async def test_relay_preserves_bytes_and_half_closes(self):
        source = local_tls_up.TEST_PROXY.removesuffix("asyncio.run(main())\n")
        namespace = {}
        exec(compile(source, "<fixed-test-proxy>", "exec"), namespace)
        reader = mock.Mock()
        reader.read = mock.AsyncMock(side_effect=[b"\x16\x03\x01\x00", b"\xffpayload", b""])
        writer = mock.Mock()
        writer.drain = mock.AsyncMock()
        writer.can_write_eof.return_value = True
        await namespace["relay"](reader, writer)
        self.assertEqual([mock.call(b"\x16\x03\x01\x00"), mock.call(b"\xffpayload")], writer.write.call_args_list)
        self.assertEqual(2, writer.drain.await_count)
        writer.write_eof.assert_called_once_with()


class SocketValidationTests(unittest.TestCase):
    def validate(self, *, directories=None, endpoint=None, accessible=True, xattr_error=errno.ENODATA):
        directories = directories or [SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)] * 2
        endpoint = endpoint or SimpleNamespace(st_uid=0, st_mode=stat.S_IFSOCK | 0o660)
        with mock.patch.object(provisioning.os, "open", side_effect=[10, 11]), \
             mock.patch.object(provisioning.os, "close"), \
             mock.patch.object(provisioning.os, "fstat", side_effect=directories), \
             mock.patch.object(provisioning.os, "stat", return_value=endpoint), \
             mock.patch.object(provisioning.os, "access", return_value=accessible), \
             mock.patch.object(provisioning.os, "getxattr", side_effect=OSError(xattr_error, "xattr")), \
             mock.patch.object(docker_socket_validation, "no_acl") as acl:
            provisioning.validate_engine_socket("/run/docker.sock")
            return acl.call_count

    def test_root_owned_system_parent_is_accepted(self):
        self.assertEqual(2, self.validate())

    def test_writable_or_untrusted_ancestry_rejected(self):
        root = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
        for directory in (SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o777),
                          SimpleNamespace(st_uid=os.geteuid() + 1, st_mode=stat.S_IFDIR | 0o700)):
            with self.subTest(directory=directory), self.assertRaisesRegex(ValueError, "ancestry"):
                self.validate(directories=[root, directory])

    def test_non_socket_inaccessible_and_world_writable_endpoints_rejected(self):
        for mode in (stat.S_IFREG | 0o600, stat.S_IFIFO | 0o600, stat.S_IFLNK | 0o777,
                     stat.S_IFSOCK | 0o666):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.validate(endpoint=SimpleNamespace(st_uid=0, st_mode=mode))
        with self.assertRaisesRegex(ValueError, "not accessible"):
            self.validate(accessible=False)

    def test_invalid_paths_and_unexpected_xattr_fail_closed(self):
        for path in ("run/docker.sock", "/run//docker.sock", "/run/./docker.sock",
                     "/run/../docker.sock", "//run/docker.sock", "/", "/run/docker.sock ",
                     "/run/docker.sock\n", "/run/docker\t.sock"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                provisioning.validate_engine_socket(path)
        with self.assertRaises(OSError):
            self.validate(xattr_error=errno.EACCES)

    def test_symlinked_ancestry_and_socket_acl_are_rejected(self):
        with mock.patch.object(provisioning.os, "open", side_effect=[10, OSError(errno.ELOOP, "symlink")]), \
             mock.patch.object(provisioning.os, "close"), \
             mock.patch.object(provisioning.os, "fstat", return_value=SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)), \
             mock.patch.object(docker_socket_validation, "no_acl"):
            with self.assertRaises(OSError):
                provisioning.validate_engine_socket("/run/docker.sock")
        with mock.patch.object(provisioning.os, "open", side_effect=[10, 11]), \
             mock.patch.object(provisioning.os, "close"), \
             mock.patch.object(provisioning.os, "fstat", return_value=SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)), \
             mock.patch.object(provisioning.os, "stat", return_value=SimpleNamespace(st_uid=0, st_mode=stat.S_IFSOCK | 0o660)), \
             mock.patch.object(provisioning.os, "getxattr", return_value=b"acl"), \
             mock.patch.object(docker_socket_validation, "no_acl"):
            with self.assertRaisesRegex(ValueError, "ACL"):
                provisioning.validate_engine_socket("/run/docker.sock")


class OrchestrationTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(provisioning, "_ENGINE_VERIFICATION_FAILED", False)
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(provisioning, "_EXPECTED_INSPECTION", None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def project(self):
        return provisioning.InstalledProject(socket_path="/private/docker.sock", engine_id="disposable-id-123",
                                             image_id="sha256:" + "a" * 64,
                                             authorization="disposable-linux-engine-approved", mi_cuts={"fresh": (b"x", b"y")})

    def test_changed_role_identity_fences_cleanup(self):
        project = self.project()
        project.root = Path("/test/private")
        project.container_id, project.proxy_id = "router", "proxy"
        with mock.patch.object(project, "_roles", return_value={"router": "router", "proxy": "replacement"}), \
             mock.patch.object(project, "_docker") as docker:
            with self.assertRaisesRegex(ValueError, "identity changed"):
                project.require_roles()
            with self.assertRaisesRegex(ValueError, "engine fenced"):
                project.cleanup()
            docker.assert_not_called()
        self.assertTrue(provisioning._ENGINE_VERIFICATION_FAILED)

    def test_worker_diagnostic_only_exposes_allowlisted_marker(self):
        target = "/tmp/foundry-worker-" + "a" * 32
        nonce = "c" * 32
        args = ["docker", "exec", "-i", "-e", "PYTHONPATH=" + target, "b" * 64,
                "timeout", "--signal=TERM", "--kill-after=5s", "360s", "python", target + "/runner.py"]
        marker = "assertion:202:580:403:permission_error:unauthorized_target"
        stderr = ("private-token\nFOUNDRY_WORKER_FAILURE:" + nonce + ":" + marker + "\nother-private-text\n").encode()
        diagnostic = provisioning.redacted_docker_stderr(args, stderr, 1, nonce)
        self.assertEqual("FOUNDRY_WORKER_FAILURE:" + marker, diagnostic)
        self.assertNotIn("private", str(provisioning.CommandFailure("docker", 1, stderr=diagnostic)))
        self.assertIn(diagnostic, str(provisioning.CommandFailure("docker", 1, stderr=diagnostic)))
        self.assertNotIn("private", provisioning.redacted_docker_stderr(args, b"FOUNDRY_WORKER_FAILURE:private-token:123\n", 1, nonce))
        self.assertNotIn(marker, provisioning.redacted_docker_stderr(["docker", "logs", "id"], stderr, 1, nonce))
        self.assertNotIn(marker, provisioning.redacted_docker_stderr(args, stderr, 124, nonce))
        self.assertNotIn(marker, provisioning.redacted_docker_stderr(args, stderr, 1, "d" * 32))
        self.assertNotIn(marker, provisioning.redacted_docker_stderr(args[:6] + ["sh", "-c"] + args[8:], stderr, 1, nonce))
        self.assertEqual(diagnostic, provisioning.redacted_docker_stderr(args, b"x" * 5000 + b"\n" + stderr, 1, nonce))

    def test_adopt_rejects_running_or_unknown_state_and_fences(self):
        image = "sha256:" + "a" * 64
        for state in ({"Running": True}, {}):
            with self.subTest(state=state), mock.patch.object(provisioning, "_ENGINE_VERIFICATION_FAILED", False):
                project = self.project()
                project.root = Path("/test/private")
                project.container_id, project.proxy_id, project.env = "router", "proxy", {}
                def docker(*args):
                    if args[:2] == ("image", "inspect"):
                        return json.dumps([{"Id": image, "Os": "linux"}])
                    return json.dumps([{"State": state}])
                with mock.patch.object(project, "require_roles", return_value={"router": "router", "proxy": "proxy"}), \
                     mock.patch.object(project, "_docker", side_effect=docker):
                    with self.assertRaisesRegex(ValueError, "running or state is unknown"):
                        project.launch(image, mi_enabled=False, adopt=True)
                self.assertTrue(provisioning._ENGINE_VERIFICATION_FAILED)

    def test_authorization_and_socket_are_required(self):
        with self.assertRaises(ValueError):
            provisioning.InstalledProject(socket_path="/private/docker.sock", engine_id="disposable-id-123",
                                          image_id="sha256:" + "a" * 64, authorization="")
        with self.assertRaises(ValueError):
            provisioning.InstalledProject(socket_path="relative/docker.sock", engine_id="disposable-id-123",
                                          image_id="sha256:" + "a" * 64,
                                          authorization="disposable-linux-engine-approved")
        provisioning.InstalledProject(socket_path="/run/docker.sock", engine_id="disposable-id-123",
                                      image_id="sha256:" + "a" * 64,
                                      authorization="disposable-linux-engine-approved")
        with self.assertRaises(ValueError):
            provisioning.InstalledProject(socket_path="/run//docker.sock", engine_id="disposable-id-123",
                                          image_id="sha256:" + "a" * 64,
                                          authorization="disposable-linux-engine-approved")
        with self.assertRaises(ValueError):
            provisioning.InstalledProject(socket_path="/private/docker.sock", engine_id="disposable-id-123",
                                          image_id="mutable:latest",
                                          authorization="disposable-linux-engine-approved")

    def test_engine_verification_does_not_contact_docker_on_invalid_socket(self):
        project = self.project()
        project.root = Path("/test/private")
        project.env = {"DOCKER_HOST": "unix:///private/docker.sock", "DOCKER_CONFIG": "/test/private/docker-config"}
        with mock.patch.object(provisioning, "validate_engine_socket", side_effect=ValueError("unsafe")), \
             mock.patch.object(project, "_run") as docker:
            with self.assertRaisesRegex(ValueError, "unsafe"):
                project._verify_engine()
        docker.assert_not_called()

    def test_partial_start_cleanup_cannot_inherit_docker_context(self):
        project = self.project()
        with tempfile.TemporaryDirectory() as tmp:
            project.root = Path(tmp) / "owned"
            project.root.mkdir()
            with mock.patch.object(provisioning, "validate_engine_socket"), \
                 mock.patch.object(project, "_run") as run:
                project.cleanup()
                run.assert_not_called()
            self.assertFalse((Path(tmp) / "owned").exists())
            self.assertIsNone(project.root)

    def test_engine_identity_mismatch_is_rejected(self):
        project = self.project()
        project.root = Path("/test/private")
        project.env = {"DOCKER_HOST": "unix:///private/docker.sock", "DOCKER_CONFIG": "/test/private/docker-config"}
        data = {"ID": "other-engine-123", "OSType": "linux", "CgroupDriver": "cgroupfs",
                "MemoryLimit": True, "SwapLimit": True, "PidsLimit": True, "CpuCfsQuota": True}
        with mock.patch.object(provisioning, "validate_engine_socket"), \
             mock.patch.object(project, "_run", return_value=json.dumps(data)):
            with self.assertRaisesRegex(ValueError, "identity"):
                project._verify_engine()

    def test_failed_verification_prevents_subsequent_docker_operations(self):
        project = self.project()
        project.root = Path("/test/private")
        project.env = {"DOCKER_HOST": "unix:///private/docker.sock", "DOCKER_CONFIG": "/test/private/docker-config"}
        data = {"ID": "other-engine-123", "OSType": "linux", "CgroupDriver": "cgroupfs",
                "MemoryLimit": True, "SwapLimit": True, "PidsLimit": True, "CpuCfsQuota": True}
        with mock.patch.object(provisioning, "validate_engine_socket"), \
             mock.patch.object(project, "_run", return_value=json.dumps(data)) as run:
            with self.assertRaisesRegex(ValueError, "identity"):
                project._docker("image", "ls")
            self.assertEqual(1, run.call_count)
            self.assertEqual(["docker", "info", "--format", "{{json .}}"], run.call_args.args[0])
            with self.assertRaisesRegex(ValueError, "no retry"):
                project.cleanup()
            self.assertEqual(1, run.call_count)

            other = self.project()
            other.root = Path("/test/other")
            other.env = {"DOCKER_HOST": "unix:///private/docker.sock", "DOCKER_CONFIG": "/test/other/docker-config"}
            with mock.patch.object(other, "_run") as other_run:
                with self.assertRaisesRegex(ValueError, "no retry"):
                    other.cleanup()
                other_run.assert_not_called()

    def test_test_startup_engine_checks_reject_changed_id(self):
        env = {"FOUNDRY_TEST_RUN_ID": "a" * 32, "FOUNDRY_TEST_ENGINE_ID": "disposable-id-123",
               "FOUNDRY_TEST_DOCKER_HOST": "unix:///run/docker.sock", "DOCKER_HOST": "unix:///run/docker.sock"}
        wrong = {"ID": "other-engine-123", "OSType": "linux", "CgroupDriver": "cgroupfs",
                 "MemoryLimit": True, "SwapLimit": True, "PidsLimit": True, "CpuCfsQuota": True}
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(local_tls_up, "validate_engine_socket"), \
             mock.patch.object(local_tls_up.subprocess, "run", return_value=mock.Mock(stdout=json.dumps(wrong).encode())) as run:
            with self.assertRaises(local_tls_up.TestEngineRefusal):
                local_tls_up.verify_test_engine()
            self.assertEqual(["docker", "info", "--format", "{{json .}}"], run.call_args.args[0])

    def test_test_startup_does_not_contact_docker_for_unsafe_socket(self):
        env = {"FOUNDRY_TEST_RUN_ID": "a" * 32, "FOUNDRY_TEST_ENGINE_ID": "disposable-id-123",
               "FOUNDRY_TEST_DOCKER_HOST": "unix:///run/docker.sock", "DOCKER_HOST": "unix:///run/docker.sock"}
        with mock.patch.dict(os.environ, env, clear=True), \
             mock.patch.object(local_tls_up, "validate_engine_socket", side_effect=ValueError("unsafe")), \
             mock.patch.object(local_tls_up.subprocess, "run") as run:
            with self.assertRaises(local_tls_up.TestEngineRefusal):
                local_tls_up.verify_test_engine()
            run.assert_not_called()

    def test_test_startup_engine_failure_blocks_all_project_cleanup(self):
        project = self.project()
        project.root = Path("/test/private")
        project.env = {"DOCKER_HOST": "unix:///private/docker.sock", "DOCKER_CONFIG": "/test/private/docker-config"}
        image = json.dumps([{"Id": project.image_id, "Os": "linux"}])
        with mock.patch.object(project, "_docker", return_value=image), \
             mock.patch.object(project, "_verify_engine"), \
             mock.patch.object(project, "_run", side_effect=provisioning.CommandFailure("local_tls_up", 70)):
            with self.assertRaises(provisioning.CommandFailure):
                project.launch(project.image_id, mi_enabled=False, adopt=False)
        self.assertTrue(project._engine_blocked)
        self.assertTrue(provisioning._ENGINE_VERIFICATION_FAILED)

    def test_global_deadline_during_startup_blocks_engine_retry(self):
        project = self.project()
        project.root = Path("/test/private")
        project.env = {"DOCKER_HOST": "unix:///private/docker.sock", "DOCKER_CONFIG": "/test/private/docker-config"}
        image = json.dumps([{"Id": project.image_id, "Os": "linux"}])
        with mock.patch.object(project, "_docker", return_value=image), \
             mock.patch.object(project, "_verify_engine"), \
             mock.patch.object(project, "_run", side_effect=TimeoutError("deadline")):
            with self.assertRaises(TimeoutError):
                project.launch(project.image_id, mi_enabled=False, adopt=False)
        self.assertTrue(project._engine_blocked)
        self.assertTrue(provisioning._ENGINE_VERIFICATION_FAILED)

    def test_nonzero_compose_start_fences_followup_engine_commands(self):
        project = self.project()
        project.root = Path("/test/private")
        project.env = {"DOCKER_HOST": "unix:///private/docker.sock", "DOCKER_CONFIG": "/test/private/docker-config"}
        image = json.dumps([{"Id": project.image_id, "Os": "linux"}])
        with mock.patch.object(project, "_docker", return_value=image), \
             mock.patch.object(project, "_verify_engine"), \
             mock.patch.object(project, "_run", side_effect=provisioning.CommandFailure("local_tls_up", 1)):
            with self.assertRaises(provisioning.CommandFailure):
                project.launch(project.image_id, mi_enabled=False, adopt=False)
        self.assertTrue(project._engine_blocked)
        self.assertTrue(provisioning._ENGINE_VERIFICATION_FAILED)

    def test_expected_mi_failure_allows_only_scoped_read_only_classification(self):
        project = self.project()
        project.root = Path("/test/private")
        project.env = {}
        project.container_id = "prior"
        project.proxy_id = "proxy"
        image = json.dumps([{"Id": project.image_id, "Os": "linux"}])
        def docker(*args, **kwargs):
            return image if args[0] == "image" else json.dumps([{"State": {"Running": False}}])
        with mock.patch.object(project, "_docker", side_effect=docker), \
             mock.patch.object(project, "_owned", side_effect=lambda kind: ["prior"] if kind == "container" else []), \
             mock.patch.object(project, "_roles", return_value={"router": "prior", "proxy": "proxy"}), \
             mock.patch.object(project, "_verify_engine"), \
             mock.patch.object(project, "_run", side_effect=provisioning.CommandFailure("startup", 1)):
            with self.assertRaises(provisioning.CommandFailure):
                project.launch(project.image_id, mi_enabled=True, adopt=True, expect_mi_failure=True)
        self.assertIs(provisioning._EXPECTED_INSPECTION, project)
        self.assertFalse(provisioning._ENGINE_VERIFICATION_FAILED)
        with mock.patch.object(provisioning.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(ValueError, "read-only"):
                project._run(["docker", "container", "rm", "prior"])
            popen.assert_not_called()
        self.assertTrue(provisioning._ENGINE_VERIFICATION_FAILED)
        project.finish_expected_inspection(verified=False)
        self.assertIsNone(provisioning._EXPECTED_INSPECTION)

    def test_expected_inspection_mismatch_fences_all_followup_calls(self):
        project = self.project()
        project._inspection_only = True
        provisioning._EXPECTED_INSPECTION = project
        project.finish_expected_inspection(verified=False)
        self.assertTrue(provisioning._ENGINE_VERIFICATION_FAILED)
        with mock.patch.object(provisioning.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(ValueError, "no retry"):
                project._run(["docker", "info"])
            popen.assert_not_called()

    def test_verified_expected_inspection_releases_the_gate(self):
        project = self.project()
        project._inspection_only = True
        provisioning._EXPECTED_INSPECTION = project
        project.finish_expected_inspection(verified=True)
        self.assertIsNone(provisioning._EXPECTED_INSPECTION)
        self.assertFalse(project._inspection_only)
        self.assertFalse(provisioning._ENGINE_VERIFICATION_FAILED)

    def test_expected_mi_startup_timeout_does_not_open_inspection(self):
        for failure in (provisioning.CommandFailure("startup", 124), subprocess.TimeoutExpired("startup", 1)):
            with self.subTest(failure=failure), mock.patch.object(provisioning, "_ENGINE_VERIFICATION_FAILED", False):
                project = self.project()
                project.root = Path("/test/private")
                project.env = {}
                project.container_id = "prior"
                project.proxy_id = "proxy"
                image = json.dumps([{"Id": project.image_id, "Os": "linux"}])
                def docker(*args, **kwargs):
                    return image if args[0] == "image" else json.dumps([{"State": {"Running": False}}])
                with mock.patch.object(project, "_docker", side_effect=docker), \
                     mock.patch.object(project, "_owned", side_effect=lambda kind: ["prior"] if kind == "container" else []), \
                     mock.patch.object(project, "_roles", return_value={"router": "prior", "proxy": "proxy"}), \
                     mock.patch.object(project, "_verify_engine"), \
                     mock.patch.object(project, "_run", side_effect=failure):
                    with self.assertRaises(type(failure)):
                        project.launch(project.image_id, mi_enabled=True, adopt=True, expect_mi_failure=True)
                self.assertTrue(provisioning._ENGINE_VERIFICATION_FAILED)
                self.assertIsNone(provisioning._EXPECTED_INSPECTION)

    def test_any_docker_timeout_fences_other_projects_and_cleanup(self):
        project = self.project()
        process = mock.Mock(pid=123, stdin=None, stdout=mock.Mock(), stderr=mock.Mock())
        selector = mock.MagicMock()
        selector.get_map.return_value = {1: True}
        with mock.patch.object(provisioning.subprocess, "Popen", return_value=process), \
             mock.patch.object(provisioning.selectors, "DefaultSelector") as factory, \
             mock.patch.object(provisioning.time, "monotonic", side_effect=[0, 2]), \
             mock.patch.object(provisioning.os, "killpg"):
            factory.return_value.__enter__.return_value = selector
            with self.assertRaises(subprocess.TimeoutExpired):
                project._run(["docker", "image", "inspect", "test"], timeout=1)
        self.assertTrue(provisioning._ENGINE_VERIFICATION_FAILED)
        other = self.project()
        with mock.patch.object(provisioning.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(ValueError, "no retry"):
                other._run(["docker", "info"])
            popen.assert_not_called()

    def test_failed_mutation_fences_but_missing_image_does_not(self):
        for args, blocked in ((["docker", "volume", "create", "test"], True),
                              (["docker", "image", "inspect", "test"], False)):
            with self.subTest(args=args), mock.patch.object(provisioning, "_ENGINE_VERIFICATION_FAILED", False):
                project = self.project()
                process = mock.Mock(pid=123, stdin=None, stdout=mock.Mock(), stderr=mock.Mock(), returncode=1)
                selector = mock.MagicMock()
                selector.get_map.return_value = {}
                with mock.patch.object(provisioning.subprocess, "Popen", return_value=process), \
                     mock.patch.object(provisioning.selectors, "DefaultSelector") as factory:
                    factory.return_value.__enter__.return_value = selector
                    with self.assertRaises(provisioning.CommandFailure):
                        project._run(args)
                self.assertEqual(blocked, provisioning._ENGINE_VERIFICATION_FAILED)

    def test_docker_environment_must_match_selected_socket(self):
        for env in ({}, {"DOCKER_HOST": "unix:///another.sock", "DOCKER_CONFIG": "/test/private/docker-config"},
                    {"DOCKER_HOST": "unix:///private/docker.sock", "DOCKER_CONFIG": "/test/private/docker-config",
                     "DOCKER_CONTEXT": "another"}):
            project = self.project()
            project.root = Path("/test/private")
            with mock.patch.object(provisioning, "_ENGINE_VERIFICATION_FAILED", False), \
                 mock.patch.object(project, "_run") as run:
                project.env = env
                with self.subTest(env=env), self.assertRaisesRegex(ValueError, "environment"):
                    project._docker("info")
                run.assert_not_called()

    def test_test_override_is_narrow_and_bounded(self):
        token = "a" * 32
        override = local_tls_up.test_override("foundry-test-" + token, token, ["--existing"], proxy_image="sha256:" + "a" * 64)
        router = override["services"]["router"]
        self.assertEqual((1.0, "512m", 128), (router["cpus"], router["mem_limit"], router["pids_limit"]))
        self.assertIn("--worker-listen-host=127.0.0.1", router["command"])
        self.assertIn("--worker-tls-certfile=/run/foundry/tls/server.crt", router["command"])
        self.assertIn("--worker-tls-reload-hostname=127.0.0.1", router["command"])
        self.assertIs(override["networks"]["backend"]["internal"], True)
        self.assertIn("--worker-tls-reload-ca-cert=/run/foundry/tls/server.crt", router["command"])
        self.assertNotIn("ports", router)
        proxy = override["services"]["proxy"]
        self.assertEqual(["127.0.0.1:0:8787"], proxy["ports"])
        self.assertEqual(["backend", "ingress"], proxy["networks"])
        self.assertEqual("65534:65534", proxy["user"])
        self.assertTrue(proxy["read_only"])
        self.assertEqual(["ALL"], proxy["cap_drop"])
        self.assertNotIn("volumes", proxy)
        self.assertEqual("no", proxy["restart"])
        self.assertEqual(token, override["networks"]["ingress"]["labels"][provisioning.LABEL])
        self.assertEqual(token, override["volumes"]["router-data"]["labels"][provisioning.LABEL])
        with self.assertRaises(ValueError):
            local_tls_up.test_override("some-other-project", token, [])

    def test_proxy_image_requires_exact_digest_and_image_identity(self):
        digest = "sha256:" + "a" * 64
        image = "sha256:" + "b" * 64
        item = {"Id": image, "Os": "linux", "RepoDigests": ["python@" + digest]}
        with mock.patch.object(local_tls_up, "verify_test_engine"), \
             mock.patch.object(local_tls_up.subprocess, "run") as run:
            run.return_value.stdout = json.dumps([item]).encode()
            local_tls_up.test_proxy_image(digest, image)
            for changed in ({**item, "Id": "sha256:" + "c" * 64}, {**item, "Os": "windows"},
                            {**item, "RepoDigests": ["other@" + digest]}, {**item, "RepoDigests": None}):
                run.return_value.stdout = json.dumps([changed]).encode()
                with self.subTest(changed=changed), self.assertRaises(ValueError):
                    local_tls_up.test_proxy_image(digest, image)
            with self.assertRaises(ValueError):
                local_tls_up.test_proxy_image("latest", image)

    def test_roles_reject_missing_duplicate_and_foreign_roles(self):
        for roles in (("router", "proxy"), ("router",), ("router", "router"), ("router", "foreign")):
            with self.subTest(roles=roles), mock.patch.object(provisioning, "_ENGINE_VERIFICATION_FAILED", False):
                project = self.project()
                identifiers = [str(index) for index in range(len(roles))]
                def docker(*args, **kwargs):
                    role = roles[int(args[-1])]
                    return json.dumps([{"Id": args[-1] + "full", "Config": {"Labels": {
                        "com.docker.compose.service": role, "com.docker.compose.project": project.project,
                        provisioning.LABEL: project.token}}}])
                with mock.patch.object(project, "_owned", return_value=identifiers), \
                     mock.patch.object(project, "_docker", side_effect=docker):
                    if roles == ("router", "proxy"):
                        self.assertEqual({"router": "0", "proxy": "1"}, project._roles())
                    else:
                        with self.assertRaises(ValueError):
                            project._roles()
                        self.assertTrue(project._engine_blocked)

    def test_start_requires_base_before_creating_temporary_files(self):
        project = self.project()
        with mock.patch.object(provisioning.tempfile, "mkdtemp") as mkdir:
            with self.assertRaisesRegex(ValueError, "proxy base digest"):
                project.start()
            mkdir.assert_not_called()

    def test_stop_checks_both_roles_and_stops_proxy_first(self):
        project = self.project()
        project.container_id, project.proxy_id, project.port = "router", "proxy", 32123
        roles = {"router": "router", "proxy": "proxy"}
        with mock.patch.object(project, "_roles", return_value=roles), \
             mock.patch.object(project, "_docker", return_value=json.dumps([{"State": {"Running": False}}])) as docker:
            project.stop()
        stops = [call.args[-1] for call in docker.call_args_list if call.args[:2] == ("container", "stop")]
        self.assertEqual(["proxy", "router"], stops)
        self.assertIsNone(project.port)
        with mock.patch.object(project, "_roles", return_value={"router": "router", "proxy": "foreign"}), \
             mock.patch.object(project, "_docker") as docker:
            with self.assertRaises(ValueError):
                project.stop()
            docker.assert_not_called()
            self.assertTrue(project._engine_blocked)

    def test_test_image_derivation_does_not_edit_canonical_file(self):
        original = (provisioning.ROOT / "Dockerfile.mi").read_text()
        derived = provisioning.test_image_dockerfile("sha256:" + "a" * 64)
        self.assertEqual(2, derived.count(provisioning.SR_TEST_REVISION))
        self.assertNotIn(provisioning.SR_OLD_REVISION, derived)
        self.assertEqual(2, derived.count("python:3.12-slim@sha256:" + "a" * 64))
        self.assertEqual(original, (provisioning.ROOT / "Dockerfile.mi").read_text())
        with self.assertRaises(ValueError):
            provisioning.test_image_dockerfile("python:latest")

    def test_legacy_derivation_accepts_only_reviewed_variants(self):
        source = (provisioning.ROOT / "Dockerfile.mi").read_bytes()
        provenance = provisioning.provenance
        actual = provenance.product_revision(source)
        base = "sha256:" + "a" * 64
        expected = provenance.pinned_dockerfile(source, provenance.NEW_SR, base)
        for revision in provenance.DOCKERFILE_SHA256:
            variant = source.replace(actual.encode(), revision.encode())
            with self.subTest(revision=revision), mock.patch.object(Path, "read_bytes", return_value=variant):
                self.assertEqual(expected, provisioning.test_image_dockerfile(base))
        with mock.patch.object(Path, "read_bytes", return_value=source + b"# injected\n"):
            with self.assertRaises(ValueError):
                provisioning.test_image_dockerfile(base)

    def test_startup_rejects_mismatched_adoption_labels(self):
        result = mock.Mock(stdout=b"foreign\n")
        empty = mock.Mock(stdout=b"")
        with mock.patch.object(local_tls_up.subprocess, "run", side_effect=[result, empty]):
            with self.assertRaisesRegex(ValueError, "ownership labels"):
                local_tls_up.check_test_ownership("foundry-test-" + "a" * 32, "a" * 32)

    def test_cleanup_validates_all_labels_before_deletion(self):
        project = self.project()
        project.root = Path("/private/fake")
        project.env = {}
        calls = []

        def docker(*args, **kwargs):
            calls.append(args)
            if "ls" in args:
                return "object1\n"
            if "inspect" in args:
                labels = {"com.docker.compose.project": project.project, provisioning.LABEL: project.token}
                if args[0] == "volume":
                    labels[provisioning.LABEL] = "wrong"
                return json.dumps([{"Config": {"Labels": labels}, "Labels": labels}])
            raise AssertionError("cleanup attempted deletion before validation")

        with mock.patch.object(project, "_verify_engine"), mock.patch.object(project, "_docker", side_effect=docker):
            with self.assertRaisesRegex(ValueError, "unowned"):
                project.cleanup()
        self.assertFalse(any("rm" in args for args in calls))

    def test_cleanup_rejects_disagreeing_label_sets(self):
        project = self.project()
        with mock.patch.object(project, "_docker", side_effect=["object1\n", ""]):
            with self.assertRaisesRegex(ValueError, "labels"):
                project._owned("container")

    def test_owned_container_listing_uses_full_ids(self):
        project = self.project()
        identifier = "a" * 64
        labels = {"com.docker.compose.project": project.project, provisioning.LABEL: project.token}
        with mock.patch.object(project, "_docker", side_effect=[identifier + "\n", identifier + "\n",
                                                                 json.dumps([{"Config": {"Labels": labels}}])]) as docker:
            self.assertEqual([identifier], project._owned("container"))
        for call in docker.call_args_list[:2]:
            self.assertIn("--no-trunc", call.args)

    def test_worker_bundle_checks_provenance_and_invokes_bounded_exec(self):
        project = self.project()
        data = b"print('fixture')\n"
        with tempfile.TemporaryDirectory() as tmp:
            project.root = Path(tmp)
            project.port = 32123
            project.container_id = "container-id"
            project.proxy_id = "proxy-id"
            with mock.patch.object(project, "_roles", return_value={"router": "container-id", "proxy": "proxy-id"}), \
                 mock.patch.object(project, "_docker", return_value="ok") as docker:
                with self.assertRaises(ValueError):
                    project.run_worker_bundle({"runner.py": data}, {"runner.py": "0" * 64}, stdin=b"{}")
                self.assertEqual(0, docker.call_count)
                self.assertEqual("ok", project.run_worker_bundle({"runner.py": data},
                                 {"runner.py": hashlib.sha256(data).hexdigest()}, stdin=b"{}"))
                args = docker.call_args.args
                self.assertIn("timeout", args)
                self.assertIn("360s", args)
                self.assertEqual(375, docker.call_args.kwargs["timeout"])
                submitted = json.loads(docker.call_args.kwargs["input_data"])
                self.assertEqual({"_foundry_diagnostic_nonce"}, set(submitted))
                self.assertRegex(submitted["_foundry_diagnostic_nonce"], r"^[0-9a-f]{32}$")
                self.assertEqual(submitted["_foundry_diagnostic_nonce"], docker.call_args.kwargs["diagnostic_nonce"])
                with self.assertRaises(ValueError):
                    project.run_worker_bundle({"../runner.py": data},
                                              {"../runner.py": hashlib.sha256(data).hexdigest()}, stdin=b"{}")

    def test_start_checks_running_container_limits_and_loopback(self):
        project = self.project()
        project.base_digest = "sha256:" + "b" * 64
        proxy_image = "sha256:" + "c" * 64
        network = {"Id": "network123", "Name": project.project + "_backend", "Internal": True,
                   "Containers": {"router-full": {}, "proxy-full": {}}}
        ingress = {"Id": "ingress123", "Name": project.project + "_ingress", "Internal": False,
                   "Containers": {"proxy-full": {}}}
        inspect = [{"Id": "router-full", "Image": project.image_id,
                    "HostConfig": {"NanoCpus": 1_000_000_000, "Memory": 536870912,
                                   "MemorySwap": 536870912, "PidsLimit": 128, "Privileged": False},
                    "State": {"Running": True, "StartedAt": "2026-01-01T00:00:00Z", "Health": {"Status": "healthy"}},
                    "Mounts": [{"Destination": "/data", "Type": "volume", "Name": project.project + "_router-data"}],
                    "NetworkSettings": {"Networks": {"backend": {"NetworkID": "network123"}}, "Ports": {"8787/tcp": None}}}]
        proxy = {"Id": "proxy-full", "Image": proxy_image,
                 "Config": {"User": "65534:65534", "Entrypoint": ["python", "-I", "-u", "-c", local_tls_up.TEST_PROXY], "Cmd": []},
                 "HostConfig": {"NanoCpus": 250000000, "Memory": 134217728, "MemorySwap": 134217728,
                                "PidsLimit": 64, "Privileged": False, "ReadonlyRootfs": True, "CapDrop": ["ALL"],
                                "CgroupnsMode": "private",
                                "PortBindings": {"8787/tcp": [{"HostIp": "127.0.0.1", "HostPort": "0"}]},
                                "SecurityOpt": ["no-new-privileges:true"], "RestartPolicy": {"Name": "no"}},
                 "State": {"Running": True, "StartedAt": "2026-01-01T00:00:00Z"}, "Mounts": [],
                 "NetworkSettings": {"Networks": {"backend": {"NetworkID": "network123"}, "ingress": {"NetworkID": "ingress123"}},
                                     "Ports": {"8787/tcp": [{"HostIp": "127.0.0.1", "HostPort": "32123"}]}}}
        def docker(*args, **kwargs):
            if args[0] == "exec":
                return ("0::/\n0::/\n134217728\n0\n64\n25000 100000\n" if args[1] == "proxy" else
                        "0::/\n0::/\n536870912\n0\n128\n100000 100000\n")
            if args[:2] == ("image", "inspect"):
                return json.dumps([{"Id": proxy_image, "Os": "linux", "RepoDigests": ["python@" + project.base_digest]}] if args[2].startswith("python:") else [{"Id": project.image_id, "Os": "linux"}])
            if args[:2] == ("network", "inspect"):
                return json.dumps([network if args[2] == "network123" else ingress])
            return json.dumps([proxy] if args[-1] == "proxy" else inspect)
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(provisioning.tempfile, "mkdtemp", return_value=tmp), \
             mock.patch.object(project, "_verify_engine"), mock.patch.object(project, "_run"), \
             mock.patch.object(provisioning, "prepare_mi"), mock.patch.object(project, "_roles", return_value={"router": "container", "proxy": "proxy"}), \
             mock.patch.object(project, "_owned", side_effect=lambda kind: ["network123", "ingress123"] if kind == "network" else [project.project + "_router-data"]), \
             mock.patch.object(project, "_docker", side_effect=docker):
            inspect[0]["Mounts"] += [
                {"Destination": "/run/foundry/tls", "Type": "bind", "Source": tmp + "/tls", "RW": False},
                *({"Destination": "/run/foundry/mi/" + name, "Type": "bind", "Source": tmp + "/mi/" + name, "RW": False}
                  for name in ("trust.json", "publication.json")),
            ]
            self.assertIs(project, project.start())
            self.assertEqual("https://127.0.0.1:32123", project.origin)
            self.assertEqual("0", project.env["FOUNDRY_ROUTER_PORT"])
            self.assertNotIn("LOCAL_TLS_ADOPT_PROJECT", project.env)
            adverse = [
                (proxy["HostConfig"], "ReadonlyRootfs", False),
                (proxy["HostConfig"], "CgroupnsMode", "host"),
                (proxy["HostConfig"], "PortBindings", {"8787/tcp": [{"HostIp": "0.0.0.0", "HostPort": "0"}]}),
                (proxy["HostConfig"], "CapDrop", []),
                (proxy["HostConfig"], "CapAdd", ["NET_ADMIN"]),
                (proxy["HostConfig"], "Memory", 0),
                (proxy["HostConfig"], "RestartPolicy", {"Name": "always"}),
                (proxy["Config"], "User", "0"),
                (proxy["Config"], "Entrypoint", ["sh"]),
                (proxy["State"], "StartedAt", ""),
                (proxy, "Image", project.image_id),
                (proxy, "Mounts", [{"Type": "bind", "Source": "/"}]),
                (proxy["NetworkSettings"]["Ports"]["8787/tcp"][0], "HostIp", "0.0.0.0"),
                (proxy["NetworkSettings"]["Ports"]["8787/tcp"][0], "HostPort", "0"),
                (inspect[0]["HostConfig"], "PortBindings", {"8787/tcp": [{"HostIp": "127.0.0.1"}]}),
                (network, "Containers", {"router-full": {}, "proxy-full": {}, "foreign": {}}),
                (ingress, "Internal", True),
                (ingress, "Containers", {"proxy-full": {}, "foreign": {}}),
            ]
            for target, key, value in adverse:
                missing = object()
                original = target.get(key, missing)
                target[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    project._validate_started(True)
                if original is missing:
                    del target[key]
                else:
                    target[key] = original
            inspect[0]["Mounts"][1]["RW"] = True
            with self.assertRaisesRegex(ValueError, "writable host mounts"):
                project.launch(project.image_id, mi_enabled=True, adopt=False)
            self.assertTrue(project._engine_blocked)
            self.assertTrue(provisioning._ENGINE_VERIFICATION_FAILED)
            with self.assertRaisesRegex(ValueError, "no retry"):
                project.cleanup()
            inspect[0]["Mounts"][1]["RW"] = False
            network["Internal"] = False
            with self.assertRaisesRegex(ValueError, "network isolation"):
                project.launch(project.image_id, mi_enabled=True, adopt=False)

        project = self.project()
        project.base_digest = "sha256:" + "b" * 64
        inspect[0]["HostConfig"]["PidsLimit"] = 0
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(provisioning.tempfile, "mkdtemp", return_value=tmp), \
             mock.patch.object(project, "_verify_engine"), mock.patch.object(project, "_run"), \
             mock.patch.object(provisioning, "prepare_mi"), mock.patch.object(project, "_roles", return_value={"router": "container", "proxy": "proxy"}), \
             mock.patch.object(project, "_docker", side_effect=docker):
            with self.assertRaisesRegex(ValueError, "limits"):
                project.start()
            self.assertIsNone(project.port)

    def test_workload_cgroup_check_fails_closed(self):
        for output in ("0::/host/container\n0::/\n536870912\n0\n128\n100000 100000\n",
                       "0::/\n0::/different\n536870912\n0\n128\n100000 100000\n",
                       "0::/\n0::/\nmax\n0\n128\n100000 100000\n",
                       "0::/\n0::/\n536870912\nmax\n128\n100000 100000\n",
                       "0::/\n0::/\n536870912\n0\nmax\n100000 100000\n",
                       "0::/\n0::/\n536870912\n0\n128\nmax 100000\n", ""):
            with self.subTest(output=output):
                project = self.project()
                project.root = Path("/test/private")
                project.env = {}
                item = {"Image": project.image_id,
                        "HostConfig": {"NanoCpus": 1000000000, "Memory": 536870912,
                                       "MemorySwap": 536870912, "PidsLimit": 128, "Privileged": False},
                        "State": {"Running": True, "StartedAt": "first", "Health": {"Status": "healthy"}}}
                def docker(*args, **kwargs):
                    if args[:2] == ("image", "inspect"):
                        return json.dumps([{"Id": project.image_id, "Os": "linux"}])
                    if args[0] == "exec":
                        self.assertEqual(("exec", "container", "/bin/cat", *provisioning._CGROUP_FILES), args)
                        return output
                    return json.dumps([item])
                with mock.patch.object(project, "_verify_engine"), mock.patch.object(project, "_run"), \
                     mock.patch.object(project, "_roles", return_value={"router": "container", "proxy": "proxy"}), \
                     mock.patch.object(project, "_docker", side_effect=docker):
                    with self.assertRaisesRegex(ValueError, "effective workload cgroup"):
                        project.launch(project.image_id, mi_enabled=False, adopt=False)
                    self.assertIsNone(project.port)
                    self.assertTrue(project._engine_blocked)
                    with self.assertRaisesRegex(ValueError, "no retry"):
                        project.cleanup()

    def test_workload_restart_during_cgroup_check_is_rejected(self):
        project = self.project()
        project.root = Path("/test/private")
        project.env = {}
        item = {"Image": project.image_id,
                "HostConfig": {"NanoCpus": 1000000000, "Memory": 536870912,
                               "MemorySwap": 536870912, "PidsLimit": 128, "Privileged": False},
                "State": {"Running": True, "StartedAt": "first", "Health": {"Status": "healthy"}}}
        after = {**item, "State": {**item["State"], "StartedAt": "second"}}
        responses = [json.dumps([{"Id": project.image_id, "Os": "linux"}]), json.dumps([item]),
                     "0::/\n0::/\n536870912\n0\n128\n100000 100000\n", json.dumps([after])]
        with mock.patch.object(project, "_verify_engine"), mock.patch.object(project, "_run"), \
             mock.patch.object(project, "_roles", return_value={"router": "container", "proxy": "proxy"}), \
             mock.patch.object(project, "_docker", side_effect=responses):
            with self.assertRaisesRegex(ValueError, "restarted"):
                project.launch(project.image_id, mi_enabled=False, adopt=False)
            self.assertIsNone(project.port)



if __name__ == "__main__":
    unittest.main()
