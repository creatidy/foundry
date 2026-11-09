"""Offline checks for bootstrap and lifecycle primitives; no Docker or network."""

import io
import json
import hashlib
import os
from pathlib import Path
import tarfile
import tempfile
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

import installed_admin
import installed_lifecycle_adapter as lifecycle
import run_installed_acceptance as entry
from test_installed_acceptance_wiring import mocked_full_run


class AdminTests(unittest.TestCase):
    def test_installed_auth_boundaries_require_csrf_and_inference_key(self):
        session = installed_admin.AdminSession(mock.Mock())
        session.cookie, session.csrf = "scarcity-router-admin=test", "valid-csrf"
        with mock.patch.object(session, "_request", side_effect=[(403, b"{}", []),
                                                                  (403, b"{}", []),
                                                                  (401, b"{}", [])]) as request:
            session.assert_auth_boundaries()
        self.assertNotIn("X-Scarcity-CSRF", request.call_args_list[0].args[3])
        self.assertEqual("invalid-test-csrf", request.call_args_list[1].args[3]["X-Scarcity-CSRF"])
        self.assertNotIn("Authorization", request.call_args_list[2].args[3])

    def test_installed_auth_boundaries_reject_unexpected_statuses(self):
        for responses in ([200], [403, 200], [403, 403, 200]):
            session = installed_admin.AdminSession(mock.Mock())
            session.cookie, session.csrf = "cookie", "csrf"
            with self.subTest(responses=responses), \
                 mock.patch.object(session, "_request", side_effect=[(status, b"{}", []) for status in responses]), \
                 self.assertRaises(AssertionError):
                session.assert_auth_boundaries()

    def test_bootstrap_and_admin_header_separation(self):
        project = mock.Mock(port=1234, container_id="owned")
        project._owned.return_value = ["owned"]
        project._docker.return_value = "a" * 43
        session = installed_admin.AdminSession(project)
        responses = [(200, b"{}", [("Set-Cookie", "scarcity-router-admin=session123; HttpOnly")]),
                     (200, b'<input name="csrf" value="test-csrf">', []),
                     (200, b'{"ok":true}', []), (401, b'{}', [])]
        with mock.patch.object(session, "_request", side_effect=responses) as request:
            session.bootstrap()
            self.assertEqual((200, {"ok": True}), session.exchange("POST", "/control/clients", {}, {}, admin=True))
            self.assertEqual((401, {}), session.exchange("POST", "/control/clients", {}, {}, admin=False))
            self.assertEqual("scarcity-router-admin=session123", request.call_args_list[2].args[3]["Cookie"])
            self.assertNotIn("Cookie", request.call_args_list[3].args[3])
            self.assertNotIn(session.password, repr(project._docker.call_args))
            with self.assertRaises(ValueError):
                session.exchange("GET", "/control/state", None, {"cookie": "override"}, admin=False)

    def test_claim_failure_does_not_include_command_output(self):
        project = mock.Mock(port=1234, container_id="owned")
        project._owned.return_value = ["owned"]
        project._docker.side_effect = RuntimeError("secret output")
        with self.assertRaisesRegex(RuntimeError, "^bootstrap claim issuance failed$"):
            installed_admin.AdminSession(project).bootstrap()


class OfflineLifecycleTests(unittest.TestCase):
    def test_reload_requires_complete_unambiguous_response_framing(self):
        old, new = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        for response in ((400, b'{"error":', [("Content-Length", "100")]),
                         (400, b'{}', []),
                         (400, b'{}', [("Content-Length", "2"), ("Transfer-Encoding", "chunked")]),
                         (400, b'{"error":1,"error":2}', [("Content-Length", "21")])):
            project = mock.Mock(root=None, image_id=old)
            adapter = lifecycle.InstalledLifecycleAdapter(project, old, new)
            adapter.admin.cookie, adapter.admin.csrf = "cookie", "csrf"
            with self.subTest(response=response), mock.patch.object(adapter.admin, "_request", return_value=response), \
                 self.assertRaises(ValueError):
                adapter.exchange("POST", "/control/mi/reload", {}, {}, admin=True)
            project.block_engine.assert_called_once_with()
        project = mock.Mock(root=None, image_id=old)
        adapter = lifecycle.InstalledLifecycleAdapter(project, old, new)
        adapter.admin.cookie, adapter.admin.csrf = "cookie", "csrf"
        raw = b'{"status":"ok"}'
        with mock.patch.object(adapter.admin, "_request", return_value=(200, raw, [("Content-Length", str(len(raw)))])):
            self.assertEqual((200, {"status": "ok"}), adapter.exchange("POST", "/control/mi/reload", {}, {}, admin=True))
        project.block_engine.assert_not_called()

    def test_reload_timeout_and_partial_mounted_write_fence(self):
        old, new = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        project = mock.Mock(root=None, image_id=old)
        adapter = lifecycle.InstalledLifecycleAdapter(project, old, new)
        adapter.admin.cookie, adapter.admin.csrf = "cookie", "csrf"
        with mock.patch.object(adapter.admin, "_request", side_effect=TimeoutError("timeout")), \
             self.assertRaises(TimeoutError):
            adapter.exchange("POST", "/control/mi/reload", {}, {}, admin=True)
        project.block_engine.assert_called_once_with()
        project.reset_mock()
        project.root = Path("/private")
        with mock.patch.object(lifecycle, "write_publication_in_place", side_effect=OSError("partial")), \
             self.assertRaises(OSError):
            adapter.write_publication_in_place(b"data")
        project.block_engine.assert_called_once_with()

    def test_entrypoint_always_requests_cleanup_on_worker_failure(self):
        args = SimpleNamespace(authorize_disposable_linux_engine=True, socket="/private/sock", engine_id="engine-id",
                               old_image_id="old", new_image_id="new", worker_sha256="a" * 64,
                               fake_appserver="fake", fake_sha256="b" * 64, mi_python="/python", mi_wheel="/mi.whl", mi_repo="/mi")
        project = mock.Mock(token="c" * 32)
        adapter = mock.Mock()
        adapter.admin.cookie, adapter.admin.csrf = "cookie", "csrf"
        with mock.patch.object(entry, "_checked_file", return_value=b"fixture"), \
             mock.patch.object(entry.host_mi_provenance, "generate_cuts", return_value={"fresh": (b"fresh", b"trust")}), \
             mock.patch.object(entry, "_validate_cuts"), \
             mock.patch.object(entry, "InstalledProject", return_value=project), \
             mock.patch.object(entry, "InstalledLifecycleAdapter", return_value=adapter), \
             mock.patch.object(entry, "_security_negatives"), mock.patch.object(entry, "_client", return_value="key"), \
             mock.patch.object(entry, "_control", return_value=mock.Mock()), \
             mock.patch.object(entry, "assert_input_boundary", return_value={'route': {'target': {'resource': {'resource_id': 'foundry-worker-a:gpt-6-sol:high'}}}}), \
             mock.patch.object(entry, "_execution", side_effect=RuntimeError("worker failed")), \
             mocked_full_run(args):
            with self.assertRaisesRegex(RuntimeError, "worker failed"):
                entry.run(args)
            self.assertEqual(2, project.cleanup.call_count)

    def test_complete_entrypoint_requires_external_boundaries(self):
        args = SimpleNamespace(authorize_disposable_linux_engine=True, authorize_image_build=True,
                               confirm_external_boundaries=False)
        with self.assertRaisesRegex(ValueError, "external host isolation"):
            entry.run(args)

    def test_publication_preserves_inode_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "mi"
            directory.mkdir(mode=0o750)
            directory.chmod(0o750)
            path = directory / "publication.json"
            path.write_bytes(b"before")
            path.chmod(0o640)
            inode = path.stat().st_ino
            lifecycle.write_publication_in_place(directory, b"after")
            self.assertEqual(inode, path.stat().st_ino)
            self.assertEqual(b"after", path.read_bytes())
            path.unlink()
            path.symlink_to("elsewhere")
            with self.assertRaises(OSError):
                lifecycle.write_publication_in_place(directory, b"bad")

    def test_archive_manifest_rejects_links_and_traversal(self):
        def archive(name, kind=tarfile.REGTYPE):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode="w") as tar:
                entry = tarfile.TarInfo(name)
                entry.type = kind
                entry.uid = entry.gid = 10001
                entry.size = 4 if kind == tarfile.REGTYPE else 0
                tar.addfile(entry, io.BytesIO(b"data") if entry.size else None)
            return stream.getvalue()

        self.assertIn("state.db", lifecycle.snapshot_manifest(archive("state.db")))
        for name, kind in (("../escape", tarfile.REGTYPE), ("link", tarfile.SYMTYPE)):
            with self.assertRaises(ValueError):
                lifecycle.snapshot_manifest(archive(name, kind))

    def test_adapter_starts_prior_image_and_reauthenticates_on_upgrade(self):
        old, new = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        project = mock.Mock(root=None, image_id=old, port=None)
        adapter = lifecycle.InstalledLifecycleAdapter(project, old, new)
        with mock.patch.object(adapter.admin, "bootstrap") as bootstrap, \
             mock.patch.object(adapter.admin, "login") as login:
            adapter.start_old()
            project.start.assert_called_once_with(mi_enabled=False)
            bootstrap.assert_called_once()
            adapter.start_new()
            project.launch.assert_called_once_with(new, mi_enabled=True, adopt=True,
                                                   mi_digest=lifecycle.fixture.EXPECTED_SHA256)
            login.assert_called_once()

    def test_new_cut_preflight_and_restart_keep_independent_digest(self):
        old, new = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        data = b"stale controlled test cut"
        digest = hashlib.sha256(data).hexdigest()
        trust = json.dumps({"publication": "/run/foundry/mi/publication.json",
                            "reference": {"sha256": digest}}).encode()
        project = mock.Mock(root=None, image_id=old, port=None)
        project.mi_cuts = {"stale": (data, trust)}
        adapter = lifecycle.InstalledLifecycleAdapter(project, old, new)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "mi"
            directory.mkdir(mode=0o750)
            directory.chmod(0o750)
            for name in ("publication.json", "trust.json"):
                (directory / name).write_bytes(b"old")
                (directory / name).chmod(0o640)
            with mock.patch.dict(lifecycle.fixture.VARIANT_SHA256, {"stale": digest}), \
                 mock.patch.dict(lifecycle.fixture.TRUST_SHA256, {"stale": hashlib.sha256(trust).hexdigest()}), \
                 mock.patch.object(adapter.admin, "bootstrap"), mock.patch.object(adapter.admin, "login"):
                project.start.side_effect = lambda **kwargs: kwargs["configure_mi"](directory)
                adapter.start_new_with_cut(data, trust, digest)
                self.assertEqual(data, (directory / "publication.json").read_bytes())
                self.assertEqual(digest, project.start.call_args.kwargs["mi_digest"])
                adapter.restart_current_cut()
                project.launch.assert_called_once_with(new, mi_enabled=True, adopt=True, mi_digest=digest)

    def test_new_cut_rejects_unpinned_digest_before_start(self):
        old, new = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        project = mock.Mock(root=None, image_id=old, port=None)
        adapter = lifecycle.InstalledLifecycleAdapter(project, old, new)
        with self.assertRaises(ValueError):
            adapter.start_new_with_cut(b"untrusted", b"{}", hashlib.sha256(b"untrusted").hexdigest())
        project.start.assert_not_called()

    def test_new_cut_refuses_mismatched_verified_cut(self):
        old, new = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        project = mock.Mock(root=None, image_id=old, port=None)
        project.mi_cuts = {}
        adapter = lifecycle.InstalledLifecycleAdapter(project, old, new)
        data = b"synthetic"
        digest = hashlib.sha256(data).hexdigest()
        with mock.patch.dict(lifecycle.fixture.VARIANT_SHA256, {"stale": digest}), \
             mock.patch.dict(lifecycle.fixture.TRUST_SHA256, {"stale": hashlib.sha256(b"{}").hexdigest()}):
            with self.assertRaisesRegex(ValueError, "verified fixture"):
                adapter.start_new_with_cut(data, b"{}", digest)
        project.start.assert_not_called()

    def test_expected_mi_failure_requires_new_matching_exited_container(self):
        old, new = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        project = mock.Mock(root=None, image_id=old, port=None, container_id="old-id", env={}, project="test", _inspection_only=True)
        adapter = lifecycle.InstalledLifecycleAdapter(project, old, new)
        adapter._initialized = True
        project.root = Path("/protected")
        project._owned.side_effect = lambda kind: {"container": ["new-id"], "volume": ["test_router-data"], "network": ["network"]}[kind]
        project.launch.side_effect = lifecycle.CommandFailure("startup", 1)
        info = [{"Image": new, "RestartCount": 0, "State": {"Status": "exited", "ExitCode": 2, "Running": False, "Restarting": False,
                                        "StartedAt": "2026-11-08T20:00:00Z", "FinishedAt": "2026-11-08T20:00:01Z"},
                 "HostConfig": {"NanoCpus": 1000000000, "Memory": 536870912, "MemorySwap": 536870912,
                                "PidsLimit": 128, "Privileged": False, "NetworkMode": "internal", "RestartPolicy": {"Name": "no"},
                                "PortBindings": {"8787/tcp": [{"HostIp": "127.0.0.1", "HostPort": "1234"}]}},
                 "Config": {"Cmd": ["--mi-config=/run/foundry/mi/trust.json"]},
                 "Mounts": [{"Destination": "/data", "Type": "volume", "Name": "test_router-data"},
                            {"Destination": "/run/foundry/tls", "Type": "bind", "RW": False, "Source": "/protected/tls"},
                            *[{"Destination": "/run/foundry/mi/" + name, "Type": "bind", "RW": False,
                               "Source": "/protected/mi/" + name} for name in ("trust.json", "publication.json")]]}]
        project._docker.side_effect = lambda *args, **kwargs: (json.dumps(info) if args[0] == "container" else
            json.dumps([{"Internal": True, "Name": "internal"}]) if args[0] == "network" else "server: mi_publication_activation_failed\n")
        with mock.patch.object(adapter, "_stopped"), mock.patch.object(lifecycle, "validate_mi"):
            adapter.start_new_expect_mi_failure("mi_publication_activation_failed")
        self.assertEqual("new-id", project.container_id)
        project.finish_expected_inspection.assert_called_once_with(verified=True)

    def test_expected_failure_rejects_preflight_timeout_and_old_container(self):
        old, new = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        for failure, expected in ((ValueError("preflight"), ValueError),
                                  (subprocess.TimeoutExpired("launch", 1), subprocess.TimeoutExpired),
                                  (lifecycle.CommandFailure("python", 124), RuntimeError),
                                  (RuntimeError("failure"), RuntimeError)):
            project = mock.Mock(root=None, image_id=old, port=None, container_id="old-id", env={})
            adapter = lifecycle.InstalledLifecycleAdapter(project, old, new)
            adapter._initialized = True
            project.root = Path("/protected")
            project.launch.side_effect = failure
            project._owned.return_value = ["old-id"]
            with mock.patch.object(adapter, "_stopped"), mock.patch.object(lifecycle, "validate_mi"), \
                 self.assertRaises(expected):
                adapter.start_new_expect_mi_failure("mi_publication_activation_failed")
            project._docker.assert_not_called()

    def test_uncertain_startup_does_not_inspect_or_retry(self):
        old, new = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        project = mock.Mock(root=None, image_id=old, port=None, container_id="old-id", env={},
                            _engine_blocked=True, _inspection_only=False)
        adapter = lifecycle.InstalledLifecycleAdapter(project, old, new)
        adapter._initialized = True
        project.root = Path("/protected")
        project.launch.side_effect = lifecycle.CommandFailure("startup", 1)
        with mock.patch.object(adapter, "_stopped"), mock.patch.object(lifecycle, "validate_mi"), \
             self.assertRaisesRegex(RuntimeError, "outcome is uncertain"):
            adapter.start_new_expect_mi_failure("mi_publication_activation_failed")
        project._owned.assert_not_called()
        project._docker.assert_not_called()

    def test_expected_failure_rejects_wrong_exit_and_redacts_logs(self):
        old, new = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        project = mock.Mock(root=None, image_id=old, port=None, container_id="old-id", env={}, project="test", _inspection_only=True)
        adapter = lifecycle.InstalledLifecycleAdapter(project, old, new)
        adapter._initialized = True
        project.root = Path("/protected")
        project._owned.side_effect = lambda kind: {"container": ["new-id"], "volume": ["test_router-data"], "network": ["network"]}[kind]
        project.launch.side_effect = lifecycle.CommandFailure("startup", 1)
        info = [{"Image": new, "RestartCount": 0, "State": {"Status": "exited", "ExitCode": 1, "Running": False, "Restarting": False,
                                        "StartedAt": "2026-11-08T20:00:00Z", "FinishedAt": "2026-11-08T20:00:01Z"},
                 "HostConfig": {"NanoCpus": 1000000000, "Memory": 536870912, "MemorySwap": 536870912,
                                "PidsLimit": 128, "Privileged": False, "NetworkMode": "internal", "RestartPolicy": {"Name": "no"},
                                "PortBindings": {"8787/tcp": [{"HostIp": "127.0.0.1", "HostPort": "1234"}]}},
                 "Config": {"Cmd": ["--mi-config=/run/foundry/mi/trust.json"]},
                 "Mounts": [{"Destination": "/data", "Type": "volume", "Name": "test_router-data"},
                            {"Destination": "/run/foundry/tls", "Type": "bind", "RW": False, "Source": "/protected/tls"},
                            *[{"Destination": "/run/foundry/mi/" + name, "Type": "bind", "RW": False,
                               "Source": "/protected/mi/" + name} for name in ("trust.json", "publication.json")]]}]
        project._docker.side_effect = lambda *args, **kwargs: (json.dumps(info) if args[0] == "container" else
            json.dumps([{"Internal": True, "Name": "internal"}]) if args[0] == "network" else "private-data\nserver: different\n")
        with mock.patch.object(adapter, "_stopped"), mock.patch.object(lifecycle, "validate_mi"):
            with self.assertRaisesRegex(AssertionError, "state mismatch"):
                adapter.start_new_expect_mi_failure("mi_publication_activation_failed")
            info[0]["State"]["ExitCode"] = 2
            info[0]["State"]["FinishedAt"] = "2026-11-08T20:01:00Z"
            with self.assertRaisesRegex(AssertionError, "state mismatch"):
                adapter.start_new_expect_mi_failure("mi_publication_activation_failed")
            info[0]["State"]["FinishedAt"] = "2026-11-08T20:00:01Z"
            with self.assertRaises(AssertionError) as caught:
                adapter.start_new_expect_mi_failure("mi_publication_activation_failed")
            self.assertNotIn("private-data", str(caught.exception))
        self.assertEqual([mock.call(verified=False)] * 3, project.finish_expected_inspection.call_args_list)

    def test_restore_uses_new_owned_volume_and_checks_readback(self):
        old, new = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        project = mock.Mock(root=None, image_id=old, port=None, project="foundry-test-" + "c" * 32,
                            token="c" * 32, container_id="d" * 64, env={})
        adapter = lifecycle.InstalledLifecycleAdapter(project, old, new)
        helper = "e" * 64
        calls = []
        volumes = []

        def owned(kind):
            return ([project.container_id, helper] if kind == "container" else volumes)

        def docker(*args, **kwargs):
            calls.append((args, kwargs))
            if args == ("volume", "ls", "-q"):
                return ""
            if args[:2] == ("volume", "create"):
                volumes.append(args[-1])
                return args[-1]
            if args[:2] == ("container", "create"):
                return helper
            if args[:2] == ("container", "rm"):
                return helper
            if args[0] == "cp" and args[1] == helper + ":/data/.":
                return b"empty" if sum(1 for call, _ in calls if call[:2] == ("cp", helper + ":/data/.")) == 1 else b"archive"
            if args[:3] == ("cp", "-a", "-"):
                self.assertEqual(b"archive", kwargs["input_data"])
                return ""
            raise AssertionError(args)

        adapter._snapshots["snapshot"] = (b"archive", {"state": "verified"}, lifecycle.hashlib.sha256(b"archive").digest())
        project._owned.side_effect = owned
        project._docker.side_effect = docker
        with mock.patch.object(adapter, "_stopped"), \
             mock.patch.object(lifecycle, "snapshot_manifest", side_effect=lambda data: {} if data == b"empty" else {"state": "verified"}):
            adapter.restore("snapshot")
        self.assertEqual(volumes[0], project.env["FOUNDRY_TEST_VOLUME"])
        self.assertIn("_restore_", volumes[0])
        self.assertTrue(any(args[:2] == ("container", "rm") for args, _ in calls))

    def test_restore_validation_failure_fences_and_retains_resources(self):
        old, new = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        project = mock.Mock(root=None, image_id=old, port=None, project="foundry-test-" + "c" * 32,
                            token="c" * 32, container_id="d" * 64, env={})
        adapter = lifecycle.InstalledLifecycleAdapter(project, old, new)
        helper, volumes, calls = "e" * 64, [], []

        def docker(*args, **kwargs):
            calls.append(args)
            if args == ("volume", "ls", "-q"):
                return ""
            if args[:2] == ("volume", "create"):
                volumes.append(args[-1])
                return args[-1]
            if args[:2] == ("container", "create"):
                return helper
            if args[0] == "cp":
                return b"not-empty"
            raise AssertionError(args)

        adapter._snapshots["snapshot"] = (b"archive", {"state": "verified"}, hashlib.sha256(b"archive").digest())
        project._owned.side_effect = lambda kind: [project.container_id, helper] if kind == "container" else volumes
        project._docker.side_effect = docker
        with mock.patch.object(adapter, "_stopped"), \
             mock.patch.object(lifecycle, "snapshot_manifest", side_effect=lambda data: {"state": "verified"}):
            with self.assertRaisesRegex(ValueError, "not empty"):
                adapter.restore("snapshot")
        project.block_engine.assert_called_once_with()
        self.assertFalse(any(args[:2] == ("container", "rm") for args in calls))
        self.assertNotIn("FOUNDRY_TEST_VOLUME", project.env)

    def test_invalid_snapshot_and_restore_fence_before_cleanup(self):
        old, new = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        project = mock.Mock(root=None, image_id=old, port=None, project="foundry-test-" + "c" * 32,
                            token="c" * 32, container_id="d" * 64, env={})
        adapter = lifecycle.InstalledLifecycleAdapter(project, old, new)
        with mock.patch.object(adapter, "_stopped"), \
             mock.patch.object(lifecycle, "snapshot_manifest", side_effect=ValueError("invalid archive")):
            with self.assertRaisesRegex(ValueError, "invalid archive"):
                adapter.snapshot()
        project.block_engine.assert_called_once_with()
        project.reset_mock()
        adapter._snapshots["snapshot"] = (b"altered", {}, b"wrong digest")
        with mock.patch.object(adapter, "_stopped"):
            with self.assertRaisesRegex(ValueError, "snapshot changed"):
                adapter.restore("snapshot")
        project.block_engine.assert_called_once_with()
        project._docker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
