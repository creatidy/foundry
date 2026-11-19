"""Offline pipe-only checks for lifecycle worker control and scenario wiring."""
import io
import hashlib
import json
import os
import tarfile
import threading
import unittest
from unittest import mock

import installed_worker_control as control
import worker_mi_acceptance as worker


class PipeProcess:
    def __init__(self):
        in_read, in_write = os.pipe()
        out_read, out_write = os.pipe()
        self.stdin = os.fdopen(in_write, "wb", buffering=0)
        self.stdout = os.fdopen(out_read, "rb", buffering=0)
        self.stderr = None
        self.finished = threading.Event()
        self.settings = None

        def run():
            try:
                with os.fdopen(in_read, "rb") as source, os.fdopen(out_write, "wb", buffering=0) as sink:
                    self.settings = json.loads(source.readline())
                    worker._live_commands(lambda: True, lambda key, response, digest: key == "private" and digest == "cut",
                                          source, sink)
            finally:
                self.finished.set()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()

    def poll(self):
        return 0 if self.finished.is_set() else None

    def wait(self, timeout):
        if not self.finished.wait(timeout):
            raise TimeoutError("pipe worker did not exit")
        return 0

    def kill(self):
        self.stdin.close()
        self.finished.wait(5)


class LiveProtocolTests(unittest.TestCase):
    def test_round_trip_and_private_settings(self):
        process = PipeProcess()
        session = control.WorkerControl(process, {"admin_cookie": "secret"}, timeout=2)
        self.assertEqual(process.settings, {"admin_cookie": "secret"})
        self.assertTrue(session.worker_ready())
        self.assertTrue(session.verify_cut("private", {"route": {}}, "cut"))
        self.assertFalse(session.verify_cut("bad", {}, "cut"))
        session.close()
        self.assertTrue(process.finished.is_set())

    def test_invalid_and_oversized_frames_fail_closed(self):
        for data in (b'{"op":"other"}\n', b'x' * (512 * 1024 + 1), b'{"op":"ready"}'):
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                worker._live_commands(lambda: True, lambda *_: True, io.BytesIO(data), io.BytesIO())
        sink = io.BytesIO()
        worker._live_commands(lambda: False, lambda *_: False,
                              io.BytesIO(b'{"op":"ready"}\n{"op":"stop"}\n'), sink)
        self.assertEqual([{"event": "ready"}, {"ok": False}, {"ok": True}],
                         [json.loads(line) for line in sink.getvalue().splitlines()])

    def test_migration_execution_protocol_requires_real_callback(self):
        sink = io.BytesIO()
        command = b'{"op":"execute","key":"test-key","mi_enabled":true}\n{"op":"stop"}\n'
        callback = mock.Mock(return_value=True)
        worker._live_commands(lambda: True, lambda *_: False, io.BytesIO(command), sink, callback)
        callback.assert_called_once_with("test-key", True)
        self.assertEqual([{"event": "ready"}, {"ok": True}, {"ok": True}],
                         [json.loads(line) for line in sink.getvalue().splitlines()])
        with self.assertRaises(ValueError):
            worker._live_commands(lambda: True, lambda *_: False, io.BytesIO(command), io.BytesIO())

    def test_worker_protocol_failure_fences_engine(self):
        session = control.WorkerControl.__new__(control.WorkerControl)
        session.closed = False
        session.project = mock.Mock()
        session._write = mock.Mock(side_effect=TimeoutError("uncertain worker"))
        session.abort = mock.Mock()
        with mock.patch.object(control, "_RETAINED_WORKERS", []):
            with self.assertRaises(TimeoutError):
                session.worker_ready()
            session.project.block_engine.assert_called_once_with()
            session.abort.assert_not_called()
            self.assertEqual([session], control._RETAINED_WORKERS)

    def test_fenced_worker_close_does_not_stop_or_close_process(self):
        session = control.WorkerControl.__new__(control.WorkerControl)
        session.closed = False
        session.project = mock.Mock()
        session.project.require_unblocked.side_effect = ValueError("fenced")
        session._request = mock.Mock()
        session.abort = mock.Mock()
        with mock.patch.object(control, "_RETAINED_WORKERS", []):
            session.close()
            session._request.assert_not_called()
            session.abort.assert_not_called()
            self.assertFalse(session.closed)
            self.assertEqual([session], control._RETAINED_WORKERS)

    def test_migration_resume_requires_bounded_verified_archive(self):
        project, admin = mock.Mock(), mock.Mock()
        for migration, archive in (("resume", None), ("initialize", b"invalid"), ("resume", b"invalid")):
            with self.subTest(migration=migration), self.assertRaises((ValueError, EOFError, tarfile.TarError)):
                control.start_live_worker(project, admin, b"helper", b"fake", helper_sha256="0" * 64,
                                          fake_sha256="0" * 64, migration=migration, worker_archive=archive)
        project._docker.assert_not_called()

    def test_worker_archive_requires_private_identities_and_redacts_bytes(self):
        def archive(mode):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode="w") as tar:
                for source in ("foundry-worker-a", "foundry-worker-b"):
                    directory = tarfile.TarInfo(source)
                    directory.type, directory.mode, directory.uid, directory.gid = tarfile.DIRTYPE, 0o700, 10001, 10001
                    tar.addfile(directory)
                    database = tarfile.TarInfo(source + "/worker-state.db")
                    database.mode, database.uid, database.gid, database.size = mode, 10001, 10001, 6
                    tar.addfile(database, io.BytesIO(b"secret"))
            return output.getvalue()
        data = archive(0o600)
        self.assertEqual(4, len(control._worker_manifest(data)))
        stored = control.WorkerArchive("a" * 32, hashlib.sha256(data).hexdigest(), data)
        self.assertNotIn("secret", repr(stored))
        with self.assertRaisesRegex(ValueError, "not private"):
            control._worker_manifest(archive(0o644))

    def test_reload_scenario_uses_callbacks_and_closes_on_failure(self):
        worker_control = mock.Mock()
        with mock.patch("installed_mi_lifecycle_scenario.run_variant_reload_acceptance", side_effect=RuntimeError("failed")) as run:
            with self.assertRaises(RuntimeError):
                control.run_variant_with_worker("adapter", "key", "cuts", worker_control)
        run.assert_called_once_with("adapter", "key", "cuts", worker_control.worker_ready, worker_control.verify_cut)
        worker_control.close.assert_called_once_with()

    def test_start_rejects_bad_fixture_before_container_operations(self):
        project = mock.Mock()
        project.port = 1234
        project.container_id = "owned"
        project._roles.return_value = {"router": "owned"}
        project._owned.return_value = ["owned"]
        admin = mock.Mock(cookie="cookie", csrf="csrf")
        with self.assertRaises(ValueError):
            control.start_live_worker(project, admin, b"helper", b"fake", helper_sha256="0" * 64,
                                      fake_sha256="0" * 64)
        project._docker.assert_not_called()

    def test_boundary_checks_exact_target_and_cut(self):
        adapter, session = mock.Mock(), mock.Mock()
        session.worker_ready.return_value = True
        session.verify_cut.return_value = True
        target = {"resource": {"resource_id": "foundry-worker-a:gpt-6-sol:high"},
                  "model": {"provider": "openai", "model": "gpt-6-sol", "variant": "high"},
                  "reasoning_effort": "high"}
        adapter.exchange.return_value = (200, {"route": {"target": target}})
        control.assert_input_boundary(adapter, "key", session, mi_enabled=False)
        adapter.exchange.return_value = (200, {"route": {"status": "no_solution", "target": None}})
        control.assert_input_boundary(adapter, "key", session, mi_enabled=True)
        session.verify_cut.assert_called_once()
        session.verify_cut.return_value = False
        with self.assertRaises(AssertionError):
            control.assert_input_boundary(adapter, "key", session, mi_enabled=True)

    def test_stale_wiring_resumes_worker_identity_after_restart(self):
        live, resumed = mock.Mock(), mock.Mock()
        saved = object()
        live.snapshot_worker.return_value = saved
        live.worker_ready.return_value = resumed.worker_ready.return_value = True
        live.verify_cut.return_value = resumed.verify_cut.return_value = True
        factory = mock.Mock(side_effect=[live, resumed])

        def scenario(adapter, cuts, start, stop, verify):
            self.assertTrue(start()())
            self.assertTrue(verify("key", {}, "cut"))
            stop()
            self.assertTrue(start()())
            self.assertTrue(verify("key", {}, "cut"))
            stop()

        with mock.patch("installed_mi_lifecycle_scenario.run_stale_startup_acceptance", side_effect=scenario):
            control.run_stale_with_worker("adapter", "cuts", factory)
        self.assertEqual(factory.call_args_list, [mock.call(False, migration="initialize", worker_archive=None),
                                                  mock.call(False, migration="resume", worker_archive=saved)])
        live.close.assert_called_once_with()
        live.snapshot_worker.assert_called_once_with()
        resumed.close.assert_called_once_with()

    def test_stale_wiring_preserves_primary_error_if_cleanup_fails(self):
        live = mock.Mock()
        live.worker_ready.return_value = True
        live.close.side_effect = RuntimeError("cleanup failed")

        def scenario(adapter, cuts, start, stop, verify):
            start()
            raise ValueError("primary failure")

        with mock.patch("installed_mi_lifecycle_scenario.run_stale_startup_acceptance", side_effect=scenario):
            with self.assertRaisesRegex(ValueError, "primary failure") as caught:
                control.run_stale_with_worker("adapter", "cuts", mock.Mock(return_value=live))
        self.assertEqual(["worker cleanup also failed: RuntimeError"], caught.exception.__notes__)
        live.close.assert_called_once_with()

    def test_stale_wiring_does_not_retry_failed_stop(self):
        live = mock.Mock()
        live.close.side_effect = RuntimeError("cleanup failed")

        def scenario(adapter, cuts, start, stop, verify):
            start()
            stop()

        with mock.patch("installed_mi_lifecycle_scenario.run_stale_startup_acceptance", side_effect=scenario):
            with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
                control.run_stale_with_worker("adapter", "cuts", mock.Mock(return_value=live))
        live.close.assert_called_once_with()

    def test_installed_variant_starts_real_control_adapter_path(self):
        adapter, session = mock.Mock(), mock.Mock()
        with mock.patch.object(control, "start_live_worker", return_value=session) as start, \
                mock.patch.object(control, "run_variant_with_worker", return_value="result") as run:
            result = control.run_variant_installed(adapter, "key", "cuts", b"helper", b"fake",
                                                   helper_sha256="a" * 64, fake_sha256="b" * 64)
        self.assertEqual(result, "result")
        start.assert_called_once_with(adapter.project, adapter.admin, b"helper", b"fake",
                                      helper_sha256="a" * 64, fake_sha256="b" * 64)
        run.assert_called_once_with(adapter, "key", "cuts", session)


if __name__ == "__main__":
    unittest.main()
