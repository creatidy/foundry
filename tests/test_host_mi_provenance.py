"""Offline tests for the isolated fixed-wheel MI execution boundary."""

import os
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import shutil
import subprocess
import types
import unittest
from unittest import mock
import zipfile

import host_mi_provenance as provenance
import mi_publication_fixture as fixture
import verified_mi_child
import run_installed_acceptance as runner


WHEEL = os.environ.get("FOUNDRY_TEST_MI_WHEEL")
REPO = os.environ.get("FOUNDRY_TEST_MI_REPO")
FAKE = os.environ.get("FOUNDRY_TEST_FAKE_APPSERVER")


class SourceCaptureTests(unittest.TestCase):
    def _verify(self, stdout_size, stderr_size, *, error=None, code=0, ticks=None, wait_timeout=False, cleanup_timeout=False):
        content = b"pinned fixture"
        wheel = io.BytesIO()
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr("model_intelligence/fixture.py", content)
        stdout, stderr = mock.Mock(), mock.Mock()
        stdout.fileno.return_value, stderr.fileno.return_value = 101, 102
        process = mock.Mock(stdout=stdout, stderr=stderr, returncode=None)
        process.poll.side_effect = lambda: process.returncode
        process.kill.side_effect = lambda: setattr(process, "returncode", -9)
        waits = []
        def wait(timeout=None):
            waits.append(timeout)
            if cleanup_timeout and timeout == 5:
                raise subprocess.TimeoutExpired("private command", timeout)
            if wait_timeout and len(waits) == 1:
                raise subprocess.TimeoutExpired("private command", timeout, output=b"private", stderr=b"private")
            if process.returncode is None:
                process.returncode = code
            return process.returncode
        process.wait.side_effect = wait
        registered = {}
        selector = mock.MagicMock()
        selector.__enter__.return_value = selector
        def register(stream, events):
            self.assertEqual(provenance.selectors.EVENT_READ, events)
            registered[stream.fileno()] = types.SimpleNamespace(fd=stream.fileno(), fileobj=stream)
        selector.register.side_effect = register
        selector.unregister.side_effect = lambda stream: registered.pop(stream.fileno())
        selector.get_map.return_value = registered
        selector.select.side_effect = lambda timeout: [(key, provenance.selectors.EVENT_READ) for key in registered.values()]
        remaining = {101: stdout_size, 102: stderr_size}
        produced = 0
        def read(fd, size):
            nonlocal produced
            self.assertLessEqual(size, 65536)
            count = min(size, remaining[fd])
            remaining[fd] -= count
            produced += count
            return (b"x" if fd == 101 else b"s") * count
        command = ["git", "--no-replace-objects", "private-repository"]
        def manifest(run, repo, revision, component):
            self.assertEqual(("/unused", fixture.MI_REVISION, "mi"), (repo, revision, component))
            self.assertEqual(b"x" * stdout_size, run(command))
            return {"model_intelligence/fixture.py": hashlib.sha256(content).hexdigest()}
        with mock.patch.object(provenance.subprocess, "Popen", return_value=process) as popen, \
             mock.patch.object(provenance.selectors, "DefaultSelector", return_value=selector), \
             mock.patch.object(provenance.os, "read", side_effect=read), \
             mock.patch.object(provenance.time, "monotonic", side_effect=ticks, return_value=0), \
             mock.patch.object(provenance.image_build_executor, "git_manifest", side_effect=manifest), \
             mock.patch.object(provenance.subprocess, "run", side_effect=AssertionError("unbounded capture")):
            if error:
                with self.assertRaises(error) as raised:
                    provenance.verify_source_wheel("/unused", wheel.getvalue())
                self.assertNotIn("private", str(raised.exception))
            else:
                provenance.verify_source_wheel("/unused", wheel.getvalue())
        popen.assert_called_once_with(command, env={
            "PATH": os.defpath, "HOME": "/tmp/kilo", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "",
            "GIT_OPTIONAL_LOCKS": "0"}, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        stdout.close.assert_called_once_with()
        stderr.close.assert_called_once_with()
        selector.__exit__.assert_called_once()
        self.assertIsNotNone(process.returncode)
        self.assertTrue(all(timeout is not None and timeout > 0 for timeout in waits))
        self.assertLessEqual(produced, provenance.MAX_SOURCE_OUTPUT + 1)
        return process, selector, waits, produced

    def test_streaming_capture_accepts_aggregate_boundary(self):
        limit = provenance.MAX_SOURCE_OUTPUT
        self.assertEqual(16 * 1024 * 1024, limit)
        for sizes in ((limit, 0), (0, limit), (limit // 2, limit // 2)):
            with self.subTest(sizes=sizes):
                process, _, _, produced = self._verify(*sizes)
                process.kill.assert_not_called()
                self.assertEqual(limit, produced)

    def test_either_stream_or_combined_overflow_kills_and_reaps(self):
        limit = provenance.MAX_SOURCE_OUTPUT
        for sizes in ((limit + 1, 0), (0, limit + 1), (limit // 2 + 1, limit // 2)):
            with self.subTest(sizes=sizes):
                process, _, waits, produced = self._verify(*sizes, error=ValueError)
                process.kill.assert_called_once_with()
                self.assertEqual([5], waits)
                self.assertEqual(limit + 1, produced)

    def test_nonzero_exit_is_generic_and_already_reaped(self):
        process, _, waits, _ = self._verify(32, 64, code=7, error=ValueError)
        process.kill.assert_not_called()
        self.assertEqual([30], waits)

    def test_command_and_global_timeouts_kill_and_reap(self):
        for ticks in ([0, 0, 31], [0, 119, 121]):
            with self.subTest(ticks=ticks):
                process, selector, waits, produced = self._verify(64, 64, ticks=ticks, error=TimeoutError)
                process.kill.assert_called_once_with()
                selector.select.assert_not_called()
                self.assertEqual([5], waits)
                self.assertEqual(0, produced)

    def test_wait_timeout_kills_reaps_and_closes_both_streams(self):
        process, _, waits, _ = self._verify(0, 0, wait_timeout=True, error=TimeoutError)
        process.kill.assert_called_once_with()
        self.assertEqual([30, 5], waits)

    def test_cleanup_timeout_is_bounded_and_closes_both_streams(self):
        process, _, waits, _ = self._verify(provenance.MAX_SOURCE_OUTPUT + 1, 0,
                                           error=TimeoutError, cleanup_timeout=True)
        process.kill.assert_called_once_with()
        self.assertEqual([5], waits)

    def test_global_deadline_bounds_select_and_wait(self):
        process, selector, waits, _ = self._verify(0, 0, ticks=[0, 115, 116, 117])
        process.kill.assert_not_called()
        selector.select.assert_called_once_with(4)
        self.assertEqual([3], waits)

    def test_expired_global_deadline_refuses_before_child(self):
        with mock.patch.object(provenance.time, "monotonic", side_effect=[0, 121]), \
             mock.patch.object(provenance.image_build_executor, "git_manifest", side_effect=lambda run, *args: run(["git"])), \
             mock.patch.object(provenance.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(TimeoutError, "MI source verification timed out"):
                provenance.verify_source_wheel("/unused", b"")
            popen.assert_not_called()


class HostMIProvenanceTests(unittest.TestCase):
    def test_rejects_changed_artifact_before_starting_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            wheel = Path(tmp) / "mi.whl"
            wheel.write_bytes(b"not the approved wheel")
            with mock.patch.object(provenance.subprocess, "run") as run, \
                    mock.patch.object(provenance.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(ValueError, "digest mismatch"):
                    provenance.generate_cuts(sys.executable, wheel, tmp)
                run.assert_not_called()
                popen.assert_not_called()
            link = Path(tmp) / "link.whl"
            link.symlink_to(wheel)
            with self.assertRaises(OSError):
                provenance.generate_cuts(sys.executable, link, tmp)

    @unittest.skipUnless(WHEEL and REPO, "set FOUNDRY_TEST_MI_WHEEL and FOUNDRY_TEST_MI_REPO")
    def test_exact_wheel_ignores_ambient_shadow_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            package = Path(tmp) / "model_intelligence"
            package.mkdir()
            (package / "__init__.py").write_text("raise RuntimeError('shadow imported')\n")
            with mock.patch.dict(os.environ, {"PYTHONPATH": tmp, "PYTHONHOME": tmp}):
                cuts = provenance.generate_cuts(sys.executable, WHEEL, REPO)
            self.assertEqual({"fresh", *fixture.VARIANT_SHA256}, set(cuts))

    @unittest.skipUnless(WHEEL, "set FOUNDRY_TEST_MI_WHEEL to the independently pinned wheel")
    def test_changed_module_in_wheel_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            changed = Path(tmp) / "changed.whl"
            with zipfile.ZipFile(WHEEL) as original, zipfile.ZipFile(changed, "w") as altered:
                for entry in original.infolist():
                    content = original.read(entry.filename)
                    if entry.filename == "model_intelligence/producer.py":
                        content += b"\n# modified module\n"
                    altered.writestr(entry, content)
            with mock.patch.object(provenance.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "digest mismatch"):
                    provenance.generate_cuts(sys.executable, changed, tmp)
                run.assert_not_called()

    @unittest.skipUnless(WHEEL and REPO, "set FOUNDRY_TEST_MI_WHEEL and FOUNDRY_TEST_MI_REPO")
    def test_installed_tampering_refused_before_producer(self):
        original = provenance.verify_installation
        for attack in ("module", "pyc", "pth", "sitecustomize", "symlink", "system_site"):
            def tamper(venv, wheel):
                venv = Path(venv)
                site, = (venv / "lib").glob("python*/site-packages")
                if attack == "module":
                    (site / "model_intelligence" / "producer.py").write_text("raise RuntimeError('tampered')")
                elif attack == "pyc":
                    (site / "model_intelligence" / "producer.pyc").write_bytes(b"fake")
                elif attack == "pth":
                    (site / "rogue.pth").write_text("import os\n")
                elif attack == "sitecustomize":
                    (site / "sitecustomize.py").write_text("raise RuntimeError('tampered')")
                elif attack == "symlink":
                    (site / "rogue").symlink_to("model_intelligence", target_is_directory=True)
                else:
                    (venv / "pyvenv.cfg").write_text("include-system-site-packages = true\n")
                return original(venv, wheel)
            with self.subTest(attack=attack), mock.patch.object(provenance, "verify_installation", side_effect=tamper), \
                    mock.patch.object(provenance.subprocess, "run", wraps=provenance.subprocess.run) as run:
                with self.assertRaises(ValueError):
                    provenance.generate_cuts(sys.executable, WHEEL, REPO)
                self.assertFalse(any("verified_mi_child.py" in str(call.args[0]) for call in run.call_args_list),
                                 "producer started before installed-file verification")

    @unittest.skipUnless(WHEEL and REPO, "set FOUNDRY_TEST_MI_WHEEL and FOUNDRY_TEST_MI_REPO")
    def test_direct_url_metadata_refused_before_producer(self):
        original = provenance.verify_installation
        attacks = ("missing", "malformed", "wrong_url", "wrong_hash", "wrong_hashes", "duplicate", "wrong_shape")
        for attack in attacks:
            def tamper(venv, wheel):
                site, = (Path(venv) / "lib").glob("python*/site-packages")
                metadata = site / provenance.DIST_INFO / "direct_url.json"
                if attack == "missing":
                    metadata.unlink()
                elif attack == "malformed":
                    metadata.write_text("{bad json")
                elif attack == "duplicate":
                    metadata.write_text('{"url":"bad","url":"' + Path(wheel).as_uri() + '","archive_info":{}}')
                elif attack == "wrong_shape":
                    metadata.write_text(json.dumps({"url": Path(wheel).as_uri(), "archive_info": []}))
                else:
                    document = {"url": Path(wheel).as_uri(), "archive_info": {}}
                    if attack == "wrong_url":
                        document["url"] = "file:///tmp/different.whl"
                    elif attack == "wrong_hash":
                        document["archive_info"]["hash"] = "sha256=" + "0" * 64
                    else:
                        document["archive_info"]["hashes"] = {"sha256": "0" * 64}
                    metadata.write_text(json.dumps(document))
                return original(venv, wheel)

            with self.subTest(attack=attack), mock.patch.object(provenance, "verify_installation", side_effect=tamper), \
                    mock.patch.object(provenance.subprocess, "run", wraps=provenance.subprocess.run) as run:
                with self.assertRaisesRegex(ValueError, "MI direct URL"):
                    provenance.generate_cuts(sys.executable, WHEEL, REPO)
                self.assertFalse(any("verified_mi_child.py" in str(call.args[0]) for call in run.call_args_list))

    @unittest.skipUnless(WHEEL and REPO, "set FOUNDRY_TEST_MI_WHEEL and FOUNDRY_TEST_MI_REPO")
    def test_direct_url_matching_archive_hash_is_accepted(self):
        original = provenance.verify_installation

        def include_hash(venv, wheel):
            site, = (Path(venv) / "lib").glob("python*/site-packages")
            metadata = site / provenance.DIST_INFO / "direct_url.json"
            metadata.write_text(json.dumps({"url": Path(wheel).as_uri(), "archive_info": {
                "hash": "sha256=" + provenance.WHEEL_SHA256,
                "hashes": {"sha256": provenance.WHEEL_SHA256}}}))
            return original(venv, wheel)

        with mock.patch.object(provenance, "verify_installation", side_effect=include_hash):
            cuts = provenance.generate_cuts(sys.executable, WHEEL, REPO)
        self.assertEqual({"fresh", *fixture.VARIANT_SHA256}, set(cuts))

    @unittest.skipUnless(WHEEL and REPO, "set FOUNDRY_TEST_MI_WHEEL and FOUNDRY_TEST_MI_REPO")
    def test_pinned_tree_mismatch_rejected(self):
        data = Path(WHEEL).read_bytes()
        with mock.patch.object(provenance.image_build_executor, "git_manifest", return_value={"model_intelligence/producer.py": "0" * 64}):
            with self.assertRaisesRegex(ValueError, "differs from pinned source tree"):
                provenance.verify_source_wheel(REPO, data)
        with tempfile.TemporaryDirectory() as tmp:
            altered = Path(tmp) / "altered.whl"
            with zipfile.ZipFile(WHEEL) as source, zipfile.ZipFile(altered, "w") as destination:
                for entry in source.infolist():
                    content = source.read(entry.filename)
                    if entry.filename == "model_intelligence/producer.py":
                        content += b"\n# changed\n"
                    destination.writestr(entry, content)
            with self.assertRaisesRegex(ValueError, "differs from pinned source tree"):
                provenance.verify_source_wheel(REPO, altered.read_bytes())

    @unittest.skipUnless(WHEEL and REPO, "set FOUNDRY_TEST_MI_WHEEL and FOUNDRY_TEST_MI_REPO")
    def test_every_complete_trust_document_is_independently_pinned(self):
        real_run = provenance.subprocess.run
        for kind in provenance.TRUST_SHA256:
            def alter(*args, **kwargs):
                result = real_run(*args, **kwargs)
                if "verified_mi_child.py" in str(args[0]):
                    payload = json.loads(result.stdout)
                    payload[kind]["trust"]["scope"]["channel"] = "tampered"
                    result.stdout = json.dumps(payload).encode()
                return result
            with self.subTest(kind=kind), mock.patch.object(provenance.subprocess, "run", side_effect=alter):
                with self.assertRaisesRegex(ValueError, "synthetic cut reference mismatch"):
                    provenance.generate_cuts(sys.executable, WHEEL, REPO)

    def test_unexpected_mi_module_origin_is_rejected(self):
        module = types.ModuleType("model_intelligence.injected")
        module.__file__ = "/tmp/injected.py"
        with mock.patch.dict(sys.modules, {module.__name__: module}):
            with self.assertRaisesRegex(RuntimeError, "outside verified installation"):
                verified_mi_child.check_origins(Path("/tmp/test-site"))

    @unittest.skipUnless(WHEEL and REPO and FAKE, "set pinned wheel, MI repository, and fake appserver paths")
    def test_runner_prepares_real_installed_producer_cuts_without_docker(self):
        helper = runner.ROOT / "tests" / "worker_mi_acceptance.py"
        fake = Path(FAKE)
        args = types.SimpleNamespace(
            worker_sha256=hashlib.sha256(helper.read_bytes()).hexdigest(),
            fake_appserver=fake,
            fake_sha256=hashlib.sha256(fake.read_bytes()).hexdigest(),
            mi_python=sys.executable,
            mi_wheel=WHEEL,
            mi_repo=REPO,
        )
        with mock.patch.object(runner, "_discover_engine") as discover:
            actual_helper, actual_fake, cuts = runner._prepare(args)
        discover.assert_not_called()
        self.assertEqual(helper.read_bytes(), actual_helper)
        self.assertEqual(fake.read_bytes(), actual_fake)
        self.assertEqual({"fresh", *fixture.VARIANT_SHA256}, set(cuts))
        altered = dict(cuts)
        document = json.loads(cuts["fresh"][1])
        document["scope"]["channel"] = "not-authorized"
        altered["fresh"] = (cuts["fresh"][0], json.dumps(document, sort_keys=True, separators=(",", ":")).encode())
        with mock.patch.object(runner, "_project") as project:
            with self.assertRaisesRegex(ValueError, "trust mismatch"):
                runner._validate_cuts(altered)
        project.assert_not_called()
        with tempfile.TemporaryDirectory() as tmp:
            from installed_provisioning import prepare_mi
            destination = Path(tmp) / "inputs"
            with self.assertRaisesRegex(ValueError, "trust reference mismatch"):
                prepare_mi(destination, altered["fresh"])
            self.assertFalse(destination.exists())

    @unittest.skipUnless(WHEEL and REPO and FAKE, "set pinned wheel, MI repository, and fake appserver paths")
    def test_full_entrypoint_reaches_first_docker_boundary_with_real_producer(self):
        base = "sha256:" + "a" * 64
        socket = "/run/docker.sock"
        report_dir = tempfile.mkdtemp(prefix="foundry-mi-test-preflight-", dir="/tmp/kilo")
        evidence_dir = tempfile.mkdtemp(prefix="foundry-mi-test-result-", dir="/tmp/kilo")
        os.rmdir(report_dir)
        os.rmdir(evidence_dir)
        try:
            report = runner.Evidence(report_dir, preflight_only=True)
            report.data.update(status="preflight_passed", socket=socket, base_digest=base,
                               engine_id="test-engine-123", preflight={"probe": {"status": "passed", "cleanup": "passed"}})
            report.save()
            report.close()
            helper = runner.ROOT / "tests" / "worker_mi_acceptance.py"
            fake = Path(FAKE)
            args = types.SimpleNamespace(
                preflight_only=False, authorize_disposable_linux_engine=True, authorize_image_build=True,
                confirm_external_boundaries=True, preflight_evidence=report_dir + "/acceptance.json",
                socket=socket, base_digest=base, engine_id="test-engine-123",
                sr_repo=str(fake.parent.parent), mi_repo=REPO, mi_python=sys.executable, mi_wheel=WHEEL,
                worker_sha256=hashlib.sha256(helper.read_bytes()).hexdigest(), fake_appserver=fake,
                fake_sha256=hashlib.sha256(fake.read_bytes()).hexdigest(), evidence_dir=evidence_dir,
                zai_python=None, zai_output_dir=None, authorize_zai_source_reads=False,
            )
            with mock.patch.object(runner, "_discover_engine", side_effect=RuntimeError("docker boundary reached")) as boundary:
                with self.assertRaisesRegex(RuntimeError, "docker boundary reached"):
                    runner.run(args)
            boundary.assert_called_once_with(args)
            report_data = json.loads((Path(evidence_dir) / "acceptance.json").read_text())
            self.assertEqual("failed", report_data["status"])
        finally:
            shutil.rmtree(report_dir, ignore_errors=True)
            shutil.rmtree(evidence_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
