"""Offline tests for the isolated fixed-wheel MI execution boundary."""

import os
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import shutil
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


class HostMIProvenanceTests(unittest.TestCase):
    def test_rejects_changed_artifact_before_starting_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            wheel = Path(tmp) / "mi.whl"
            wheel.write_bytes(b"not the approved wheel")
            with mock.patch.object(provenance.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "digest mismatch"):
                    provenance.generate_cuts(sys.executable, wheel, tmp)
                run.assert_not_called()
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
