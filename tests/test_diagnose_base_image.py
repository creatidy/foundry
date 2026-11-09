"""Offline tests for bounded, read-only image diagnostics."""

import json
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

import diagnose_base_image as diagnostic
import image_build_executor as build
import installed_provisioning as provisioning
import run_installed_acceptance as runner


class DiagnosticTests(unittest.TestCase):
    def test_stderr_is_bounded_and_allowlisted(self):
        args = ["docker", "image", "inspect", diagnostic.PINNED]
        missing = ("Error response from daemon: No such image: " + diagnostic.PINNED).encode()
        self.assertEqual(missing.decode(), provisioning.redacted_docker_stderr(args, missing))
        missing_object = ("Error: No such object: " + diagnostic.PINNED).encode()
        self.assertEqual(missing_object.decode(), provisioning.redacted_docker_stderr(args, missing_object))
        self.assertEqual("Docker reported permission denied; details redacted",
                         provisioning.redacted_docker_stderr(args, b"permission denied /secret/token"))
        self.assertEqual("Docker reported daemon unavailable; details redacted",
                         provisioning.redacted_docker_stderr(args, b"Cannot connect to the Docker daemon at /secret"))
        for content in (b"secret-token", missing + b" secret-token", missing + b" "):
            redacted = provisioning.redacted_docker_stderr(args, content)
            self.assertEqual("Docker stderr redacted: unrecognized diagnostic", redacted)
            self.assertNotIn("secret-token", redacted)
            self.assertLessEqual(len(redacted), 256)
        self.assertEqual("Docker stderr redacted: oversized diagnostic",
                         provisioning.redacted_docker_stderr(args, missing + b" " * 5000 + b"secret-token"))

    def test_reference_results_are_bounded_and_do_not_copy_image_secrets(self):
        image_id = "sha256:" + "b" * 64
        item = {"Id": image_id, "Os": "linux", "Architecture": "amd64",
                "RepoDigests": ["python@" + diagnostic.DIGEST, "private/secret@sha256:" + "c" * 64],
                "Config": {"Env": ["PASSWORD=secret-token"]}}
        project = mock.Mock()
        project._docker.return_value = json.dumps([item])
        result = diagnostic.inspect_reference(project, diagnostic.PINNED)
        self.assertEqual("inspected", result["classification"])
        self.assertEqual([diagnostic.DIGEST], result["python_repository_digests"])
        self.assertNotIn("secret", json.dumps(result))
        item["RepoDigests"] = ["python@sha256:" + "d" * 64]
        project._docker.return_value = json.dumps([item])
        self.assertEqual("reference_mismatch", diagnostic.inspect_reference(project, diagnostic.PINNED)["classification"])
        item["RepoDigests"] = None
        project._docker.return_value = json.dumps([item])
        self.assertEqual([], diagnostic.inspect_reference(project, diagnostic.TAG)["python_repository_digests"])
        item["RepoDigests"] = ["python@sha256:" + ("a" * 64)] * 17
        project._docker.return_value = json.dumps([item])
        self.assertEqual("unexpected_failure", diagnostic.inspect_reference(project, diagnostic.TAG)["classification"])

    def test_docker_failures_keep_only_safe_status_and_message(self):
        for stderr, operation, expected in (
            ("Error: No such image: " + diagnostic.PINNED, "image_inspect", "daemon_reported_missing_image"),
            ("Docker reported permission denied; details redacted", "other", "permission_denied"),
            ("Docker reported daemon unavailable; details redacted", "other", "daemon_unavailable"),
            ("secret-token", "image_inspect", "unexpected_failure"),
            ("secret-token", "other", "engine_verification_failed"),
        ):
            with self.subTest(expected=expected):
                project = mock.Mock()
                project._docker.side_effect = provisioning.CommandFailure("docker", 1, stderr=stderr, operation=operation)
                result = diagnostic.inspect_reference(project, diagnostic.PINNED)
                self.assertEqual(expected, result["classification"])
                self.assertEqual(1, result["exit_status"])
                self.assertNotIn("secret-token", json.dumps(result))

    def test_timeout_is_recorded_without_command_or_stderr(self):
        project = mock.Mock()
        project._docker.side_effect = subprocess.TimeoutExpired(["docker", "secret-token"], 20, stderr=b"secret-token")
        result = diagnostic.inspect_reference(project, diagnostic.PINNED)
        self.assertEqual({"classification": "timeout", "exit_status": None, "stderr": ""}, result)
        self.assertNotIn("secret-token", json.dumps(result))

    def test_pinned_preflight_failure_is_classified_without_probe_creation(self):
        reference = "python:3.12-slim@" + diagnostic.DIGEST
        cases = (
            (provisioning.CommandFailure("docker", 1, stderr="Error: No such image: " + reference,
                                         operation="image_inspect"), "daemon_reported_missing_image", 1),
            (provisioning.CommandFailure("docker", 2, stderr="Docker reported permission denied; details redacted"),
             "permission_denied", 2),
            (provisioning.CommandFailure("docker", 1, stderr="private-secret", operation="image_inspect"),
             "unexpected_failure", 1),
        )
        for error, kind, status in cases:
            with self.subTest(kind=kind), mock.patch.object(build, "InstalledProject") as cls:
                executor = build.DockerExecutor(socket_path=diagnostic.SOCKET, engine_id=diagnostic.ENGINE,
                                                authorization="approved", build_authorization="disposable-linux-image-build-approved")
                executor.temp = object()
                cls.return_value._docker.side_effect = error
                with self.assertRaises(build.ImageInspectionFailure) as caught:
                    executor.preflight(base_digest=diagnostic.DIGEST)
                self.assertEqual(kind, caught.exception.diagnostic["classification"])
                self.assertEqual(status, caught.exception.diagnostic["exit_status"])
                self.assertNotIn("private-secret", json.dumps(caught.exception.diagnostic))
                self.assertEqual(1, cls.return_value._docker.call_count)

    def test_pinned_preflight_reports_successful_metadata_mismatch(self):
        with mock.patch.object(build, "InstalledProject") as cls:
            executor = build.DockerExecutor(socket_path=diagnostic.SOCKET, engine_id=diagnostic.ENGINE,
                                            authorization="approved", build_authorization="disposable-linux-image-build-approved")
            executor.temp = object()
            cls.return_value._docker.return_value = json.dumps([{"Id": "sha256:" + "b" * 64,
                                                                  "Os": "linux", "RepoDigests": []}])
            with self.assertRaises(build.ImageInspectionFailure) as caught:
                executor.preflight(base_digest=diagnostic.DIGEST)
            self.assertEqual({"classification": "reference_mismatch", "exit_status": 0, "stderr": ""},
                             caught.exception.diagnostic)
            self.assertEqual(1, cls.return_value._docker.call_count)
            cls.return_value._docker.return_value = json.dumps([{"Id": "sha256:" + "b" * 64, "Os": "linux",
                                                                  "RepoDigests": ["private.example/secret@" + diagnostic.DIGEST]}])
            with self.assertRaises(build.ImageInspectionFailure) as wrong_repository:
                executor.preflight(base_digest=diagnostic.DIGEST)
            self.assertEqual("reference_mismatch", wrong_repository.exception.diagnostic["classification"])
            self.assertEqual(2, cls.return_value._docker.call_count)

    def test_pinned_preflight_timeout_does_not_retain_command_or_stderr(self):
        with mock.patch.object(build, "InstalledProject") as cls:
            executor = build.DockerExecutor(socket_path=diagnostic.SOCKET, engine_id=diagnostic.ENGINE,
                                            authorization="approved", build_authorization="disposable-linux-image-build-approved")
            executor.temp = object()
            cls.return_value._docker.side_effect = subprocess.TimeoutExpired(["docker", "secret-token"], 20, stderr=b"secret-token")
            with self.assertRaises(build.ImageInspectionFailure) as caught:
                executor.preflight(base_digest=diagnostic.DIGEST)
            self.assertEqual({"classification": "timeout", "exit_status": None, "stderr": ""}, caught.exception.diagnostic)
            self.assertNotIn("secret-token", str(caught.exception))

    def test_preflight_report_retains_safe_failure(self):
        args = SimpleNamespace(preflight_only=True, authorize_engine_preflight=True, base_digest=diagnostic.DIGEST,
                               socket=diagnostic.SOCKET, engine_id=diagnostic.ENGINE, zai_python=None,
                               zai_output_dir=None, authorize_zai_source_reads=False, evidence_dir="/tmp/kilo/mock")
        evidence = mock.Mock(data={"preflight": {}})
        executor = mock.MagicMock()
        executor.__enter__.return_value = executor
        executor.preflight.side_effect = build.ImageInspectionFailure("permission_denied", exit_status=1,
                                                                       stderr="Docker reported permission denied; details redacted")
        with mock.patch.object(runner, "Evidence", return_value=evidence), \
             mock.patch.object(runner, "_discover_engine", return_value=diagnostic.ENGINE), \
             mock.patch.object(runner.build, "DockerExecutor", return_value=executor):
            with self.assertRaises(build.ImageInspectionFailure):
                runner.run(args)
        self.assertEqual("failed", evidence.data["status"])
        self.assertEqual("permission_denied", evidence.data["preflight"]["image_inspection"]["classification"])
        self.assertEqual(1, evidence.data["preflight"]["image_inspection"]["exit_status"])

    def test_unapproved_or_wrong_endpoint_performs_no_docker(self):
        args = SimpleNamespace(authorize_read_only_image_inspection=False, socket=diagnostic.SOCKET,
                               engine_id=diagnostic.ENGINE, base_digest=diagnostic.DIGEST)
        with mock.patch.object(diagnostic, "InstalledProject") as project:
            with self.assertRaises(ValueError):
                diagnostic.run(args)
            args.authorize_read_only_image_inspection = True
            args.socket = "/another.sock"
            with self.assertRaises(ValueError):
                diagnostic.run(args)
        project.assert_not_called()

    def test_unexpected_inspection_stops_before_second_reference(self):
        args = SimpleNamespace(authorize_read_only_image_inspection=True, socket=diagnostic.SOCKET,
                               engine_id=diagnostic.ENGINE, base_digest=diagnostic.DIGEST,
                               evidence_dir="/tmp/kilo/mock")
        evidence = mock.Mock(data={"image_inspection": {}})
        failure = {"classification": "unexpected_failure", "exit_status": 1,
                   "stderr": "Docker stderr redacted: unrecognized diagnostic"}
        with mock.patch.object(diagnostic, "Evidence", return_value=evidence), \
             mock.patch.object(diagnostic, "InstalledProject"), \
             mock.patch.object(diagnostic, "inspect_reference", return_value=failure) as inspect:
            with self.assertRaisesRegex(ValueError, "inspection or engine"):
                diagnostic.run(args)
        self.assertEqual(1, inspect.call_count)
        self.assertEqual("failed", evidence.data["status"])

    def test_combined_report_refuses_more_than_sixteen_digests(self):
        args = SimpleNamespace(authorize_read_only_image_inspection=True, socket=diagnostic.SOCKET,
                               engine_id=diagnostic.ENGINE, base_digest=diagnostic.DIGEST,
                               evidence_dir="/tmp/kilo/mock")
        evidence = mock.Mock(data={"image_inspection": {}})
        responses = [
            {"classification": "inspected", "python_repository_digests": ["sha256:" + f"{n:064x}" for n in range(16)]},
            {"classification": "inspected", "python_repository_digests": ["sha256:" + f"{16:064x}"]},
        ]
        with mock.patch.object(diagnostic, "Evidence", return_value=evidence), \
             mock.patch.object(diagnostic, "InstalledProject"), \
             mock.patch.object(diagnostic, "inspect_reference", side_effect=responses):
            with self.assertRaisesRegex(ValueError, "combined Python repository digest limit"):
                diagnostic.run(args)
        self.assertEqual("failed", evidence.data["status"])
        self.assertNotIn("tag", evidence.data["image_inspection"])

    def test_reference_mismatch_has_distinct_terminal_status(self):
        args = SimpleNamespace(authorize_read_only_image_inspection=True, socket=diagnostic.SOCKET,
                               engine_id=diagnostic.ENGINE, base_digest=diagnostic.DIGEST,
                               evidence_dir="/tmp/kilo/mock")
        evidence = mock.Mock(data={"image_inspection": {}})
        responses = [{"classification": "reference_mismatch", "python_repository_digests": []},
                     {"classification": "inspected", "python_repository_digests": []}]
        with mock.patch.object(diagnostic, "Evidence", return_value=evidence), \
             mock.patch.object(diagnostic, "InstalledProject"), \
             mock.patch.object(diagnostic, "inspect_reference", side_effect=responses):
            diagnostic.run(args)
        self.assertEqual("diagnostic_complete_reference_mismatch", evidence.data["status"])


if __name__ == "__main__":
    unittest.main()
