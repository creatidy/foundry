"""Offline negative boundary tests; no real source acquisition."""

import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import zai_real_source_check as check


class Claim:
    def __init__(self, subject, observation_id="observation"):
        self.subject = subject
        self.observation_id = observation_id


class RealSourceBoundaryTests(unittest.TestCase):
    def test_requires_authorization_before_directory_or_subprocess(self):
        with mock.patch.object(check, "check_directory") as directory, mock.patch.object(check.subprocess, "run") as process:
            with self.assertRaises(ValueError):
                check.run("/not-inspected", authorization="")
            directory.assert_not_called()
            process.assert_not_called()

    def test_rejects_changed_source_or_bound(self):
        sources = [SimpleNamespace(source_id=a, reference=b, max_bytes=c) for a, b, c in check.EXPECTED_SOURCES]
        for replacement in (SimpleNamespace(source_id="api", reference="https://attacker.invalid/", max_bytes=551),
                            SimpleNamespace(source_id="api", reference=check.EXPECTED_SOURCES[1][1], max_bytes=552)):
            altered = sources.copy()
            altered[1] = replacement
            with self.assertRaises(ValueError):
                check.verify_sources(altered)
        with self.assertRaises(ValueError):
            check.verify_sources(sources[:-1])

    def test_rejects_wrong_distribution_and_editable_provenance(self):
        dist = mock.Mock()
        record = {"url": check.MI_URL, "vcs_info": {"vcs": "git", "commit_id": check.MI_REVISION}}
        for altered in ({**record, "vcs_info": {"vcs": "git", "commit_id": "0" * 40}},
                        {**record, "dir_info": {"editable": True}},
                        {**record, "url": "https://attacker.invalid/mi.git"}):
            dist.read_text.return_value = json.dumps(altered)
            with mock.patch.object(check.importlib.metadata, "distribution", return_value=dist):
                with self.assertRaises(ValueError):
                    check.verify_distribution()

    def test_missing_scope_effort_and_freshness_are_not_promoted(self):
        scope = SimpleNamespace(channel=None, configuration=(("adapter", "fixed"),))
        subject = SimpleNamespace(channel="zai-api", configuration=None)
        origin = SimpleNamespace(observation_id="observation", fresh_until=None)
        public = SimpleNamespace(applicability=scope,
                                 evidence=SimpleNamespace(observations=[origin], claims=[Claim(subject)]))
        result = check.assess(public, scope, Claim)
        self.assertEqual("not-established", result["router_applicability"])
        self.assertIsNone(result["router_binding"])
        self.assertTrue(all(value == 1 for value in result["blockers"].values()))
        with self.assertRaises(ValueError):
            check.assess(public, SimpleNamespace(channel="other"), Claim)
        public.evidence.observations = []
        with self.assertRaises(ValueError):
            check.assess(public, scope, Claim)

    def test_rejects_nonprivate_nonempty_and_symlink_directories(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "output"
            target.mkdir(mode=0o700)
            (target / "existing").write_text("do not overwrite")
            with self.assertRaises(ValueError):
                check.check_directory(target)
            (target / "existing").unlink()
            target.chmod(0o755)
            with self.assertRaises(ValueError):
                check.check_directory(target)
            target.chmod(0o700)
            link = root / "link"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                check.check_directory(link)

    def test_failed_worker_never_returns_success_or_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(check, "_require_verified_host_mi"), mock.patch.object(check.subprocess, "run", return_value=SimpleNamespace(
                    returncode=1, stdout=b"", stderr=b"secret source error")):
                with self.assertRaisesRegex(RuntimeError, "source publication subprocess failed") as error:
                    check.run(temp, authorization=check.AUTHORIZATION)
            self.assertNotIn("secret", str(error.exception))

    def test_worker_success_without_reference_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            with mock.patch.object(check, "_require_verified_host_mi"), mock.patch.object(check.subprocess, "run", return_value=SimpleNamespace(
                    returncode=0, stdout=b"{}", stderr=b"")):
                with self.assertRaisesRegex(ValueError, "invalid source publication subprocess result"):
                    check.run(temp, authorization=check.AUTHORIZATION)

    def test_gate_precedes_worker_launch_and_mi_metadata(self):
        with mock.patch.object(check, "check_directory") as directory, \
             mock.patch.object(check.subprocess, "run") as process, \
             mock.patch.object(check, "verify_distribution") as metadata:
            with self.assertRaisesRegex(RuntimeError, "host MI execution disabled"):
                check.run("/not-inspected", authorization=check.AUTHORIZATION)
            with self.assertRaisesRegex(RuntimeError, "host MI execution disabled"):
                check._acquire("/not-inspected")
            directory.assert_not_called()
            process.assert_not_called()
            metadata.assert_not_called()


if __name__ == "__main__":
    unittest.main()
