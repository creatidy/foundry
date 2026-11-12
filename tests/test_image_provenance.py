import copy
import hashlib
from pathlib import Path
import unittest
from unittest.mock import Mock

import image_provenance as p


class ImageProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.source = (Path(__file__).resolve().parents[1] / "Dockerfile.mi").read_bytes()
        self.base = "sha256:" + "a" * 64
        self.image = "sha256:" + "b" * 64
        self.sr = {"scarcity_router/__init__.py": hashlib.sha256(b"sr").hexdigest()}
        self.mi = {"model_intelligence/__init__.py": hashlib.sha256(b"mi").hexdigest()}
        self.evidence = {"image_id": self.image, "os": "linux", "base_digest": self.base,
                         "sr_revision": p.NEW_SR, "mi_url": p.MI_URL, "mi_revision": p.MI,
                         "mi_vcs": "git", "mi_editable": False,
                         "sr_files": self.sr.copy(), "mi_files": self.mi.copy(),
                         "static_package_checks_passed": True}
        self.executor = Mock()
        self.executor.build.return_value = self.image
        self.executor.inspect.return_value = self.evidence

    def verify(self, **kwargs):
        values = dict(executor=self.executor, source=self.source, revision=p.NEW_SR,
                      base_digest=self.base, expected_sr=self.sr, expected_mi=self.mi)
        values.update(kwargs)
        return p.verify_build(**values)

    def test_all_reviewed_sources_derive_both_historical_definitions(self):
        actual = p.product_revision(self.source)
        sources = {revision: self.source.replace(actual.encode(), revision.encode())
                   for revision in p.DOCKERFILE_SHA256}
        definitions = {}
        for source_revision, source in sources.items():
            self.assertEqual(p.DOCKERFILE_SHA256[source_revision], hashlib.sha256(source).hexdigest())
            self.assertEqual(source_revision, p.product_revision(source))
            for revision in p.TEST_SR_REVISIONS:
                with self.subTest(source=source_revision, target=revision):
                    definition = p.dockerfile(source, revision, self.base)
                    if revision in definitions:
                        self.assertEqual(definitions[revision], definition)
                    definitions[revision] = definition
                    text = definition.decode()
                    self.assertEqual(text.count(revision), 2)
                    self.assertNotIn(p.NEW_SR if revision == p.OLD_SR else p.OLD_SR, text)
                    self.assertEqual(text.count("FROM python:3.12-slim@" + self.base), 2)
                    for expected in (p.MI, "pip install --no-compile", "PYTHONDONTWRITEBYTECODE=1",
                                     "PYTHONSAFEPATH=1", "PYTHONNOUSERSITE=1"):
                        self.assertIn(expected, text)
        self.assertNotEqual(definitions[p.OLD_SR], definitions[p.NEW_SR])

    def test_mock_build_and_inspect_are_bounded(self):
        self.assertEqual(self.verify(), self.image)
        self.executor.build.assert_called_once_with(dockerfile=p.dockerfile(self.source, p.NEW_SR, self.base),
                                                    timeout=p.MAX_SECONDS, output_limit=p.MAX_OUTPUT)
        self.executor.inspect.assert_called_once_with(image_id=self.image, timeout=p.MAX_SECONDS,
                                                      output_limit=p.MAX_OUTPUT)

    def test_unknown_build_inputs_fail_before_execution(self):
        source_revision = p.product_revision(self.source)
        other = p.NEW_SR if source_revision == p.OLD_SR else p.OLD_SR
        for overrides in ({"source": self.source + b"\n"},
                          {"source": self.source.replace(source_revision.encode(), other.encode(), 1)},
                          {"source": self.source.replace(b"FROM ", b"FROM malicious/", 1)},
                          {"source": self.source + b"\xff"}, {"source": self.source.decode()},
                          {"revision": "0" * 40},
                          {"base_digest": "sha256:" + "A" * 64}, {"expected_sr": {}},
                          {"expected_mi": {"../x": "a" * 64}}):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                self.verify(**overrides)
        self.executor.build.assert_not_called()

    def test_mismatched_evidence_fails_closed(self):
        for field, value in (("image_id", "sha256:" + "c" * 64), ("os", "windows"),
                             ("base_digest", "sha256:" + "c" * 64), ("sr_revision", p.OLD_SR),
                             ("mi_url", "https://example.org/mi"), ("mi_revision", "0" * 40),
                             ("mi_vcs", "hg"), ("mi_editable", True),
                             ("static_package_checks_passed", False), ("static_package_checks_passed", 1),
                             ("sr_files", {"scarcity_router/__init__.py": "f" * 64}),
                             ("mi_files", {**self.mi, "extra.py": "f" * 64})):
            evidence = copy.deepcopy(self.evidence)
            evidence[field] = value
            self.executor.inspect.return_value = evidence
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify()
        self.executor.inspect.return_value = {**self.evidence, "unexpected": True}
        with self.assertRaises(ValueError):
            self.verify()
        old = dict(self.evidence)
        del old["static_package_checks_passed"]
        old["package_import_checks_passed"] = True
        self.executor.inspect.return_value = old
        with self.assertRaisesRegex(ValueError, "incomplete or unknown"):
            self.verify()

    def test_bad_build_id_stops_inspection(self):
        self.executor.build.return_value = "latest"
        with self.assertRaises(ValueError):
            self.verify()
        self.executor.inspect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
