"""Offline checks for the controlled MI publication fixture."""

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

import mi_publication_fixture as fixture


@unittest.skipUnless(importlib.util.find_spec("model_intelligence"), "MI package is unavailable; provenance must be verified separately")
class ControlledPublicationTests(unittest.TestCase):
    def test_deterministic_publication_and_reference(self):
        from model_intelligence.contract import decode_public_evidence
        from model_intelligence.publication import CutReference

        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            results = []
            for directory in (Path(first), Path(second)):
                trust = fixture.publish_fixture(directory, publication_path="/run/foundry/mi/publication.json")
                data = (directory / (fixture.EXPECTED_SHA256 + ".json")).read_bytes()
                self.assertEqual(fixture.EXPECTED_SHA256, hashlib.sha256(data).hexdigest())
                self.assertEqual(fixture.EXPECTED_SHA256, (directory / "current").read_text())
                reference = CutReference(**trust["reference"])
                decoded = decode_public_evidence(data, reference, max_bytes=fixture.MAX_BYTES)
                self.assertEqual(fixture.evidence(), decoded)
                self.assertEqual("gpt-6-sol", trust["bindings"][0]["identity"]["model"])
                self.assertEqual("worker_bridged", trust["scope"]["channel"])
                self.assertEqual("high", trust["scope"]["configuration"]["reasoning_effort"])
                self.assertEqual(trust, fixture.publish_fixture(directory, publication_path=trust["publication"]))
                results.append((trust, data))
            self.assertEqual(results[0], results[1])

    def test_corrupt_existing_artifact_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture.publish_fixture(root, publication_path="/run/foundry/mi/publication.json")
            artifact = root / (fixture.EXPECTED_SHA256 + ".json")
            artifact.write_bytes(b"corrupt")
            with self.assertRaises(ValueError):
                fixture.publish_fixture(root, publication_path="/run/foundry/mi/publication.json")
            self.assertEqual(b"corrupt", artifact.read_bytes())
            self.assertEqual(fixture.EXPECTED_SHA256, (root / "current").read_text())

    def test_negative_cuts_have_independently_fixed_references(self):
        from model_intelligence.contract import decode_public_evidence
        from model_intelligence.publication import CutReference

        for kind, expected in fixture.VARIANT_SHA256.items():
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                trust = fixture.publish_fixture(root, publication_path="/run/foundry/mi/publication.json", kind=kind)
                data = (root / (expected + ".json")).read_bytes()
                self.assertEqual(expected, hashlib.sha256(data).hexdigest())
                self.assertEqual(expected, trust["reference"]["sha256"])
                decoded = decode_public_evidence(data, CutReference(**trust["reference"]), max_bytes=fixture.MAX_BYTES)
                self.assertEqual(fixture.evidence_variant(kind), decoded)
                if kind == "stale":
                    self.assertTrue(decoded.evidence.observations[0].stale(fixture.EVALUATED_AT))
                elif kind == "withdrawn":
                    self.assertTrue(decoded.notices[0].reported_critical)
                    self.assertEqual(frozenset({"statement:foundry-claim-1"}), decoded.notices[0].targets)
                else:
                    self.assertNotEqual(fixture.evidence().applicability, decoded.applicability)

    def test_bad_predeclared_reference_rejects_before_writes(self):
        original = fixture.EXPECTED_SHA256
        try:
            fixture.EXPECTED_SHA256 = "0" * 64
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with self.assertRaisesRegex(ValueError, "controlled-fixture-reference-mismatch"):
                    fixture.publish_fixture(root, publication_path="/run/foundry/mi/publication.json")
                self.assertEqual([], list(root.iterdir()))
        finally:
            fixture.EXPECTED_SHA256 = original


if __name__ == "__main__":
    unittest.main()
