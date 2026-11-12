"""Offline SR/MI store checks; not installed or container acceptance.

These tests use the actual available SR and MI Python packages, and disposable
temporary directories. Copying a closed local store is not a Docker-volume
backup procedure and does not prove an image upgrade or deployment rollback.
"""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import mi_publication_fixture as fixture


@unittest.skipUnless(
    importlib.util.find_spec("scarcity_router") and importlib.util.find_spec("model_intelligence"),
    "SR and MI packages are required; source provenance must be checked separately",
)
class OfflineStoreTests(unittest.TestCase):
    def setUp(self):
        from scarcity_router.mi_server_config import load_mi_server_config
        from scarcity_router.server_store import ServerStore

        self.load = load_mi_server_config
        self.store_type = ServerStore
        temporary = tempfile.TemporaryDirectory(prefix="foundry-sr-mi-offline-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.publisher = self.root / "publisher"
        self.publisher.mkdir()
        self.publication = self.root / "publication.json"
        trust = fixture.publish_fixture(self.publisher, publication_path=str(self.publication))
        self.publication.write_bytes((self.publisher / (fixture.EXPECTED_SHA256 + ".json")).read_bytes())
        self.trust = self.root / "trust.json"
        self.trust.write_text(json.dumps(trust), encoding="utf-8")
        self.state = self.root / "state"

    def test_failed_reload_keeps_active_and_durable_cut(self):
        store = self.store_type.open(self.state)
        try:
            server = self.load(self.trust).activate(store)
            original_reference = server.reference
            original_digest = store.current_mi_cut_digest()
            original_bytes = self.publication.read_bytes()
            self.publication.write_bytes(b"invalid publication")
            with self.assertRaisesRegex(ValueError, "mi_publication_activation_failed"):
                server.reload(self.trust)
            self.assertEqual(original_reference, server.reference)
            self.assertEqual(original_digest, store.current_mi_cut_digest())
            self.assertEqual(original_reference, server.admission(fixture.EVALUATED_AT).expected)
            self.publication.write_bytes(original_bytes)
        finally:
            store.close()

        reopened = self.store_type.open(self.state)
        try:
            self.assertEqual(original_digest, reopened.current_mi_cut_digest())
            self.assertEqual(original_reference, self.load(self.trust).activate(reopened).reference)
        finally:
            reopened.close()

    def test_native_preflight_and_actual_mi_activation_use_same_fixture(self):
        directory = self.root / "native-mi"
        directory.mkdir(mode=0o750)
        directory.chmod(0o750)
        publication = directory / "publication.json"
        publication.write_bytes(self.publication.read_bytes())
        trust = json.loads(self.trust.read_text(encoding="utf-8"))
        trust["publication"] = str(publication)
        config = directory / "trust.json"
        config.write_text(json.dumps(trust), encoding="utf-8")
        for path in (publication, config):
            path.chmod(0o640)
        script = Path(__file__).resolve().parents[1] / "scripts" / "local_runtime.py"
        environment = {"HOME": str(self.root), "PATH": os.defpath, "PYTHONNOUSERSITE": "1",
                       "PYTHONDONTWRITEBYTECODE": "1", "FOUNDRY_MI_DIR": str(directory),
                       "FOUNDRY_MI_SHA256": fixture.EXPECTED_SHA256}
        for safe_path in (False, True):
            with self.subTest(safe_path=safe_path):
                env = {**environment, **({"PYTHONSAFEPATH": "1"} if safe_path else {})}
                result = subprocess.run([sys.executable, "-B", str(script), "--native-mi-check"],
                                        env=env, capture_output=True, text=True, timeout=30, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
        store = self.store_type.open(self.state)
        try:
            server = self.load(config).activate(store)
            self.assertEqual(fixture.EXPECTED_SHA256, server.reference.sha256)
        finally:
            store.close()

    def test_closed_store_snapshot_restores_to_separate_directory(self):
        store = self.store_type.open(self.state)
        try:
            original = self.load(self.trust).activate(store)
            expected_digest = store.current_mi_cut_digest()
            expected_reference = original.reference
        finally:
            store.close()

        snapshot = self.root / "snapshot"
        restored = self.root / "restored"
        shutil.copytree(self.state, snapshot)
        shutil.copytree(snapshot, restored)
        copy = self.store_type.open(restored)
        try:
            self.assertEqual(expected_digest, copy.current_mi_cut_digest())
            self.assertEqual(expected_reference, self.load(self.trust).activate(copy).reference)
        finally:
            copy.close()

    def test_binding_only_reload_is_durable_and_invalidates_other_instance(self):
        store = self.store_type.open(self.state)
        second_store = self.store_type.open(self.state)
        try:
            server = self.load(self.trust).activate(store)
            second = self.load(self.trust).activate(second_store)
            before = store.current_mi_cut_digest()
            document = json.loads(self.trust.read_text(encoding="utf-8"))
            binding = json.loads(json.dumps(document["bindings"][0]))
            binding["identity"]["variant"] = "another-test-variant"
            document["bindings"].append(binding)
            self.trust.write_text(json.dumps(document), encoding="utf-8")
            server.reload(self.trust)
            after = store.current_mi_cut_digest()
            self.assertNotEqual(before, after)
            self.assertEqual(2, len(server.admission(fixture.EVALUATED_AT).captured[1]))
            with self.assertRaisesRegex(ValueError, "mi_cut_changed_restart_or_reload"):
                second.admission(fixture.EVALUATED_AT)
        finally:
            second_store.close()
            store.close()

        reopened = self.store_type.open(self.state)
        try:
            self.assertEqual(after, reopened.current_mi_cut_digest())
            self.assertEqual(2, len(self.load(self.trust).activate(reopened).admission(
                fixture.EVALUATED_AT).captured[1]))
        finally:
            reopened.close()

    def test_controlled_variant_transition_contract(self):
        for kind in ("stale", "withdrawn", "incompatible"):
            with self.subTest(kind=kind):
                state = self.root / ("state-" + kind)
                producer = self.root / ("producer-" + kind)
                producer.mkdir()
                original_data = self.publication.read_bytes()
                original_trust = self.trust.read_bytes()
                store = self.store_type.open(state)
                try:
                    server = self.load(self.trust).activate(store)
                    prior = store.current_mi_cut_digest()
                    trust = fixture.publish_fixture(producer, publication_path=str(self.publication), kind=kind)
                    self.publication.write_bytes((producer / (fixture.VARIANT_SHA256[kind] + ".json")).read_bytes())
                    self.trust.write_text(json.dumps(trust), encoding="utf-8")
                    if kind in ("stale", "incompatible"):
                        with self.assertRaisesRegex(ValueError, "mi_publication_activation_failed"):
                            server.reload(self.trust)
                        self.assertEqual(prior, store.current_mi_cut_digest())
                    else:
                        server.reload(self.trust)
                        self.assertNotEqual(prior, store.current_mi_cut_digest())
                        self.assertEqual(fixture.VARIANT_SHA256[kind], server.reference.sha256)
                finally:
                    store.close()
                    self.publication.write_bytes(original_data)
                    self.trust.write_bytes(original_trust)

    def test_incompatible_scope_fails_before_startup_activation(self):
        store = self.store_type.open(self.state)
        try:
            self.load(self.trust).activate(store)
            prior = store.current_mi_cut_digest()
            document = json.loads(self.trust.read_text(encoding="utf-8"))
            document["scope"]["scope_id"] = "foundry-incompatible-fixture/1"
            self.trust.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "mi_publication_activation_failed"):
                self.load(self.trust).activate(store)
            self.assertEqual(prior, store.current_mi_cut_digest())
        finally:
            store.close()

    def test_synthetic_cut_admission_and_negative_variants(self):
        from scarcity_router.selection_types import (
            CapabilityAssessment, CapabilityAssessments, CapacityScopeRef, ModelCatalog,
            ModelCatalogEntry, ModelHardProperties, ModelIdentity,
        )

        unknown = CapabilityAssessment(None)
        identity = ModelIdentity("openai", "gpt-6-sol", "high")
        catalog = ModelCatalog(1, "2026-10-26", (ModelCatalogEntry(
            identity=identity, display_name="Controlled synthetic model",
            hard_properties=ModelHardProperties(supports_reasoning_mode=True,
                                                input_context_tokens=8192, output_tokens=8192),
            capabilities=CapabilityAssessments(unknown, unknown, unknown, unknown, unknown, unknown),
            capacity_bindings=(CapacityScopeRef("openai", "synthetic"),), reasoning_effort="high",
        ),))
        for kind in ("fresh", "stale", "withdrawn"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                producer = root / "producer"
                producer.mkdir()
                publication = root / "publication.json"
                trust = fixture.publish_fixture(producer, publication_path=str(publication), kind=kind)
                digest = trust["reference"]["sha256"]
                publication.write_bytes((producer / (digest + ".json")).read_bytes())
                config = root / "trust.json"
                config.write_text(json.dumps(trust), encoding="utf-8")
                store = self.store_type.open(root / "state")
                try:
                    admission = self.load(config).activate(store).admission(fixture.EVALUATED_AT)
                    projected, blocked = admission.prepare(catalog, fixture.EVALUATED_AT)
                    if kind == "fresh":
                        self.assertNotIn(identity, blocked)
                        self.assertEqual(4096, projected.entries[0].hard_properties.input_context_tokens)
                    else:
                        self.assertIn(identity, blocked)
                finally:
                    store.close()


if __name__ == "__main__":
    unittest.main()
