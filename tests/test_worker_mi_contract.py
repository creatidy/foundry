"""Offline checks for the externally provisioned worker harness contract."""
import base64
import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import worker_mi_acceptance as worker
from worker_mi_acceptance import WorkerConfig, _assert_audit, _assert_private, _assert_retained, _blocked_source, _tampered, _verify_payload


class WorkerConfigTests(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec("scarcity_router"), "SR package unavailable")
    def test_gateway_pin_explicitly_carries_effort(self):
        from scarcity_router.gateway_coordinator import parse_pinned_reference

        pin = parse_pinned_reference(f"sr-pin:foundry-worker-a:gpt-6-sol:high/{worker.MODEL}@rd-fixture")
        self.assertEqual("high", pin.model.variant)
        self.assertEqual("high", pin.reasoning_effort)
        self.assertEqual("rd-fixture", pin.decision_id)

    def test_explicit_loopback_isolation_and_existing_paths_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ca = root / "ca.pem"
            ca.touch()
            exchange = lambda *_: (200, {})
            callbacks = {"audit_records": lambda: [], "mi_receipt": lambda *_: None,
                         "mi_receipt_by_id": lambda *_: None, "mi_cut": lambda *_: None}
            WorkerConfig("127.0.0.1", 1234, ca, root, exchange, True, **callbacks).validate()
            for missing in callbacks:
                with self.subTest(missing=missing):
                    incomplete = {**callbacks, missing: None}
                    with self.assertRaises(ValueError):
                        WorkerConfig("127.0.0.1", 1234, ca, root, exchange, True, **incomplete).validate()
            for host, port, isolated in (("example.com", 1234, True), ("192.0.2.1", 1234, True),
                                         ("::1", 1234, True), ("127.0.0.1", True, True),
                                         ("127.0.0.1", 0, True), ("127.0.0.1", 1234, False)):
                with self.subTest(host=host, port=port, isolated=isolated):
                    with self.assertRaises(ValueError):
                        WorkerConfig(host, port, ca, root, exchange, isolated, **callbacks).validate()

    def test_source_grant_covers_each_supported_effort(self):
        blocked = _blocked_source("foundry-worker-a")
        self.assertEqual(len(blocked), 6)
        self.assertEqual(blocked, sorted(set(blocked)))
        self.assertIn("foundry-worker-a:gpt-6-sol:high", blocked)
        with self.assertRaises(ValueError):
            _blocked_source("other")

    def test_existing_fixture_sources_fail_before_pairing(self):
        worker._assert_unused_sources([{"source_id": "other"}])
        for sources in (None, [None], [{"source_id": "foundry-worker-a"}], [{"source_id": "foundry-worker-b"}]):
            with self.subTest(sources=sources), self.assertRaises(ValueError):
                worker._assert_unused_sources(sources)

    def test_missing_projection_contract_fails_closed(self):
        class OldServer:
            pass

        class CurrentServer:
            def retain_projection(self):
                pass

            def verify_projection(self):
                pass

        with self.assertRaises(RuntimeError):
            worker._require_projection_support(OldServer)
        worker._require_projection_support(CurrentServer)

    def test_result_case_allowlists_synthetic_fields_and_identifiers(self):
        secret = "secret-cookie-token-prompt-private-context"
        source = "foundry-worker-a"
        response = {"route": {"decision_id": "rd-" + "1" * 32,
                              "target": {"resource": {"resource_id": source + ":gpt-6-sol:high", "private": secret},
                                         "model": {"provider": "openai", "model": "gpt-6-sol", "variant": "high",
                                                   "private": secret}, "reasoning_effort": "high"}},
                    "mi_projection": {"request_id": "2" * 32}, "private": secret}
        record = {"request_id": "chatcmpl-" + "3" * 32, "decision_id": "rd-" + "1" * 32, "private": secret}
        args = (source, "client-1234abcd", response, record, "4" * 64, "5" * 64, "6" * 64)
        result = worker._result_case(*args)
        self.assertNotIn(secret, json.dumps(result))
        self.assertEqual(result["projection_receipt_sha256"], "5" * 64)
        self.assertEqual(result["gateway_request_id"], record["request_id"])
        for index in (1, 4, 5, 6):
            changed = list(args)
            changed[index] = secret
            with self.subTest(index=index), self.assertRaises(AssertionError):
                worker._result_case(*changed)
        changed = copy.deepcopy(response)
        changed["route"]["decision_id"] = secret
        with self.assertRaises(AssertionError):
            worker._result_case(source, args[1], changed, *args[3:])

    def test_projection_mutations_and_privacy_check(self):
        response = {"mi_projection": {"schema_version": 1, "request_id": "original"},
                    "route": {"status": "selected"}, "decision": {"a": 1},
                    "mi_utilization": {"identifier": "urn:mi:utilization:sha256:123"}}
        original = _verify_payload(response)
        changes = _tampered(original)
        self.assertEqual(len(changes), 4)
        for field, changed in zip(("projection", "route", "decision", "mi_utilization"), changes):
            self.assertNotEqual(original[field], changed[field])
            self.assertTrue(all(original[other] == changed[other] for other in original if other != field))
        _assert_private({"resource": "foundry-worker-b:gpt-6-sol:high"}, "foundry-worker-a")
        with self.assertRaises(AssertionError):
            _assert_private({"nested": ["foundry-worker-a:gpt-6-sol:low"]}, "foundry-worker-a")

    def test_retained_chain_rejects_missing_and_wrong_evidence(self):
        cut = json.dumps({"format_version": 1, "payload_schema": "synthetic"}).encode()
        cut_ref = {"format_version": 1, "payload_schema": "synthetic", "sha256": hashlib.sha256(cut).hexdigest()}
        decision, context = b'{"decision":true}', b'{"context":true}'
        evaluated = "2026-10-26T12:00:00+00:00"
        payload = {"cut": {"format": 1, "schema": "synthetic", "sha256": cut_ref["sha256"]},
                   "evaluated_at": evaluated, "decision_sha256": hashlib.sha256(decision).hexdigest(),
                   "context_sha256": hashlib.sha256(context).hexdigest()}
        manifest = json.dumps({"format_version": 1, "payload_schema": "mi.utilization-working/1",
                               "scope": "local-utilization", "members": [], "sources": [],
                               "payload": json.dumps(payload)}).encode()
        encode = lambda value: base64.b64encode(value).decode()
        receipt = {"cut_reference": cut_ref, "cut_blob_sha256": cut_ref["sha256"], "evaluated_at": evaluated,
                   "decision": encode(decision), "context": encode(context), "utilization": encode(manifest)}
        identifier = hashlib.sha256(manifest).hexdigest()
        reference = {"source": "model_intelligence", "version": "mi.utilization-working/1",
                     "identifier": "urn:mi:utilization:sha256:" + identifier}
        with mock.patch.object(worker, "EXPECTED_CUT", cut_ref):
            _assert_retained(receipt, lambda _: cut, reference, identifier)
            for lookup in (lambda _: None, lambda _: b"wrong"):
                with self.assertRaises(AssertionError):
                    _assert_retained(receipt, lookup, reference, identifier)
            for field, value in (("cut_reference", None), ("cut_blob_sha256", "0" * 64),
                                 ("decision", encode(b"wrong")), ("context", encode(b"wrong")),
                                 ("utilization", "invalid!")):
                changed = copy.deepcopy(receipt)
                changed[field] = value
                with self.subTest(field=field), self.assertRaises(AssertionError):
                    _assert_retained(changed, lambda _: cut, reference, identifier)
            with self.assertRaises(AssertionError):
                _assert_retained(receipt, lambda _: cut, {**reference, "identifier": "wrong"}, identifier)
            with self.assertRaises(AssertionError):
                _assert_retained(receipt, lambda _: cut, reference, "0" * 64)

    def test_audit_requires_exact_selected_and_executed_identity(self):
        target = {"resource": {"resource_id": "r"}, "model": {"provider": "p", "model": "m", "variant": "v"},
                  "reasoning_effort": "high", "context_evidence": {"reference": "test"}}
        response = {"route": {"decision_id": "d", "target": target}}
        identity = {"resource_id": "r", "provider": "p", "model": "m", "variant": "v",
                    "reasoning_effort": "high", "context_evidence": {"reference": "test"}}
        record = {"decision_id": "d", "client_id": "c", "result_status": "completed",
                  "selected_target": identity, "executed_target": dict(identity)}
        _assert_audit(record, response, "c")
        for key in identity:
            changed = copy.deepcopy(record)
            changed["selected_target"][key] = "wrong"
            changed["executed_target"][key] = "wrong"
            with self.subTest(field=key), self.assertRaises(AssertionError):
                _assert_audit(changed, response, "c")
        with self.assertRaises(AssertionError):
            _assert_audit(None, response, "c")

    def test_precise_gateway_errors_and_backend_trace(self):
        allowed = {(403, "permission_error", "unauthorized_target")}
        worker._assert_gateway_error(403, {"error": {"type": "permission_error", "code": "unauthorized_target"}}, allowed)
        for status, payload in ((401, {"error": {"type": "permission_error", "code": "unauthorized_target"}}),
                                (403, {"error": {"type": "api_error", "code": "unauthorized_target"}}),
                                (500, {"error": {"type": "api_error", "code": "invalid_state"}}), (403, {})):
            with self.subTest(status=status, payload=payload), self.assertRaises(AssertionError):
                worker._assert_gateway_error(status, payload, allowed)
        with tempfile.TemporaryDirectory() as tmp:
            trace = Path(tmp) / "trace"
            workers = {"a": {"trace": trace}}
            self.assertEqual(worker._turns(workers), {"a": []})
            trace.write_text('\n'.join(json.dumps(item) for item in [
                {"event": "request", "method": "model/list"},
                {"event": "request", "method": "turn/start", "params": {"model": "test"}},
            ]))
            self.assertEqual(len(worker._turns(workers)["a"]), 1)

    @unittest.skipUnless(importlib.util.find_spec("scarcity_router") and importlib.util.find_spec("model_intelligence"),
                         "local SR and MI sources required")
    def test_real_sr_admission_receipt_and_context(self):
        from dataclasses import replace
        from scarcity_router.routing_core import PinnedTarget, admit_pinned_target
        from tests.test_mi_admission import ActiveMIAdmissionTests

        request, mi = ActiveMIAdmissionTests().world(amount=16000)
        entries = tuple(replace(entry, hard_properties=replace(entry.hard_properties, input_context_tokens=None),
                                capacity_binding_resources=("openai-sub",)) for entry in request.catalog.entries)
        resources = []
        for resource in request.registry_snapshot.entries:
            if resource.identity.resource_id == "openai-sub":
                identity = replace(resource.identity, variant=entries[0].identity.variant)
                resource = replace(resource, identity=identity, observation=replace(resource.observation, identity=identity))
            resources.append(resource)
        request = replace(request, catalog=replace(request.catalog, catalog_version=None, updated_on=None, entries=entries),
                          registry_snapshot=replace(request.registry_snapshot, entries=tuple(resources)))
        model = request.catalog.entries[0]
        pin = PinnedTarget("openai-sub", model.identity, decision_id="rd-fixture", reasoning_effort=model.reasoning_effort)
        request = replace(request, request=replace(request.request, pinned_target=pin), mi_admission=mi)
        admission = admit_pinned_target(request, pinned_target=pin)
        self.assertTrue(admission.approved)
        use = admission.mi_use
        self.assertIsNotNone(use)
        cut = use.cut
        from scarcity_router.mi_consumer import MIConsumer
        from scarcity_router.mi_server_config import MIServer
        from scarcity_router.server_store import ServerStore
        consumer = MIConsumer(expected_scope=cut.public.applicability, bindings=mi.captured[1], max_bytes=256 * 1024)
        consumer.adopt(cut.data, cut.reference)
        with tempfile.TemporaryDirectory() as tmp:
            store = ServerStore.open(Path(tmp))
            try:
                server = MIServer(consumer, cut.reference, store, "unused-by-retain")
                server.retain(use, "request-fixture", "client-fixture")
                identifier = store.get_mi_receipt_for_request("client-fixture", "request-fixture")
                receipt = json.loads(store.get_mi_receipt(identifier))
                retained_cut = store.get_retained_mi_cut(cut.reference.sha256)
            finally:
                store.close()
        target = admission.target.to_dict()
        identity = {"resource_id": target["resource"]["resource_id"], **target["model"],
                    "reasoning_effort": target["reasoning_effort"], "context_evidence": target.get("context_evidence")}
        record = {"executed_target": identity}
        response = {"route": {"decision_id": pin.decision_id}}
        decision, context = _assert_retained(receipt, lambda _: retained_cut,
                                              receipt_id=identifier,
                                              expected_cut=receipt["cut_reference"])
        worker._assert_execution_admission(decision, context, receipt, response, record, input_limit=16000)
        mutations = [("decision", "approved", False), ("decision", "resource_id", "other"),
                     ("decision", "reason_codes", ["admission_rejected"]),
                     ("decision", "bound_decision_id", "other"),
                     ("context", "operation", "route"), ("context", "blocked", [target["model"]]),
                     ("context", "pin", {**context["pin"], "resource_id": "other"})]
        for source, field, value in mutations:
            d, c = copy.deepcopy(decision), copy.deepcopy(context)
            (d if source == "decision" else c)[field] = value
            with self.subTest(source=source, field=field), self.assertRaises(AssertionError):
                worker._assert_execution_admission(d, c, receipt, response, record, input_limit=16000)
        changed = copy.deepcopy(context)
        entry = next(item for item in changed["evaluated_catalog"]["entries"] if item["identity"] == target["model"])
        entry["hard_properties"]["input_context_tokens"] += 1
        with self.assertRaises(AssertionError):
            worker._assert_execution_admission(decision, changed, receipt, response, record, input_limit=16000)

        from scarcity_router.gateway_coordinator import _admission_rejection
        from scarcity_router.routing_core import ClientAuthorization
        blocked = replace(request, client_authorization=ClientAuthorization(blocked_resource_ids=(pin.resource_id,)))
        denied = admit_pinned_target(blocked, pinned_target=pin)
        self.assertFalse(denied.approved)
        error = _admission_rejection(denied)
        worker._assert_gateway_error(error.http_status, error.to_payload(), {(403, "permission_error", "unauthorized_target")})
        missing = replace(request, registry_snapshot=replace(request.registry_snapshot, entries=tuple(
            entry for entry in request.registry_snapshot.entries if entry.identity.resource_id != pin.resource_id)))
        denied = admit_pinned_target(missing, pinned_target=pin)
        error = _admission_rejection(denied)
        worker._assert_gateway_error(error.http_status, error.to_payload(), {(404, "not_found_error", "pin_target_not_found")})

    @unittest.skipUnless(importlib.util.find_spec("model_intelligence"), "MI package required")
    def test_real_mi_fixture_and_utilization_frames(self):
        import mi_publication_fixture as fixture
        from model_intelligence.publication import CutReference
        from model_intelligence.utilization import encode_utilization

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture.publish_fixture(root, publication_path="/run/foundry/mi/publication.json")
            cut = (root / (fixture.EXPECTED_SHA256 + ".json")).read_bytes()
            now = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
            decision, context = b'{"decision":true}', b'{"context":true}'
            manifest, reference = encode_utilization(CutReference(**worker.EXPECTED_CUT), evaluated_at=now,
                                                      decision=decision, context=context)
            encode = lambda value: base64.b64encode(value).decode()
            receipt = {"cut_reference": worker.EXPECTED_CUT, "cut_blob_sha256": fixture.EXPECTED_SHA256,
                       "evaluated_at": now.isoformat(), "decision": encode(decision),
                       "context": encode(context), "utilization": encode(manifest)}
            _assert_retained(receipt, lambda _: cut, reference, hashlib.sha256(manifest).hexdigest())


if __name__ == "__main__":
    unittest.main()
