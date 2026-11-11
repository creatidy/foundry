"""Offline orchestration checks only; these are not installed acceptance."""

import hashlib
import json
import unittest
from unittest import mock

import installed_mi_lifecycle_scenario as scenario
from installed_worker_control import WorkerArchive


class ScenarioWiringTests(unittest.TestCase):
    def setUp(self):
        self.adapter = mock.Mock()
        self.adapter.old_image_id = "sha256:" + "1" * 64
        self.adapter.new_image_id = "sha256:" + "2" * 64
        self.publication = b"offline orchestration input"
        self.patcher = mock.patch.object(scenario, "EXPECTED_SHA256", hashlib.sha256(self.publication).hexdigest())
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.worker = mock.Mock()
        self.worker.execute.return_value = True
        data = b"independent worker archive"
        self.archive = WorkerArchive("a" * 32, hashlib.sha256(data).hexdigest(), data)
        self.worker.snapshot_worker.return_value = self.archive
        self.start_worker = mock.Mock(return_value=self.worker)

    def test_refuses_invalid_inputs_before_any_operation(self):
        self.adapter.old_image_id = self.adapter.new_image_id
        with self.assertRaises(ValueError):
            scenario.run_lifecycle_acceptance(self.adapter, self.publication, start_worker=self.start_worker)
        self.adapter.start_old.assert_not_called()
        self.adapter.old_image_id = "sha256:" + "1" * 64
        with self.assertRaises(ValueError):
            scenario.run_lifecycle_acceptance(self.adapter, b"different", start_worker=self.start_worker)
        self.adapter.start_old.assert_not_called()

    def test_unexpected_reload_retains_input_and_fences(self):
        selection = {"route": {}, "decision": {}, "mi_utilization": {}, "mi_projection": {}}

        def exchange(method, path, body, headers, *, admin):
            if path == "/control/clients":
                return 200, {"api_key": "temporary-test-key"}
            if path == "/v1/select":
                return 200, selection
            if path == "/v1/mi/verify-projection":
                return 200, {"valid": True}
            if path == "/control/mi/reload":
                return ((500, {}) if admin else (401, {"error": {"code": "unauthenticated", "message": "administrator session required"}}))
            raise AssertionError(path)

        self.adapter.exchange.side_effect = exchange
        with self.assertRaises(AssertionError):
            scenario.run_lifecycle_acceptance(self.adapter, self.publication, start_worker=self.start_worker)
        self.adapter.write_publication_in_place.assert_called_once_with(b"invalid synthetic publication")
        self.adapter.block_engine.assert_called()
        self.adapter.snapshot.assert_called_once_with()
        self.adapter.restore.assert_not_called()

    def test_reload_rejects_incomplete_unexpected_and_timeout_results(self):
        cases = [(400, {}), (400, {"error": {"code": "invalid_request"}}),
                 (200, {"status": "ok"}), (503, {})]
        for result in cases:
            with self.subTest(result=result):
                adapter = mock.Mock()
                adapter.exchange.return_value = result
                with self.assertRaises(AssertionError):
                    scenario._reload(adapter, expected=400)
                adapter.block_engine.assert_called()
        adapter = mock.Mock()
        adapter.exchange.side_effect = TimeoutError("uncertain")
        with self.assertRaises(TimeoutError):
            scenario._reload(adapter, expected=400)
        adapter.block_engine.assert_called()

    def test_rejected_reload_does_not_restore_when_retained_check_fails(self):
        selection = {"route": {}, "decision": {}, "mi_utilization": {}, "mi_projection": {}}
        checks = iter((True, False))
        def exchange(method, path, body, headers, *, admin):
            if path == "/control/clients":
                return 200, {"api_key": "key"}
            if path == "/v1/select":
                return 200, selection
            if path == "/v1/mi/verify-projection":
                return 200, {"valid": next(checks)}
            if path == "/control/mi/reload":
                return ((400, {"error": {"code": "invalid_request", "message": "MI publication reload rejected; previous state retained"}})
                        if admin else (401, {"error": {"code": "unauthenticated", "message": "administrator session required"}}))
            raise AssertionError(path)
        self.adapter.exchange.side_effect = exchange
        with self.assertRaisesRegex(AssertionError, "retained"):
            scenario.run_lifecycle_acceptance(self.adapter, self.publication, start_worker=self.start_worker)
        self.adapter.write_publication_in_place.assert_called_once_with(b"invalid synthetic publication")
        self.adapter.block_engine.assert_called()

    def test_snapshot_order_and_rollback_wiring(self):
        selection = {"route": {}, "decision": {}, "mi_utilization": {}, "mi_projection": {}}
        self.adapter.snapshot.side_effect = ["prior", "migrated"]
        self.adapter.restore.side_effect = lambda snapshot: restored.append(snapshot)
        restored = []
        issued = iter(("old-key", "later-key"))

        def exchange(method, path, body, headers, *, admin):
            if path == "/control/clients":
                return 200, {"api_key": next(issued)}
            if path == "/v1/select":
                return (401, {}) if restored and headers.get("Authorization") == "Bearer later-key" else (200, selection)
            if path == "/v1/mi/verify-projection":
                return 200, {"valid": True}
            if path == "/control/mi/reload":
                if not admin:
                    return 401, {"error": {"code": "unauthenticated", "message": "administrator session required"}}
                return ((400, {"error": {"code": "invalid_request", "message": "MI publication reload rejected; previous state retained"}})
                        if self.adapter.write_publication_in_place.call_count == 1 else (200, {"status": "ok"}))
            raise AssertionError(path)

        self.adapter.exchange.side_effect = exchange
        scenario.run_lifecycle_acceptance(self.adapter, self.publication, start_worker=self.start_worker)
        self.assertEqual([mock.call("initialize", None)] + [mock.call("resume", self.archive)] * 3,
                         self.start_worker.call_args_list)
        self.assertEqual(4, self.worker.execute.call_count)
        self.assertEqual([mock.call("old-key", mi_enabled=False), mock.call("old-key", mi_enabled=True),
                          mock.call("old-key", mi_enabled=True), mock.call("old-key", mi_enabled=False)],
                         self.worker.execute.call_args_list)
        self.assertEqual(4, self.worker.close.call_count)
        self.assertEqual(["migrated", "prior"], restored)
        calls = [call[0] for call in self.adapter.method_calls if call[0] not in ("exchange", "require_unblocked")]
        self.assertEqual(["start_old", "stop", "snapshot", "start_new",
                          "write_publication_in_place", "write_publication_in_place", "stop",
                          "start_new", "stop", "snapshot", "start_new", "stop", "restore",
                          "start_new", "stop", "restore", "start_old", "stop"], calls)

    def test_missing_worker_or_failed_execution_cannot_pass(self):
        with self.assertRaisesRegex(ValueError, "worker control"):
            scenario.run_lifecycle_acceptance(self.adapter, self.publication)
        self.adapter.start_old.assert_not_called()
        self.adapter.exchange.return_value = (200, {"api_key": "key"})
        self.worker.execute.return_value = False
        with self.assertRaisesRegex(AssertionError, "did not route and execute"):
            scenario.run_lifecycle_acceptance(self.adapter, self.publication, start_worker=self.start_worker)
        self.worker.close.assert_called_once_with()
        self.adapter.snapshot.assert_not_called()

    def test_variant_reload_wiring_and_worker_gate(self):
        cuts = {}
        digests = {}
        for kind in ("fresh", "stale", "incompatible", "withdrawn"):
            data = self.publication if kind == "fresh" else kind.encode()
            digest = hashlib.sha256(data).hexdigest()
            if kind != "fresh":
                digests[kind] = digest
            cuts[kind] = (data, json.dumps({"reference": {"sha256": digest},
                                           "publication": "/run/foundry/mi/publication.json"}).encode())
        patcher = mock.patch.object(scenario.fixture, "VARIANT_SHA256", digests)
        patcher.start()
        self.addCleanup(patcher.stop)
        current = ["fresh"]
        self.adapter.write_publication_in_place.side_effect = lambda data: current.__setitem__(
            0, next(kind for kind, pair in cuts.items() if pair[0] == data))

        def exchange(method, path, body, headers, *, admin):
            if path == "/control/mi/reload":
                return ((400, {"error": {"code": "invalid_request", "message": "MI publication reload rejected; previous state retained"}})
                        if current[0] in ("stale", "incompatible") else (200, {"status": "ok"}))
            if path == "/v1/mi/verify-projection":
                return 200, {"valid": True}
            if path == "/v1/select":
                route = ({"status": "no_solution", "target": None} if current[0] == "withdrawn" else
                         {"target": {"model": {"provider": "openai", "model": "gpt-6-sol", "variant": "high"},
                                     "resource": {"resource_id": "foundry-worker-a:gpt-6-sol:high"},
                                     "reasoning_effort": "high"}})
                return 200, {"route": route, "decision": {}, "mi_utilization": {}, "mi_projection": {}}
            raise AssertionError(path)

        self.adapter.exchange.side_effect = exchange
        with self.assertRaisesRegex(AssertionError, "routable"):
            scenario.run_variant_reload_acceptance(self.adapter, "key", cuts, lambda: False, lambda *args: True)
        self.adapter.exchange.assert_not_called()
        scenario.run_variant_reload_acceptance(self.adapter, "key", cuts, lambda: True, lambda *args: True)
        self.assertEqual("withdrawn", current[0])
        self.assertEqual(3, sum(call.args[1] == "/control/mi/reload" for call in self.adapter.exchange.call_args_list))

    def test_preactivation_failure_restores_trust_and_verifies_projection(self):
        trust = json.dumps({"reference": {"sha256": hashlib.sha256(self.publication).hexdigest()},
                            "scope": {"scope_id": "fresh"}}).encode()
        retained = {"route": {}, "decision": {}, "mi_utilization": {}, "mi_projection": {}}
        self.adapter.exchange.side_effect = [(200, {"valid": True}), (200, retained), (200, {"valid": True})]
        scenario.run_preactivation_failure(self.adapter, trust, "key", retained, lambda *args: True)
        self.adapter.start_new_expect_mi_failure.assert_called_once_with("mi_publication_activation_failed")
        self.assertEqual(trust, self.adapter.write_trust_in_place.call_args_list[-1].args[0])
        self.adapter.start_new.assert_called_once_with()

    def test_unclassified_preactivation_failure_retains_trust_without_retry(self):
        trust = json.dumps({"reference": {"sha256": hashlib.sha256(self.publication).hexdigest()},
                            "scope": {"scope_id": "fresh"}}).encode()
        self.adapter.start_new_expect_mi_failure.side_effect = RuntimeError("uncertain")
        with self.assertRaisesRegex(RuntimeError, "uncertain"):
            scenario.run_preactivation_failure(self.adapter, trust, "key", {}, lambda *args: True)
        self.assertEqual(1, self.adapter.write_trust_in_place.call_count)
        self.adapter.start_new.assert_not_called()

    def test_stale_startup_checks_new_selection_after_restart(self):
        data = b"stale test"
        digest = hashlib.sha256(data).hexdigest()
        patcher = mock.patch.object(scenario.fixture, "VARIANT_SHA256", {"stale": digest})
        patcher.start()
        self.addCleanup(patcher.stop)
        trust = json.dumps({"reference": {"sha256": digest}}).encode()
        def selection(name, blocked=True):
            return {"route": {"status": "no_solution" if blocked else "selected", "target": None},
                    "decision": {"id": name}, "mi_utilization": {}, "mi_projection": {}}

        for failure in (None, "route", "worker", "cut", "cleanup", "route_cleanup"):
            with self.subTest(failure=failure):
                adapter = mock.Mock()
                before = selection("before")
                after = selection("after", blocked=failure not in ("route", "route_cleanup"))
                adapter.exchange.side_effect = [(200, {"api_key": "key"}), (200, before),
                                                (200, {"valid": True}), (200, {"valid": True}),
                                                (200, after), (200, {"valid": True})]
                events = []
                adapter.stop.side_effect = lambda: events.append("stop router")
                adapter.restart_current_cut.side_effect = lambda: events.append("restart router")
                starts = mock.Mock(side_effect=[lambda: True, lambda: failure != "worker"])
                def start_worker():
                    events.append("start worker")
                    return starts()
                def stop():
                    events.append("stop worker")
                    if failure in ("cleanup", "route_cleanup") and events.count("stop worker") == 2:
                        raise RuntimeError("cleanup failed")
                verify = mock.Mock(side_effect=lambda key, response, cut: not (
                    failure == "cut" and response is after))
                if failure is None:
                    scenario.run_stale_startup_acceptance(adapter, {"stale": (data, trust)},
                                                          start_worker, stop, verify)
                    self.assertEqual([mock.call("key", before, digest), mock.call("key", before, digest),
                                      mock.call("key", after, digest)], verify.call_args_list)
                    self.assertEqual(2, sum(call.args[1] == "/v1/select"
                                            for call in adapter.exchange.call_args_list))
                else:
                    expected = RuntimeError if failure == "cleanup" else AssertionError
                    with self.assertRaises(expected) as raised:
                        scenario.run_stale_startup_acceptance(adapter, {"stale": (data, trust)},
                                                              start_worker, stop, verify)
                    if failure == "route_cleanup":
                        self.assertIn("controlled model was not blocked", str(raised.exception))
                        self.assertIn("worker cleanup also failed: RuntimeError", raised.exception.__notes__)
                adapter.start_new_with_cut.assert_called_once_with(data, trust, digest)
                self.assertEqual(["start worker", "stop worker", "stop router", "restart router",
                                  "start worker", "stop worker"], events)


if __name__ == "__main__":
    unittest.main()
