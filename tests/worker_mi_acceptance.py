"""Opt-in acceptance against an explicitly provisioned, isolated SR instance.

No listener or server is created here. The caller owns provisioning and supplies
an authenticated admin exchange, loopback worker endpoint, CA, and scratch dir.
Requires the matching SR and MI packages plus the pinned SR fake app-server file.
The fake Codex app server is the only simulated backend; routing is unmodified.
"""
from __future__ import annotations

import copy
import base64
import contextlib
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

SOURCES = ("foundry-worker-a", "foundry-worker-b")
EFFORTS = ("low", "medium", "high", "xhigh", "max", "ultra")
MODEL = "openai/gpt-6-sol/high~high"
PROMPT = "Foundry synthetic acceptance request"
EXPECTED_CUT = {"format_version": 1, "payload_schema": "mi.public-evidence-working/2",
                "sha256": "c63233c4ad8ccd79f87ea01e18e0d79559f8802474f399442f0e8a99d67db74f"}
FIXTURE_CUTS = frozenset({EXPECTED_CUT["sha256"],
    "fcfd20a3e30abb80adf63291f62772318ec444ff2f93bc654cb7e62ae7e64691",
    "c7090c7fdf6670fec532bef0ada37cad74b734d398f8d167dc98fecd1b878c12",
    "e8fdf18ef2b2b77586b237b8cc490af6293e60c651741874dbf3e4782599b1aa"})
Exchange = Callable[[str, str, object | None, dict[str, str]], tuple[int, object]]


@dataclass(frozen=True)
class WorkerConfig:
    worker_host: str
    worker_port: int
    ca_file: Path
    scratch: Path
    exchange: Exchange
    isolated: bool
    audit_records: Callable[[], list[dict]] | None = None
    backend_file: Path | None = None
    mi_receipt: Callable[[str, str], tuple[str | None, object]] | None = None
    mi_receipt_by_id: Callable[[str], object] | None = None
    mi_cut: Callable[[str], bytes | None] | None = None
    migration: str | None = None

    def validate(self) -> None:
        try:
            host = ipaddress.ip_address(self.worker_host)
        except ValueError as exc:
            raise ValueError("worker host must be a numeric loopback address") from exc
        if host.version != 4 or not host.is_loopback or type(self.worker_port) is not int or not 1 <= self.worker_port <= 65535:
            raise ValueError("worker endpoint must be a valid IPv4 loopback address")
        if self.isolated is not True or not callable(self.exchange):
            raise ValueError("explicit isolated instance and exchange are required")
        if self.migration not in (None, "initialize", "resume"):
            raise ValueError("invalid migration mode")
        callbacks = (self.audit_records,) if self.migration else (self.audit_records, self.mi_receipt,
                                                                 self.mi_receipt_by_id, self.mi_cut)
        if not all(callable(callback) for callback in callbacks):
            raise ValueError("audit and retained MI evidence callbacks are required")
        if not self.ca_file.is_file() or not self.scratch.is_dir():
            raise ValueError("existing CA file and isolated scratch directory required")


def _ok(result: tuple[int, object]) -> dict:
    status, payload = result
    if status != 200 or not isinstance(payload, dict):
        raise AssertionError(f"unexpected HTTP response: {status}: {payload!r}")
    return payload


def _blocked_source(source: str) -> list[str]:
    if source not in SOURCES:
        raise ValueError("unknown fixture source")
    return sorted(f"{source}:gpt-6-sol:{effort}" for effort in EFFORTS)


def _assert_unused_sources(sources: object) -> None:
    if (not isinstance(sources, list) or any(not isinstance(item, dict) for item in sources)
            or any(item.get("source_id") in SOURCES for item in sources)):
        raise ValueError("fixture sources require a clean isolated store")


def _require_projection_support(mi_server: type) -> None:
    if not all(callable(getattr(mi_server, name, None)) for name in ("retain_projection", "verify_projection")):
        raise RuntimeError("installed SR lacks the required MI projection contract")


def _verify_payload(response: dict) -> dict:
    return {"projection": response["mi_projection"], "route": response["route"],
            "decision": response["decision"], "mi_utilization": response["mi_utilization"]}


def _tampered(payload: dict) -> list[dict]:
    variants = []
    for field in ("projection", "route", "decision", "mi_utilization"):
        changed = copy.deepcopy(payload)
        if field == "projection":
            changed[field]["request_id"] = "changed-request"
        elif field == "route":
            changed[field]["status"] = "changed"
        elif field == "decision":
            changed[field] = {}
        else:
            changed[field] = {}
        variants.append(changed)
    return variants


def _assert_private(value: object, source: str) -> None:
    if source in json.dumps(value, sort_keys=True):
        raise AssertionError("restricted response leaked excluded source identity")


def _assert_retained(receipt: object, cut_lookup: Callable[[str], bytes | None],
                     reference: object | None = None, receipt_id: str | None = None,
                     expected_cut: dict | None = None) -> None:
    """Check the SR-retained utilization chain against the fixed fresh fixture."""
    expected_cut = EXPECTED_CUT if expected_cut is None else expected_cut
    try:
        if not isinstance(receipt, dict) or receipt["cut_reference"] != expected_cut:
            raise ValueError("wrong or unavailable cut reference")
        cut_digest = receipt["cut_blob_sha256"]
        cut = cut_lookup(cut_digest)
        if (cut_digest != expected_cut["sha256"] or not isinstance(cut, bytes)
                or not 0 < len(cut) <= 256 * 1024 or hashlib.sha256(cut).hexdigest() != cut_digest):
            raise ValueError("wrong or unavailable retained cut")
        frame = json.loads(cut)
        if frame["format_version"] != 1 or frame["payload_schema"] != expected_cut["payload_schema"]:
            raise ValueError("invalid retained cut framing")
        manifest, decision, context = (base64.b64decode(receipt[name], validate=True)
                                       for name in ("utilization", "decision", "context"))
        if not all(0 < len(item) <= 256 * 1024 for item in (manifest, decision, context)):
            raise ValueError("invalid retained evidence size")
        manifest_hash = hashlib.sha256(manifest).hexdigest()
        if receipt_id is not None and manifest_hash != receipt_id:
            raise ValueError("projection receipt identifier mismatch")
        expected_reference = {"source": "model_intelligence", "version": "mi.utilization-working/1",
                              "identifier": "urn:mi:utilization:sha256:" + manifest_hash}
        if reference is not None and reference != expected_reference:
            raise ValueError("public utilization reference mismatch")
        utilization = json.loads(manifest)
        if (utilization["format_version"] != 1 or utilization["payload_schema"] != "mi.utilization-working/1"
                or utilization["scope"] != "local-utilization" or utilization["members"] != []
                or utilization["sources"] != []):
            raise ValueError("invalid utilization framing")
        payload = json.loads(utilization["payload"])
        expected = {"cut": {"format": 1, "schema": expected_cut["payload_schema"], "sha256": cut_digest},
                    "evaluated_at": receipt["evaluated_at"], "decision_sha256": hashlib.sha256(decision).hexdigest(),
                    "context_sha256": hashlib.sha256(context).hexdigest()}
        if payload != expected:
            raise ValueError("utilization evidence does not match receipt")
        return json.loads(decision), json.loads(context)
    except (KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
        raise AssertionError("retained MI evidence invalid or unavailable") from exc


def _assert_execution_admission(decision, context, receipt, response, record, *, input_limit=4096):
    """Check SR's retained pinned admission, not just the receipt's hashes."""
    try:
        selected = response["route"]
        target = decision["target"]
        identity = record["executed_target"]
        model = {name: identity[name] for name in ("provider", "model", "variant")}
        pin = {"resource_id": identity["resource_id"], "model": model,
               "reasoning_effort": identity["reasoning_effort"], "decision_id": selected["decision_id"]}
        entries = [item for item in context["evaluated_catalog"]["entries"] if item["identity"] == model]
        if (decision["approved"] is not True or "admission_approved" not in decision["reason_codes"]
                or decision["resource_id"] != identity["resource_id"]
                or decision.get("bound_decision_id") != selected["decision_id"]
                or target["resource"]["resource_id"] != identity["resource_id"]
                or target["model"] != model or target.get("reasoning_effort") != identity["reasoning_effort"]
                or target.get("context_evidence") != identity.get("context_evidence")
                or context["operation"] != "admit" or context["pin"] != pin
                or context["request"]["pinned_target"] != pin
                or context["admission_reference"] != receipt["cut_reference"]
                or context["evaluated_at"] != receipt["evaluated_at"]
                or model in context["blocked"] or len(entries) != 1
                or entries[0]["reasoning_effort"] != identity["reasoning_effort"]
                or entries[0]["hard_properties"]["input_context_tokens"] != input_limit):
            raise ValueError("execution admission mismatch")
    except (KeyError, TypeError, ValueError) as exc:
        raise AssertionError("retained execution admission does not match audit and MI context") from exc


def _assert_gateway_error(status, payload, expected):
    if (not isinstance(payload, dict) or not isinstance(payload.get("error"), dict)
            or (status, payload["error"].get("type"), payload["error"].get("code")) not in expected):
        raise AssertionError("unexpected gateway rejection")


def _turns(workers):
    result = {}
    for source, worker in workers.items():
        trace = worker["trace"]
        entries = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
        result[source] = [entry for entry in entries if entry.get("event") == "request"
                          and entry.get("method") == "turn/start"]
    return result


def _assert_audit(record: object, response: dict, client_id: str) -> None:
    route = response["route"]
    target = route["target"]
    expected = {"resource_id": target["resource"]["resource_id"], **{
        name: target["model"][name] for name in ("provider", "model", "variant")},
        "reasoning_effort": target["reasoning_effort"], "context_evidence": target["context_evidence"]}
    if (not isinstance(record, dict) or record.get("client_id") != client_id
            or record.get("decision_id") != route["decision_id"] or record.get("result_status") != "completed"
            or not isinstance(record.get("selected_target"), dict)
            or record["selected_target"] != record.get("executed_target")
            or any(record["selected_target"].get(key) != value for key, value in expected.items())):
        raise AssertionError("audit selected/executed identity mismatch")


def _result_case(source: str, client_id: str, response: dict, record: dict,
                 binding_id: str, projection_receipt_id: str, execution_receipt_id: str) -> dict:
    """Select only fixed synthetic identities and SR-generated opaque identifiers."""
    target = response["route"]["target"]
    model = target["model"]
    if (source not in SOURCES or target["resource"]["resource_id"] != f"{source}:gpt-6-sol:high"
            or (model.get("provider"), model.get("model"), model.get("variant"), target.get("reasoning_effort"))
            != ("openai", "gpt-6-sol", "high", "high")):
        raise AssertionError("unexpected synthetic identity")
    identifiers = {
        "client_id": (client_id, r"client-[0-9a-f]{8}"),
        "selection_decision_id": (response["route"]["decision_id"], r"rd-[0-9a-f]{32}"),
        "projection_request_id": (response["mi_projection"]["request_id"], r"[0-9a-f]{32}"),
        "projection_binding_sha256": (binding_id, r"[0-9a-f]{64}"),
        "projection_receipt_sha256": (projection_receipt_id, r"[0-9a-f]{64}"),
        "gateway_request_id": (record["request_id"], r"chatcmpl-[0-9a-f]{32}"),
        "gateway_decision_id": (record["decision_id"], r"rd-[0-9a-f]{32}"),
        "execution_receipt_sha256": (execution_receipt_id, r"[0-9a-f]{64}"),
    }
    if any(not isinstance(value, str) or re.fullmatch(pattern, value) is None
           for value, pattern in identifiers.values()):
        raise AssertionError("invalid acceptance result identifier")
    return {"source_id": source, "resource_id": target["resource"]["resource_id"],
            "model": {"provider": model["provider"], "model": model["model"], "variant": model["variant"],
                      "reasoning_effort": target["reasoning_effort"]},
            **{name: value for name, (value, _) in identifiers.items()}}


def run_worker_acceptance(config: WorkerConfig, live_callback=None) -> dict | None:
    """Exercise real pairing, discovery, MI selection, verification and execution.

    exchange(method, path, body, headers) must use verified HTTPS and add the
    administrator session and CSRF only for /control/ requests. Its responses
    must be decoded JSON. The caller must have loaded the fresh controlled MI
    fixture and ensure the server and scratch storage are disposable and bounded.
    This function deliberately makes no claim about default Foundry Compose.
    """
    config.validate()
    if (config.backend_file is None or not config.backend_file.is_file()
            or not os.access(config.backend_file, os.X_OK)):
        raise ValueError("explicit executable pinned SR fake app server required")
    from scarcity_router.control_api import format_utc
    from scarcity_router.worker_codex_adapter import CodexLocalAdapter
    from scarcity_router.worker_client import WorkerOrigin, WorkerRuntime, ca_connect_factory
    from scarcity_router.worker_local_adapters import LocalAdapterRegistry
    from scarcity_router.worker_local_store import WorkerLocalStore

    scenario = {"init": "ok", "account": "chatgpt", "models": [{
        "id": "gpt-6-sol", "model": "gpt-6-sol", "displayName": "gpt-6-sol", "hidden": False,
        "isDefault": True, "supportedReasoningEfforts": [{"reasoningEffort": e} for e in EFFORTS],
    }], "turn": {"deltas": ["Hel", "lo"], "usage": {"last": {"inputTokens": 11, "outputTokens": 7}},
                  "status": "completed"}}

    class FixtureSpawner:
        # Same process protocol as SR's FakeCodexSpawner, using its fake server.
        def __init__(self, trace):
            self.trace = trace
            self.processes = []

        def __call__(self, spec):
            args = (["--version", "0.155.1"] if list(spec.argv[1:2]) == ["--version"]
                    else ["--app-server", json.dumps(scenario)])
            env = dict(spec.env)
            env["SR_FAKE_TRACE"] = str(self.trace)
            proc = subprocess.Popen([sys.executable, str(config.backend_file), *args], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                                    cwd=spec.cwd, start_new_session=True)
            self.processes.append(proc)
            return proc

        def reap_all(self):
            for proc in self.processes:
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=5)
                for stream in (proc.stdin, proc.stdout, proc.stderr):
                    if stream is not None:
                        stream.close()

    def admin(method: str, path: str, body: object | None = None) -> dict:
        return _ok(config.exchange(method, path, body, {}))

    def client(key: str, path: str, body: object) -> dict:
        return _ok(config.exchange("POST", path, body, {"Authorization": f"Bearer {key}"}))

    if config.migration != "resume" and any(config.scratch.iterdir()):
        raise ValueError("worker scratch must be unused")
    sources = admin("GET", "/control/sources")["sources"]
    if config.migration != "resume":
        _assert_unused_sources(sources)
    else:
        if not isinstance(sources, list) or {item.get("source_id") for item in sources} != set(SOURCES):
            raise ValueError("migration source configuration changed")
    workers = {}
    try:
        connect_verified = ca_connect_factory(str(config.ca_file))
        origin = WorkerOrigin.parse(f"srws://{config.worker_host}:{config.worker_port}")

        for source_id in SOURCES:
            directory = config.scratch / source_id
            if config.migration == "resume":
                if not directory.is_dir() or not (directory / "worker-state.db").is_file():
                    raise ValueError("preserved worker identity is missing")
            else:
                directory.mkdir(mode=0o700)
            trace = directory / "trace.jsonl"
            spawner = FixtureSpawner(trace)
            registry = LocalAdapterRegistry()
            registry.register(CodexLocalAdapter(source_id=source_id, state_dir=directory, discovery_roots=(),
                path_lookup=lambda name: "/usr/bin/bwrap" if name == "bwrap" else str(config.backend_file) if name == "codex" else None,
                spawner=spawner, inventory_ttl_seconds=2, platform_name="linux", platform_release="6.x-generic"))
            store = WorkerLocalStore(directory / "worker-state.db")
            worker = {"store": store, "registry": registry, "spawner": spawner,
                      "trace": trace, "transports": [], "runtime": None, "thread": None}
            workers[source_id] = worker

            def connect(ref, worker=worker):
                transport = connect_verified(ref)
                worker["transports"].append(transport)
                return transport

            worker["connect"] = connect
            runtime = WorkerRuntime(origin=origin, store=store, local_adapters=registry,
                                    state_report_interval_seconds=2, connect_factory=connect)
            worker["runtime"] = runtime
            if config.migration == "resume":
                identity = store.load_identity()
                source = next(item for item in sources if item["source_id"] == source_id)
                if identity is None or source.get("worker_id") != identity.worker_id:
                    raise ValueError("preserved worker identity does not match the restored source")
            else:
                code = admin("POST", "/control/workers/pairing-codes", {"label": source_id})["pairing_code"]
                identity = runtime.pair(code)
                admin("POST", "/control/sources", {"source_id": source_id, "kind": "codex_subscription",
                      "label": source_id, "worker_id": identity.worker_id, "entitlement": "subscription_included"})
                admin("POST", f"/control/sources/{source_id}/model-policy", {"allowed_models": ["gpt-6-sol"]})
            worker["thread"] = threading.Thread(target=runtime.run, name=source_id, daemon=True)
            worker["thread"].start()

        def wait_for(predicate, message, timeout=60):
            deadline = time.monotonic() + timeout
            while True:
                result = predicate()
                if result:
                    return result
                if time.monotonic() >= deadline:
                    raise AssertionError(message)
                time.sleep(0.5)

        def discovered():
            views = {item["source_id"]: item for item in admin("GET", "/control/sources")["sources"]}
            return views if all(views.get(s, {}).get("runtime_version") and views[s].get("routable") for s in SOURCES) else None

        views = wait_for(discovered, "both worker inventories did not become routable")
        now = datetime.now(timezone.utc)
        for source_id in (() if config.migration == "resume" else SOURCES):
            admin("POST", f"/control/sources/{source_id}/model-policy", {
                "allowed_models": ["gpt-6-sol"], "context_evidence": [{
                    "model": "gpt-6-sol", "variant": "high", "runtime_version": views[source_id]["runtime_version"],
                    "input_tokens": 8192, "evidence_ref": "local:foundry-synthetic-test",
                    "verified_at": format_utc(now - timedelta(minutes=1)),
                    "valid_until": format_utc(now + timedelta(hours=1)),
                }],
            })
        if live_callback is not None:
            def worker_ready():
                views_now = {item["source_id"]: item for item in admin("GET", "/control/sources")["sources"]}
                for source_id, worker in workers.items():
                    view = views_now.get(source_id, {})
                    model = next((entry for entry in view.get("detected_models", [])
                                  if entry.get("slug") == "gpt-6-sol"), {})
                    evidence = view.get("context_evidence", [])
                    try:
                        observed = datetime.fromisoformat(view["observed_at"].replace("Z", "+00:00"))
                        now = datetime.now(timezone.utc)
                        fresh = timedelta(0) <= now - observed < timedelta(minutes=5)
                        valid = any(item.get("model") == "gpt-6-sol" and item.get("variant") == "high"
                                    and item.get("runtime_version") == view.get("runtime_version")
                                    and item.get("input_tokens") == 8192
                                    and datetime.fromisoformat(item["verified_at"].replace("Z", "+00:00")) <= now
                                    < datetime.fromisoformat(item["valid_until"].replace("Z", "+00:00"))
                                    for item in evidence)
                    except (KeyError, TypeError, ValueError, AttributeError):
                        return False
                    if (not worker["thread"].is_alive() or view.get("connected") is not True
                            or view.get("source_authenticated") != "authenticated"
                            or model.get("state") != "routable" or "high" not in model.get("reasoning_efforts", [])
                            or not fresh or not valid):
                        return False
                return True
            wait_for(worker_ready, "controlled workers not ready")
            def execute(key, mi_enabled):
                if not worker_ready() or not isinstance(key, str) or not key or type(mi_enabled) is not bool:
                    return False
                response = client(key, "/v1/select", {"requirement": {"task_level": "L0", "capability_minima": {},
                    "hard_constraints": {"minimum_input_context_tokens": 4096}}})
                if mi_enabled:
                    from scarcity_router.mi_server_config import MIServer
                    _require_projection_support(MIServer)
                    if client(key, "/v1/mi/verify-projection", _verify_payload(response)).get("valid") is not True:
                        return False
                elif response.get("mi_utilization") is not None or response.get("mi_projection") is not None:
                    return False
                target = response.get("route", {}).get("target") or {}
                model, resource = target.get("model") or {}, target.get("resource") or {}
                source = next((s for s in SOURCES if resource.get("resource_id") == f"{s}:gpt-6-sol:high"), None)
                if (source is None or (model.get("provider"), model.get("model"), model.get("variant"),
                                       target.get("reasoning_effort")) != ("openai", "gpt-6-sol", "high", "high")):
                    return False
                before = _turns(workers)
                result = client(key, "/v1/chat/completions", {"model":
                    f"sr-pin:{resource['resource_id']}/{MODEL}@{response['route']['decision_id']}",
                    "messages": [{"role": "user", "content": PROMPT}]})
                after = _turns(workers)
                if result["choices"][0]["message"]["content"] != "Hello" or len(after[source]) != len(before[source]) + 1:
                    return False
                turn = after[source][-1].get("params", {})
                if turn.get("model") != "gpt-6-sol" or turn.get("effort") != "high":
                    return False
                records = config.audit_records()
                record = next((r for r in reversed(records) if r.get("request_id") == result.get("id") and
                               r.get("decision_id") == response["route"]["decision_id"]), None)
                if not isinstance(record, dict) or not isinstance(record.get("client_id"), str):
                    return False
                _assert_audit(record, response, record["client_id"])
                if mi_enabled:
                    receipt_id, receipt = config.mi_receipt(record["client_id"], record["request_id"])
                    if not isinstance(receipt_id, str):
                        return False
                    decision, context = _assert_retained(receipt, config.mi_cut, receipt_id=receipt_id)
                    _assert_execution_admission(decision, context, receipt, response, record)
                return worker_ready()
            live_callback(worker_ready, execute)
            return
        first = admin("POST", "/control/clients", {"label": "foundry unrestricted"})
        key = first["api_key"]
        request = {"requirement": {"task_level": "L0", "capability_minima": {},
                    "hard_constraints": {"minimum_input_context_tokens": 4096}}}
        def selection(client_key):
            return client(client_key, "/v1/select", request)

        response = wait_for(lambda: (r if (r := selection(key))["route"].get("target") else None),
                            "worker target never became eligible")
        route = response["route"]
        resource = route["target"]["resource"]["resource_id"]
        preferred = next((source for source in SOURCES if resource == f"{source}:gpt-6-sol:high"), None)
        if preferred is None:
            raise AssertionError(f"unexpected worker target: {route!r}")
        alternate = next(source for source in SOURCES if source != preferred)
        model = route["target"]["model"]
        if (model.get("provider"), model.get("model"), model.get("variant")) != ("openai", "gpt-6-sol", "high"):
            raise AssertionError(f"expected exact model identity, got {model!r}")
        if route["target"].get("reasoning_effort") != "high":
            raise AssertionError("selected target did not evidence the synthetic high effort")
        restricted = admin("POST", "/control/clients", {"label": "foundry restricted", "authorization": {
            "blocked_resource_ids": _blocked_source(preferred)}})
        restricted_key = restricted["api_key"]
        verify = _verify_payload(response)
        if client(key, "/v1/mi/verify-projection", verify).get("valid") is not True:
            raise AssertionError("own projection verification failed")
        if client(restricted_key, "/v1/mi/verify-projection", verify).get("valid") is not False:
            raise AssertionError("projection accepted for another client")
        second = wait_for(lambda: (r if (r := selection(restricted_key))["route"].get("target") else None),
                          "restricted client has no eligible alternate")
        if second["route"]["target"]["resource"]["resource_id"] != f"{alternate}:gpt-6-sol:high":
            raise AssertionError("restricted client selected wrong source")
        if second["route"]["target"].get("reasoning_effort") != "high":
            raise AssertionError("restricted target did not evidence the synthetic high effort")
        _assert_private(second, preferred)
        second_verify = _verify_payload(second)
        checked = client(restricted_key, "/v1/mi/verify-projection", second_verify)
        _assert_private(checked, preferred)
        if checked.get("valid") is not True:
            raise AssertionError("second client's own projection verification failed")
        for changed in _tampered(verify):
            if client(key, "/v1/mi/verify-projection", changed).get("valid") is not False:
                raise AssertionError("modified projection component accepted")
        request["requirement"]["hard_constraints"]["minimum_input_context_tokens"] = 4097
        if selection(key)["route"]["status"] != "no_solution":
            raise AssertionError("MI input allowance did not block 4097 tokens")
        request["requirement"]["hard_constraints"]["minimum_input_context_tokens"] = 4096
        result = client(key, "/v1/chat/completions", {
            "model": f"sr-pin:{resource}/{MODEL}@{route['decision_id']}", "messages": [{"role": "user", "content": PROMPT}],
        })
        if result["choices"][0]["message"]["content"] != "Hello":
            raise AssertionError("unexpected deterministic backend response")
        entries = [json.loads(line) for line in workers[preferred]["trace"].read_text().splitlines()]
        turn = next((entry.get("params", {}) for entry in entries
                     if entry.get("event") == "request" and entry.get("method") == "turn/start"), None)
        if not turn or turn.get("model") != "gpt-6-sol" or turn.get("effort") != "high":
            raise AssertionError(f"wrong backend model or effort: {turn!r}")
        alternate_resource = f"{alternate}:gpt-6-sol:high"
        restricted_result = client(restricted_key, "/v1/chat/completions", {
            "model": f"sr-pin:{alternate_resource}/{MODEL}@{second['route']['decision_id']}",
            "messages": [{"role": "user", "content": PROMPT}],
        })
        _assert_private(restricted_result, preferred)
        if restricted_result["choices"][0]["message"]["content"] != "Hello":
            raise AssertionError("unexpected restricted backend response")
        before = _turns(workers)
        if not all(before[source] for source in SOURCES):
            raise AssertionError("both positive controls must reach the fake backend")
        forbidden_status, forbidden = config.exchange("POST", "/v1/chat/completions", {
            "model": f"sr-pin:{resource}/{MODEL}", "messages": [{"role": "user", "content": PROMPT}],
        }, {"Authorization": f"Bearer {restricted_key}"})
        _assert_gateway_error(forbidden_status, forbidden, {(403, "permission_error", "unauthorized_target")})
        _assert_private(forbidden, preferred)
        if _turns(workers) != before:
            raise AssertionError("restricted request reached a fake backend")
        records = config.audit_records()
        _assert_private(records, PROMPT)
        cases = []
        for source, issued, selected in ((preferred, first, response), (alternate, restricted, second)):
            client_id = issued["client_id"]
            selected_route = selected["route"]
            record = next((item for item in reversed(records) if item.get("client_id") == client_id
                           and item.get("decision_id") == selected_route["decision_id"]
                           and item.get("result_status") == "completed"), None)
            _assert_audit(record, selected, client_id)
            execution_id, execution_receipt = config.mi_receipt(client_id, record["request_id"])
            if not isinstance(execution_id, str):
                raise AssertionError("execution receipt link missing")
            decision, context = _assert_retained(execution_receipt, config.mi_cut, receipt_id=execution_id)
            _assert_execution_admission(decision, context, execution_receipt, selected, record)
            binding_id, binding = config.mi_receipt(client_id, selected["mi_projection"]["request_id"])
            if (not isinstance(binding, dict) or binding.get("schema_version") != 1
                    or binding.get("mi_utilization") != selected["mi_utilization"]
                    or binding.get("route") != selected_route or not isinstance(binding.get("receipt_id"), str)):
                raise AssertionError("retained MI projection link mismatch")
            _assert_retained(config.mi_receipt_by_id(binding["receipt_id"]), config.mi_cut,
                             selected["mi_utilization"], binding["receipt_id"])
            cases.append(_result_case(source, client_id, selected, record, binding_id,
                                      binding["receipt_id"], execution_id))

        worker = workers[alternate]
        worker["runtime"].request_stop()
        for transport in worker["transports"]:
            transport.close()
        worker["thread"].join(timeout=15)
        if worker["thread"].is_alive():
            raise RuntimeError("worker failed to disconnect")
        def connected():
            sources = admin("GET", "/control/sources")["sources"]
            return next(item["connected"] for item in sources if item["source_id"] == alternate)

        wait_for(lambda: not connected(), "worker disconnect not observed", timeout=30)
        before = _turns(workers)
        unavailable_status, unavailable = config.exchange("POST", "/v1/chat/completions", {
            "model": f"sr-pin:{alternate_resource}/{MODEL}",
            "messages": [{"role": "user", "content": PROMPT}],
        }, {"Authorization": f"Bearer {restricted_key}"})
        _assert_gateway_error(unavailable_status, unavailable, {
            (404, "not_found_error", "pin_target_not_found"),
            (503, "api_error", "target_unavailable"),
            (503, "api_error", "adapter_unavailable"),
        })
        _assert_private(unavailable, preferred)
        if _turns(workers) != before:
            raise AssertionError("disconnected request reached a fake backend")
        runtime = WorkerRuntime(origin=origin, store=worker["store"], local_adapters=worker["registry"],
                                state_report_interval_seconds=2, connect_factory=worker["connect"])
        worker["runtime"] = runtime
        worker["thread"] = threading.Thread(target=runtime.run, name=alternate, daemon=True)
        worker["thread"].start()
        wait_for(connected, "worker did not reconnect", timeout=90)
        recovered = wait_for(lambda: (r if ((r := selection(restricted_key))["route"].get("target") or {}).get("resource", {}).get("resource_id")
                             == alternate_resource else None), "worker did not recover after reconnect", timeout=90)
        if recovered["route"]["target"].get("reasoning_effort") != "high":
            raise AssertionError("reconnected target did not evidence the synthetic high effort")
        resumed = client(restricted_key, "/v1/chat/completions", {
            "model": f"sr-pin:{alternate_resource}/{MODEL}@{recovered['route']['decision_id']}",
            "messages": [{"role": "user", "content": PROMPT}],
        })
        _assert_private(resumed, preferred)
        if resumed["choices"][0]["message"]["content"] != "Hello":
            raise AssertionError("execution did not recover after reconnect")
        after = _turns(workers)
        if len(after[alternate]) != len(before[alternate]) + 1 or after[preferred] != before[preferred]:
            raise AssertionError("recovered execution did not reach only the expected fake backend")
        result = {"schema_version": 1, "synthetic": True, "cut_sha256": EXPECTED_CUT["sha256"],
                  "limitations": ["same_container_test_worker", "fake_backend_and_spawner", "sandbox_not_verified"],
                  "cases": cases, "checks": {
                      "both_sources_routable": True, "both_own_projections_valid": True,
                      "cross_client_projection_rejected": True, "modified_projections_rejected": True,
                      "restricted_source_excluded_from_selection": True, "restricted_pin_non_200": True,
                      "restricted_responses_exclude_preferred_source": True,
                      "input_4097_no_solution": True, "both_gateway_executions_completed": True,
                      "preferred_backend_model_and_effort_observed": True,
                      "both_audit_targets_match_selection": True,
                      "both_execution_and_projection_receipts_verified": True,
                      "alternate_disconnect_and_recovery": True,
                  }}
    finally:
        stuck = []
        for source_id, worker in workers.items():
            if worker["runtime"] is not None:
                worker["runtime"].request_stop()
            for transport in worker["transports"]:
                transport.close()
            if worker["thread"] is not None:
                worker["thread"].join(timeout=15)
            worker["spawner"].reap_all()
            if worker["thread"] is not None and worker["thread"].is_alive():
                stuck.append(source_id)
            else:
                worker["store"].close()
        if stuck:
            raise RuntimeError(f"workers failed to stop: {stuck}")
    return result


def run_in_container(settings: dict, live_callback=None) -> dict | None:
    """Execute in SR's network namespace; caller supplies ephemeral credentials.

    Settings must arrive through a protected stdin, not command-line arguments.
    The provisioning layer owns source provenance and container isolation.
    """
    if settings.get("isolated") is not True:
        raise ValueError("explicit isolated container required")
    cookie, csrf = settings["admin_cookie"], settings["admin_csrf"]
    if not isinstance(cookie, str) or not cookie or not isinstance(csrf, str) or not csrf:
        raise ValueError("admin session and CSRF required")
    port = settings["http_port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid loopback HTTPS port")
    ca = Path(settings["ca_file"])
    context = ssl.create_default_context(cafile=str(ca))

    def exchange(method, path, body, headers):
        if not path.startswith(("/control/", "/v1/")) or "\r" in path or "\n" in path:
            raise ValueError("invalid endpoint")
        merged = dict(headers)
        if path.startswith("/control/"):
            merged.update({"Cookie": cookie, "X-Scarcity-CSRF": csrf})
        data = json.dumps(body).encode() if body is not None else None
        if data is not None:
            merged["Content-Type"] = "application/json"
        connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=30)
        try:
            connection.request(method, path, body=data, headers=merged)
            result = connection.getresponse()
            raw = result.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError("response exceeds bound")
            return result.status, json.loads(raw) if raw else None
        finally:
            connection.close()

    if not isinstance(settings.get("store_file"), str) or not settings["store_file"]:
        raise ValueError("existing absolute store path required")
    store = Path(settings["store_file"])
    if not store.is_absolute() or not store.is_file() or store.name != "server-state.sqlite3":
        raise ValueError("existing absolute SR store path required")
    from scarcity_router.mi_server_config import MIServer
    from scarcity_router.server_store import ServerStore

    migration = settings.get("migration")
    if migration not in (None, "initialize", "resume"):
        raise ValueError("invalid migration mode")
    if migration is None:
        _require_projection_support(MIServer)
    retained_store = ServerStore.open(store.parent, migrate=False)

    def read_rows(query, parameters=()):
        with sqlite3.connect(store.as_uri() + "?mode=ro", uri=True, timeout=5) as db:
            return db.execute(query, parameters).fetchall()

    def audit():
        return [json.loads(row[0]) for row in read_rows("SELECT payload FROM audit_records ORDER BY seq DESC LIMIT 100")][::-1]

    def receipt(client_id, request_id):
        identifier = retained_store.get_mi_receipt_for_request(client_id, request_id)
        data = retained_store.get_mi_receipt(identifier) if identifier is not None else None
        if data is None:
            return identifier, None
        parsed = json.loads(data)
        if isinstance(parsed, dict) and "receipt_id" in parsed and hashlib.sha256(data).hexdigest() != identifier:
            raise ValueError("projection binding digest mismatch")
        return identifier, parsed

    def receipt_by_id(identifier):
        data = retained_store.get_mi_receipt(identifier)
        return json.loads(data) if data is not None else None

    def retained_cut(identifier):
        return retained_store.get_retained_mi_cut(identifier)

    def verify_cut(key, response, digest):
        if not isinstance(key, str) or not key or digest not in FIXTURE_CUTS or not isinstance(response, dict):
            return False
        try:
            key_hash = hashlib.sha256(key.encode()).hexdigest()
            clients = [client_id for client_id, stored in retained_store.active_client_key_hashes().items()
                       if hmac.compare_digest(key_hash, stored)]
            if len(clients) != 1:
                return False
            payload = _verify_payload(response)
            status, verified = exchange("POST", "/v1/mi/verify-projection", payload,
                                        {"Authorization": f"Bearer {key}"})
            if status != 200 or verified != {"schema_version": 1, "valid": True}:
                return False
            _, binding = receipt(clients[0], response["mi_projection"]["request_id"])
            if (not isinstance(binding, dict) or binding.get("schema_version") != 1
                    or binding.get("route") != response["route"]
                    or binding.get("mi_utilization") != response["mi_utilization"]
                    or not isinstance(binding.get("receipt_id"), str)):
                return False
            _assert_retained(receipt_by_id(binding["receipt_id"]), retained_cut, response["mi_utilization"],
                             binding["receipt_id"], {**EXPECTED_CUT, "sha256": digest})
            return True
        except (AssertionError, KeyError, ValueError, TypeError):
            return False

    try:
        read_rows("SELECT * FROM audit_records LIMIT 0")
        if settings.get("verify_only") is True:
            if live_callback is None:
                raise ValueError("verification-only mode requires live control")
            live_callback(lambda: False, verify_cut, None)
            return
        if settings.get("verify_only", False) is not False:
            raise ValueError("invalid verification mode")
        scratch = Path(settings["scratch"])
        if not scratch.is_absolute() or scratch.parent.stat().st_uid != os.geteuid() or scratch.parent.stat().st_mode & 0o077:
            raise ValueError("scratch parent must be an owned private directory")
        if migration == "resume":
            if not scratch.is_dir() or scratch.is_symlink():
                raise ValueError("preserved worker state missing")
        else:
            scratch.mkdir(mode=0o700)
        return run_worker_acceptance(WorkerConfig(
            "127.0.0.1", settings["worker_port"], ca, scratch, exchange, True,
            audit_records=audit, backend_file=Path(settings["backend_file"]), mi_receipt=receipt,
            mi_receipt_by_id=receipt_by_id, mi_cut=retained_cut, migration=migration,
        ), live_callback=(lambda ready, execute: live_callback(ready, verify_cut, execute)) if live_callback is not None else None)
    finally:
        retained_store.close()


def _live_commands(ready, verify_cut, source, sink, execute=None):
    """Serve bounded JSON lines; responses contain only booleans, never secrets."""
    def send(value):
        sink.write(json.dumps(value, separators=(",", ":")).encode() + b"\n")
        sink.flush()

    send({"event": "ready"})
    for _ in range(128):
        line = source.readline(512 * 1024 + 1)
        if not line or len(line) > 512 * 1024 or not line.endswith(b"\n"):
            raise ValueError("invalid protocol frame")
        try:
            request = json.loads(line)
            op = request.get("op") if isinstance(request, dict) else None
            if op == "ready" and set(request) == {"op"}:
                send({"ok": ready() is True})
            elif op == "verify_cut" and set(request) == {"op", "key", "response", "digest"}:
                send({"ok": verify_cut(request["key"], request["response"], request["digest"]) is True})
            elif op == "execute" and set(request) == {"op", "key", "mi_enabled"} and callable(execute):
                send({"ok": execute(request["key"], request["mi_enabled"]) is True})
            elif op == "stop" and set(request) == {"op"}:
                send({"ok": True})
                return
            else:
                raise ValueError("invalid protocol operation")
        except (ValueError, TypeError, KeyError, UnicodeDecodeError):
            raise ValueError("invalid protocol frame") from None
    raise ValueError("protocol request limit exceeded")


def serve_live():
    """In-container entry point; credentials and requests travel only on stdin."""
    source, sink = sys.stdin.buffer, sys.stdout.buffer
    try:
        line = source.readline(8193)
        if not line or len(line) > 8192 or not line.endswith(b"\n"):
            raise ValueError("invalid initial frame")
        settings = json.loads(line)
        with open(os.devnull, "w") as discard, contextlib.redirect_stdout(discard), contextlib.redirect_stderr(discard):
            run_in_container(settings, lambda ready, verify, execute: _live_commands(ready, verify, source, sink, execute))
    except Exception:
        sink.write(b'{"event":"error"}\n')
        sink.flush()
        raise SystemExit(1) from None


if __name__ == "__main__":
    settings = json.load(sys.stdin)
    print(json.dumps(run_in_container(settings), separators=(",", ":")))
