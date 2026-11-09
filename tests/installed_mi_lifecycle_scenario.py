"""Installed SR/MI lifecycle scenario for a disposable gated Compose project.

This module does not provision or connect by itself. An adapter must own the
project, verify both image IDs and isolation, bound every operation, and provide
stopped-volume snapshots and restores into a distinct empty test-owned volume.
Never adapt an existing installation or use production credentials or data.
"""

from __future__ import annotations

import re
import hashlib
import json
from typing import Callable, Protocol

import mi_publication_fixture as fixture
from mi_publication_fixture import EXPECTED_SHA256


class LifecycleAdapter(Protocol):
    old_image_id: str
    new_image_id: str

    def start_old(self) -> None: ...
    def start_new(self) -> None: ...
    def stop(self) -> None: ...
    def snapshot(self) -> object: ...
    def restore(self, snapshot: object) -> None: ...
    def write_publication_in_place(self, data: bytes) -> None: ...
    def write_trust_in_place(self, data: bytes) -> None: ...
    def start_new_expect_mi_failure(self, error_code: str) -> None: ...
    def start_new_with_cut(self, publication: bytes, trust: bytes, expected_digest: str) -> None: ...
    def restart_current_cut(self) -> None: ...
    def exchange(self, method: str, path: str, body: object | None,
                 headers: dict[str, str], *, admin: bool) -> tuple[int, object]: ...
    def block_engine(self) -> None: ...
    def require_unblocked(self) -> None: ...


def run_preactivation_failure(adapter: LifecycleAdapter, fresh_trust: bytes,
                              client_key: str, retained: dict,
                              verify_cut: Callable[[str, dict, str], bool]) -> None:
    """With a stopped fresh-cut store, reject a validly parsed incompatible trust.

    The adapter must verify SR actually launched, exited with the requested MI
    error, and never became accepting; an unrelated failure or timeout is not a
    passing result. This deliberately passes Foundry's independent digest check.
    """
    document = json.loads(fresh_trust)
    if document["reference"]["sha256"] != EXPECTED_SHA256:
        raise ValueError("fresh trust reference required")
    document["scope"]["scope_id"] = "foundry-incompatible-fixture/1"
    adapter.write_trust_in_place(json.dumps(document, sort_keys=True, separators=(",", ":")).encode())
    # Do not modify a bind-mounted input if the failed startup could not be
    # classified as an exited, owned container on the verified engine.
    adapter.start_new_expect_mi_failure("mi_publication_activation_failed")
    adapter.write_trust_in_place(fresh_trust)
    adapter.start_new()
    _verify_retained(adapter, client_key, retained)
    selection = _exchange(adapter, "/v1/select", {"requirement": {"task_level": "L0",
                          "capability_minima": {}, "hard_constraints": {}}}, key=client_key)
    _verify_retained(adapter, client_key, selection)
    if not callable(verify_cut) or verify_cut(client_key, selection, EXPECTED_SHA256) is not True:
        raise AssertionError("fresh active cut not verified after startup failure")


def _exchange(adapter: LifecycleAdapter, path: str, body: object, *, key: str | None = None,
              admin: bool = False, expected: int = 200) -> dict:
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    status, response = adapter.exchange("POST", path, body, headers, admin=admin)
    if status != expected or not isinstance(response, dict):
        raise AssertionError(f"unexpected {path} response: {status}")
    return response


def _reload(adapter: LifecycleAdapter, *, expected: int, key: str | None = None) -> None:
    responses = {
        200: {"status": "ok"},
        400: {"error": {"code": "invalid_request", "message": "MI publication reload rejected; previous state retained"}},
        401: {"error": {"code": "unauthenticated", "message": "administrator session required"}},
    }
    if expected not in responses or (expected == 401) != (key is not None):
        raise ValueError("unsupported reload assertion")
    try:
        adapter.require_unblocked()
        headers = {"Authorization": f"Bearer {key}"} if key is not None else {}
        status, response = adapter.exchange("POST", "/control/mi/reload", {}, headers, admin=key is None)
        if status != expected or response != responses[expected]:
            raise AssertionError("MI reload outcome was not the expected complete response")
        adapter.require_unblocked()
    except BaseException:
        adapter.block_engine()
        raise


def _verify_retained(adapter: LifecycleAdapter, key: str, response: dict) -> None:
    payload = {name: response[name] for name in ("route", "decision", "mi_utilization")}
    payload["projection"] = response["mi_projection"]
    if _exchange(adapter, "/v1/mi/verify-projection", payload, key=key).get("valid") is not True:
        raise AssertionError("SR rejected the retained client projection")


def _bound_selection(adapter: LifecycleAdapter, key: str, *, blocked: bool,
                     worker_ready: Callable[[], bool],
                     verify_cut: Callable[[str, dict, str], bool], digest: str) -> dict:
    if not callable(worker_ready) or worker_ready() is not True:
        raise AssertionError("controlled worker must be confirmed routable before selection")
    body = {"requirement": {"task_level": "L0", "capability_minima": {},
                             "hard_constraints": {"minimum_input_context_tokens": 4096}}}
    response = _exchange(adapter, "/v1/select", body, key=key)
    if worker_ready() is not True:
        raise AssertionError("controlled worker lost routability during selection")
    route = response["route"]
    if blocked:
        if route.get("status") != "no_solution" or route.get("target") is not None:
            raise AssertionError("controlled model was not blocked")
    else:
        target = route.get("target") or {}
        model = target.get("model") or {}
        resource = target.get("resource") or {}
        if ((model.get("provider"), model.get("model"), model.get("variant")) != ("openai", "gpt-6-sol", "high")
                or target.get("reasoning_effort") != "high"
                or resource.get("resource_id") not in ("foundry-worker-a:gpt-6-sol:high", "foundry-worker-b:gpt-6-sol:high")):
            raise AssertionError("controlled model was not eligible")
    _verify_retained(adapter, key, response)
    if not callable(verify_cut) or verify_cut(key, response, digest) is not True:
        raise AssertionError("retained projection does not verify against the expected cut")
    return response


def run_variant_reload_acceptance(adapter: LifecycleAdapter, client_key: str,
                                  cuts: dict[str, tuple[bytes, bytes]],
                                  worker_ready: Callable[[], bool],
                                  verify_cut: Callable[[str, dict, str], bool]) -> tuple[dict, dict]:
    """Exercise fresh -> rejected stale/incompatible -> accepted withdrawal.

    Caller keeps the same real, routable synthetic worker and its attested 8192
    input ceiling alive throughout. Other eligible models must be excluded. The
    withdrawal changes durable state and is intentionally not rolled back here.
    """
    if set(cuts) != {"fresh", "stale", "withdrawn", "incompatible"}:
        raise ValueError("all independently pinned fixture cuts are required")
    for kind, (publication, trust_bytes) in cuts.items():
        expected = EXPECTED_SHA256 if kind == "fresh" else fixture.VARIANT_SHA256[kind]
        trust = json.loads(trust_bytes)
        if (hashlib.sha256(publication).hexdigest() != expected or
                trust["reference"]["sha256"] != expected or
                trust["publication"] != "/run/foundry/mi/publication.json"):
            raise ValueError("synthetic cut reference mismatch")
    fresh = cuts["fresh"]
    retained = _bound_selection(adapter, client_key, blocked=False, worker_ready=worker_ready,
                                verify_cut=verify_cut, digest=EXPECTED_SHA256)
    for kind in ("stale", "incompatible"):
        publication, trust = cuts[kind]
        adapter.write_publication_in_place(publication)
        adapter.write_trust_in_place(trust)
        try:
            _reload(adapter, expected=400)
            _verify_retained(adapter, client_key, retained)
            _bound_selection(adapter, client_key, blocked=False, worker_ready=worker_ready,
                             verify_cut=verify_cut, digest=EXPECTED_SHA256)
            adapter.require_unblocked()
        except BaseException:
            adapter.block_engine()
            raise
        adapter.write_publication_in_place(fresh[0])
        adapter.write_trust_in_place(fresh[1])
    adapter.write_publication_in_place(cuts["withdrawn"][0])
    adapter.write_trust_in_place(cuts["withdrawn"][1])
    try:
        _reload(adapter, expected=200)
        _verify_retained(adapter, client_key, retained)
        withdrawal = _bound_selection(adapter, client_key, blocked=True, worker_ready=worker_ready,
                                      verify_cut=verify_cut, digest=fixture.VARIANT_SHA256["withdrawn"])
    except BaseException:
        adapter.block_engine()
        raise
    return retained, withdrawal


def run_stale_startup_acceptance(adapter: LifecycleAdapter, cuts: dict[str, tuple[bytes, bytes]],
                                 start_worker: Callable[[], Callable[[], bool]],
                                 stop_worker: Callable[[], None],
                                 verify_cut: Callable[[str, dict, str], bool]) -> None:
    """Start the pinned stale cut in a separate clean store and verify retention.

    start_new_with_cut must refuse anything but a new, empty test-owned volume,
    run Foundry's guarded start with the supplied independent digest, and create
    a new admin. start_worker must configure a real routable source matching the
    fresh baseline, with no alternative models, and return a liveness probe.
    """
    publication, trust = cuts["stale"]
    digest = fixture.VARIANT_SHA256["stale"]
    if (hashlib.sha256(publication).hexdigest() != digest or
            json.loads(trust)["reference"]["sha256"] != digest):
        raise ValueError("stale fixture reference mismatch")
    adapter.start_new_with_cut(publication, trust, digest)
    issued = _exchange(adapter, "/control/clients", {"label": "foundry stale cut"}, admin=True)
    key = issued.get("api_key")
    if (not isinstance(key, str) or not key or not callable(start_worker) or
            not callable(stop_worker)):
        raise ValueError("stale test needs a client and real worker starter")
    ready = start_worker()
    try:
        retained = _bound_selection(adapter, key, blocked=True, worker_ready=ready,
                                    verify_cut=verify_cut, digest=digest)
    finally:
        stop_worker()
    adapter.stop()
    adapter.restart_current_cut()
    _verify_retained(adapter, key, retained)
    if verify_cut(key, retained, digest) is not True:
        raise AssertionError("stale projection cut did not survive restart")


def run_lifecycle_acceptance(adapter: LifecycleAdapter, fresh_publication: bytes, *, start_worker=None) -> None:
    """Run the scenario on an explicitly authorized isolated test adapter.

    start_worker(mode, archive) must start the pinned real worker bundle. In
    initialize mode it pairs fresh workers; in resume mode it must restore the
    independently captured worker-local archive without re-pairing or changing
    the server's source configuration. Its execute(key) verifies actual routed
    execution; close() stops workers, and snapshot_worker() captures their state.

    start_old starts the real prior image on a new owned volume without MI;
    start_new uses that same volume and the independently validated fresh MI
    fixture. stop waits for SR to exit before snapshot/restore. restore replaces
    the selected data volume with a distinct, initially empty owned volume.
    exchange uses verified HTTPS; admin=True adds the real admin session and
    CSRF, while False never does. Publication writes preserve the mounted inode.
    The caller must perform verified cleanup, including on exceptions.
    """
    for image_id in (adapter.old_image_id, adapter.new_image_id):
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise ValueError("both independently verified image IDs are required")
    if (adapter.old_image_id == adapter.new_image_id or
            hashlib.sha256(fresh_publication).hexdigest() != EXPECTED_SHA256):
        raise ValueError("distinct prior and MI images and fresh publication required")
    if not callable(start_worker):
        raise ValueError("real persistent migration worker control is required")

    def request(path: str, body: object, *, key: str | None = None, admin: bool = False,
                expected: int = 200) -> dict:
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        status, response = adapter.exchange("POST", path, body, headers, admin=admin)
        if status != expected or not isinstance(response, dict):
            raise AssertionError(f"unexpected {path} response: {status}")
        return response

    def new_client(label: str) -> str:
        key = request("/control/clients", {"label": label}, admin=True).get("api_key")
        if not isinstance(key, str) or not key:
            raise AssertionError("SR did not issue a client key")
        return key

    select_request = {"requirement": {"task_level": "L0", "capability_minima": {},
                                      "hard_constraints": {}}}

    def select(key: str) -> dict:
        return request("/v1/select", select_request, key=key)

    def verify(key: str, response: dict) -> None:
        payload = {name: response[name] for name in ("route", "decision", "mi_utilization")}
        payload["projection"] = response["mi_projection"]
        if request("/v1/mi/verify-projection", payload, key=key).get("valid") is not True:
            raise AssertionError("SR rejected the retained client projection")

    adapter.start_old()
    original_key = new_client("foundry migration original")
    control = start_worker("initialize", None)
    try:
        if control.execute(original_key, mi_enabled=False) is not True:
            raise AssertionError("old image did not route and execute through the paired worker")
    finally:
        control.close()
    worker_snapshot = control.snapshot_worker()
    from installed_worker_control import WorkerArchive
    if (not isinstance(worker_snapshot, WorkerArchive) or not worker_snapshot.data or
            hashlib.sha256(worker_snapshot.data).hexdigest() != worker_snapshot.sha256):
        raise ValueError("independent worker snapshot is required")
    adapter.stop()
    prior_snapshot = adapter.snapshot()

    adapter.start_new()
    control = start_worker("resume", worker_snapshot)
    try:
        if control.execute(original_key, mi_enabled=True) is not True:
            raise AssertionError("upgraded image did not execute through the original worker")
        first = select(original_key)
        verify(original_key, first)
    finally:
        control.close()

    _reload(adapter, key=original_key, expected=401)
    adapter.write_publication_in_place(b"invalid synthetic publication")
    try:
        _reload(adapter, expected=400)
        verify(original_key, first)
        verify(original_key, select(original_key))
        adapter.require_unblocked()
    except BaseException:
        adapter.block_engine()
        raise
    adapter.write_publication_in_place(fresh_publication)
    try:
        _reload(adapter, expected=200)
        verify(original_key, first)
    except BaseException:
        adapter.block_engine()
        raise

    adapter.stop()
    adapter.start_new()
    verify(original_key, first)
    adapter.stop()
    saved = adapter.snapshot()

    adapter.start_new()
    later_key = new_client("foundry post-backup client")
    select(later_key)
    adapter.stop()
    adapter.restore(saved)
    adapter.start_new()
    verify(original_key, first)
    request("/v1/select", select_request, key=later_key, expected=401)
    control = start_worker("resume", worker_snapshot)
    try:
        if control.execute(original_key, mi_enabled=True) is not True:
            raise AssertionError("restored new image did not execute through the original worker")
    finally:
        control.close()
    adapter.stop()

    # Rollback uses the pre-upgrade bytes and the prior image, not a migrated
    # store opened by an older image (which may correctly refuse newer schemas).
    adapter.restore(prior_snapshot)
    adapter.start_old()
    control = start_worker("resume", worker_snapshot)
    try:
        if control.execute(original_key, mi_enabled=False) is not True:
            raise AssertionError("rolled-back image did not execute through the original worker")
    finally:
        control.close()
    request("/v1/select", select_request, key=later_key, expected=401)
    adapter.stop()
