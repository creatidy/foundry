"""Bounded private stdin/stdout control for a test worker in SR's namespace.

The caller supplies an owned, non-TTY docker-exec process with a hard lifetime
limit; this module does not provision or connect to an engine itself.
"""
import json
import hashlib
import os
from pathlib import Path
import re
import selectors
import subprocess
import tarfile
import tempfile
import time
import uuid
from dataclasses import dataclass, field


_RUNNER = b"from worker_mi_acceptance import serve_live\nserve_live()\n"
_RETAINED_WORKERS = []


@dataclass(frozen=True)
class WorkerArchive:
    """Private, run-labelled worker state, independent of the SR snapshot."""
    run_id: str
    sha256: str
    data: bytes = field(repr=False)


def _worker_manifest(data):
    from installed_lifecycle_adapter import snapshot_manifest
    manifest = snapshot_manifest(data)
    for source in ("foundry-worker-a", "foundry-worker-b"):
        directory = manifest.get(source)
        database = manifest.get(source + "/worker-state.db")
        if (directory is None or directory[0] != tarfile.DIRTYPE or directory[1] != 0o700 or
                database is None or database[0] not in (tarfile.REGTYPE, tarfile.AREGTYPE) or database[1] != 0o600):
            raise ValueError("worker identity archive incomplete or not private")
    return manifest


def start_live_worker(project, admin, helper, fake, *, helper_sha256, fake_sha256, verify_only=False,
                      migration=None, worker_archive=None):
    """Copy a bounded pinned bundle and start a same-container live worker.

    The caller must separately authorize and verify project/engine isolation and
    source provenance. The in-container timeout also bounds orphaned workers if
    the host-side docker client is lost; no worker listener is published.
    """
    if (type(verify_only) is not bool or migration not in (None, "initialize", "resume") or
            (migration is not None and verify_only) or
            ((migration == "resume") != (worker_archive is not None))):
        raise ValueError("invalid worker mode")
    if worker_archive is not None:
        if (not isinstance(worker_archive, WorkerArchive) or worker_archive.run_id != project.token or
                not re.fullmatch(r"[0-9a-f]{32}", worker_archive.run_id) or
                not isinstance(worker_archive.data, bytes) or
                hashlib.sha256(worker_archive.data).hexdigest() != worker_archive.sha256):
            raise ValueError("worker archive identity or digest mismatch")
        expected_manifest = _worker_manifest(worker_archive.data)
    if project.port is None or project._owned("container") != [project.container_id]:
        raise ValueError("one running owned container is required")
    if not admin.cookie or not admin.csrf:
        raise ValueError("authenticated admin session required")
    for data, digest in ((helper, helper_sha256), (fake, fake_sha256)):
        if (not isinstance(data, bytes) or len(data) > 1024 * 1024
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or hashlib.sha256(data).hexdigest() != digest):
            raise ValueError("invalid pinned worker fixture")
    target = "/tmp/foundry-worker-" + project.token + "-" + uuid.uuid4().hex
    settings = {"isolated": True, "admin_cookie": admin.cookie, "admin_csrf": admin.csrf,
                "http_port": 8787, "worker_port": 8788, "ca_file": "/run/foundry/tls/server.crt",
                "store_file": "/data/server-state.sqlite3", "scratch": target + "/scratch",
                 "backend_file": target + "/codex_fake_appserver.py", "verify_only": verify_only}
    if migration is not None:
        settings["migration"] = migration
    with tempfile.TemporaryDirectory(prefix="worker-live-", dir=project.root) as tmp:
        directory = Path(tmp)
        for name, content in (("runner.py", _RUNNER), ("worker_mi_acceptance.py", helper),
                              ("codex_fake_appserver.py", fake)):
            path = directory / name
            path.write_bytes(content)
            if name == "codex_fake_appserver.py":
                path.chmod(0o755)
        project._docker("exec", project.container_id, "mkdir", "-m", "700", target, timeout=20)
        project._docker("cp", str(directory) + "/.", project.container_id + ":" + target, timeout=30)
    if worker_archive is not None:
        project._docker("exec", project.container_id, "mkdir", "-m", "700", target + "/scratch", timeout=20)
        project._docker("cp", "-a", "-", project.container_id + ":" + target + "/scratch", timeout=60,
                        input_data=worker_archive.data)
        copied = project._docker("cp", project.container_id + ":" + target + "/scratch/.", "-", timeout=60, binary=True)
        actual = _worker_manifest(copied)
        if {k: v for k, v in actual.items() if k != "."} != {k: v for k, v in expected_manifest.items() if k != "."}:
            raise ValueError("restored worker archive mismatch")
    if project._owned("container") != [project.container_id]:
        raise ValueError("worker container ownership changed")
    project._verify_engine()
    process = subprocess.Popen(["docker", "exec", "-i", "-e", "PYTHONPATH=" + target, project.container_id,
                                "timeout", "--signal=TERM", "--kill-after=5s", "600s",
                                "python", target + "/runner.py"], cwd=project.root, env=project.env,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               start_new_session=True)
    session = WorkerControl(process, settings, project=project)
    if migration is not None:
        session.migration_project = project
        session.migration_target = target
    return session


class WorkerControl:
    def __init__(self, process, settings, *, timeout=120, project=None):
        self.process = process
        self.project = project
        self.timeout = timeout
        self.buffer = bytearray()
        self.closed = False
        try:
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            self._write(settings, 8192)
            if self._read() != {"event": "ready"}:
                raise RuntimeError("worker failed to become ready")
        except BaseException:
            if self.project is not None:
                self.project.block_engine()
                _RETAINED_WORKERS.append(self)
            else:
                self.abort()
            raise

    def _write(self, document, maximum=512 * 1024):
        data = json.dumps(document, separators=(",", ":")).encode() + b"\n"
        if len(data) > maximum:
            raise ValueError("worker protocol frame too large")
        deadline = time.monotonic() + self.timeout
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdin, selectors.EVENT_WRITE)
            offset = 0
            while offset < len(data):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError("worker protocol write timed out")
                offset += os.write(self.process.stdin.fileno(), data[offset:offset + 65536])

    def _read(self):
        deadline = time.monotonic() + self.timeout
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            while b"\n" not in self.buffer:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise TimeoutError("worker protocol read timed out")
                chunk = os.read(self.process.stdout.fileno(), 4096)
                if not chunk:
                    raise RuntimeError("worker protocol closed")
                self.buffer.extend(chunk)
                if len(self.buffer) > 8192:
                    raise ValueError("worker protocol response too large")
        line, _, remaining = self.buffer.partition(b"\n")
        self.buffer = bytearray(remaining)
        try:
            value = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            raise ValueError("invalid worker protocol response") from None
        return value

    def _request(self, body):
        if self.closed:
            raise RuntimeError("worker control is closed")
        try:
            self._write(body)
            result = self._read()
            if not isinstance(result, dict) or set(result) != {"ok"} or type(result["ok"]) is not bool:
                raise ValueError("invalid worker protocol response")
            return result["ok"]
        except BaseException:
            if self.project is not None:
                self.project.block_engine()
                if self not in _RETAINED_WORKERS:
                    _RETAINED_WORKERS.append(self)
            else:
                self.abort()
            raise

    def worker_ready(self):
        return self._request({"op": "ready"})

    def verify_cut(self, key, response, digest):
        return self._request({"op": "verify_cut", "key": key, "response": response, "digest": digest})

    def execute(self, key, *, mi_enabled):
        if type(mi_enabled) is not bool:
            raise ValueError("explicit MI expectation required")
        return self._request({"op": "execute", "key": key, "mi_enabled": mi_enabled})

    def snapshot_worker(self):
        """Capture closed test worker identities independently of the SR volume."""
        if not self.closed or not hasattr(self, "migration_project"):
            raise ValueError("closed migration worker required")
        project = self.migration_project
        if project._owned("container") != [project.container_id]:
            raise ValueError("worker container ownership changed")
        data = project._docker("cp", project.container_id + ":" + self.migration_target + "/scratch/.", "-",
                               timeout=60, binary=True)
        _worker_manifest(data)
        return WorkerArchive(project.token, hashlib.sha256(data).hexdigest(), data)

    def close(self):
        if self.closed:
            return
        if self.project is not None:
            try:
                self.project.require_unblocked()
            except ValueError:
                if self not in _RETAINED_WORKERS:
                    _RETAINED_WORKERS.append(self)
                return
        try:
            if self._request({"op": "stop"}) is not True:
                raise RuntimeError("worker refused shutdown")
            self.process.stdin.close()
            if self.process.wait(timeout=20) != 0:
                raise RuntimeError("worker shutdown failed")
        except BaseException:
            if self.project is not None:
                self.project.block_engine()
                if self not in _RETAINED_WORKERS:
                    _RETAINED_WORKERS.append(self)
            raise
        finally:
            if self.project is None:
                self.abort()
            else:
                try:
                    self.project.require_unblocked()
                except ValueError:
                    if self not in _RETAINED_WORKERS:
                        _RETAINED_WORKERS.append(self)
                else:
                    self.abort()

    def abort(self):
        if self.closed:
            return
        self.closed = True
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=5)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def run_variant_with_worker(adapter, client_key, cuts, control):
    """Run the real reload scenario while the supplied worker control is live."""
    from installed_mi_lifecycle_scenario import run_variant_reload_acceptance
    try:
        return run_variant_reload_acceptance(adapter, client_key, cuts, control.worker_ready, control.verify_cut)
    finally:
        control.close()


def run_variant_installed(adapter, client_key, cuts, helper, fake, *, helper_sha256, fake_sha256):
    """Start the owned live runner and perform the negative reload scenario."""
    session = start_live_worker(adapter.project, adapter.admin, helper, fake,
                                helper_sha256=helper_sha256, fake_sha256=fake_sha256)
    return run_variant_with_worker(adapter, client_key, cuts, session)


def run_stale_with_worker(adapter, cuts, start_control):
    """Restart the verifier after SR restarts, without pretending workers survived."""
    from installed_mi_lifecycle_scenario import run_stale_startup_acceptance
    active = [None]

    def start_worker():
        active[0] = start_control(False)
        return active[0].worker_ready

    def stop_worker():
        active[0].close()
        active[0] = None

    def verify_cut(key, response, digest):
        if active[0] is None:
            active[0] = start_control(True)
        return active[0].verify_cut(key, response, digest)

    try:
        return run_stale_startup_acceptance(adapter, cuts, start_worker, stop_worker, verify_cut)
    finally:
        if active[0] is not None:
            active[0].close()


def run_stale_installed(adapter, cuts, helper, fake, *, helper_sha256, fake_sha256):
    """Provision live workers, then a verifier after the controlled restart."""
    def start(verify_only):
        return start_live_worker(adapter.project, adapter.admin, helper, fake,
                                 helper_sha256=helper_sha256, fake_sha256=fake_sha256,
                                 verify_only=verify_only)
    return run_stale_with_worker(adapter, cuts, start)


def assert_input_boundary(adapter, client_key, control, *, mi_enabled):
    """Compare identical controlled inventory with and without the MI cut."""
    if type(mi_enabled) is not bool or control.worker_ready() is not True:
        raise AssertionError("controlled worker is not ready")
    status, response = adapter.exchange("POST", "/v1/select", {
        "requirement": {"task_level": "L0", "capability_minima": {},
                        "hard_constraints": {"minimum_input_context_tokens": 4097}}},
        {"Authorization": "Bearer " + client_key}, admin=False)
    if status != 200 or not isinstance(response, dict) or control.worker_ready() is not True:
        raise AssertionError("boundary selection or worker readiness failed")
    route = response["route"]
    if mi_enabled:
        if route.get("status") != "no_solution" or route.get("target") is not None:
            raise AssertionError("MI-bound request was not blocked")
        from mi_publication_fixture import EXPECTED_SHA256
        if control.verify_cut(client_key, response, EXPECTED_SHA256) is not True:
            raise AssertionError("MI-bound selection did not retain the expected cut")
    else:
        target = route.get("target") or {}
        model, resource = target.get("model") or {}, target.get("resource") or {}
        if ((model.get("provider"), model.get("model"), model.get("variant")) != ("openai", "gpt-6-sol", "high")
                or target.get("reasoning_effort") != "high"
                or resource.get("resource_id") not in ("foundry-worker-a:gpt-6-sol:high", "foundry-worker-b:gpt-6-sol:high")):
            raise AssertionError("unbound request did not select the controlled target")
    return response
