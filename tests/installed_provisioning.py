"""Test-only installed provisioning, gated to an approved disposable Linux engine.

MI package metadata is provenance evidence, not authentication of installed files
or of an image. Runtime operations require explicit separate operator approval.
"""

import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import uuid

import mi_publication_fixture as fixture
import host_mi_provenance

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from local_tls_init import no_acl, open_parent
from docker_socket_validation import validate_engine_socket

ROOT = Path(__file__).resolve().parents[1]
LABEL = "org.creatidy.foundry.test-run"
SR_TEST_REVISION = "8fc4f91ff1aa4c52f4738d436fc2ac12d0b8acb1"
SR_OLD_REVISION = "f96d58e6d7d0fffdbe70476850d824efa5de2fb5"
_ENGINE_VERIFICATION_FAILED = False
_EXPECTED_INSPECTION = None
_CGROUP_FILES = ("/proc/self/cgroup", "/proc/1/cgroup", "/sys/fs/cgroup/memory.max",
                 "/sys/fs/cgroup/memory.swap.max", "/sys/fs/cgroup/pids.max",
                 "/sys/fs/cgroup/cpu.max")


class CommandFailure(RuntimeError):
    def __init__(self, command, returncode, *, stderr="", operation="other"):
        super().__init__("bounded command failed: " + command)
        self.returncode = returncode
        self.stderr = stderr
        self.operation = operation


def redacted_docker_stderr(args, stderr):
    """Preserve only recognized public image errors, never arbitrary daemon text."""
    if not stderr:
        return ""
    if len(stderr) > 4096:
        return "Docker stderr redacted: oversized diagnostic"
    text = bytes(stderr).decode("utf-8", "replace")
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    if (len(args) == 4 and args[:3] == ["docker", "image", "inspect"] and
            (args[3] == "python:3.12-slim" or
             re.fullmatch(r"python:3\.12-slim@sha256:[0-9a-f]{64}", args[3]))):
        for prefix in ("Error response from daemon: No such image: ", "Error: No such image: ",
                       "Error response from daemon: No such object: ", "Error: No such object: "):
            if text == prefix + args[3]:
                return prefix + args[3]
    lower = text.lower()
    if args and args[0] == "docker" and "permission denied" in lower:
        return "Docker reported permission denied; details redacted"
    if args and args[0] == "docker" and ("cannot connect to the docker daemon" in lower or
                                           "is the docker daemon running" in lower):
        return "Docker reported daemon unavailable; details redacted"
    return "Docker stderr redacted: unrecognized diagnostic"


def test_image_dockerfile(base_digest):
    """Derive a test Dockerfile, not a reproducible or authenticated image.

    The caller independently verifies base_digest, source and resulting image.
    Apt and transitive dependencies in the existing Dockerfile remain unpinned.
    """
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", base_digest):
        raise ValueError("independently pinned base manifest digest required")
    source = (ROOT / "Dockerfile.mi").read_text(encoding="utf-8")
    if (source.count(SR_OLD_REVISION) != 2 or source.count("FROM python:3.12-slim") != 2 or
            source.count(fixture.MI_REVISION) != 1):
        raise ValueError("Dockerfile.mi does not match the inspected source contract")
    return source.replace(SR_OLD_REVISION, SR_TEST_REVISION).replace(
        "FROM python:3.12-slim", "FROM python:3.12-slim@" + base_digest)


class InstalledProject:
    """One uniquely labelled Compose project on an explicitly approved engine.

    The operator must separately establish disposable engine/host isolation and
    storage quotas. Docker metadata alone cannot prove these properties.
    """

    def __init__(self, *, socket_path, engine_id, image_id, authorization):
        if authorization != "disposable-linux-engine-approved":
            raise ValueError("explicit disposable engine authorization required")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise ValueError("independently pinned image ID required")
        if not re.fullmatch(r"[A-Za-z0-9:._-]{12,128}", engine_id):
            raise ValueError("expected Docker engine ID required")
        socket_path = os.fspath(socket_path)
        if (not isinstance(socket_path, str) or not socket_path.startswith("/") or socket_path == "/" or
                os.path.normpath(socket_path) != socket_path or socket_path.startswith("//") or
                any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in socket_path)):
            raise ValueError("absolute normalized Unix socket required")
        path = Path(socket_path)
        self.socket_path = path
        self.engine_id = engine_id
        self.image_id = image_id
        self.token = uuid.uuid4().hex
        self.project = "foundry-test-" + self.token
        self.root = None
        self.container_id = None
        self.port = None
        self.env = None
        self._engine_blocked = False
        self._inspection_only = False

    def _run(self, args, timeout=20, input_data=None, *, binary=False, merge_output=False, output_limit=None):
        global _ENGINE_VERIFICATION_FAILED
        docker = bool(args) and args[0] == "docker"
        # Read-only Docker calls may still time out, but a failed mutation can
        # have taken effect even if the CLI did not receive a successful reply.
        read_only = (docker and (args[1:2] == ["info"] or
                     (len(args) >= 3 and args[1] in ("image", "container", "network", "volume")
                      and args[2] in ("inspect", "ls")) or args[1:2] == ["logs"] or
                     (args[1:2] == ["cp"] and len(args) >= 4 and args[-1] == "-")))
        mutation = docker and not read_only
        if docker and (self._engine_blocked or _ENGINE_VERIFICATION_FAILED):
            raise ValueError("engine verification previously failed; no retry permitted")
        if _EXPECTED_INSPECTION is not None:
            allowed = docker and (args == ["docker", "info", "--format", "{{json .}}"] or
                       (len(args) >= 3 and args[1] in ("container", "network", "volume")
                        and args[2] in ("ls", "inspect")) or
                       (len(args) == 3 and args[1] == "logs"))
            if _EXPECTED_INSPECTION is not self or not self._inspection_only or not allowed:
                self._engine_blocked = True
                _ENGINE_VERIFICATION_FAILED = True
                raise ValueError("expected-failure inspection permits only owned read-only checks")
        if input_data is not None and (not isinstance(input_data, bytes) or len(input_data) > 16 * 1024 * 1024):
            raise ValueError("stdin exceeds limit")
        if output_limit is None:
            output_limit = 16 * 1024 * 1024 if binary else 1024 * 1024
        if type(output_limit) is not int or output_limit < 1 or output_limit > 128 * 1024 * 1024:
            raise ValueError("invalid output limit")
        proc = subprocess.Popen(args, cwd=self.root, env=self.env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                                start_new_session=True)
        output = {proc.stdout: bytearray(), proc.stderr: bytearray()}
        deadline = time.monotonic() + timeout
        try:
            with selectors.DefaultSelector() as selector:
                for stream in output:
                    selector.register(stream, selectors.EVENT_READ)
                if input_data is not None:
                    os.set_blocking(proc.stdin.fileno(), False)
                    selector.register(proc.stdin, selectors.EVENT_WRITE)
                sent = 0
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(args, timeout)
                    for key, _ in selector.select(remaining):
                        if key.fileobj is proc.stdin:
                            sent += os.write(key.fd, input_data[sent:sent + 65536])
                            if sent == len(input_data):
                                selector.unregister(proc.stdin)
                                proc.stdin.close()
                            continue
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            output[key.fileobj].extend(chunk)
                            if sum(map(len, output.values())) > output_limit:
                                raise ValueError("command output exceeded limit")
                proc.wait(timeout=max(0, deadline - time.monotonic()))
        except BaseException as exc:
            if docker and (mutation or isinstance(exc, (subprocess.TimeoutExpired, TimeoutError))):
                self._engine_blocked = True
                _ENGINE_VERIFICATION_FAILED = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            raise
        finally:
            proc.stdout.close()
            proc.stderr.close()
            if proc.stdin is not None and not proc.stdin.closed:
                proc.stdin.close()
        out, err = output.values()
        if proc.returncode:
            if mutation:
                self._engine_blocked = True
                _ENGINE_VERIFICATION_FAILED = True
            operation = "image_inspect" if args[:3] == ["docker", "image", "inspect"] else "other"
            raise CommandFailure(args[0], proc.returncode, stderr=redacted_docker_stderr(args, err), operation=operation)
        if merge_output:
            out.extend(b"\n")
            out.extend(err)
        return bytes(out) if binary else out.decode()

    def _docker(self, *args, timeout=20, input_data=None, binary=False, merge_output=False, output_limit=None):
        self._verify_engine()
        kwargs = {"binary": binary, "merge_output": merge_output}
        if output_limit is not None:
            kwargs["output_limit"] = output_limit
        return self._run(["docker", *args], timeout, input_data, **kwargs)

    def _verify_engine(self):
        global _ENGINE_VERIFICATION_FAILED
        if self._engine_blocked or _ENGINE_VERIFICATION_FAILED:
            raise ValueError("engine verification previously failed; no retry permitted")
        try:
            if (self.root is None or not isinstance(self.env, dict) or
                    self.env.get("DOCKER_HOST") != "unix://" + str(self.socket_path) or
                    self.env.get("DOCKER_CONFIG") != str(self.root / "docker-config") or
                    any(key in self.env for key in ("DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"))):
                raise ValueError("isolated Docker environment is not initialized")
            validate_engine_socket(str(self.socket_path))
            data = json.loads(self._run(["docker", "info", "--format", "{{json .}}"], timeout=20))
            if data.get("ID") != self.engine_id or data.get("OSType") != "linux":
                raise ValueError("unexpected engine identity or non-Linux engine")
            if not data.get("CgroupDriver") or data.get("CgroupDriver") == "none":
                raise ValueError("engine has no cgroup driver")
            if not all(data.get(key) is True for key in ("MemoryLimit", "SwapLimit", "PidsLimit", "CpuCfsQuota")):
                raise ValueError("engine does not report required resource control support")
        except BaseException:
            self._engine_blocked = True
            _ENGINE_VERIFICATION_FAILED = True
            raise

    def start(self, *, mi_enabled=True, configure_mi=None, mi_digest=fixture.EXPECTED_SHA256):
        if self.root is not None:
            raise ValueError("project has already been started")
        self.root = Path(tempfile.mkdtemp(prefix="foundry-accept-"))
        os.chmod(self.root, 0o700)
        for name in ("compose.yaml", "scripts/local_tls_up.py", "scripts/local_tls_init.py",
                     "scripts/docker_socket_validation.py"):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        (self.root / ".env").write_text("")
        self.env = {"PATH": os.defpath, "HOME": str(self.root), "DOCKER_HOST": "unix://" + str(self.socket_path),
                    "DOCKER_CONFIG": str(self.root / "docker-config"),
                    "FOUNDRY_ROUTER_IMAGE": self.image_id, "FOUNDRY_MI_IMAGE_ID": self.image_id,
                    "FOUNDRY_ROUTER_HOST": "127.0.0.1", "FOUNDRY_ROUTER_PORT": "0",
                    "FOUNDRY_TLS_DIR": str(self.root / "tls"), "TLS_DEST": str(self.root / "tls"),
                    "FOUNDRY_MI_DIR": str(self.root / "mi"), "FOUNDRY_MI_SHA256": fixture.EXPECTED_SHA256,
                    "LOCAL_TLS_PROJECT": self.project, "FOUNDRY_TEST_RUN_ID": self.token,
                    "FOUNDRY_TEST_AUTHORIZATION": "disposable-linux-engine-approved",
                    "FOUNDRY_TEST_ENGINE_ID": self.engine_id,
                    "FOUNDRY_TEST_DOCKER_HOST": "unix://" + str(self.socket_path)}
        self._verify_engine()
        self._run([sys.executable, "scripts/local_tls_init.py"], timeout=30)
        prepare_mi(self.root / "mi")
        if configure_mi is not None:
            configure_mi(self.root / "mi")
        return self.launch(self.image_id, mi_enabled=mi_enabled, adopt=False, mi_digest=mi_digest)

    def launch(self, image_id, *, mi_enabled, adopt, mi_digest=fixture.EXPECTED_SHA256,
               expect_mi_failure=False):
        if self.root is None or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise ValueError("initialized project and pinned image required")
        if type(expect_mi_failure) is not bool or (expect_mi_failure and
                (not mi_enabled or not adopt or self.container_id is None or self.port is not None)):
            raise ValueError("expected MI failure requires a stopped adopted project")
        if mi_enabled and mi_digest not in {fixture.EXPECTED_SHA256, *fixture.VARIANT_SHA256.values()}:
            raise ValueError("independently pinned MI fixture digest required")
        image = json.loads(self._docker("image", "inspect", image_id))
        if len(image) != 1 or image[0].get("Id") != image_id or image[0].get("Os") != "linux":
            raise ValueError("pinned Linux image not present")
        if adopt:
            containers = self._owned("container")
            if containers:
                if len(containers) != 1 or containers[0] != self.container_id:
                    raise ValueError("unexpected existing container")
                state = json.loads(self._docker("container", "inspect", self.container_id))[0]["State"]
                if state.get("Running"):
                    raise ValueError("existing container is still running")
            self._owned("network")
            self._owned("volume")
            self.env["LOCAL_TLS_ADOPT_PROJECT"] = self.project
        else:
            self.env.pop("LOCAL_TLS_ADOPT_PROJECT", None)
        self.image_id = image_id
        self.env["FOUNDRY_ROUTER_IMAGE"] = image_id
        if mi_enabled:
            self.env.update(FOUNDRY_MI_IMAGE_ID=image_id, FOUNDRY_MI_DIR=str(self.root / "mi"),
                            FOUNDRY_MI_SHA256=mi_digest)
        else:
            for name in ("FOUNDRY_MI_IMAGE_ID", "FOUNDRY_MI_DIR", "FOUNDRY_MI_SHA256"):
                self.env.pop(name, None)
        global _ENGINE_VERIFICATION_FAILED, _EXPECTED_INSPECTION
        self._verify_engine()
        try:
            self._run([sys.executable, "scripts/local_tls_up.py"], timeout=180)
        except CommandFailure as exc:
            # A failed Compose invocation may have created or changed resources.
            # Its exit code alone cannot establish a safe cleanup boundary.
            if expect_mi_failure and exc.returncode == 1 and _EXPECTED_INSPECTION is None:
                self._inspection_only = True
                _EXPECTED_INSPECTION = self
            else:
                self._engine_blocked = True
                _ENGINE_VERIFICATION_FAILED = True
            raise
        except BaseException:
            self._engine_blocked = True
            _ENGINE_VERIFICATION_FAILED = True
            raise
        if expect_mi_failure:
            self._engine_blocked = True
            _ENGINE_VERIFICATION_FAILED = True
            raise RuntimeError("expected MI startup failure did not occur")
        try:
            return self._validate_started(mi_enabled)
        except BaseException:
            self.block_engine()
            raise

    def _validate_started(self, mi_enabled):
        containers = self._owned("container")
        if len(containers) != 1:
            raise ValueError("expected exactly one project container")
        self.container_id = containers[0]
        data = json.loads(self._docker("container", "inspect", self.container_id))[0]
        host = data["HostConfig"]
        if (data["Image"] != self.image_id or host.get("NanoCpus") != 1_000_000_000 or
                host.get("Memory") != 512 * 1024 * 1024 or host.get("MemorySwap") != 512 * 1024 * 1024 or
                host.get("PidsLimit") != 128 or host.get("Privileged") is not False or
                not data["State"].get("Running") or data["State"].get("Health", {}).get("Status") != "healthy"):
            raise ValueError("container image, limits or health do not match")
        # Require a private cgroup namespace rooted at the workload's cgroup;
        # otherwise /sys/fs/cgroup may describe a different ancestor.
        effective = self._docker("exec", self.container_id, "/bin/cat", *_CGROUP_FILES, timeout=20)
        if effective.splitlines() != ["0::/", "0::/", "536870912", "0", "128", "100000 100000"]:
            raise ValueError("effective workload cgroup limits unverified")
        if self._owned("container") != [self.container_id]:
            raise ValueError("workload container ownership changed during cgroup check")
        after = json.loads(self._docker("container", "inspect", self.container_id))
        started = data["State"].get("StartedAt")
        if (not isinstance(started, str) or not started or len(after) != 1 or
                after[0].get("Image") != self.image_id or after[0].get("State", {}).get("Running") is not True or
                after[0]["State"].get("StartedAt") != started):
            raise ValueError("workload restarted during cgroup check")
        expected_binds = {"/run/foundry/tls": str(self.root / "tls")}
        if mi_enabled:
            expected_binds.update({"/run/foundry/mi/" + name: str(self.root / "mi" / name)
                                   for name in ("trust.json", "publication.json")})
        actual_mounts = data.get("Mounts", [])
        if (len(actual_mounts) != len(expected_binds) + 1 or
                any(sum(m.get("Destination") == target and m.get("Type") == "bind" and
                        m.get("Source") == source and m.get("RW") is False for m in actual_mounts) != 1
                    for target, source in expected_binds.items())):
            raise ValueError("container has unexpected or writable host mounts")
        expected_volume = self.env.get("FOUNDRY_TEST_VOLUME", self.project + "_router-data")
        mounts = [entry for entry in data.get("Mounts", []) if entry.get("Destination") == "/data"]
        if (len(mounts) != 1 or mounts[0].get("Type") != "volume" or
                mounts[0].get("Name") != expected_volume or expected_volume not in self._owned("volume")):
            raise ValueError("container data volume is not the owned selected volume")
        networks = self._owned("network")
        attached = data["NetworkSettings"].get("Networks", {})
        if len(networks) != 1 or len(attached) != 1:
            raise ValueError("container must use exactly one owned internal network")
        network = json.loads(self._docker("network", "inspect", networks[0]))
        network_id = next(iter(attached.values())).get("NetworkID", "")
        if (len(network) != 1 or network[0].get("Internal") is not True or
                not network[0].get("Id", "").startswith(networks[0]) or
                network_id != network[0].get("Id")):
            raise ValueError("container network isolation is unverified")
        ports = data["NetworkSettings"]["Ports"]
        bindings = ports.get("8787/tcp") or []
        if (len(bindings) != 1 or bindings[0].get("HostIp") != "127.0.0.1" or
                any(value for key, value in ports.items() if key != "8787/tcp")):
            raise ValueError("unexpected listener publication")
        self.port = int(bindings[0]["HostPort"])
        return self

    def finish_expected_inspection(self, *, verified):
        """End the single read-only classification window, fencing any failure."""
        global _ENGINE_VERIFICATION_FAILED, _EXPECTED_INSPECTION
        if _EXPECTED_INSPECTION is not self or not self._inspection_only or type(verified) is not bool:
            self._engine_blocked = True
            _ENGINE_VERIFICATION_FAILED = True
            raise ValueError("invalid expected-failure inspection state")
        if verified and (self._engine_blocked or _ENGINE_VERIFICATION_FAILED):
            verified = False
            self._inspection_only = False
            _EXPECTED_INSPECTION = None
            raise ValueError("expected-failure inspection was blocked")
        self._inspection_only = False
        _EXPECTED_INSPECTION = None
        if not verified:
            self._engine_blocked = True
            _ENGINE_VERIFICATION_FAILED = True

    def block_engine(self):
        """Forbid further Docker activity when classification is uncertain."""
        global _ENGINE_VERIFICATION_FAILED
        self._engine_blocked = True
        _ENGINE_VERIFICATION_FAILED = True

    def require_unblocked(self):
        if self._engine_blocked or _ENGINE_VERIFICATION_FAILED or _EXPECTED_INSPECTION is not None:
            raise ValueError("engine fenced; no retry or mounted-input changes permitted")

    @property
    def origin(self):
        if self.port is None:
            raise ValueError("project is not ready")
        return "https://127.0.0.1:" + str(self.port)

    @property
    def ca_file(self):
        if self.port is None:
            raise ValueError("project is not ready")
        return self.root / "tls" / "server.crt"

    def tls_context(self):
        return ssl.create_default_context(cafile=str(self.ca_file))

    def stop(self):
        try:
            self._stop_owned()
        except BaseException:
            self.block_engine()
            raise

    def _stop_owned(self):
        if self.container_id is None or self._owned("container") != [self.container_id]:
            raise ValueError("expected owned container is not present")
        self._docker("container", "stop", "--time", "5", self.container_id, timeout=20)
        info = json.loads(self._docker("container", "inspect", self.container_id))[0]
        if info["State"].get("Running"):
            raise RuntimeError("container did not stop")
        self.port = None

    def run_worker_bundle(self, files, expected_sha256, *, stdin):
        """Run an independently pinned, small test bundle inside the router.

        Both mappings must contain the same allowlisted relative paths. The
        caller is responsible for obtaining the expected digests independently;
        this method does not establish source or image provenance. No host
        workspace or Docker socket is mounted into the container.
        """
        allowed = {"runner.py", "worker_mi_acceptance.py", "codex_fake_appserver.py"}
        if (self.port is None or set(files) != set(expected_sha256) or
                "runner.py" not in files or not set(files).issubset(allowed) or
                not isinstance(stdin, bytes) or len(stdin) > 8192):
            raise ValueError("invalid worker fixture bundle")
        if len(files) > len(allowed) or sum(len(value) for value in files.values()) > 1024 * 1024:
            raise ValueError("worker fixture bundle too large")
        for name, data in files.items():
            if (not isinstance(data, bytes) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256[name]) or
                    hashlib.sha256(data).hexdigest() != expected_sha256[name]):
                raise ValueError("worker fixture digest mismatch")
        if self._owned("container") != [self.container_id]:
            raise ValueError("worker container ownership changed")
        with tempfile.TemporaryDirectory(prefix="worker-bundle-", dir=self.root) as tmp:
            directory = Path(tmp)
            for name, data in files.items():
                path = directory / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                if name == "codex_fake_appserver.py":
                    path.chmod(0o755)
            target = "/tmp/foundry-worker-" + self.token
            self._docker("exec", self.container_id, "mkdir", "-m", "700", target)
            self._docker("cp", str(directory) + "/.", self.container_id + ":" + target, timeout=30)
            return self._docker("exec", "-i", "-e", "PYTHONPATH=" + target, self.container_id,
                                "timeout", "--signal=TERM", "--kill-after=5s", "360s",
                                "python", target + "/runner.py", timeout=375, input_data=stdin)

    def _owned(self, kind):
        try:
            return self._owned_verified(kind)
        except BaseException:
            self.block_engine()
            raise

    def _owned_verified(self, kind):
        args = [kind, "ls", "-q", "--filter", "label=com.docker.compose.project=" + self.project]
        if kind == "container":
            args.insert(2, "-a")
        ids = self._docker(*args).splitlines()
        run_args = [kind, "ls", "-q", "--filter", "label=" + LABEL + "=" + self.token]
        if kind == "container":
            run_args.insert(2, "-a")
        if set(ids) != set(self._docker(*run_args).splitlines()):
            raise ValueError("project and test-run labels do not identify the same resources")
        if len(ids) > 8 or len(set(ids)) != len(ids):
            raise ValueError("unexpected project resource count")
        for identifier in ids:
            info = json.loads(self._docker(kind, "inspect", identifier))[0]
            labels = info.get("Config", {}).get("Labels", {}) if kind == "container" else info.get("Labels", {})
            if labels.get(LABEL) != self.token or labels.get("com.docker.compose.project") != self.project:
                raise ValueError("refusing unowned project resource")
        return ids

    def cleanup(self):
        """Delete only resources with both matching labels; verify none remain."""
        if self.root is None:
            return
        self.require_unblocked()
        if self.env is None:
            shutil.rmtree(self.root)
            self.root = None
            return
        self._verify_engine()
        owned = {kind: self._owned(kind) for kind in ("container", "network", "volume")}
        for kind in ("container", "network", "volume"):
            if owned[kind]:
                args = [kind, "rm"] + (["--force"] if kind == "container" else []) + owned[kind]
                self._docker(*args, timeout=30)
        if any(self._owned(kind) for kind in ("container", "network", "volume")):
            raise RuntimeError("project cleanup incomplete")
        shutil.rmtree(self.root)
        self.root = None
        self.port = None


def verify_mi_metadata():
    """Reject anything but the declared direct VCS revision and package location."""
    dist = importlib.metadata.distribution("model-intelligence")
    direct = json.loads(dist.read_text("direct_url.json") or "null")
    if (not isinstance(direct, dict) or
            direct.get("url") != "https://forgejo.creatidy.com/Creatidy/model-intelligence.git" or
            direct.get("vcs_info", {}).get("vcs") != "git" or
            direct.get("vcs_info", {}).get("commit_id") != fixture.MI_REVISION or
            direct.get("dir_info", {}).get("editable", False)):
        raise ValueError("MI distribution provenance does not match the pinned revision")
    spec = importlib.util.find_spec("model_intelligence")
    expected = Path(dist.locate_file("model_intelligence/__init__.py")).resolve()
    if spec is None or spec.origin is None or Path(spec.origin).resolve() != expected:
        raise ValueError("MI import does not resolve to the declared distribution")


def prepare_mi(destination):
    """Create protected local_tls_up inputs in a new directory under a 0700 parent.

    The returned digest is independently fixed in the fixture. No existing
    destination is adopted, and no TLS, container, network or volume is created.
    """
    host_mi_provenance.require_verified_host_mi()
    verify_mi_metadata()
    destination = os.fspath(destination)
    parent, name = open_parent(destination)
    directory = None
    created = False
    written = []
    try:
        # The publisher's scratch directory remains private and is discarded.
        with tempfile.TemporaryDirectory(prefix="mi-fixture-", dir=os.path.dirname(destination)) as scratch:
            trust = fixture.publish_fixture(Path(scratch), publication_path="/run/foundry/mi/publication.json")
            data = (Path(scratch) / (fixture.EXPECTED_SHA256 + ".json")).read_bytes()
            if (len(data) > fixture.MAX_BYTES or hashlib.sha256(data).hexdigest() != fixture.EXPECTED_SHA256 or
                    trust.get("reference", {}).get("sha256") != fixture.EXPECTED_SHA256 or
                    trust.get("publication") != "/run/foundry/mi/publication.json"):
                raise ValueError("MI publication reference mismatch")
            trust_data = json.dumps(trust, sort_keys=True, separators=(",", ":")).encode("utf-8")
            if len(trust_data) > 256 * 1024:
                raise ValueError("MI trust configuration too large")
            os.mkdir(name, 0o700, dir_fd=parent)
            created = True
            directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.fchown(directory, -1, os.getegid())
            os.fchmod(directory, 0o750)
            no_acl(directory)
            for filename, content in (("trust.json", trust_data), ("publication.json", data)):
                fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
                written.append(filename)
                with os.fdopen(fd, "wb") as stream:
                    os.fchown(stream.fileno(), -1, os.getegid())
                    os.fchmod(stream.fileno(), 0o640)
                    no_acl(stream.fileno())
                    stream.write(content)
        return fixture.EXPECTED_SHA256
    except BaseException:
        if created:
            if directory is not None:
                for filename in written:
                    os.unlink(filename, dir_fd=directory)
            os.rmdir(name, dir_fd=parent)
        raise
    finally:
        if directory is not None:
            os.close(directory)
        os.close(parent)
