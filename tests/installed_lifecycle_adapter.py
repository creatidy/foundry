"""Utilities for an installed acceptance adapter, not a complete adapter."""

import hashlib
import io
import json
from datetime import datetime, timedelta
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from local_tls_init import no_acl, open_parent
from local_tls_up import validate_mi
from installed_admin import AdminSession
from installed_provisioning import LABEL, CommandFailure
import mi_publication_fixture as fixture


def write_mi_in_place(destination, filename, data):
    """Update a protected test input without replacing its mounted inode."""
    if filename not in ("publication.json", "trust.json"):
        raise ValueError("unknown MI input")
    if not isinstance(data, bytes) or len(data) > 256 * 1024:
        raise ValueError("publication must be bounded bytes")
    parent, name = open_parent(os.fspath(destination))
    directory = None
    fd = None
    try:
        directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        info = os.fstat(directory)
        if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (os.geteuid(), os.getegid(), 0o750):
            raise ValueError("invalid MI directory")
        no_acl(directory)
        fd = os.open(filename, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) !=
                (os.geteuid(), os.getegid(), 0o640)):
            raise ValueError("invalid publication file")
        no_acl(fd)
        os.ftruncate(fd, 0)
        pending = memoryview(data)
        while pending:
            written = os.write(fd, pending)
            if written <= 0:
                raise OSError("short publication write")
            pending = pending[written:]
        os.fsync(fd)
        after = os.stat(filename, dir_fd=directory, follow_symlinks=False)
        if (after.st_dev, after.st_ino, after.st_nlink) != (before.st_dev, before.st_ino, 1):
            raise ValueError("publication inode changed")
    finally:
        if fd is not None:
            os.close(fd)
        if directory is not None:
            os.close(directory)
        os.close(parent)


def write_publication_in_place(destination, data):
    write_mi_in_place(destination, "publication.json", data)


def snapshot_manifest(data):
    """Validate a bounded offline tar snapshot and return a content manifest.

    This is only an archive verifier, not a Docker volume backup or restore.
    """
    if not isinstance(data, bytes) or len(data) > 16 * 1024 * 1024:
        raise ValueError("snapshot exceeds limit")
    result = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for member in archive:
            if len(result) >= 1024:
                raise ValueError("too many snapshot entries")
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or not (member.isdir() or member.isfile()) or
                    member.issym() or member.islnk() or member.sparse is not None or member.mode & 0o7000 or
                    (str(path) != "." and (member.uid, member.gid) != (10001, 10001))):
                raise ValueError("unsafe snapshot entry")
            name = str(path)
            if name in result:
                raise ValueError("duplicate snapshot entry")
            total += member.size
            if total > 12 * 1024 * 1024:
                raise ValueError("snapshot contents exceed limit")
            content = archive.extractfile(member).read() if member.isfile() else b""
            if len(content) != member.size:
                raise ValueError("truncated snapshot")
            result[name] = (member.type, member.mode, member.uid, member.gid, hashlib.sha256(content).hexdigest())
    return result


class InstalledLifecycleAdapter:
    """Lifecycle operations for one explicitly approved InstalledProject.

    Archive and container operations are intentionally bounded and fail closed;
    they have not been runtime-validated on a Docker engine.
    """

    def __init__(self, project, old_image_id, new_image_id):
        if (any(not re.fullmatch(r"sha256:[0-9a-f]{64}", image)
                for image in (old_image_id, new_image_id)) or old_image_id == new_image_id):
            raise ValueError("distinct pinned image IDs required")
        if project.root is not None or project.image_id != old_image_id:
            raise ValueError("unused project configured with old image required")
        self.project = project
        self.old_image_id = old_image_id
        self.new_image_id = new_image_id
        self.admin = AdminSession(project)
        self._initialized = False
        self._snapshots = {}
        self._mi_digest = fixture.EXPECTED_SHA256

    def _start(self, image, mi_enabled, *, check_onboarding_origin=False):
        if check_onboarding_origin and self._initialized:
            raise ValueError("onboarding Origin check requires a fresh administrator store")
        if not self._initialized:
            if image != self.old_image_id:
                raise ValueError("old image must start first")
            self.project.start(mi_enabled=False)
            if check_onboarding_origin:
                self.admin.assert_onboarding_origin()
            self.admin.bootstrap()
            self._initialized = True
        else:
            if self.project.port is not None:
                raise ValueError("stop the container before starting")
            if mi_enabled:
                self.project.launch(image, mi_enabled=True, adopt=True, mi_digest=self._mi_digest)
            else:
                self.project.launch(image, mi_enabled=False, adopt=True)
            self.admin.login()

    def start_old(self, *, check_onboarding_origin=False):
        self._start(self.old_image_id, False, check_onboarding_origin=check_onboarding_origin)

    def start_new(self):
        self._start(self.new_image_id, True)

    def start_new_with_cut(self, publication, trust, expected_digest):
        """Start a predeclared cut on a completely new project and volume."""
        allowed = {fixture.EXPECTED_SHA256, *fixture.VARIANT_SHA256.values()}
        if (self._initialized or self.project.root is not None or expected_digest not in allowed or
                not isinstance(publication, bytes) or not isinstance(trust, bytes) or
                hashlib.sha256(publication).hexdigest() != expected_digest):
            raise ValueError("new project and independently pinned publication required")
        if len(trust) > 256 * 1024:
            raise ValueError("MI trust exceeds limit")
        kind = "fresh" if expected_digest == fixture.EXPECTED_SHA256 else next(
            name for name, digest in fixture.VARIANT_SHA256.items() if digest == expected_digest)
        fixture.validate_cut(kind, (publication, trust))
        if (not isinstance(self.project.mi_cuts, dict) or
                self.project.mi_cuts.get(kind) != (publication, trust)):
            raise ValueError("MI cut does not match the verified fixture")
        def configure(directory):
            write_mi_in_place(directory, "publication.json", publication)
            write_mi_in_place(directory, "trust.json", trust)
            validate_mi(str(directory), expected_digest)
        self.project.image_id = self.new_image_id
        self._mi_digest = expected_digest
        self.project.start(mi_enabled=True, configure_mi=configure, mi_digest=expected_digest)
        self.admin.bootstrap()
        self._initialized = True

    def restart_current_cut(self):
        if not self._initialized or self.project.port is not None:
            raise ValueError("initialized, stopped project required")
        self.start_new()

    def start_new_expect_mi_failure(self, error_code):
        """Accept only a newly launched, owned SR process with the exact MI error."""
        if error_code != "mi_publication_activation_failed" or not self._initialized:
            raise ValueError("unsupported activation failure assertion")
        project = self.project
        try:
            self._stopped()
            validate_mi(str(project.root / "mi"), self._mi_digest)
            previous = project.container_id
            project.launch(self.new_image_id, mi_enabled=True, adopt=True, mi_digest=self._mi_digest,
                           expect_mi_failure=True)
        except CommandFailure as exc:
            if exc.returncode != 1 or not project._inspection_only:
                project.block_engine()
                raise RuntimeError("startup outcome is uncertain; MI activation failure not established") from None
        except BaseException:
            project.block_engine()
            raise
        else:
            project.block_engine()
            raise AssertionError("Router unexpectedly started successfully")
        verified = False
        try:
            self._inspect_expected_mi_failure(previous)
            verified = True
        finally:
            project.finish_expected_inspection(verified=verified)
        project.stop()

    def _inspect_expected_mi_failure(self, previous):
        project = self.project
        roles = project._roles()
        if roles["router"] == previous:
            raise AssertionError("activation failure did not create a new owned container")
        identifier = roles["router"]
        info = json.loads(project._docker("container", "inspect", identifier))[0]
        state = info.get("State", {})
        try:
            started = datetime.fromisoformat(state["StartedAt"].replace("Z", "+00:00"))
            finished = datetime.fromisoformat(state["FinishedAt"].replace("Z", "+00:00"))
            timely_exit = timedelta(0) <= finished - started < timedelta(seconds=60)
        except (KeyError, TypeError, ValueError):
            timely_exit = False
        args = info.get("Config", {}).get("Cmd") or []
        volume = project.env.get("FOUNDRY_TEST_VOLUME", project.project + "_router-data")
        mounts = info.get("Mounts", [])
        host = info.get("HostConfig", {})
        bindings = host.get("PortBindings") or {}
        data_mount = [item for item in mounts if item.get("Destination") == "/data"]
        mi_mounts = [item for item in mounts if item.get("Destination") in
                     ("/run/foundry/mi/trust.json", "/run/foundry/mi/publication.json")]
        if (info.get("Image") != self.new_image_id or state.get("Status") != "exited" or
                state.get("ExitCode") != 2 or state.get("Running") is not False or
                state.get("Restarting") is not False or info.get("RestartCount") != 0 or
                host.get("RestartPolicy", {}).get("Name") != "no" or
                host.get("NanoCpus") != 1_000_000_000 or host.get("Memory") != 512 * 1024 * 1024 or
                host.get("MemorySwap") != 512 * 1024 * 1024 or host.get("PidsLimit") != 128 or
                host.get("Privileged") is not False or len(mounts) != 3 or
                not timely_exit or state["StartedAt"].startswith("0001-") or
                "--mi-config=/run/foundry/mi/trust.json" not in args or
                len(data_mount) != 1 or data_mount[0].get("Type") != "volume" or
                data_mount[0].get("Name") != volume or volume not in project._owned("volume") or
                len(mi_mounts) != 2 or {item["Destination"] for item in mi_mounts} !=
                {"/run/foundry/mi/trust.json", "/run/foundry/mi/publication.json"} or
                any(item.get("Type") != "bind" or item.get("RW") is not False or
                                           item.get("Source") != str(project.root / "mi" / item["Destination"].rsplit("/", 1)[1])
                                           for item in mi_mounts)):
            raise AssertionError("activation failure container identity or state mismatch")
        project._validate_publications(info, running=False)
        project._validate_transport(info)
        networks = project._owned("network")
        if len(networks) != 1:
            raise AssertionError("activation failure network ownership mismatch")
        inspected = [json.loads(project._docker("network", "inspect", item)) for item in networks]
        if any(len(item) != 1 for item in inspected):
            raise AssertionError("activation failure network inspection mismatch")
        network = {item[0].get("Name"): item[0] for item in inspected}
        backend = network.get(project.project + "_backend", {})
        if (set(network) != {project.project + "_backend"} or
                backend.get("Internal") is not False or backend.get("Driver") != "bridge" or
                host.get("NetworkMode") != backend.get("Name") or
                set(backend.get("Containers", {})) not in (set(), {info.get("Id")})):
            raise AssertionError("activation failure canonical bridge topology mismatch")
        logs = project._docker("logs", identifier, timeout=20, merge_output=True)
        if ("server: mi_publication_activation_failed" not in logs.splitlines() or
                any("server component listening on " in line for line in logs.splitlines())):
            raise AssertionError("expected MI activation failure was not established")
        project.container_id = identifier
        project.port = None

    def stop(self):
        self.project.stop()
        self.admin.cookie = self.admin.csrf = None

    def exchange(self, method, path, body, headers, *, admin):
        if method == "POST" and path == "/control/mi/reload":
            self.project.require_unblocked()
            try:
                supplied = dict(headers)
                if any(name.lower() in ("cookie", "x-scarcity-csrf") for name in supplied):
                    raise ValueError("caller cannot supply session headers")
                if admin:
                    if not self.admin.cookie or not self.admin.csrf:
                        raise ValueError("administrator session not established")
                    supplied.update({"Cookie": self.admin.cookie, "X-Scarcity-CSRF": self.admin.csrf})
                status, raw, response_headers = self.admin._request(method, path, body, supplied)
                lengths = [value for name, value in response_headers if name.lower() == "content-length"]
                if (len(lengths) != 1 or lengths[0] != str(len(raw)) or
                        any(name.lower() == "transfer-encoding" for name, _ in response_headers)):
                    raise ValueError("reload response framing is incomplete or ambiguous")
                def unique(pairs):
                    result = {}
                    for name, value in pairs:
                        if name in result:
                            raise ValueError("duplicate reload response field")
                        result[name] = value
                    return result
                return status, json.loads(raw, object_pairs_hook=unique)
            except BaseException:
                self.project.block_engine()
                raise
        return self.admin.exchange(method, path, body, headers, admin=admin)

    def block_engine(self):
        self.project.block_engine()

    def require_unblocked(self):
        self.project.require_unblocked()

    def write_publication_in_place(self, data):
        self.project.require_unblocked()
        try:
            write_publication_in_place(self.project.root / "mi", data)
        except BaseException:
            self.project.block_engine()
            raise

    def write_trust_in_place(self, data):
        self.project.require_unblocked()
        try:
            write_mi_in_place(self.project.root / "mi", "trust.json", data)
        except BaseException:
            self.project.block_engine()
            raise

    def _stopped(self):
        try:
            self._validate_stopped()
        except BaseException:
            self.project.block_engine()
            raise

    def _validate_stopped(self):
        project = self.project
        if project.port is not None or project._roles() != {"router": project.container_id}:
            raise ValueError("stopped owned router required")
        import json
        info = json.loads(project._docker("container", "inspect", project.container_id))[0]
        if info["State"].get("Running"):
            raise ValueError("router must be stopped")
        expected = project.env.get("FOUNDRY_TEST_VOLUME", project.project + "_router-data")
        mounts = [item for item in info.get("Mounts", []) if item.get("Destination") == "/data"]
        if (len(mounts) != 1 or mounts[0].get("Type") != "volume" or
                mounts[0].get("Name") != expected or expected not in project._owned("volume")):
            raise ValueError("stopped container data volume is not owned")

    def snapshot(self):
        self._stopped()
        try:
            data = self.project._docker("cp", self.project.container_id + ":/data/.", "-", timeout=60, binary=True)
            manifest = snapshot_manifest(data)
            if not any(name != "." for name in manifest):
                raise ValueError("empty snapshot")
            key = uuid.uuid4().hex
            self._snapshots[key] = (data, manifest, hashlib.sha256(data).digest())
            return key
        except BaseException:
            self.project.block_engine()
            raise

    def restore(self, snapshot):
        self._stopped()
        try:
            if snapshot not in self._snapshots:
                raise ValueError("snapshot is not owned by this adapter")
            data, manifest, digest = self._snapshots[snapshot]
            if hashlib.sha256(data).digest() != digest or snapshot_manifest(data) != manifest:
                raise ValueError("snapshot changed")
        except BaseException:
            self.project.block_engine()
            raise
        project = self.project
        volume = project.project + "_restore_" + uuid.uuid4().hex
        try:
            if volume in project._docker("volume", "ls", "-q").splitlines():
                raise ValueError("restore volume already exists")
            project._docker("volume", "create", "--label", "com.docker.compose.project=" + project.project,
                            "--label", "com.docker.compose.volume=router-data",
                            "--label", LABEL + "=" + project.token, volume)
            if volume not in project._owned("volume"):
                raise ValueError("restore volume was not created with required labels")
            helper = project._docker("container", "create", "--network", "none", "--cpus", "1",
                                     "--memory", "512m", "--memory-swap", "512m", "--pids-limit", "128",
                                     "--label", "com.docker.compose.project=" + project.project,
                                     "--label", LABEL + "=" + project.token,
                                     "--mount", "type=volume,source=" + volume + ",target=/data",
                                     "--entrypoint", "/bin/true", self.new_image_id).strip()
            if not re.fullmatch(r"[0-9a-f]{12,64}", helper) or helper not in project._owned("container"):
                raise ValueError("restore helper ownership not verified")
            empty = project._docker("cp", helper + ":/data/.", "-", timeout=60, binary=True)
            if any(name != "." for name in snapshot_manifest(empty)):
                raise ValueError("restore volume is not empty")
            project._docker("cp", "-a", "-", helper + ":/data", timeout=60, input_data=data)
            restored = project._docker("cp", helper + ":/data/.", "-", timeout=60, binary=True)
            actual = snapshot_manifest(restored)
            # Root directory metadata belongs to the new volume, not the archive.
            if {k: v for k, v in actual.items() if k != "."} != {k: v for k, v in manifest.items() if k != "."}:
                raise ValueError("restored volume did not match snapshot")
            if helper not in project._owned("container"):
                raise ValueError("restore helper ownership changed")
            project._docker("container", "rm", helper)
        except BaseException:
            project.block_engine()
            raise
        project.env["FOUNDRY_TEST_VOLUME"] = volume
