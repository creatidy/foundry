"""Opt-in test image executor and Git object based package manifests.

Never use on an owner engine. The operator must separately authorize the exact
build, verify host/daemon isolation, network destinations and storage quotas.
Neither Git SHA-1 nor a configured remote authenticates the source's owner.
"""

import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import time

import image_provenance as p
from installed_provisioning import CommandFailure, InstalledProject, ROOT

IMAGE_LABEL = "org.creatidy.foundry.image-build"
CONTAINER_LABEL = "org.creatidy.foundry.image-test"
PREFLIGHT_LABEL = "org.creatidy.foundry.preflight"
SITE_ARCHIVE_LIMIT = 128 * 1024 * 1024
SITE_ENTRY_LIMIT = 50000
PROBE = ("import json,os; from pathlib import Path; "
         "p=Path('/sys/fs/cgroup'); s=os.statvfs('/'); "
         "print(json.dumps({'memory':(p/'memory.max').read_text().strip(),"
         "'swap':(p/'memory.swap.max').read_text().strip(),"
         "'pids':(p/'pids.max').read_text().strip(),"
         "'cpu':(p/'cpu.max').read_text().strip(),"
         "'pid':os.getpid(),"
         "'self_cgroup':Path('/proc/self/cgroup').read_text().strip(),"
         "'pid1_cgroup':Path('/proc/1/cgroup').read_text().strip(),"
         "'cgroup_mounts':[x for x in Path('/proc/self/mountinfo').read_text().splitlines() "
         "if len(x.split())>4 and (x.split()[4]=='/sys/fs/cgroup' or "
         "x.split()[4].startswith('/sys/fs/cgroup/'))],"
         "'available':s.f_bavail*s.f_frsize}))")


class ImageInspectionFailure(ValueError):
    """Safe, bounded details of a failed pinned-image preflight."""

    def __init__(self, classification, *, exit_status, stderr):
        super().__init__("pinned image inspection failed: " + classification)
        self.diagnostic = {"classification": classification, "exit_status": exit_status, "stderr": stderr}


def git_manifest(run, repo, revision, product):
    """Hash pinned Git objects, independent of checkout files and Git refs.

    run is a bounded bytes-returning command runner. Object and tree hashes are
    recomputed; authentication of the supplied canonical commit remains external.
    """
    if (product, revision) not in (("sr", p.OLD_SR), ("sr", p.NEW_SR), ("mi", p.MI)):
        raise ValueError("unknown product or revision")
    if not Path(repo).is_absolute():
        raise ValueError("absolute source repository required")

    def obj(kind, oid):
        if not re.fullmatch(r"[0-9a-f]{40}", oid):
            raise ValueError("invalid object ID")
        data = run(["git", "-C", str(repo), "--no-replace-objects", "cat-file", kind, oid])
        if not isinstance(data, bytes) or len(data) > 16 * 1024 * 1024:
            raise ValueError("invalid or oversized git object")
        header = (kind + " " + str(len(data))).encode() + b"\0"
        if hashlib.sha1(header + data).hexdigest() != oid:
            raise ValueError("git object hash mismatch")
        return data

    commit = obj("commit", revision)
    match = re.match(rb"tree ([0-9a-f]{40})\n", commit)
    if not match:
        raise ValueError("invalid commit object")
    files = {}
    count = 0

    def tree(oid, prefix=""):
        nonlocal count
        if prefix.count("/") > 64:
            raise ValueError("git tree nesting too deep")
        data = obj("tree", oid)
        pos = 0
        while pos < len(data):
            space = data.find(b" ", pos)
            zero = data.find(b"\0", space + 1)
            if space < 0 or zero < 0 or zero + 21 > len(data):
                raise ValueError("invalid tree object")
            mode, name = data[pos:space], data[space + 1:zero]
            pos = zero + 21
            child = data[zero + 1:pos].hex()
            try:
                path = prefix + name.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ValueError("non-ASCII git path") from exc
            if not re.fullmatch(r"[A-Za-z0-9_.+/-]+", path) or any(x in ("", ".", "..") for x in path.split("/")):
                raise ValueError("invalid git path")
            count += 1
            if count > p.MAX_FILES:
                raise ValueError("git tree too large")
            if mode == b"40000":
                tree(child, path + "/")
            elif mode in (b"100644", b"100755"):
                if product == "sr" and path.startswith("scarcity_router/"):
                    target = path
                elif product == "sr" and path == "examples/selector-policy.json":
                    target = "scarcity_router/default-selector-policy.json"
                elif product == "mi" and path.startswith("src/model_intelligence/"):
                    target = path.removeprefix("src/")
                else:
                    continue
                if target in files:
                    raise ValueError("duplicate installed path")
                files[target] = hashlib.sha256(obj("blob", child)).hexdigest()
            else:
                raise ValueError("unsupported git tree entry")

    tree(match.group(1).decode())
    return p._manifest(files)


def _tar_files(data, root):
    """Read Docker cp output without extracting untrusted paths to the host."""
    result = {}
    total = 0
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive:
            name = member.name.removeprefix("./").rstrip("/")
            if name in seen or len(seen) >= p.MAX_FILES:
                raise ValueError("duplicate or oversized archive")
            seen.add(name)
            if name == root and member.isdir():
                continue
            if not name.startswith(root + "/"):
                raise ValueError("unexpected archive path")
            path = name[len(root) + 1:]
            if member.isdir():
                continue
            if not member.isfile() or member.size > 16 * 1024 * 1024:
                raise ValueError("unsafe archive member")
            total += member.size
            if total > 16 * 1024 * 1024:
                raise ValueError("archive exceeds size limit")
            if "__pycache__" in path.split("/") or path.endswith(".pyc"):
                raise ValueError("package bytecode is not allowed")
            name = root + "/" + path
            if name in result or len(result) >= p.MAX_FILES:
                raise ValueError("duplicate or oversized archive")
            result[name] = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
    return p._manifest(result)


def _tar_single(data, name):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        entries = archive.getmembers()
        if len(entries) != 1 or entries[0].name.removeprefix("./") != name or not entries[0].isfile() or entries[0].size > 16384:
            raise ValueError("invalid evidence archive")
        return archive.extractfile(entries[0]).read()


def _site_packages(data):
    """Inspect a bounded site-packages snapshot without importing its code."""
    if not isinstance(data, bytes) or len(data) > SITE_ARCHIVE_LIMIT:
        raise ValueError("site-packages archive exceeds limit")
    manifests = {"scarcity_router": {}, "model_intelligence": {}}
    seen = set()
    direct = None
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for member in archive:
            name = member.name.removeprefix("./").rstrip("/")
            if (name in seen or len(seen) >= SITE_ENTRY_LIMIT or not name.isascii() or
                    not re.fullmatch(r"[A-Za-z0-9_.+/-]+", name) or
                    any(part in ("", ".", "..") for part in name.split("/"))):
                raise ValueError("invalid or duplicate site-packages path")
            seen.add(name)
            if name == "site-packages" and member.isdir():
                continue
            if not name.startswith("site-packages/"):
                raise ValueError("unexpected site-packages archive path")
            path = name.removeprefix("site-packages/")
            parts = path.split("/")
            root = parts[0]
            if not (member.isdir() or member.isfile()) or member.sparse is not None:
                raise ValueError("unsafe site-packages archive member")
            if member.size > 32 * 1024 * 1024:
                raise ValueError("site-packages member exceeds limit")
            total += member.size
            if total > SITE_ARCHIVE_LIMIT:
                raise ValueError("site-packages contents exceed limit")
            if (name.lower().endswith((".pth", ".egg-link")) or
                    (root in ("sitecustomize", "usercustomize") or
                     root.startswith(("sitecustomize.", "usercustomize."))) or
                    (len(parts) == 1 and root.endswith(".zip")) or
                    (root == "__pycache__" and len(parts) > 1 and
                     parts[1].startswith(("sitecustomize.", "usercustomize.")))):
                raise ValueError("site-packages import redirection hook")
            for package in manifests:
                if root.startswith(package + "."):
                    raise ValueError("alternate package import root")
            if root in manifests:
                if len(parts) == 1:
                    if not member.isdir():
                        raise ValueError("package root is not a directory")
                    continue
                if "__pycache__" in parts or path.endswith((".pyc", ".pyo")):
                    raise ValueError("package bytecode is not allowed")
                if member.isfile():
                    stream = archive.extractfile(member)
                    manifests[root][path] = hashlib.sha256(stream.read()).hexdigest()
            if path == "model_intelligence-0.1.0.dist-info/direct_url.json":
                if not member.isfile() or member.size > 16384:
                    raise ValueError("invalid MI direct URL evidence")
                direct = json.loads(archive.extractfile(member).read())
    if (not isinstance(direct, dict) or
            any(package + "/__init__.py" not in manifest for package, manifest in manifests.items())):
        raise ValueError("missing package or MI provenance evidence")
    return p._manifest(manifests["scarcity_router"]), p._manifest(manifests["model_intelligence"]), direct


def _verify_python_config(config, pyvenv):
    env = config.get("Env")
    if not isinstance(env, list) or any(not isinstance(item, str) or "=" not in item for item in env):
        raise ValueError("invalid Python image environment")
    pairs = [item.split("=", 1) for item in env]
    values = dict(pairs)
    if (len(values) != len(pairs) or any(key in values for key in ("PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE")) or
            any(values.get(key) != "1" for key in ("PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "PYTHONSAFEPATH")) or
            not values.get("PATH", "").startswith("/opt/sr/bin:") or
            config.get("Entrypoint") != ["python", "-m", "scarcity_router.control_server"]):
        raise ValueError("unsafe Python image configuration")
    try:
        lines = pyvenv.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("invalid virtual environment configuration") from exc
    entries = [line.split("=", 1)[1].strip().lower() for line in lines
               if "=" in line and line.split("=", 1)[0].strip().lower() == "include-system-site-packages"]
    if entries != ["false"]:
        raise ValueError("system site-packages are not disabled")


def _probe_cgroup_attributed(evidence):
    if (not isinstance(evidence, dict) or type(evidence.get("pid")) is not int or
            evidence["pid"] != 1 or evidence.get("self_cgroup") != "0::/" or
            evidence.get("pid1_cgroup") != "0::/"):
        return False
    mounts = evidence.get("cgroup_mounts")
    if not isinstance(mounts, list) or len(mounts) != 1 or not isinstance(mounts[0], str):
        return False
    fields = mounts[0].split()
    if len(fields) < 10 or fields[3:5] != ["/", "/sys/fs/cgroup"] or fields.count("-") != 1:
        return False
    separator = fields.index("-")
    return separator >= 6 and separator + 3 < len(fields) and fields[separator + 1] == "cgroup2"


class DockerExecutor:
    """One no-cache build on an explicitly approved disposable Linux engine.

    Docker build network and dependency resolution are not locked. BuildKit can
    ignore legacy build resource flags; storage and builder isolation must be
    enforced externally. Time/output limits do not establish disk or PID quotas.
    """

    def __init__(self, *, socket_path, engine_id, authorization, build_authorization):
        if build_authorization != "disposable-linux-image-build-approved":
            raise ValueError("separate image build authorization required")
        self.project = InstalledProject(socket_path=socket_path, engine_id=engine_id,
                                        image_id="sha256:" + "0" * 64, authorization=authorization)
        self.temp = None
        self.built = None
        self.base = None
        self.base_layers = None
        self.attempted = False
        self.preflight_base = None
        self.probe_uncertain = False
        self.cleanup_failed = False

    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="foundry-image-build-")
        root = Path(self.temp.name)
        self.project.root = root
        self.project.env = {"PATH": os.defpath, "HOME": str(root),
                            "DOCKER_HOST": "unix://" + str(self.project.socket_path),
                            "DOCKER_CONFIG": str(root / "docker-config"),
                            "GIT_NO_REPLACE_OBJECTS": "1", "GIT_CONFIG_NOSYSTEM": "1",
                            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
                            "GIT_ALLOW_PROTOCOL": ""}
        try:
            self.project._verify_engine()
        except BaseException:
            self.temp.cleanup()
            self.temp = None
            raise
        return self

    def __exit__(self, exc_type, exc, traceback):
        try:
            try:
                self.cleanup()
            except BaseException:
                self.cleanup_failed = True
                if exc is None:
                    raise
                exc.add_note("Image or probe cleanup is unverified; inspect retained resources.")
        finally:
            self.temp.cleanup()
            self.temp = None

    def git_manifest(self, repo, revision, product):
        if self.temp is None:
            raise ValueError("executor is not active")
        deadline = time.monotonic() + 120
        def run(args):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("git manifest deadline exceeded")
            return self.project._run(args, timeout=min(30, remaining), binary=True)
        return git_manifest(run, repo, revision, product)

    def preflight(self, *, base_digest):
        """Probe cgroup v2 and free space, not builder quotas or host isolation.

        Requires separate authorization before entering the executor. On an
        uncertain create/start result, retain the labelled container for review.
        """
        if self.temp is None or self.attempted or not p._DIGEST.fullmatch(base_digest):
            raise ValueError("invalid preflight request")
        self.preflight_base = None
        project = self.project
        project._verify_engine()
        try:
            output = project._docker("image", "inspect", "python:3.12-slim@" + base_digest)
        except subprocess.TimeoutExpired:
            raise ImageInspectionFailure("timeout", exit_status=None, stderr="") from None
        except CommandFailure as exc:
            missing = {prefix + "python:3.12-slim@" + base_digest for prefix in
                       ("Error response from daemon: No such image: ", "Error: No such image: ",
                        "Error response from daemon: No such object: ", "Error: No such object: ")}
            safe_stderr = exc.stderr if exc.stderr in missing | {
                "Docker reported permission denied; details redacted",
                "Docker reported daemon unavailable; details redacted",
                "Docker stderr redacted: unrecognized diagnostic", "Docker stderr redacted: oversized diagnostic",
                ""} else "Docker stderr redacted: unrecognized diagnostic"
            if safe_stderr in missing and exc.operation == "image_inspect":
                classification = "daemon_reported_missing_image"
            elif safe_stderr == "Docker reported permission denied; details redacted":
                classification = "permission_denied"
            elif safe_stderr == "Docker reported daemon unavailable; details redacted":
                classification = "daemon_unavailable"
            else:
                classification = "unexpected_failure"
            status = exc.returncode if type(exc.returncode) is int and -255 <= exc.returncode <= 255 else None
            raise ImageInspectionFailure(classification, exit_status=status, stderr=safe_stderr) from exc
        try:
            base = json.loads(output)
            valid = (isinstance(base, list) and len(base) == 1 and isinstance(base[0], dict) and
                     base[0].get("Os") == "linux" and p._DIGEST.fullmatch(base[0].get("Id", "")) and
                     isinstance(base[0].get("RepoDigests"), list) and
                     any(x in {"python@" + base_digest, "docker.io/library/python@" + base_digest}
                         for x in base[0]["RepoDigests"]))
        except (ValueError, TypeError):
            raise ImageInspectionFailure("unexpected_failure", exit_status=0, stderr="") from None
        if not valid:
            raise ImageInspectionFailure("reference_mismatch", exit_status=0, stderr="")
        image = base[0]["Id"]
        token = project.token
        self.probe_uncertain = True
        cid = project._docker("create", "--pull", "never", "--network", "none", "--cgroupns", "private", "--read-only",
                              "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                              "--memory", "512m", "--memory-swap", "512m", "--cpus", "1",
                              "--pids-limit", "128", "--user", "65534:65534", "--label",
                              PREFLIGHT_LABEL + "=" + token, "--entrypoint", "python", image,
                              "-c", PROBE, timeout=30).strip()
        if not re.fullmatch(r"[0-9a-f]{64}", cid):
            raise ValueError("uncertain preflight container identity; retain for review")
        info = json.loads(project._docker("container", "inspect", cid))
        if len(info) != 1:
            raise ValueError("preflight container inspect failed; retain for review")
        item = info[0]
        host = item.get("HostConfig", {})
        if (item.get("Id") != cid or item.get("Image") != image or
                item.get("Config", {}).get("Labels", {}).get(PREFLIGHT_LABEL) != token or
                item.get("State", {}).get("Running") is not False or host.get("NetworkMode") != "none" or
                host.get("Memory") != 536870912 or host.get("MemorySwap") != 536870912 or
                host.get("NanoCpus") != 1000000000 or host.get("PidsLimit") != 128 or
                host.get("ReadonlyRootfs") is not True or host.get("Privileged") is not False or
                host.get("CgroupnsMode") != "private"):
            raise ValueError("preflight container settings unverified; retain for review")
        output = project._docker("start", "--attach", cid, timeout=30)
        # A completed probe can be removed, but only after rechecking ownership.
        try:
            evidence = json.loads(output)
            if (not _probe_cgroup_attributed(evidence) or
                    evidence.get("memory") != "536870912" or evidence.get("swap") != "0" or
                    evidence.get("pids") != "128" or evidence.get("cpu") != "100000 100000" or
                    type(evidence.get("available")) is not int or evidence["available"] < 10 * 1024**3):
                raise ValueError("effective cgroup limits or available storage unverified")
        finally:
            info = json.loads(project._docker("container", "inspect", cid))
            if (len(info) != 1 or info[0].get("Id") != cid or info[0].get("Image") != image or
                    info[0].get("Config", {}).get("Labels", {}).get(PREFLIGHT_LABEL) != token or
                    info[0].get("State", {}).get("Running") is not False or
                    info[0].get("State", {}).get("ExitCode") != 0):
                raise ValueError("preflight completion or ownership unverified; retain for review")
            project._docker("container", "rm", cid, timeout=30)
            self.probe_uncertain = False
        self.preflight_base = base_digest
        return evidence

    def build(self, *, dockerfile, timeout, output_limit):
        if self.temp is None or self.attempted or timeout != p.MAX_SECONDS or output_limit != p.MAX_OUTPUT:
            raise ValueError("invalid build request")
        match = re.findall(rb"FROM python:3\.12-slim@(sha256:[0-9a-f]{64})", dockerfile)
        if len(match) != 2 or match[0] != match[1]:
            raise ValueError("invalid pinned base")
        self.base = match[0].decode()
        if self.preflight_base != self.base:
            raise ValueError("successful preflight for this base required")
        source = (ROOT / "Dockerfile.mi").read_bytes()
        if dockerfile not in tuple(p.dockerfile(source, revision, self.base) for revision in p.TEST_SR_REVISIONS):
            raise ValueError("unrecognized test image definition")
        base = json.loads(self.project._docker("image", "inspect", "python:3.12-slim@" + self.base))
        if len(base) != 1 or base[0].get("Os") != "linux" or not any(
                item in {"python@" + self.base, "docker.io/library/python@" + self.base}
                for item in base[0].get("RepoDigests", [])):
            raise ValueError("independently provisioned base digest not present")
        layers = base[0].get("RootFS", {}).get("Layers")
        if (not isinstance(layers, list) or not layers or len(layers) > 128 or
                any(not isinstance(x, str) or not p._DIGEST.fullmatch(x) for x in layers)):
            raise ValueError("base layer evidence unavailable")
        self.base_layers = layers[:]
        context = self.project.root / "context"
        context.mkdir(mode=0o700)
        iidfile = self.project.root / "image-id"
        self.attempted = True
        self.project._docker("build", "--no-cache", "--memory", "1g", "--memory-swap", "1g",
                             "--cpu-period", "100000", "--cpu-quota", "100000",
                             "--label", IMAGE_LABEL + "=" + self.project.token, "--iidfile", str(iidfile),
                             "--file", "-", str(context), timeout=timeout, input_data=dockerfile)
        image = iidfile.read_text(encoding="ascii").strip()
        if not p._DIGEST.fullmatch(image):
            raise ValueError("invalid build image ID")
        self.built = image
        return image

    def inspect(self, *, image_id, timeout, output_limit):
        if self.temp is None or image_id != self.built or timeout != p.MAX_SECONDS or output_limit != p.MAX_OUTPUT:
            raise ValueError("invalid image inspection request")
        project = self.project
        deadline = time.monotonic() + timeout
        def docker(*args, **kwargs):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("image inspection deadline exceeded")
            return project._docker(*args, timeout=min(30, remaining), **kwargs)
        image = json.loads(docker("image", "inspect", image_id))
        if (len(image) != 1 or image[0].get("Id") != image_id or image[0].get("Os") != "linux" or
                image[0].get("Config", {}).get("Labels", {}).get(IMAGE_LABEL) != project.token or
                not isinstance(image[0].get("RootFS", {}).get("Layers"), list) or
                image[0]["RootFS"]["Layers"][:len(self.base_layers)] != self.base_layers):
            raise ValueError("image inspect mismatch")
        token = project.token
        cid = docker("create", "--network", "none", "--read-only", "--tmpfs", "/data",
                              "--memory", "512m", "--memory-swap", "512m", "--pids-limit", "128",
                              "--label", CONTAINER_LABEL + "=" + token, image_id).strip()
        if not re.fullmatch(r"[0-9a-f]{64}", cid):
            raise ValueError("invalid created container ID")
        owned = False
        try:
            info = json.loads(docker("container", "inspect", cid))
            if (len(info) != 1 or info[0].get("Id") != cid or info[0].get("Image") != image_id or
                    info[0].get("Config", {}).get("Labels", {}).get(CONTAINER_LABEL) != token or
                    info[0].get("State", {}).get("Running") is not False):
                raise ValueError("unowned inspection container")
            owned = True
            def cp(path):
                return docker("cp", cid + ":" + path, "-", binary=True)
            pyvenv = _tar_single(cp("/opt/sr/pyvenv.cfg"), "pyvenv.cfg")
            _verify_python_config(image[0].get("Config", {}), pyvenv)
            site = docker("cp", cid + ":/opt/sr/lib/python3.12/site-packages", "-",
                          binary=True, output_limit=SITE_ARCHIVE_LIMIT)
            sr, mi, direct = _site_packages(site)
            commit = _tar_single(cp("/opt/foundry-sr-commit"), "foundry-sr-commit").decode("ascii").strip()
            return {"image_id": image_id, "os": "linux", "base_digest": self.base, "sr_revision": commit,
                     "mi_url": direct.get("url"), "mi_revision": direct.get("vcs_info", {}).get("commit_id"),
                     "mi_vcs": direct.get("vcs_info", {}).get("vcs"),
                     "mi_editable": direct.get("dir_info", {}).get("editable", False), "sr_files": sr, "mi_files": mi,
                     "static_package_checks_passed": True}
        finally:
            if owned:
                info = json.loads(project._docker("container", "inspect", cid, timeout=30))
                if (len(info) != 1 or info[0].get("Id") != cid or info[0].get("Image") != image_id or
                        info[0].get("Config", {}).get("Labels", {}).get(CONTAINER_LABEL) != token or
                        info[0].get("State", {}).get("Running") is not False):
                    raise ValueError("inspection container ownership changed")
                project._docker("container", "rm", cid, timeout=30)

    def cleanup(self):
        """Remove only the uniquely labelled, untagged image without consumers.

        Build caches and intermediate images are not owned by this label and are
        deliberately retained. A failed/ambiguous create is also retained.
        """
        if self.probe_uncertain:
            raise ValueError("probe cleanup is uncertain; retain resources for review")
        if self.temp is None or not self.attempted:
            return
        if self.built is None:
            raise ValueError("build completion is uncertain; retain resources for review")
        project = self.project
        project._verify_engine()
        containers = project._docker("container", "ls", "--all", "--no-trunc", "--quiet", "--filter",
                                     "label=" + CONTAINER_LABEL + "=" + project.token).splitlines()
        if (len(containers) > 1 or len(set(containers)) != len(containers) or
                any(not re.fullmatch(r"[0-9a-f]{64}", item) for item in containers)):
            raise ValueError("ambiguous labelled inspection containers")
        for cid in containers:
            data = json.loads(project._docker("container", "inspect", cid))
            if (self.built is None or len(data) != 1 or data[0].get("Id") != cid or
                    data[0].get("Image") != self.built or
                    data[0].get("Config", {}).get("Labels", {}).get(CONTAINER_LABEL) != project.token or
                    data[0].get("State", {}).get("Running") is not False):
                raise ValueError("refusing to remove unowned inspection container")
            project._docker("container", "rm", cid, timeout=30)
        ids = project._docker("image", "ls", "--all", "--no-trunc", "--quiet", "--filter",
                              "label=" + IMAGE_LABEL + "=" + project.token).splitlines()
        if len(ids) > 1 or len(set(ids)) != len(ids) or any(not p._DIGEST.fullmatch(i) for i in ids):
            raise ValueError("ambiguous labelled build images")
        if self.built is not None and ids != [self.built]:
            raise ValueError("built image ownership unavailable")
        if not ids:
            return
        image = ids[0]
        data = json.loads(project._docker("image", "inspect", image))
        if (len(data) != 1 or data[0].get("Id") != image or
                data[0].get("Config", {}).get("Labels", {}).get(IMAGE_LABEL) != project.token or
                data[0].get("RepoTags") not in (None, [], ["<none>:<none>"]) or
                data[0].get("RepoDigests") not in (None, [])):
            raise ValueError("refusing to remove unowned or referenced image")
        if project._docker("container", "ls", "--all", "--quiet", "--no-trunc", "--filter",
                           "ancestor=" + image).strip():
            raise ValueError("refusing to remove image with containers")
        project._docker("image", "rm", image, timeout=30)
        self.built = None
        self.attempted = False


def build_verified(executor, *, source, revision, base_digest, sr_repo, mi_repo):
    """Derive expected manifests from pinned objects, then build and compare.

    Repositories and their canonical commit identities must be independently
    authenticated. A URL in local git configuration is not authentication.
    """
    sr = executor.git_manifest(sr_repo, revision, "sr")
    mi = executor.git_manifest(mi_repo, p.MI, "mi")
    return p.verify_build(executor=executor, source=source, revision=revision,
                          base_digest=base_digest, expected_sr=sr, expected_mi=mi)
