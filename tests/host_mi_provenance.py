"""Install and execute the independently pinned MI wheel in a private venv."""

import base64
import hashlib
import io
import json
import os
from pathlib import Path
import selectors
import shutil
import stat
import subprocess
import tempfile
import time
import zipfile

import image_build_executor
import mi_publication_fixture as fixture


# MI INSTALLED_ACCEPTANCE.md: wheel built from the SR MI pin, with the
# documented backend and SOURCE_DATE_EPOCH, independently of this invocation.
WHEEL_SHA256 = "1ca0b6a0d0e99a5df4a75c66b625f9433553afda09f6b5928be574369a29d019"
MAX_WHEEL_BYTES = 4 * 1024 * 1024
# Aggregate stdout and stderr cap, matching git_manifest's object-size limit.
MAX_SOURCE_OUTPUT = 16 * 1024 * 1024
DIST_INFO = "model_intelligence-0.1.0.dist-info"
TRUST_SHA256 = fixture.TRUST_SHA256


def verify_installation(venv, wheel):
    """Compare the installed site-packages to the authenticated wheel before Python starts."""
    venv = Path(venv)
    config = (venv / "pyvenv.cfg").read_text()
    settings = [line.split("=", 1)[1].strip().lower() for line in config.splitlines()
                if "=" in line and line.split("=", 1)[0].strip().lower() == "include-system-site-packages"]
    if settings != ["false"]:
        raise ValueError("venv system site-packages not disabled")
    sites = list((venv / "lib").glob("python*/site-packages"))
    if len(sites) != 1 or sites[0].is_symlink():
        raise ValueError("unexpected venv site-packages")
    site = sites[0]
    with zipfile.ZipFile(wheel) as archive:
        expected = {entry.filename: archive.read(entry) for entry in archive.infolist() if not entry.is_dir()}
    record = f"{DIST_INFO}/RECORD"
    if record not in expected or not any(name.startswith("model_intelligence/") and name.endswith(".py") for name in expected):
        raise ValueError("invalid pinned MI wheel contents")
    # RECORD is rewritten by uv. These files are installer-generated, not
    # executable, and do not determine the trust of the installed wheel files.
    extra = {f"{DIST_INFO}/{name}" for name in ("INSTALLER", "REQUESTED", "direct_url.json", "uv_cache.json")}
    actual = set()
    for path in site.rglob("*"):
        if path.is_symlink():
            raise ValueError("symlink in installed site-packages")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("non-regular installed file")
        name = path.relative_to(site).as_posix()
        actual.add(name)
        if name in expected and name != record:
            if path.read_bytes() != expected[name]:
                raise ValueError("installed MI file differs from pinned wheel")
        elif name != record and name not in extra:
            raise ValueError(f"unexpected installed file or import hook: {name}")
    if not set(expected).issubset(actual):
        raise ValueError("installed MI wheel file missing")
    direct_url = site / DIST_INFO / "direct_url.json"
    if not direct_url.is_file() or direct_url.stat().st_size > 16384:
        raise ValueError("missing or invalid MI direct URL metadata")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate MI direct URL metadata key")
            result[key] = value
        return result

    try:
        direct = json.loads(direct_url.read_bytes(), object_pairs_hook=unique_object)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid MI direct URL metadata") from exc
    if (not isinstance(direct, dict) or set(direct) != {"url", "archive_info"}
            or direct["url"] != Path(wheel).as_uri() or not isinstance(direct["archive_info"], dict)):
        raise ValueError("MI direct URL does not identify the installed wheel")
    info = direct["archive_info"]
    if (set(info) - {"hash", "hashes"}
            or ("hash" in info and info["hash"] != "sha256=" + WHEEL_SHA256)
            or ("hashes" in info and (not isinstance(info["hashes"], dict)
                                      or info["hashes"] not in ({}, {"sha256": WHEEL_SHA256})))):
        raise ValueError("MI direct URL archive hash mismatch")
    return site


def verify_source_wheel(repo, wheel_data):
    """Compare every MI package file to the exact pinned Git commit objects."""
    deadline = time.monotonic() + 120
    environment = {"PATH": os.defpath, "HOME": "/tmp/kilo", "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "",
                   "GIT_OPTIONAL_LOCKS": "0"}

    def run(command):
        now = time.monotonic()
        if now >= deadline:
            raise TimeoutError("MI source verification timed out")
        command_deadline = min(deadline, now + 30)
        process = None
        try:
            process = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
            output, total = bytearray(), 0
            with selectors.DefaultSelector() as selector:
                for stream in (process.stdout, process.stderr):
                    selector.register(stream, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = command_deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("MI source verification timed out")
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fd, min(65536, MAX_SOURCE_OUTPUT - total + 1))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > MAX_SOURCE_OUTPUT:
                            raise ValueError("MI source output exceeds limit")
                        if key.fileobj is process.stdout:
                            output.extend(chunk)
                remaining = command_deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("MI source verification timed out")
                if process.wait(timeout=remaining):
                    raise ValueError("pinned MI source object unavailable")
            return bytes(output)
        except (subprocess.TimeoutExpired, TimeoutError):
            raise TimeoutError("MI source verification timed out") from None
        except OSError:
            raise ValueError("pinned MI source object unavailable") from None
        finally:
            if process is not None:
                try:
                    if process.poll() is None:
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            raise TimeoutError("MI source process cleanup not confirmed") from None
                finally:
                    try:
                        process.stdout.close()
                    finally:
                        process.stderr.close()

    source = image_build_executor.git_manifest(run, repo, fixture.MI_REVISION, "mi")
    with zipfile.ZipFile(io.BytesIO(wheel_data)) as archive:
        entries = [entry for entry in archive.infolist()
                   if not entry.is_dir() and entry.filename.startswith("model_intelligence/")]
        wheel = {entry.filename: hashlib.sha256(archive.read(entry)).hexdigest() for entry in entries}
    if len(wheel) != len(entries) or wheel != source:
        raise ValueError("MI wheel package differs from pinned source tree")


def generate_cuts(python, wheel, mi_repo):
    """Return {kind: (publication bytes, trust JSON bytes)} from the pinned wheel.

    Trust the interpreter, standard library, uv, this harness and private temp
    directory; no ambient site packages or source checkout are imported.
    """
    python, wheel, mi_repo = Path(python), Path(wheel), Path(mi_repo)
    if (not python.is_absolute() or not python.is_file() or not wheel.is_absolute()
            or not mi_repo.is_absolute() or not mi_repo.is_dir()):
        raise ValueError("absolute existing Python, wheel and MI repository required")
    fd = os.open(wheel, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_WHEEL_BYTES:
            raise ValueError("invalid MI wheel")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(MAX_WHEEL_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_WHEEL_BYTES or hashlib.sha256(data).hexdigest() != WHEEL_SHA256:
        raise ValueError("MI wheel digest mismatch")
    verify_source_wheel(mi_repo, data)
    with tempfile.TemporaryDirectory(prefix="foundry-verified-mi-", dir="/tmp/kilo") as tmp:
        root = Path(tmp)
        copied = root / "model_intelligence-0.1.0-py3-none-any.whl"
        copied.write_bytes(data)
        uv = shutil.which("uv")
        if uv is None:
            raise RuntimeError("trusted uv is required for offline MI installation")
        venv = root / "installed"
        environment = {"PATH": os.defpath, "HOME": tmp, "TMPDIR": tmp,
                       "UV_OFFLINE": "1", "UV_PYTHON_DOWNLOADS": "never", "UV_NO_CONFIG": "1"}
        def install(*command):
            result = subprocess.run(command, cwd=tmp, env=environment, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
            if result.returncode:
                raise RuntimeError("offline MI installation failed")

        install(uv, "venv", "--offline", "--python", str(python), str(venv))
        sites = list((venv / "lib").glob("python*/site-packages"))
        if len(sites) != 1 or sites[0].is_symlink():
            raise ValueError("unexpected venv site-packages")
        # uv creates a virtualenv compatibility import hook. This producer does
        # not need it; remove it before installation or producer startup.
        for name in ("_virtualenv.pth", "_virtualenv.py"):
            (sites[0] / name).unlink(missing_ok=True)
        requirements = root / "requirements.txt"
        requirements.write_text(f"model-intelligence @ {copied.as_uri()} --hash=sha256:{WHEEL_SHA256}\n")
        installed_python = venv / "bin" / "python"
        install(uv, "pip", "install", "--offline", "--no-cache", "--no-deps", "--require-hashes",
                "--python", str(installed_python), "-r", str(requirements))
        site = verify_installation(venv, copied)
        child = Path(__file__).with_name("verified_mi_child.py").resolve()
        result = subprocess.run(
            [str(installed_python), "-I", "-B", str(child), str(site), str(root)],
            cwd=tmp, env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False,
        )
        if result.returncode or result.stderr or len(result.stdout) > 2 * 1024 * 1024:
            raise RuntimeError("verified MI producer subprocess failed")
        document = json.loads(result.stdout)
    expected = {"fresh": fixture.EXPECTED_SHA256, **fixture.VARIANT_SHA256}
    if not isinstance(document, dict) or set(document) != set(expected):
        raise ValueError("invalid MI producer output")
    cuts = {}
    for kind, digest in expected.items():
        item = document[kind]
        if not isinstance(item, dict) or set(item) != {"publication", "trust"}:
            raise ValueError("invalid MI producer output")
        publication = base64.b64decode(item["publication"], validate=True)
        trust = item["trust"]
        trust_bytes = json.dumps(trust, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        if (len(publication) > fixture.MAX_BYTES or hashlib.sha256(publication).hexdigest() != digest
                or not isinstance(trust, dict) or trust.get("reference") != {
                    "format_version": 1, "payload_schema": fixture.PAYLOAD_SCHEMA, "sha256": digest}
                or trust.get("publication") != "/run/foundry/mi/publication.json"
                or hashlib.sha256(trust_bytes).hexdigest() != TRUST_SHA256[kind]):
            raise ValueError("synthetic cut reference mismatch")
        cuts[kind] = (publication, trust_bytes)
    return cuts
