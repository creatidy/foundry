"""Test-only image build evidence contract.

The caller must independently authenticate the source checkouts, build executor,
base manifest and expected file manifests. A matching image ID is not source
authentication. Unlocked apt and pip dependencies prevent reproducible builds.
"""

import hashlib
import re

OLD_SR = "f96d58e6d7d0fffdbe70476850d824efa5de2fb5"
NEW_SR = "8fc4f91ff1aa4c52f4738d436fc2ac12d0b8acb1"
MI = "d65891668b7e79f7b666c021f02a1b4bf8c4ca9c"
MI_URL = "https://forgejo.creatidy.com/Creatidy/model-intelligence.git"
DOCKERFILE_SHA256 = "274e359a8b4c499f53c64119a1b4b9aff7b7b64848a51b91fb9bcd082fa7860f"
MAX_FILES = 10000
MAX_SECONDS = 900
MAX_OUTPUT = 1024 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


def dockerfile(source, revision, base_digest):
    """Return the exact test-only Dockerfile bytes for an allowlisted revision."""
    if revision not in (OLD_SR, NEW_SR) or not isinstance(base_digest, str) or not _DIGEST.fullmatch(base_digest):
        raise ValueError("unknown revision or invalid base digest")
    if not isinstance(source, bytes) or hashlib.sha256(source).hexdigest() != DOCKERFILE_SHA256:
        raise ValueError("unrecognized Dockerfile.mi")
    text = source.decode("utf-8")
    if (text.count(OLD_SR) != 2 or text.count("FROM python:3.12-slim") != 2 or text.count(MI) != 1 or
            text.count("/opt/sr/bin/pip install '/src[mi]'") != 1 or
            text.count('ENV PATH="/opt/sr/bin:$PATH" PYTHONUNBUFFERED=1') != 1):
        raise ValueError("unexpected Dockerfile structure")
    text = text.replace(OLD_SR, revision).replace(
        "FROM python:3.12-slim", "FROM python:3.12-slim@" + base_digest)
    text = text.replace("/opt/sr/bin/pip install '/src[mi]'", "/opt/sr/bin/pip install --no-compile '/src[mi]'")
    text = text.replace("PYTHONUNBUFFERED=1", "PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 "
                        "PYTHONNOUSERSITE=1 PYTHONSAFEPATH=1")
    text = text.replace("\nFROM python:3.12-slim@" + base_digest + "\n",
                        "\nRUN git -C /src rev-parse HEAD > /tmp/foundry-sr-commit\n\n"
                        "FROM python:3.12-slim@" + base_digest + "\n", 1)
    text = text.replace("COPY --from=build /opt/sr /opt/sr\n",
                        "COPY --from=build /opt/sr /opt/sr\n"
                        "COPY --from=build /tmp/foundry-sr-commit /opt/foundry-sr-commit\n")
    return text.encode("utf-8")


def _manifest(value):
    if not isinstance(value, dict) or not value or len(value) > MAX_FILES:
        raise ValueError("missing or oversized source manifest")
    for name, digest in value.items():
        if (not isinstance(name, str) or len(name) > 1024 or not name.isascii() or
                not re.fullmatch(r"[A-Za-z0-9_.+/-]+", name) or
                any(part in ("", ".", "..") for part in name.split("/")) or
                not isinstance(digest, str) or not _HASH.fullmatch(digest)):
            raise ValueError("invalid manifest entry")
    return value


def verify_build(*, executor, source, revision, base_digest, expected_sr, expected_mi):
    """Build and verify through a separately trusted, bounded executor.

    executor.build receives keyword arguments dockerfile (bytes), timeout and
    output_limit; it must build exactly those bytes in an empty context without
    cache, enforce the limits and return the full image ID. executor.inspect
    receives image_id, timeout and output_limit and must independently inspect
    that exact immutable image, returning the documented evidence fields below.
    output_limit bounds command diagnostics; the separately bounded binary
    site-packages archive may be larger.
    The executor must also capture trustworthy build-stage evidence for the SR
    checkout revision and resolved base digest; neither can be recovered from
    the final image ID or inferred from the MI direct_url metadata. If it cannot
    establish either, it must raise rather than report a guessed value.
    It must obtain exhaustive installed package file digests from the image,
    reject SR/MI bytecode, symlinks, import hooks and unexpected package roots,
    and obtain direct_url.json from the installed MI distribution.
    Manifests are independently derived from authenticated git trees using the
    same installed relative paths, including generated/packaged resources. The
    executor must perform the documented static package and configuration checks
    on the initial image. These do not verify runtime import resolution. The base
    interpreter and transitive dependencies remain unpinned or separately
    trusted; their code can affect imports and is not authenticated.

    Neither the image ID nor this contract authenticates the Forgejo identity,
    the supplied Git objects, the executor, or the base registry. The returned
    ID is suitable only after those external obligations are met.
    """
    definition = dockerfile(source, revision, base_digest)
    sr = _manifest(expected_sr)
    mi = _manifest(expected_mi)
    image_id = executor.build(dockerfile=definition, timeout=MAX_SECONDS, output_limit=MAX_OUTPUT)
    if not isinstance(image_id, str) or not _DIGEST.fullmatch(image_id):
        raise ValueError("build did not return a full immutable image ID")
    result = executor.inspect(image_id=image_id, timeout=MAX_SECONDS, output_limit=MAX_OUTPUT)
    if not isinstance(result, dict) or set(result) != {
        "image_id", "os", "base_digest", "sr_revision", "mi_url", "mi_revision",
        "mi_vcs", "mi_editable", "sr_files", "mi_files", "static_package_checks_passed"
    }:
        raise ValueError("incomplete or unknown image evidence")
    if (result["image_id"] != image_id or result["os"] != "linux" or
            result["base_digest"] != base_digest or result["sr_revision"] != revision or
            result["mi_url"] != MI_URL or result["mi_revision"] != MI or
            result["mi_vcs"] != "git" or result["mi_editable"] is not False or
            result["static_package_checks_passed"] is not True or
            _manifest(result["sr_files"]) != sr or _manifest(result["mi_files"]) != mi):
        raise ValueError("image evidence mismatch")
    return image_id
