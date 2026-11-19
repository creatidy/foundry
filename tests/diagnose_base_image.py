"""Explicitly authorized read-only inspection of one pinned Docker image."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from installed_provisioning import CommandFailure, InstalledProject
from run_installed_acceptance import Evidence


DIGEST = "sha256:05a994d2344eb364cc186910f4fc8786a38215f39f00d0acc25bff33a08f4177"
ENGINE = "f63fba5b-68ce-42f9-bb64-5a7619ab6cad"
SOCKET = "/run/docker.sock"
TAG = "python:3.12-slim"
PINNED = TAG + "@" + DIGEST
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")


def inspect_reference(project, reference):
    if reference not in (PINNED, TAG):
        raise ValueError("unexpected image reference")
    try:
        raw = project._docker("image", "inspect", reference, timeout=20)
    except subprocess.TimeoutExpired:
        return {"classification": "timeout", "exit_status": None, "stderr": ""}
    except CommandFailure as exc:
        allowed = {"", "Docker reported permission denied; details redacted",
                   "Docker reported daemon unavailable; details redacted",
                   "Docker stderr redacted: unrecognized diagnostic",
                   "Docker stderr redacted: oversized diagnostic",
                   "Error response from daemon: No such image: " + reference,
                   "Error: No such image: " + reference,
                   "Error response from daemon: No such object: " + reference,
                   "Error: No such object: " + reference}
        text = exc.stderr if exc.stderr in allowed else "Docker stderr redacted: unrecognized diagnostic"
        if exc.operation == "image_inspect" and text in {
                "Error response from daemon: No such image: " + reference,
                "Error: No such image: " + reference,
                "Error response from daemon: No such object: " + reference,
                "Error: No such object: " + reference}:
            kind = "daemon_reported_missing_image"
        elif text == "Docker reported permission denied; details redacted":
            kind = "permission_denied"
        elif text == "Docker reported daemon unavailable; details redacted":
            kind = "daemon_unavailable"
        elif exc.operation != "image_inspect":
            kind = "engine_verification_failed"
        else:
            kind = "unexpected_failure"
        status = exc.returncode if type(exc.returncode) is int and -255 <= exc.returncode <= 255 else None
        return {"classification": kind, "exit_status": status, "stderr": text}

    try:
        items = json.loads(raw)
        if not isinstance(items, list) or len(items) != 1 or not isinstance(items[0], dict):
            raise ValueError("invalid inspect envelope")
        item = items[0]
        identity = item.get("Id")
        digests = item.get("RepoDigests")
        if digests is None:
            digests = []
        if (not isinstance(identity, str) or not _SHA.fullmatch(identity) or
                not isinstance(digests, list) or len(digests) > 16):
            raise ValueError("invalid image identity")
        found = set()
        for value in digests:
            if not isinstance(value, str):
                raise ValueError("invalid repository digest")
            match = re.fullmatch(r"(?:docker\.io/library/)?python@(sha256:[0-9a-f]{64})", value)
            if match:
                found.add(match.group(1))
        operating_system = "linux" if item.get("Os") == "linux" else "other"
        architecture = "amd64" if item.get("Architecture") == "amd64" else "other"
        if reference == PINNED and (DIGEST not in found or operating_system != "linux" or architecture != "amd64"):
            classification = "reference_mismatch"
        else:
            classification = "inspected"
        return {"classification": classification, "exit_status": 0, "stderr": "",
                "image_id": identity, "python_repository_digests": sorted(found),
                "operating_system": operating_system, "architecture": architecture}
    except (TypeError, ValueError):
        return {"classification": "unexpected_failure", "exit_status": 0, "stderr": ""}


def run(args):
    if not args.authorize_read_only_image_inspection:
        raise ValueError("explicit read-only image inspection authorization required")
    if args.socket != SOCKET or args.engine_id != ENGINE or args.base_digest != DIGEST:
        raise ValueError("diagnostic requires the exact approved socket, engine and digest")
    report = Evidence(args.evidence_dir, preflight_only=True)
    report.data.update(scope="read_only_image_diagnostic", socket=SOCKET, engine_id=ENGINE,
                       base_digest=DIGEST, image_inspection={})
    try:
        with tempfile.TemporaryDirectory(prefix="foundry-image-diagnostic-") as tmp:
            project = InstalledProject(socket_path=SOCKET, engine_id=ENGINE, image_id="sha256:" + "0" * 64,
                                       authorization="disposable-linux-engine-approved")
            project.root = Path(tmp)
            project.env = {"PATH": os.defpath, "HOME": tmp, "DOCKER_HOST": "unix://" + SOCKET,
                           "DOCKER_CONFIG": tmp + "/docker-config"}
            for name, reference in (("pinned", PINNED), ("tag", TAG)):
                result = inspect_reference(project, reference)
                if name == "tag":
                    pinned_digests = report.data["image_inspection"]["pinned"].get("python_repository_digests", [])
                    if len(set(pinned_digests) | set(result.get("python_repository_digests", []))) > 16:
                        raise ValueError("combined Python repository digest limit exceeded")
                report.data["image_inspection"][name] = result
                report.save()
                if result["classification"] in {"permission_denied", "daemon_unavailable",
                                                "engine_verification_failed", "unexpected_failure", "timeout"}:
                    raise ValueError("diagnostic inspection or engine verification failed")
            first = report.data["image_inspection"]["pinned"]
            second = report.data["image_inspection"]["tag"]
            if first["classification"] == second["classification"] == "inspected":
                report.data["same_image"] = first["image_id"] == second["image_id"]
            report.data["status"] = ("diagnostic_complete_reference_mismatch"
                                     if first["classification"] == "reference_mismatch"
                                     else "diagnostic_complete")
    except BaseException:
        report.data["status"] = "failed"
        raise
    finally:
        try:
            report.save()
        finally:
            report.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorize-read-only-image-inspection", action="store_true")
    parser.add_argument("--socket", required=True)
    parser.add_argument("--engine-id", required=True)
    parser.add_argument("--base-digest", required=True)
    parser.add_argument("--evidence-dir", required=True)
    run(parser.parse_args())


if __name__ == "__main__":
    main()
