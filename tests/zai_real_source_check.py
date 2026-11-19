"""Opt-in test-only Z.ai source publication; never runs during test discovery.

Requires a separately installed, non-editable canonical MI VCS distribution.
This does not create an SR binding, authenticate a publisher, or establish source
freshness. Network access requires separate explicit approval of this exact batch.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys

MI_REVISION = "e8a6b81546994438038d22fd08fc041c6901d9cd"
MI_URL = "https://forgejo.creatidy.com/Creatidy/model-intelligence.git"
CATALOG = "https://raw.githubusercontent.com/anomalyco/models.dev/f014f106dd414d575de2d0160d91267e2e7cb119/"
EXPECTED_SOURCES = (
    ("catalog", CATALOG + "models/zhipuai/glm-5.3-flash.toml", 1661),
    ("api", CATALOG + "providers/zai/models/glm-5.3-flash.toml", 551),
    ("coding", CATALOG + "providers/zai-coding-plan/models/glm-5.3-flash.toml", 437),
    ("prices", "https://docs.z.ai/guides/overview/pricing.md", 4096),
    ("plans", "https://docs.z.ai/devpack/overview.md", 8315),
    ("campaign", "https://docs.z.ai/devpack/notice/event-glm-5.3-flash.md", 1947),
    ("interface", "https://docs.z.ai/api-reference/llm/chat-completion.md", 44328),
    ("cohort", "https://docs.z.ai/devpack/notice/usage-revision.md", 10063),
)
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
SOURCE_TIMEOUT = 5.0
PROCESS_TIMEOUT = 120
AUTHORIZATION = "approved-eight-zai-source-reads"


def verify_distribution():
    """Check VCS metadata and import origin; metadata is not artifact authentication."""
    dist = importlib.metadata.distribution("model-intelligence")
    info = json.loads(dist.read_text("direct_url.json") or "null")
    if (not isinstance(info, dict) or info.get("url") != MI_URL or
            info.get("vcs_info", {}).get("vcs") != "git" or
            info.get("vcs_info", {}).get("commit_id") != MI_REVISION or
            info.get("dir_info", {}).get("editable", False)):
        raise ValueError("canonical MI VCS metadata required")
    spec = importlib.util.find_spec("model_intelligence")
    expected = Path(dist.locate_file("model_intelligence/__init__.py")).resolve()
    if spec is None or spec.origin is None or Path(spec.origin).resolve() != expected:
        raise ValueError("MI import origin does not match installed distribution")


def verify_sources(sources):
    actual = tuple((s.source_id, s.reference, s.max_bytes) for s in sources)
    if actual != EXPECTED_SOURCES:
        raise ValueError("canonical source policy changed; explicit review required")


def check_directory(directory):
    directory = Path(directory)
    if not directory.is_absolute() or directory.resolve() != directory:
        raise ValueError("absolute non-symlink output directory required")
    info = directory.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
            stat.S_IMODE(info.st_mode) != 0o700 or any(directory.iterdir())):
        raise ValueError("new empty operator-owned 0700 output directory required")
    return directory


def assess(public, expected_scope, model_claim_type):
    """Report blockers, not a guessed association or a positive admission result."""
    if public.applicability != expected_scope:
        raise ValueError("publication scope mismatch")
    observations = {item.observation_id: item for item in public.evidence.observations}
    claims = [item for item in public.evidence.claims if isinstance(item, model_claim_type)]
    if not claims or not observations:
        raise ValueError("empty source evidence")
    missing = {"scope_channel": 0, "subject_channel": 0, "subject_configuration": 0,
               "reasoning_effort": 0, "configuration_mismatch": 0, "unknown_freshness": 0}
    for claim in claims:
        subject = claim.subject
        origin = observations.get(claim.observation_id)
        if origin is None:
            raise ValueError("claim provenance missing")
        configuration = subject.configuration
        missing["scope_channel"] += public.applicability.channel is None
        missing["subject_channel"] += subject.channel is None or subject.channel != public.applicability.channel
        missing["subject_configuration"] += configuration is None
        missing["reasoning_effort"] += configuration is None or dict(configuration).get("reasoning_effort") is None
        missing["configuration_mismatch"] += configuration != public.applicability.configuration
        missing["unknown_freshness"] += origin.fresh_until is None
    return {"model_claims": len(claims), "blockers": missing,
            "router_applicability": "not-established", "router_binding": None}


def _require_verified_host_mi():
    # This script also runs with -I, where its sibling modules are not importable.
    # Do not inspect metadata or invoke import hooks as a substitute for provenance.
    raise RuntimeError("host MI execution disabled: installed code and import path are not independently verified")


def _acquire(directory):
    _require_verified_host_mi()
    verify_distribution()
    from model_intelligence import zai
    from model_intelligence.evidence import ModelClaim
    from model_intelligence.producer import retained

    verify_sources(zai.SOURCES)
    now = datetime.now(timezone.utc)
    result = zai.refresh(directory, at=now, max_artifact_bytes=MAX_ARTIFACT_BYTES, timeout=SOURCE_TIMEOUT)
    if not result.succeeded or result.reference is None:
        raise ValueError("complete source refresh failed")
    active = retained(directory, max_bytes=MAX_ARTIFACT_BYTES)
    if active is None or active[1] != result.reference or hashlib.sha256(active[0]).hexdigest() != result.reference.sha256:
        raise ValueError("retained publication mismatch")
    if (len(result.sources) != len(EXPECTED_SOURCES) or
            any(item.source_id != expected[0] or item.reference != expected[1] or
                not item.retrieved or not isinstance(item.revision, str) or
                not re.fullmatch(r"content-sha256:[0-9a-f]{64}", item.revision) or
                type(item.bytes_received) is not int or not 0 < item.bytes_received <= expected[2]
                for item, expected in zip(result.sources, EXPECTED_SOURCES))):
        raise ValueError("incomplete source refresh")
    summary = assess(active[2], zai.SCOPE, ModelClaim)
    summary.update({"source_revision": MI_REVISION, "cut_sha256": result.reference.sha256,
                    "payload_schema": result.reference.payload_schema,
                    "retrieved_sources": len(result.sources), "integrity_not_authenticity": True})
    return summary


def run(directory, *, authorization):
    """Run one bounded subprocess after explicit authorization, never implicitly."""
    if authorization != AUTHORIZATION:
        raise ValueError("explicit source acquisition authorization required")
    _require_verified_host_mi()
    directory = check_directory(directory)
    result = subprocess.run([sys.executable, "-I", str(Path(__file__).resolve()), "--worker", "--output-dir", str(directory),
                             "--authorization", authorization],
                            env={"PATH": os.defpath, "HOME": str(directory), "LANG": "C.UTF-8"},
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=PROCESS_TIMEOUT, check=False)
    if result.returncode != 0 or len(result.stdout) > 8192 or result.stderr:
        raise RuntimeError("source publication subprocess failed; preserve its private output directory")
    summary = json.loads(result.stdout)
    if (not isinstance(summary, dict) or summary.get("source_revision") != MI_REVISION or
            summary.get("router_applicability") != "not-established" or
            summary.get("router_binding") is not None or
            summary.get("integrity_not_authenticity") is not True or
            summary.get("retrieved_sources") != len(EXPECTED_SOURCES) or
            not isinstance(summary.get("cut_sha256"), str) or
            not re.fullmatch(r"[0-9a-f]{64}", summary["cut_sha256"])):
        raise ValueError("invalid source publication subprocess result")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--authorization", required=True)
    args = parser.parse_args()
    try:
        if args.authorization != AUTHORIZATION:
            raise ValueError("explicit authorization required")
        if args.worker:
            signal.alarm(PROCESS_TIMEOUT - 5)
            summary = _acquire(check_directory(args.output_dir))
        else:
            summary = run(args.output_dir, authorization=args.authorization)
        print(json.dumps(summary, sort_keys=True))
    except Exception:
        # No source text, local paths, credentials, or untrusted error text are echoed.
        print("source check refused", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
