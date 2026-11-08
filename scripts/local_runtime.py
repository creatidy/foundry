"""Select an auditable existing SR environment, then exec the native launcher."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
MINIMUM = "925ec06681c7fa085edd5015f57663e85d735768"
ACCEPTED = {MINIMUM, "c67900723cd6ec7430a36dd0357ee17061f811b6"}
CANONICAL = "https://forgejo.creatidy.com/Creatidy/scarcity-router.git"
PROBE = """
import importlib.metadata, importlib.util, json, sys
if sys.version_info < (3, 12):
    raise SystemExit('SR requires Python 3.12 or newer')
d = importlib.metadata.distribution('scarcity-router')
s = importlib.util.find_spec('scarcity_router.control_server')
print(json.dumps({'module': s.origin, 'prefix': sys.prefix,
                  'source': json.loads(d.read_text('direct_url.json') or '{}')}))
"""


def run(args, *, cwd=None):
    return subprocess.run(
        args, cwd=cwd or ROOT, check=True, text=True, capture_output=True, timeout=10,
    ).stdout.strip()


def verify(python):
    """Local Git evidence is trusted operator input, not publisher authentication."""
    evidence = json.loads(run([str(python), "-B", "-c", PROBE]))
    source = evidence["source"]
    url = urlsplit(source.get("url", ""))
    if url.scheme != "file" or url.netloc or "dir_info" not in source:
        raise ValueError("requires a retained inspected checkout (uv local-checkout install)")
    checkout = Path(unquote(url.path))
    if not checkout.is_absolute():
        raise ValueError("source checkout must be absolute")

    def git(*args):
        return run(["git", "--no-replace-objects", "-C", str(checkout), *args])

    if git("remote", "get-url", "origin") != CANONICAL:
        raise ValueError("source origin is not the canonical SR HTTPS repository")
    revision = git("rev-parse", "HEAD")
    if revision not in ACCEPTED:
        raise ValueError("source revision is not in Foundry's inspected SR compatibility set")
    package = Path(evidence["module"]).parent
    if Path(evidence["module"]).name != "control_server.py":
        raise ValueError("unexpected control-server import resolution")
    entries = git("ls-tree", "-r", "-z", revision, "scarcity_router").split("\0")
    expected = {}
    for entry in filter(None, entries):
        metadata, name = entry.split("\t", 1)
        mode, kind, digest = metadata.split()
        if mode != "100644" or kind != "blob":
            raise ValueError("unsupported source package entry")
        expected[str(Path(name).relative_to("scarcity_router"))] = digest
    if not {"control_server.py", "server_ownership.py", "__init__.py"} <= expected.keys():
        raise ValueError("source lacks the composed startup/ownership contract")
    policy_digest = git("rev-parse", f"{revision}:examples/selector-policy.json")
    editable = source["dir_info"].get("editable", False)
    # Hatch must include this resource in every non-editable installation.
    if not editable or (package / "default-selector-policy.json").exists():
        expected["default-selector-policy.json"] = policy_digest
    actual = {
        str(path.relative_to(package)): path
        for path in package.rglob("*")
        if path.is_file() and "__pycache__" not in path.relative_to(package).parts
    }
    if actual.keys() != expected.keys():
        raise ValueError("imported SR package file set differs from source revision")
    # SR prefers the source-tree example when present, even beside an installed copy.
    policy_source = package.resolve().parent / "examples/selector-policy.json"
    if editable and not policy_source.is_file():
        raise ValueError("editable SR default selector-policy source is missing")
    if editable or policy_source.is_file():
        expected["../examples/selector-policy.json"] = policy_digest
        actual["../examples/selector-policy.json"] = policy_source
    for name, path in actual.items():
        data = path.read_bytes()
        digest = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if digest != expected[name]:
            raise ValueError(f"imported SR differs from source revision: {name}")
    return Path(evidence["prefix"]).resolve(), checkout, revision


def discover():
    if os.environ.get("PYTHONPATH") or os.environ.get("PYTHONHOME"):
        raise ValueError("unset PYTHONPATH and PYTHONHOME; ordinary SR imports are required")
    override = os.environ.get("FOUNDRY_SR_CHECKOUT")
    checkout = Path(override) if override else ROOT.parent / "scarcity-router"
    if not checkout.is_absolute():
        raise ValueError("FOUNDRY_SR_CHECKOUT must be an absolute checkout path")
    candidates = [checkout / ".venv/bin/python"]
    uv = shutil.which("uv")
    if not override and uv:
        tool_dir = Path(run([uv, "tool", "dir"]))
        if not tool_dir.is_absolute():
            raise ValueError("uv tool dir did not return an absolute directory")
        candidates.append(tool_dir / "scarcity-router/bin/python")
    compatible = {}
    for python in candidates:
        if not python.exists():
            continue
        try:
            prefix, source, revision = verify(python)
        except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as exc:
            reason = str(exc) if isinstance(exc, ValueError) else "runtime probe/Git provenance check failed"
            print(f"Rejected SR runtime {python}: {reason}", file=sys.stderr)
            continue
        compatible[prefix] = (python, source, revision)
    if len(compatible) > 1:
        raise ValueError(
            "ambiguous SR runtimes; select an inspected checkout explicitly with "
            "FOUNDRY_SR_CHECKOUT=/absolute/checkout make start"
        )
    if not compatible:
        raise ValueError(
            "no verifiable compatible SR runtime. See README 'Install SR if absent'. "
            "Use uv tool install --python 3.12 /absolute/inspected/scarcity-router "
            "only if installation is needed; existing installations are never replaced automatically."
        )
    return next(iter(compatible.values()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify discovery without starting SR")
    args = parser.parse_args()
    try:
        python, checkout, revision = discover()
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"Foundry: {exc}", file=sys.stderr)
        return 2
    print(f"SR interpreter: {python}\nSR source: {checkout}\nSR revision: {revision}", flush=True)
    if not args.check:
        os.chdir(ROOT)
        os.execv(str(ROOT / "scripts/local-start.sh"), [str(ROOT / "scripts/local-start.sh"), str(python)])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
