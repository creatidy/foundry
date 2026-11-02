#!/usr/bin/env python3
"""Guarded Windows/WSL local TLS startup and read-only resume."""

import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import ssl
import stat
import subprocess
import sys
import time

from local_tls_up import check_project, validate
from local_tls_init import open_parent


ROOT = Path(__file__).resolve().parent.parent
COMPOSE_SHA256 = "1f099d26343f07e34c11232bac52e4fbbb70f424a1992c6edab2d4b1c29959a0"
SOCKET = "unix:///var/run/docker.sock"


def run(*args):
    return subprocess.run(list(args), check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, timeout=30).stdout


def request(path, cert, fingerprint):
    context = ssl.create_default_context(cafile=cert)
    conn = http.client.HTTPSConnection("127.0.0.1", 8787, context=context, timeout=3)
    try:
        conn.connect()
        if hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest() != fingerprint:
            raise ValueError("TLS peer fingerprint mismatch")
        conn.request("GET", path)
        response = conn.getresponse()
        body = response.read(4096)
        return response.status, response.getheader("Location"), body
    finally:
        conn.close()


def attest_container_certificate(container_id, fingerprint):
    # Read only the mounted leaf, never its private key.
    code = ("import hashlib,os,ssl,stat,sys; "
            "f=os.open('/run/foundry/tls/server.crt',os.O_RDONLY|os.O_NOFOLLOW); "
            "s=os.fstat(f); (stat.S_ISREG(s.st_mode) and s.st_size<=1048576) or sys.exit(2); "
            "p=os.read(f,1048577).decode('ascii'); os.close(f); "
            "(p.count('-----BEGIN CERTIFICATE-----')==1) or sys.exit(2); "
            "print(hashlib.sha256(ssl.PEM_cert_to_DER_cert(p)).hexdigest())")
    if run("docker", "exec", container_id, "python", "-c", code).strip() != fingerprint:
        raise ValueError("container TLS leaf fingerprint mismatch")


def verify_bind_source(source, tls, distribution):
    if source == tls:
        return
    prefix = "/run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/" + distribution + "/"
    if not source.startswith(prefix) or not re.fullmatch(r"[a-f0-9]{64}", source[len(prefix):]):
        raise ValueError("unrecognized translated TLS bind source")
    # WSL's shared mount is exposed under this path in Docker Desktop's VM.
    shared = "/mnt/wsl/docker-desktop-bind-mounts/" + distribution + "/" + source[len(prefix):]
    original_parent, original_name = open_parent(tls)
    descriptors = [original_parent]
    try:
        original = os.open(original_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=original_parent)
        descriptors.append(original)
        current = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        descriptors.append(current)
        for component in shared.strip("/").split("/"):
            current = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            descriptors.append(current)
        for name in (None, "server.crt", "server.key"):
            if name is None:
                a, b = os.fstat(original), os.fstat(current)
            else:
                a = os.stat(name, dir_fd=original, follow_symlinks=False)
                b = os.stat(name, dir_fd=current, follow_symlinks=False)
                if not os.path.samestat(a, b) or not stat.S_ISREG(a.st_mode):
                    raise ValueError("translated TLS file identity mismatch")
            if not os.path.samestat(a, b):
                raise ValueError("translated TLS directory identity mismatch")
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def verify_project(project, image, tls, config, image_config, fingerprint, distribution):
    label = "label=com.docker.compose.project=" + project
    ids = run("docker", "container", "ls", "--all", "--filter", label, "--quiet").splitlines()
    volumes = run("docker", "volume", "ls", "--filter", label, "--quiet").splitlines()
    networks = run("docker", "network", "ls", "--filter", label, "--quiet").splitlines()
    volume_name = config["volumes"]["router-data"]["name"]
    network_name = config["networks"]["backend"]["name"]
    if (len(ids) != 1 or not re.fullmatch(r"[a-f0-9]{12,64}", ids[0]) or
            volumes != [volume_name] or len(networks) != 1):
        raise ValueError("project contains missing or extra resources")
    container = json.loads(run("docker", "inspect", ids[0]))
    if len(container) != 1:
        raise ValueError("router container identity is ambiguous")
    c = container[0]
    labels = c["Config"]["Labels"]
    expected_command = config["services"]["router"]["command"] + [
        "--tls-reload-ca-cert=/run/foundry/tls/server.crt"]
    mounts = c["Mounts"]
    data = [m for m in mounts if m["Destination"] == "/data"]
    cert = [m for m in mounts if m["Destination"] == "/run/foundry/tls"]
    host = c["HostConfig"]
    expected_env = dict(value.split("=", 1) for value in image_config.get("Env", []) or [])
    expected_env.update({"SR_HEALTHCHECK_URL": "https://127.0.0.1:8787/healthz",
                         "SR_HEALTHCHECK_CA": "/run/foundry/tls/server.crt"})
    actual_env = c["Config"].get("Env") or []
    image_user = image_config.get("User", "")
    if (not c["State"]["Running"] or c["Image"] != image or
            labels.get("com.docker.compose.project") != project or
            labels.get("com.docker.compose.service") != "router" or
            labels.get("com.docker.compose.container-number") != "1" or
            c["Config"]["Cmd"] != expected_command or len(mounts) != 2 or
            c["Config"].get("Entrypoint") != image_config.get("Entrypoint") or
            not re.fullmatch(r"[1-9][0-9]*(?::[0-9]+)?", image_user) or
            c["Config"].get("User") != image_user or
            len(actual_env) != len(expected_env) or
            dict(value.split("=", 1) for value in actual_env) != expected_env or
            len(data) != 1 or data[0]["Type"] != "volume" or not data[0]["RW"] or
            data[0]["Name"] != volume_name or len(cert) != 1 or
            cert[0]["Type"] != "bind" or cert[0]["RW"] or
            host.get("Privileged") or host.get("NetworkMode") != network_name or
            host.get("CapAdd") or host.get("CapDrop") or host.get("Devices") or
            host.get("DeviceRequests") or host.get("DeviceCgroupRules") or
            host.get("PidMode") not in ("", None) or host.get("UTSMode") not in ("", None) or
            host.get("UsernsMode") not in ("", None) or host.get("IpcMode") not in ("", None, "private", "shareable") or
            host.get("CgroupnsMode") not in ("", None, "private") or
            host.get("SecurityOpt") != ["no-new-privileges:true"] or
            host.get("GroupAdd") != [str(os.getegid())] or
            host.get("PortBindings") != {"8787/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8787"}]} or
            set(c["NetworkSettings"]["Networks"]) != {network_name}):
        raise ValueError("running router configuration does not match")
    verify_bind_source(cert[0]["Source"], tls, distribution)
    volume = json.loads(run("docker", "volume", "inspect", volume_name))
    if (len(volume) != 1 or volume[0]["Name"] != volume_name or
            volume[0].get("Driver") != "local" or volume[0].get("Options") not in (None, {}) or
            volume[0].get("Labels", {}).get("com.docker.compose.project") != project or
            volume[0].get("Labels", {}).get("com.docker.compose.volume") != "router-data"):
        raise ValueError("data volume identity mismatch")
    consumers = run("docker", "container", "ls", "--all", "--filter", "volume=" + volume_name, "--quiet").splitlines()
    if len(consumers) != 1 or not c["Id"].startswith(consumers[0]):
        raise ValueError("data volume has other or ambiguous consumers")
    network = json.loads(run("docker", "network", "inspect", networks[0]))
    if (len(network) != 1 or network[0]["Name"] != network_name or
            network[0].get("Labels", {}).get("com.docker.compose.project") != project or
            network[0].get("Labels", {}).get("com.docker.compose.network") != "backend" or
            set(network[0].get("Containers", {})) != {c["Id"]}):
        raise ValueError("network identity or membership mismatch")
    attest_container_certificate(ids[0], fingerprint)
    return ids[0]


def main(args):
    if len(args) != 7:
        print("Expected project, image ID, TLS directory, fingerprint, engine ID, adoption and distribution.", file=sys.stderr)
        return 1
    project, image, tls, fingerprint, engine, adoption, distribution = args
    if (not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", project) or
            not re.fullmatch(r"sha256:[a-f0-9]{64}", image) or
            not re.fullmatch(r"/[A-Za-z0-9_./-]+", tls) or
            not re.fullmatch(r"[a-f0-9]{64}", fingerprint) or
            not re.fullmatch(r"[A-Za-z0-9:_-]+", engine) or adoption not in ("-", project) or
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", distribution)):
        print("Invalid first-run inputs.", file=sys.stderr)
        return 1
    if platform.system() != "Linux" or not re.search(r"microsoft-standard-WSL2", platform.release(), re.I):
        print("The selected environment is not an identifiable WSL2 Linux kernel.", file=sys.stderr)
        return 1
    try:
        if any(os.environ.get(name) for name in ("DOCKER_HOST", "DOCKER_CONTEXT")):
            raise ValueError("Docker host/context overrides are not accepted")
        if any(os.environ.get(name) for name in os.environ if name.startswith(("COMPOSE_", "FOUNDRY_MI_"))):
            raise ValueError("Compose or MI overrides are not accepted")
        if hashlib.sha256((ROOT / "compose.yaml").read_bytes()).hexdigest() != COMPOSE_SHA256:
            raise ValueError("Compose file differs from the inspected version")
        validate(tls)
        cert = str(Path(tls) / "server.crt")
        der = ssl.PEM_cert_to_DER_cert(Path(cert).read_text(encoding="ascii"))
        if hashlib.sha256(der).hexdigest() != fingerprint:
            raise ValueError("TLS fingerprint mismatch")
        # Context inspect is a local CLI operation, before any daemon contact.
        context = json.loads(run("docker", "context", "inspect"))
        if len(context) != 1 or context[0]["Endpoints"]["docker"]["Host"] != SOCKET:
            raise ValueError("selected WSL Docker endpoint is not the accepted local socket")
        os.environ["DOCKER_HOST"] = SOCKET
        actual = json.loads(run("docker", "info", "--format", "{{json .}}"))
        if actual.get("OSType") != "linux" or actual.get("ID") != engine:
            raise ValueError("WSL and Windows Docker engine identities do not match")
        images = json.loads(run("docker", "image", "inspect", image))
        if len(images) != 1 or images[0].get("Id") != image:
            raise ValueError("verified image ID unavailable")
        os.chdir(ROOT)
        os.environ.update(LOCAL_TLS_PROJECT=project, TLS_DEST=tls,
                          FOUNDRY_ROUTER_IMAGE=image, FOUNDRY_ROUTER_HOST="127.0.0.1",
                          FOUNDRY_TLS_DIR=tls, FOUNDRY_ROUTER_PORT="8787")
        os.environ.pop("LOCAL_TLS_ADOPT_PROJECT", None)
        base = ["docker", "compose", "-p", project, "--env-file", ".env", "-f", "compose.yaml"]
        config = json.loads(run(*base, "config", "--format", "json", "--no-path-resolution"))
        if config.get("name") != project or config["services"]["router"]["image"] != image:
            raise ValueError("unexpected Compose configuration")
        existing = check_project(project, config)
        if existing:
            if adoption != project:
                raise ValueError("existing project requires matching adoption acknowledgement")
        elif subprocess.run([sys.executable, str(ROOT / "scripts/local_tls_up.py")], timeout=90).returncode:
            raise ValueError("startup failed; inspect project before retrying")
        container_id = verify_project(project, image, tls, config, images[0]["Config"], fingerprint, distribution)
        for attempt in range(30):
            try:
                status, _, body = request("/healthz", cert, fingerprint)
                if status == 200 and json.loads(body) == {"status": "ok"}:
                    break
            except (OSError, ValueError, http.client.HTTPException):
                pass
            time.sleep(1)
        else:
            raise ValueError("verified TLS liveness check failed")
        status, location, _ = request("/admin", cert, fingerprint)
        print("Verified HTTPS liveness; this does not establish operational readiness.")
        if status in (302, 303, 307, 308) and location == "/admin/login":
            print("SR reports an administrator is configured; no claim issued. Authenticated readiness is unknown.")
            return 0
        if status not in (302, 303, 307, 308) or location != "/admin/onboarding":
            print("Administrator state is unknown or already configured; no claim issued.")
            return 1
        print("SR redirected to onboarding: no administrator was observed at this instant.")
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            print("Private interactive terminal required; no claim issued.")
            return 1
        if input("Issue one bootstrap claim to this terminal? Type YES: ") != "YES":
            print("No claim issued; onboarding incomplete.")
            return 1
        validate(tls)
        if verify_project(project, image, tls, config, images[0]["Config"], fingerprint, distribution) != container_id:
            raise ValueError("router identity changed after consent")
        status, location, _ = request("/admin", cert, fingerprint)
        if status not in (302, 303, 307, 308) or location != "/admin/onboarding":
            raise ValueError("administrator state changed after consent")
        # Never capture, retry, or place the claim in an argument or environment.
        result = subprocess.run(["docker", "exec", container_id, "python", "-m", "scarcity_router.control_server",
                                 "--data-dir", "/data", "--issue-bootstrap-claim"], timeout=30)
        if result.returncode:
            print("Claim issuance failed; no automatic retry.", file=sys.stderr)
            return 1
        print("Open https://127.0.0.1:8787/admin/onboarding only in a browser that already trusts the verified leaf.")
        print("Administrator completion and authenticated readiness are unknown.")
        return 0
    except (OSError, EOFError, ValueError, KeyError, IndexError, TypeError, json.JSONDecodeError,
            subprocess.SubprocessError, http.client.HTTPException) as exc:
        print("First run stopped: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
