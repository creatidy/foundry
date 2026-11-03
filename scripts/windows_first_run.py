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
import subprocess
import sys
import tempfile
import time

from local_tls_up import check_project, validate
import windows_managed_tls as managed_tls


ROOT = Path(__file__).resolve().parent.parent
COMPOSE_SHA256 = "1f099d26343f07e34c11232bac52e4fbbb70f424a1992c6edab2d4b1c29959a0"
SOCKET = "unix:///var/run/docker.sock"
MANAGED_ACTIVATED = True


def run(*args):
    return subprocess.run(list(args), check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, timeout=30).stdout


def request(path, cert, fingerprint):
    context = ssl.create_default_context(cadata=cert) if cert.startswith("-----BEGIN CERTIFICATE-----") else ssl.create_default_context(cafile=cert)
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
    if source != tls:
        raise ValueError("translated TLS bind custody is not established")


def require_safe_key_custody():
    # Docker Desktop can expose the original key through a traversable WSL alias,
    # and its reported pathname does not identify the already-mounted key.
    raise ValueError("Docker Desktop TLS key custody is not established; startup and adoption refused")


def verify_container_user(container_id, image_user):
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*(?::[A-Za-z0-9_][A-Za-z0-9_.-]*)?", image_user):
        raise ValueError("invalid image user")
    code = ("import grp,json,os,pwd; "
            "print(json.dumps({'users':[[p.pw_name,p.pw_uid,p.pw_gid] for p in pwd.getpwall()],"
            "'groups':[[g.gr_name,g.gr_gid] for g in grp.getgrall()],"
            "'uids':os.getresuid(),'gids':os.getresgid(),'supplementary':os.getgroups(),"
            "'pid1':open('/proc/1/status',encoding='ascii').read()}))")
    identity = json.loads(run("docker", "exec", container_id, "python", "-c", code))
    user, _, group = image_user.partition(":")
    users = identity["users"]
    matches = [row for row in users if (str(row[1]) == user if user.isdecimal() else row[0] == user)]
    if len(matches) != 1:
        raise ValueError("image user is missing or ambiguous")
    _, uid, default_gid = matches[0]
    if type(uid) is not int or uid <= 0 or sum(row[1] == uid for row in users) != 1:
        raise ValueError("image user is root or ambiguous")
    groups = identity["groups"]
    matches = [row for row in groups if (str(row[1]) == group if group.isdecimal() else row[0] == group)] if group else [row for row in groups if row[1] == default_gid]
    if len(matches) != 1:
        raise ValueError("image group is missing or ambiguous")
    gid = matches[0][1]
    if type(gid) is not int or gid <= 0 or sum(row[1] == gid for row in groups) != 1:
        raise ValueError("image group is root or ambiguous")
    status = dict(line.split(":", 1) for line in identity["pid1"].splitlines() if ":" in line)
    pid_groups = status.get("Groups", "").split()
    if (identity["uids"] != [uid] * 3 or identity["gids"] != [gid] * 3 or
            os.getegid() == 0 or 0 in identity["supplementary"] or "0" in pid_groups or
            os.getegid() not in identity["supplementary"] or str(os.getegid()) not in pid_groups or
            status.get("Uid", "").split() != [str(uid)] * 4 or
            status.get("Gid", "").split() != [str(gid)] * 4):
        raise ValueError("running container user identity mismatch")


def verify_project(project, image, tls, config, image_config, fingerprint, distribution,
                   managed_volume=None, allow_stopped=False):
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
    if not re.fullmatch(r"[a-f0-9]{64}", c.get("Id", "")) or not c["Id"].startswith(ids[0]):
        raise ValueError("router container identity mismatch")
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
    running = c["State"]["Running"]
    if ((not running and not allow_stopped) or c["Image"] != image or
            labels.get("com.docker.compose.project") != project or
            labels.get("com.docker.compose.service") != "router" or
            labels.get("com.docker.compose.container-number") != "1" or
            c["Config"]["Cmd"] != expected_command or len(mounts) != 2 or
            c["Config"].get("Entrypoint") != image_config.get("Entrypoint") or
            c["Config"].get("User") != image_user or
            len(actual_env) != len(expected_env) or
            dict(value.split("=", 1) for value in actual_env) != expected_env or
            len(data) != 1 or data[0]["Type"] != "volume" or not data[0]["RW"] or
            data[0]["Name"] != volume_name or len(cert) != 1 or
            cert[0]["Type"] != ("volume" if managed_volume else "bind") or cert[0]["RW"] or
            (managed_volume is not None and cert[0].get("Name") != managed_volume) or
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
    if managed_volume is None:
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
            set(network[0].get("Containers", {})) != ({c["Id"]} if running else set())):
        raise ValueError("network identity or membership mismatch")
    if running:
        verify_container_user(ids[0], image_user)
        attest_container_certificate(ids[0], fingerprint)
    return c["Id"]


def managed_flow(project, image, distribution):
    """Managed-volume flow; caller must enforce the managed activation gate."""
    os.chdir(ROOT)
    os.environ.update(FOUNDRY_ROUTER_IMAGE=image, FOUNDRY_ROUTER_HOST="127.0.0.1",
                      FOUNDRY_TLS_DIR="/dev/null", FOUNDRY_ROUTER_PORT="8787")
    with tempfile.TemporaryDirectory(prefix="foundry-managed-") as tmp:
        envfile = os.path.join(tmp, "env")
        with open(envfile, "x", encoding="ascii") as stream:
            stream.write("")
        base = ["docker", "compose", "-p", project, "--env-file", envfile, "-f", "compose.yaml"]
        config = json.loads(run(*base, "config", "--format", "json", "--no-path-resolution"))
        if config.get("name") != project or config["services"]["router"]["image"] != image:
            raise ValueError("unexpected Compose configuration")
        images = json.loads(run("docker", "image", "inspect", image))
        if (len(images) != 1 or images[0].get("Id") != image or
                not images[0].get("Config", {}).get("User") or os.getegid() == 0):
            raise ValueError("image identity or non-root operator group is invalid")
        probe = run("docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--tmpfs",
                    "/data:rw,noexec,nosuid,size=1m", "--entrypoint", "python", image,
                    "-c", "import os; print(str(os.geteuid())+':'+str(os.getegid()))").strip()
        if probe != "10001:10001":
            raise ValueError("image default user is not the expected non-root identity")
        found = managed_tls.discover_tls_volume(project, image)
        label = "label=com.docker.compose.project=" + project
        ids = run("docker", "container", "ls", "--all", "--filter", label, "--quiet").splitlines()
        if len(ids) > 1:
            raise ValueError("project has extra containers")
        if found is None:
            if ids or check_project(project, config):
                raise ValueError("project is not fresh")
            volume, nonce, cert = managed_tls.initialize_tls_volume(project, image)
        else:
            if not ids:
                raise ValueError("unattached managed TLS volume requires manual inspection")
            volume, nonce = found
            cert = managed_tls.verify_tls_volume(project, image, volume, nonce,
                                                  allowed_consumer=ids[0] if ids else None)
        fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert)).hexdigest()
        print("Public certificate obtained from the verified local Docker volume:\n" + cert)
        print("SHA256:", fingerprint)
        print("Certificate confirmation is public and does not issue a claim.")
        if input("Confirm this certificate and project for this session? Type YES: ") != "YES":
            raise ValueError("certificate confirmation declined")
        container_id = None
        if ids:
            container_id = verify_project(project, image, "", config, images[0]["Config"], fingerprint,
                                          distribution, managed_volume=volume, allow_stopped=True)
        elif check_project(project, config):
            raise ValueError("orphaned or ambiguous project resources")
        current = managed_tls.verify_tls_volume(project, image, volume, nonce, allowed_consumer=container_id)
        if current != cert:
            raise ValueError("TLS certificate changed after confirmation")
        if container_id:
            state = json.loads(run("docker", "inspect", container_id))[0]["State"]
            if not state["Running"]:
                run("docker", "start", container_id)
        else:
            override = {"services": {"router": {
                "command": config["services"]["router"]["command"] + ["--tls-reload-ca-cert=/run/foundry/tls/server.crt"],
                "group_add": [str(os.getegid())],
                "environment": {"SR_HEALTHCHECK_CA": "/run/foundry/tls/server.crt"},
                "volumes": [{"type": "volume", "source": "managed-tls", "target": "/run/foundry/tls",
                             "read_only": True, "volume": {"nocopy": True}}]}},
                "volumes": {"managed-tls": {"external": True, "name": volume}}}
            override_path = os.path.join(tmp, "override.json")
            with open(override_path, "x", encoding="ascii") as stream:
                json.dump(override, stream)
            composed = base + ["-f", override_path]
            merged = json.loads(run(*composed, "config", "--format", "json", "--no-path-resolution"))
            mounts = merged["services"]["router"]["volumes"]
            tls_mounts = [m for m in mounts if m.get("target") == "/run/foundry/tls"]
            if (len(mounts) != 2 or len(tls_mounts) != 1 or tls_mounts[0].get("type") != "volume" or
                    tls_mounts[0].get("source") != "managed-tls" or not tls_mounts[0].get("read_only") or
                    not tls_mounts[0].get("volume", {}).get("nocopy") or
                    merged["volumes"]["managed-tls"]["name"] != volume):
                raise ValueError("unsafe merged Compose TLS mount")
            if check_project(project, config):
                raise ValueError("project collision before startup")
            managed_tls._inspect(project, image, volume, nonce)
            run(*composed, "up", "-d", "--no-build", "--pull", "never")
        container_id = verify_project(project, image, "", config, images[0]["Config"], fingerprint,
                                      distribution, managed_volume=volume)
        for _ in range(30):
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
        if status in (302, 303, 307, 308) and location == "/admin/login":
            print("Administrator configured. Login: https://127.0.0.1:8787/admin/login")
            print("Use a browser that trusts the verified certificate. Authenticated readiness unknown.")
            return 0
        if status not in (302, 303, 307, 308) or location != "/admin/onboarding":
            raise ValueError("administrator state unknown")
        if verify_project(project, image, "", config, images[0]["Config"], fingerprint,
                          distribution, managed_volume=volume) != container_id:
            raise ValueError("router identity changed before instructions")
        print("SERVER_RUNNING — ADMIN_ONBOARDING_INCOMPLETE: no administrator exists.")
        print("Personally run this command in a trusted private native Windows terminal, "
              "not through an agent or recorded session:")
        print("docker.exe --host npipe:////./pipe/dockerDesktopLinuxEngine exec " + container_id +
              " python -m scarcity_router.control_server --data-dir /data --issue-bootstrap-claim")
        print("Open https://127.0.0.1:8787/admin/onboarding in a browser that trusts the verified certificate.")
        print("Copy the 15-minute claim into the form and set the administrator password there. "
              "Do not put the claim in logs, URLs, files or shared channels.")
        return 2


def managed_main(args):
    if len(args) != 4:
        print("Expected managed project, image, engine and distribution.", file=sys.stderr)
        return 1
    project, image, engine, distribution = args
    if (not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", project) or
            not re.fullmatch(r"sha256:[a-f0-9]{64}", image) or
            not re.fullmatch(r"[A-Za-z0-9:_-]+", engine) or
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", distribution)):
        print("Invalid managed first-run inputs.", file=sys.stderr)
        return 1
    if platform.system() != "Linux" or not re.search(r"microsoft-standard-WSL2", platform.release(), re.I):
        print("The selected environment is not an identifiable WSL2 Linux kernel.", file=sys.stderr)
        return 1
    try:
        if any(os.environ.get(name) for name in ("DOCKER_HOST", "DOCKER_CONTEXT")) or any(
                os.environ.get(name) for name in os.environ if name.startswith(("COMPOSE_", "FOUNDRY_MI_"))):
            raise ValueError("Docker, Compose or MI overrides are not accepted")
        if hashlib.sha256((ROOT / "compose.yaml").read_bytes()).hexdigest() != COMPOSE_SHA256:
            raise ValueError("Compose file differs from the inspected version")
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
        if not MANAGED_ACTIVATED:
            raise ValueError("managed TLS activation is disabled pending independent review")
        return managed_flow(project, image, distribution)
    except (OSError, EOFError, ValueError, KeyError, IndexError, TypeError, RuntimeError,
            subprocess.SubprocessError, http.client.HTTPException):
        print("Managed first run stopped; inspect the local project and prerequisites.", file=sys.stderr)
        return 1


def main(args):
    if args and args[0] == "managed":
        return managed_main(args[1:])
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
        require_safe_key_custody()
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
        print("Onboarding is unavailable on the legacy bind-mounted path.")
        return 1
    except (OSError, EOFError, ValueError, KeyError, IndexError, TypeError, json.JSONDecodeError,
            subprocess.SubprocessError, http.client.HTTPException):
        print("First run stopped; inspect the local project and prerequisites.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
