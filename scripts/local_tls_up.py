#!/usr/bin/env python3
"""Local HTTP and explicit verified-TLS startup using one canonical Compose."""

import argparse
import json
import hashlib
import os
import re
import stat
import subprocess
import sys
import tempfile

from local_tls_init import no_acl, open_parent
from docker_socket_validation import validate_engine_socket


def validate_mi(destination, expected, *, publication="/run/foundry/mi/publication.json"):
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("independent MI digest required")
    parent, name = open_parent(destination)
    directory = None
    files = []
    try:
        directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        info = os.fstat(directory)
        if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (os.geteuid(), os.getegid(), 0o750):
            raise ValueError("invalid MI directory ownership or mode")
        no_acl(directory)
        data = []
        for name, limit in (("trust.json", 256 * 1024), ("publication.json", 16 * 1024 * 1024)):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            files.append(fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) !=
                    (os.geteuid(), os.getegid(), 0o640)):
                raise ValueError("invalid MI file ownership or mode")
            no_acl(fd)
            with os.fdopen(os.dup(fd), "rb") as stream:
                content = stream.read(limit + 1)
            if len(content) > limit:
                raise ValueError("MI file too large")
            data.append(content)
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate MI configuration key")
                result[key] = value
            return result
        config = json.loads(data[0], object_pairs_hook=unique)
        if (config["publication"] != publication or
            config["reference"]["sha256"] != expected or
            hashlib.sha256(data[1]).hexdigest() != expected):
            raise ValueError("MI reference mismatch")
    finally:
        for fd in files:
            os.close(fd)
        if directory is not None:
            os.close(directory)
        os.close(parent)


def validate(destination):
    parent, name = open_parent(destination)
    directory = None
    files = []
    try:
        directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        info = os.fstat(directory)
        if (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (os.geteuid(), os.getegid(), 0o750):
            raise ValueError("invalid TLS directory ownership or mode")
        no_acl(directory)
        for name in ("server.crt", "server.key"):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            files.append(fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) !=
                    (os.geteuid(), os.getegid(), 0o640)):
                raise ValueError("invalid TLS file ownership or mode")
            no_acl(fd)
        cert, key = (f"/proc/self/fd/{fd}" for fd in files)
        def openssl(*args):
            return subprocess.run(["openssl", *args], pass_fds=tuple(files), check=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
        pem = os.read(files[0], 1024 * 1024)
        if pem.count(b"-----BEGIN CERTIFICATE-----") != 1 or len(pem) == 1024 * 1024:
            raise ValueError("expected one leaf certificate")
        constraints = openssl("x509", "-in", cert, "-noout", "-ext", "basicConstraints")
        if b"CA:FALSE" not in constraints:
            raise ValueError("certificate is not a leaf")
        openssl("verify", "-CAfile", cert, "-verify_ip", "127.0.0.1", "-purpose", "sslserver", cert)
        if openssl("x509", "-in", cert, "-pubkey", "-noout") != openssl("pkey", "-in", key, "-pubout"):
            raise ValueError("certificate and key do not match")
    finally:
        for fd in files:
            os.close(fd)
        if directory is not None:
            os.close(directory)
        os.close(parent)


class TestEngineRefusal(Exception):
    pass


def verify_test_engine():
    """Recheck the selected test daemon immediately before each Docker call."""
    if not os.environ.get("FOUNDRY_TEST_RUN_ID"):
        return
    expected = os.environ.get("FOUNDRY_TEST_ENGINE_ID", "")
    host = os.environ.get("FOUNDRY_TEST_DOCKER_HOST", "")
    if (not re.fullmatch(r"[A-Za-z0-9:._-]{12,128}", expected) or
            not host.startswith("unix:///") or os.environ.get("DOCKER_HOST") != host or
            any(key in os.environ for key in ("DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"))):
        raise TestEngineRefusal("test engine configuration invalid")
    try:
        validate_engine_socket(host[len("unix://"):])
        result = subprocess.run(["docker", "info", "--format", "{{json .}}"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                                timeout=20 if os.environ.get("FOUNDRY_TEST_RUN_ID") else None)
        data = json.loads(result.stdout)
        if (data.get("ID") != expected or data.get("OSType") != "linux" or
                not data.get("CgroupDriver") or data["CgroupDriver"] == "none" or
                not all(data.get(key) is True for key in ("MemoryLimit", "SwapLimit", "PidsLimit", "CpuCfsQuota"))):
            raise TestEngineRefusal("test engine identity or controls changed")
        return data
    except (OSError, ValueError, TypeError, AttributeError, subprocess.SubprocessError) as exc:
        raise TestEngineRefusal("test engine identity or controls unavailable") from exc


def test_mount_group(data):
    """Translate the operator's group only for the verified rootless test daemon."""
    options = data.get("SecurityOptions")
    if not isinstance(options, list) or not all(isinstance(item, str) for item in options):
        raise TestEngineRefusal("test engine security options unavailable")
    if "name=rootless" not in options:
        return str(os.getegid())
    try:
        import http.client
        import socket
        import struct

        path = os.environ["FOUNDRY_TEST_DOCKER_HOST"][len("unix://"):]
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(path)
            pid, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if pid <= 0 or uid != os.geteuid():
                raise ValueError("rootless socket peer is not the operator")
            connection.sendall(b"GET /info HTTP/1.0\r\nHost: localhost\r\n\r\n")
            response = http.client.HTTPResponse(connection)
            response.begin()
            if response.status != 200:
                raise ValueError("rootless engine info unavailable")
            info = json.loads(response.read(1024 * 1024 + 1))
            if (info.get("ID") != os.environ["FOUNDRY_TEST_ENGINE_ID"] or
                    "name=rootless" not in info.get("SecurityOptions", [])):
                raise ValueError("rootless engine identity changed")
            with open(f"/proc/{pid}/gid_map", encoding="ascii") as stream:
                mappings = [tuple(map(int, line.split())) for line in stream]
        if not any(len(entry) == 3 and entry == (0, os.getegid(), 1) for entry in mappings):
            raise ValueError("rootless group mapping does not match operator")
        return "0"
    except (KeyError, OSError, ValueError, TypeError, AttributeError, http.client.HTTPException, struct.error) as exc:
        raise TestEngineRefusal("rootless test group mapping unavailable") from exc


def check_project(project, config):
    label = "label=com.docker.compose.project=" + project
    existing = False
    for kind, args in (("container", ["container", "ls", "--all"]),
                       ("network", ["network", "ls"]),
                       ("volume", ["volume", "ls"])):
        verify_test_engine()
        result = subprocess.run(["docker", *args, "--filter", label, "--quiet"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                                timeout=20 if os.environ.get("FOUNDRY_TEST_RUN_ID") else None)
        existing |= bool(result.stdout.strip())
    for kind, section in (("network", "networks"), ("volume", "volumes")):
        names = {entry["name"] for entry in config.get(section, {}).values()}
        verify_test_engine()
        result = subprocess.run(["docker", kind, "ls", "--format", "{{.Name}}"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True,
                                timeout=20 if os.environ.get("FOUNDRY_TEST_RUN_ID") else None)
        existing |= bool(names.intersection(result.stdout.splitlines()))
    return existing


def test_override(project, token, command, volume_name=None):
    """Fixed test-only configuration; never accepts an arbitrary override file."""
    if not re.fullmatch(r"[0-9a-f]{32}", token) or project != "foundry-test-" + token:
        raise ValueError("invalid test project identity")
    label = {"org.creatidy.foundry.test-run": token}
    volume = {"labels": label}
    if volume_name:
        if not re.fullmatch(re.escape(project) + r"_restore_[0-9a-f]{32}", volume_name):
            raise ValueError("invalid test volume name")
        volume["name"] = volume_name
    return {
        "services": {"router": {
            "command": command,
            "cpus": 1.0, "mem_limit": "512m", "memswap_limit": "512m", "pids_limit": 128,
            "cgroup": "private",
            "restart": "no", "labels": label,
            "logging": {"driver": "json-file", "options": {"max-size": "1m", "max-file": "2"}},
        }},
        "networks": {"backend": {"internal": False, "labels": label}},
        "volumes": {"router-data": volume},
    }


def check_test_ownership(project, token):
    """Do not let test-only adoption take over another project's resources."""
    volumes = set()
    for kind in ("container", "network", "volume"):
        base = ["docker", kind, "ls", "--quiet"]
        if kind == "container":
            base.append("--all")
        def listed(label):
            verify_test_engine()
            result = subprocess.run(base + ["--filter", "label=" + label], check=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            return set(result.stdout.decode().splitlines())
        project_ids = listed("com.docker.compose.project=" + project)
        run_ids = listed("org.creatidy.foundry.test-run=" + token)
        if project_ids != run_ids or len(project_ids) > 8:
            raise ValueError("test ownership labels do not match")
        if kind == "volume":
            volumes = project_ids
        for identifier in project_ids:
            verify_test_engine()
            result = subprocess.run(["docker", kind, "inspect", identifier], check=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
            item = json.loads(result.stdout)[0]
            labels = item.get("Config", {}).get("Labels", {}) if kind == "container" else item.get("Labels", {})
            if (labels.get("com.docker.compose.project") != project or
                    labels.get("org.creatidy.foundry.test-run") != token):
                raise ValueError("unowned test resource")
    return volumes


def mount_group():
    """Rootless Docker maps the invoking host user's primary group to zero."""
    verify_test_engine()
    result = subprocess.run(["docker", "info", "--format", "{{json .SecurityOptions}}"],
                            check=True, capture_output=True, timeout=20)
    options = json.loads(result.stdout)
    if not isinstance(options, list) or not all(isinstance(value, str) for value in options):
        raise ValueError("Docker group mapping unavailable")
    return "0" if "name=rootless" in options else str(os.getegid())


def tls_settings(base):
    """Resolve only TLS keys as structured data through Compose's own dotenv."""
    keys = ("TLS_DEST", "FOUNDRY_TLS_DIR", "FOUNDRY_ROUTER_HOST")
    labels = {"org.creatidy.foundry." + key.lower(): "${" + key + "-}" for key in keys}
    with tempfile.TemporaryDirectory(prefix="foundry-tls-settings-") as tmp:
        path = os.path.join(tmp, "settings.json")
        with open(path, "x", encoding="utf-8") as stream:
            json.dump({"services": {"router": {"labels": labels}}}, stream)
        verify_test_engine()
        result = subprocess.run(base + ["-f", path, "config", "--format", "json", "--no-path-resolution"],
                                check=True, capture_output=True, timeout=30)
    rendered = json.loads(result.stdout)["services"]["router"]["labels"]
    if not isinstance(rendered, dict) or any(not isinstance(rendered.get(name), str) for name in labels):
        raise ValueError("invalid Compose TLS projection")
    # Compose config escapes dollars for reuse as Compose input, including JSON.
    return {key: rendered["org.creatidy.foundry." + key.lower()].replace("$$", "$") for key in keys}


def apply_test_override(project, override, command):
    """Bound the canonical service without replacing its topology or transport."""
    token = os.environ["FOUNDRY_TEST_RUN_ID"]
    router = override["services"]["router"]
    group = router.get("group_add") or [mount_group()]
    if group != [test_mount_group(verify_test_engine())]:
        raise TestEngineRefusal("product and test engine group mapping disagree")
    bounded = test_override(project, token, command, os.environ.get("FOUNDRY_TEST_VOLUME"))
    router.update(bounded["services"]["router"])
    router["group_add"] = group
    override.update(networks=bounded["networks"], volumes=bounded["volumes"])


def check_test_adoption(project, adoption):
    token = os.environ["FOUNDRY_TEST_RUN_ID"]
    selected = os.environ.get("FOUNDRY_TEST_VOLUME")
    if selected and not adoption:
        raise ValueError("restored volume requires test project adoption")
    volumes = check_test_ownership(project, token)
    if selected and selected not in volumes:
        raise ValueError("restored volume is not owned by test project")
    if not adoption and volumes:
        raise ValueError("test resources already exist")


def tls_override(destination, hostname, *, leaf=False):
    if (not os.path.isabs(destination) or not os.path.isdir(destination) or
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", hostname)):
        raise ValueError("absolute TLS directory and certificate hostname required")
    for name in ("server.crt", "server.key"):
        with open(os.path.join(destination, name), "rb"):
            pass
    command = ["--host=0.0.0.0", "--port=8787", "--data-dir=/data",
               "--tls-certfile=/run/foundry/tls/server.crt",
               "--tls-keyfile=/run/foundry/tls/server.key",
               "--tls-reload-hostname=" + hostname,
               "--worker-listen-host=0.0.0.0", "--worker-listen-port=8790",
               "--worker-tls-certfile=/run/foundry/tls/server.crt",
               "--worker-tls-keyfile=/run/foundry/tls/server.key",
               "--worker-tls-reload-hostname=" + hostname]
    environment = {"SR_HEALTHCHECK_URL": "https://" + hostname + ":8787/healthz"}
    if leaf:
        command += ["--tls-reload-ca-cert=/run/foundry/tls/server.crt",
                    "--worker-tls-reload-ca-cert=/run/foundry/tls/server.crt"]
        environment["SR_HEALTHCHECK_CA"] = "/run/foundry/tls/server.crt"
    return {"command": command, "environment": environment,
            "extra_hosts": [hostname + ":127.0.0.1"],
            "group_add": [str(os.getegid())],
            "volumes": [{"type": "bind", "source": destination.replace("$", "$$"),
                         "target": "/run/foundry/tls", "read_only": True,
                         "bind": {"create_host_path": False}}]}


def tls_config():
    """Render the explicit advanced TLS model without starting any service."""
    base = ["docker", "compose"] + (["--env-file", ".env"] if os.path.isfile(".env") else [])
    settings = tls_settings(base + ["-f", "compose.yaml"])
    override = tls_override(settings["FOUNDRY_TLS_DIR"], settings["FOUNDRY_ROUTER_HOST"])
    with tempfile.TemporaryDirectory(prefix="foundry-tls-config-") as tmp:
        path = os.path.join(tmp, "override.json")
        with open(path, "x", encoding="utf-8") as stream:
            json.dump({"services": {"router": override}}, stream)
        result = subprocess.run(base + ["-f", "compose.yaml", "-f", path, "config", "--format", "json",
                                        "--no-path-resolution"], check=True, capture_output=True, timeout=30)
        return json.loads(result.stdout)


def local_http_main():
    """Build the default source once, then start its resolved local image ID."""
    try:
        token = os.environ.get("FOUNDRY_TEST_RUN_ID", "")
        project = os.environ.get("LOCAL_TLS_PROJECT", "")
        adoption = os.environ.get("LOCAL_TLS_ADOPT_PROJECT", "")
        if token:
            test_override(project, token, [])
            if (os.environ.get("FOUNDRY_TEST_AUTHORIZATION") != "disposable-linux-engine-approved" or
                    (adoption and adoption != project)):
                raise ValueError("test startup requires explicit project authorization")
        if any(os.environ.get(key) for key in ("TLS_DEST", "FOUNDRY_TLS_DIR", "FOUNDRY_ROUTER_HOST")):
            raise ValueError("TLS settings require explicit tls-up, not local HTTP")
        base = ["docker", "compose"] + (["-p", project] if token else []) + (["--env-file", ".env"] if os.path.isfile(".env") else []) + ["-f", "compose.yaml"]
        verify_test_engine()
        if any(tls_settings(base).values()):
            raise ValueError("effective Compose TLS settings require explicit tls-up")
        verify_test_engine()
        result = subprocess.run(base + ["config", "--format", "json"], check=True,
                                capture_output=True, timeout=30)
        config = json.loads(result.stdout)
        if token and (config["name"] != project or set(config["services"]) != {"router"}):
            raise ValueError("unexpected test Compose project or services")
        router = config["services"]["router"]
        if token and not re.fullmatch(r"sha256:[0-9a-f]{64}", router["image"]):
            raise ValueError("test startup requires an already verified immutable image")
        command = router["command"]
        if "--local-container-http" not in command or any(arg.startswith("--tls-") for arg in command):
            raise ValueError("not the canonical local HTTP command")
        mi_dir, digest = os.environ.get("FOUNDRY_MI_DIR", ""), os.environ.get("FOUNDRY_MI_SHA256", "")
        expected = os.environ.get("FOUNDRY_MI_IMAGE_ID", "")
        if mi_dir or digest or expected:
            validate_mi(mi_dir, digest)
        if router["image"] == "foundry-sr-mi:5bd4fa4-local":
            verify_test_engine()
            subprocess.run(base + ["build", "router"], check=True, timeout=900)
        verify_test_engine()
        result = subprocess.run(["docker", "image", "inspect", router["image"]], check=True,
                                capture_output=True, timeout=30)
        images = json.loads(result.stdout)
        if len(images) != 1 or not re.fullmatch(r"sha256:[0-9a-f]{64}", images[0]["Id"]):
            raise ValueError("image identity unavailable")
        health = images[0].get("Config", {}).get("Healthcheck", {}).get("Test", [])
        if (not isinstance(health, list) or len(health) < 2 or health[0] not in ("CMD", "CMD-SHELL") or
                router.get("entrypoint") is not None or "healthcheck" in router):
            raise ValueError("image liveness contract unavailable")
        image = images[0]["Id"]
        if token and image != router["image"]:
            raise ValueError("test image identity changed")
        if expected and expected != image:
            raise ValueError("MI image identity mismatch")
        override = {"image": image}
        if mi_dir:
            command = command + ["--mi-config=/run/foundry/mi/trust.json"]
            override.update(command=command, restart="no", group_add=[mount_group()], volumes=[
                {"type": "bind", "source": os.path.join(mi_dir, name).replace("$", "$$"),
                 "target": "/run/foundry/mi/" + name, "read_only": True,
                 "bind": {"create_host_path": False}} for name in ("trust.json", "publication.json")])
        override = {"services": {"router": override}}
        if token:
            apply_test_override(project, override, command)
        with tempfile.TemporaryDirectory(prefix="foundry-local-http-") as tmp:
            path = os.path.join(tmp, "override.json")
            with open(path, "x", encoding="utf-8") as stream:
                json.dump(override, stream)
            if mi_dir:
                validate_mi(mi_dir, digest)
            if token:
                if check_project(project, config) and not adoption:
                    raise ValueError("project resources already exist")
                check_test_adoption(project, adoption)
            command = base + ["-f", path, "up", "-d", "--no-build", "--pull", "never",
                              "--wait", "--wait-timeout", "60"]
            if mi_dir or token:
                command.append("--force-recreate")
            verify_test_engine()
            if token:
                group = override["services"]["router"]["group_add"]
                if group != [mount_group()] or group != [test_mount_group(verify_test_engine())]:
                    raise TestEngineRefusal("test engine group mapping changed")
            return subprocess.run(command, timeout=90).returncode
    except TestEngineRefusal:
        print("Test engine identity verification failed.", file=sys.stderr)
        return 70
    except subprocess.TimeoutExpired:
        print("Local HTTP startup timed out.", file=sys.stderr)
        return 124 if os.environ.get("FOUNDRY_TEST_RUN_ID") else 1
    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, subprocess.SubprocessError):
        print("Local HTTP startup not confirmed: check Docker, image and protected MI inputs; inspect resources before retrying.", file=sys.stderr)
        return 1


def main(argv=()):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--local-http", action="store_true")
    modes.add_argument("--tls", action="store_true")
    args = parser.parse_args(argv)
    if args.local_http:
        return local_http_main()
    try:
        project = os.environ.get("LOCAL_TLS_PROJECT", "")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", project):
            raise ValueError("explicit valid local TLS project is required")
        adoption = os.environ.get("LOCAL_TLS_ADOPT_PROJECT", "")
        if adoption and adoption != project:
            raise ValueError("adoption acknowledgement does not match project")
        token = os.environ.get("FOUNDRY_TEST_RUN_ID", "")
        if token:
            test_override(project, token, [])
            if os.environ.get("FOUNDRY_TEST_AUTHORIZATION") != "disposable-linux-engine-approved":
                raise ValueError("test startup requires explicit authorization")
        base = ["docker", "compose", "-p", project] + (["--env-file", ".env"] if os.path.isfile(".env") else []) + ["-f", "compose.yaml"]
        verify_test_engine()
        settings = tls_settings(base)
        destination = settings["FOUNDRY_TLS_DIR" if args.tls else "TLS_DEST"]
        if not args.tls:
            validate(destination)
        mi_dir = os.environ.get("FOUNDRY_MI_DIR", "")
        mi_digest = os.environ.get("FOUNDRY_MI_SHA256", "")
        image_id = os.environ.get("FOUNDRY_MI_IMAGE_ID", "")
        if mi_dir or mi_digest or image_id:
            validate_mi(mi_dir, mi_digest)
            if image_id and not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
                raise ValueError("independent MI image ID required")
        verify_test_engine()
        result = subprocess.run(base + ["config", "--format", "json", "--no-path-resolution"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                                timeout=20 if os.environ.get("FOUNDRY_TEST_RUN_ID") else None)
        config = json.loads(result.stdout)
        if config["name"] != project:
            raise ValueError("unexpected Compose project")
        router = config["services"]["router"]
        if token and (set(config["services"]) != {"router"} or
                      not re.fullmatch(r"sha256:[0-9a-f]{64}", router["image"])):
            raise ValueError("test startup requires one router with an immutable image")
        if mi_dir or token:
            verify_test_engine()
            result = subprocess.run(["docker", "image", "inspect", router["image"]],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30)
            images = json.loads(result.stdout)
            health = images[0]["Config"].get("Healthcheck", {}).get("Test") if len(images) == 1 else None
            if (len(images) != 1 or (image_id and images[0]["Id"] != image_id) or
                (token and images[0]["Id"] != router["image"]) or
                not isinstance(health, list) or len(health) < 2 or health[0] not in ("CMD", "CMD-SHELL") or
                "healthcheck" in router or router.get("entrypoint") is not None):
                raise ValueError("MI image or healthcheck not accepted")
            image_id = images[0]["Id"]
        hostname = settings["FOUNDRY_ROUTER_HOST"]
        if not args.tls and (hostname != "127.0.0.1" or settings["FOUNDRY_TLS_DIR"] != destination):
            raise ValueError("local leaf directory or hostname mismatch")
        override = {"services": {"router": tls_override(destination, hostname, leaf=not args.tls)}}
        override["services"]["router"]["group_add"] = [mount_group()]
        if mi_dir:
            override["services"]["router"]["command"].append("--mi-config=/run/foundry/mi/trust.json")
            override["services"]["router"]["image"] = image_id
            override["services"]["router"]["restart"] = "no"
            override["services"]["router"]["volumes"] += [
                {"type": "bind", "source": os.path.join(mi_dir, name).replace("$", "$$"),
                 "target": "/run/foundry/mi/" + name, "read_only": True,
                 "bind": {"create_host_path": False}}
                for name in ("trust.json", "publication.json")
            ]
        if token:
            apply_test_override(project, override, override["services"]["router"]["command"])
        with tempfile.TemporaryDirectory(prefix="foundry-local-tls-") as tmp:
            path = os.path.join(tmp, "override.json")
            with open(path, "x", encoding="utf-8") as stream:
                json.dump(override, stream)
            # Reject a changed directory immediately before asking Docker to mount it.
            if not args.tls:
                validate(destination)
            if mi_dir:
                validate_mi(mi_dir, mi_digest)
            if check_project(project, config):
                if not adoption:
                    raise ValueError("project resources already exist")
            if token:
                check_test_adoption(project, adoption)
            command = base + ["-f", path, "up", "-d", "--no-build", "--pull", "never"]
            if mi_dir or token:
                command += ["--force-recreate", "--wait", "--wait-timeout", "60"]
                data = verify_test_engine()
                if token and (override["services"]["router"]["group_add"] != [test_mount_group(data)] or
                              override["services"]["router"]["group_add"] != [mount_group()]):
                    raise TestEngineRefusal("test engine group mapping changed")
                return subprocess.run(command, timeout=90).returncode
            verify_test_engine()
            return subprocess.run(command).returncode
    except TestEngineRefusal:
        print("Test engine identity verification failed.", file=sys.stderr)
        return 70
    except subprocess.TimeoutExpired:
        print("Local TLS startup timed out.", file=sys.stderr)
        return 124 if os.environ.get("FOUNDRY_TEST_RUN_ID") else 1
    except (OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, subprocess.SubprocessError):
        print("Local TLS startup refused: check the project, protected TLS/MI inputs, Compose configuration and Docker.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
