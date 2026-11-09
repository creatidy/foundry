#!/usr/bin/env python3
"""Explicit loopback-only leaf trust override for the canonical Compose file."""

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


def validate_mi(destination, expected):
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
        if (config["publication"] != "/run/foundry/mi/publication.json" or
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
    except (OSError, ValueError, TypeError, AttributeError, subprocess.SubprocessError) as exc:
        raise TestEngineRefusal("test engine identity or controls unavailable") from exc


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
            "command": command + ["--worker-listen-host=127.0.0.1", "--worker-listen-port=8788",
                                  "--worker-tls-certfile=/run/foundry/tls/server.crt",
                                  "--worker-tls-keyfile=/run/foundry/tls/server.key",
                                  "--worker-tls-reload-hostname=127.0.0.1",
                                  "--worker-tls-reload-ca-cert=/run/foundry/tls/server.crt"],
            "cpus": 1.0, "mem_limit": "512m", "memswap_limit": "512m", "pids_limit": 128,
            "restart": "no", "labels": label,
            "logging": {"driver": "json-file", "options": {"max-size": "1m", "max-file": "2"}},
        }},
        "networks": {"backend": {"internal": True, "labels": label}},
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


def main():
    try:
        project = os.environ.get("LOCAL_TLS_PROJECT", "")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", project):
            raise ValueError("explicit valid local TLS project is required")
        adoption = os.environ.get("LOCAL_TLS_ADOPT_PROJECT", "")
        if adoption and adoption != project:
            raise ValueError("adoption acknowledgement does not match project")
        destination = os.environ.get("TLS_DEST", "")
        validate(destination)
        mi_dir = os.environ.get("FOUNDRY_MI_DIR", "")
        mi_digest = os.environ.get("FOUNDRY_MI_SHA256", "")
        image_id = os.environ.get("FOUNDRY_MI_IMAGE_ID", "")
        if mi_dir or mi_digest or image_id:
            validate_mi(mi_dir, mi_digest)
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
                raise ValueError("independent MI image ID required")
        base = ["docker", "compose", "-p", project, "--env-file", ".env", "-f", "compose.yaml"]
        verify_test_engine()
        result = subprocess.run(base + ["config", "--format", "json", "--no-path-resolution"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                                timeout=20 if os.environ.get("FOUNDRY_TEST_RUN_ID") else None)
        config = json.loads(result.stdout)
        if config["name"] != project:
            raise ValueError("unexpected Compose project")
        router = config["services"]["router"]
        if mi_dir:
            verify_test_engine()
            result = subprocess.run(["docker", "image", "inspect", router["image"]],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30)
            images = json.loads(result.stdout)
            health = images[0]["Config"].get("Healthcheck", {}).get("Test") if len(images) == 1 else None
            if (len(images) != 1 or images[0]["Id"] != image_id or
                not isinstance(health, list) or len(health) < 2 or health[0] not in ("CMD", "CMD-SHELL") or
                "healthcheck" in router or router.get("entrypoint") is not None):
                raise ValueError("MI image or healthcheck not accepted")
        mounts = [m for m in router["volumes"] if m.get("target") == "/run/foundry/tls"]
        if (len(mounts) != 1 or mounts[0].get("type") != "bind" or
            mounts[0].get("source") != destination or not mounts[0].get("read_only") or
            router["environment"].get("SR_HEALTHCHECK_URL") != "https://127.0.0.1:8787/healthz"):
            raise ValueError("Compose TLS directory or loopback hostname mismatch")
        command = router["command"]
        if ("--tls-reload-hostname=127.0.0.1" not in command or
            any(arg.startswith("--tls-reload-ca-cert") for arg in command)):
            raise ValueError("unexpected SR TLS command")
        override = {"services": {"router": {
            "command": command + ["--tls-reload-ca-cert=/run/foundry/tls/server.crt"],
            "group_add": [str(os.getegid())],
            "environment": {"SR_HEALTHCHECK_CA": "/run/foundry/tls/server.crt"},
        }}}
        if mi_dir:
            override["services"]["router"]["command"].append("--mi-config=/run/foundry/mi/trust.json")
            override["services"]["router"]["image"] = image_id
            override["services"]["router"]["restart"] = "no"
            override["services"]["router"]["volumes"] = [
                {"type": "bind", "source": os.path.join(mi_dir, name).replace("$", "$$"),
                 "target": "/run/foundry/mi/" + name, "read_only": True,
                 "bind": {"create_host_path": False}}
                for name in ("trust.json", "publication.json")
            ]
        token = os.environ.get("FOUNDRY_TEST_RUN_ID", "")
        if token:
            if os.environ.get("FOUNDRY_TEST_AUTHORIZATION") != "disposable-linux-engine-approved":
                raise ValueError("test startup requires explicit authorization")
            bounded = test_override(project, token, override["services"]["router"]["command"],
                                    os.environ.get("FOUNDRY_TEST_VOLUME"))
            override["services"]["router"].update(bounded["services"]["router"])
            override["networks"] = bounded["networks"]
            override["volumes"] = bounded["volumes"]
        with tempfile.TemporaryDirectory(prefix="foundry-local-tls-") as tmp:
            path = os.path.join(tmp, "override.json")
            with open(path, "x", encoding="utf-8") as stream:
                json.dump(override, stream)
            # Reject a changed directory immediately before asking Docker to mount it.
            validate(destination)
            if mi_dir:
                validate_mi(mi_dir, mi_digest)
            if check_project(project, config):
                if not adoption:
                    raise ValueError("project resources already exist")
            if token:
                selected_volume = os.environ.get("FOUNDRY_TEST_VOLUME")
                if selected_volume and not adoption:
                    raise ValueError("restored volume requires test project adoption")
                if adoption:
                    volumes = check_test_ownership(project, token)
                    if selected_volume and selected_volume not in volumes:
                        raise ValueError("restored volume is not owned by test project")
            command = base + ["-f", path, "up", "-d", "--no-build", "--pull", "never"]
            if mi_dir or token:
                command += ["--force-recreate", "--wait", "--wait-timeout", "60"]
                verify_test_engine()
                return subprocess.run(command, timeout=90).returncode
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
    sys.exit(main())
