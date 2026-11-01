#!/usr/bin/env python3
"""Explicit loopback-only leaf trust override for the canonical Compose file."""

import json
import os
import stat
import subprocess
import sys
import tempfile

from local_tls_init import no_acl, open_parent


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
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
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


def main():
    try:
        destination = os.environ.get("TLS_DEST", "")
        validate(destination)
        base = ["docker", "compose", "--env-file", ".env", "-f", "compose.yaml"]
        result = subprocess.run(base + ["config", "--format", "json", "--no-path-resolution"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        config = json.loads(result.stdout)
        router = config["services"]["router"]
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
        with tempfile.TemporaryDirectory(prefix="foundry-local-tls-") as tmp:
            path = os.path.join(tmp, "override.json")
            with open(path, "x", encoding="utf-8") as stream:
                json.dump(override, stream)
            # Reject a changed directory immediately before asking Docker to mount it.
            validate(destination)
            return subprocess.run(base + ["-f", path, "up", "-d", "--no-build", "--pull", "never"]).returncode
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("Local TLS startup refused: check the protected leaf, Compose configuration and Docker.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
