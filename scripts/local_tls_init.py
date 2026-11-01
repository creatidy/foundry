#!/usr/bin/env python3
"""Create a directly trusted loopback test leaf, never a CA or trust store."""

import hashlib
import os
import ssl
import stat
import subprocess
import sys


def no_acl(fd):
    for name in ("system.posix_acl_access", "system.posix_acl_default"):
        try:
            os.getxattr(fd, name)
        except OSError as exc:
            import errno
            if exc.errno == errno.ENODATA:
                continue
            raise
        raise ValueError("filesystem ACLs are not supported")


def open_parent(path):
    if not os.path.isabs(path) or path == "/" or any(
        part in (".", "..") for part in path.split("/")
    ):
        raise ValueError("destination must be an absolute, normalized path")
    parts = path.split("/")[1:]
    if any(not part for part in parts):
        raise ValueError("destination must be an absolute, normalized path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            new_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new_fd
            info = os.fstat(fd)
            # Root-owned sticky directories such as /tmp do not allow other users
            # to replace entries owned by this operator.
            sticky_root = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if info.st_uid not in (0, os.geteuid()) or (
                info.st_mode & 0o022 and not sticky_root
            ):
                raise ValueError("unsafe directory ancestry")
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("parent must be owned by the operator and mode 0700")
        no_acl(fd)
        return fd, parts[-1]
    except BaseException:
        os.close(fd)
        raise


def generate(destination):
    parent, name = open_parent(destination)
    directory = None
    created = False
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
        created = True
        directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        os.fchown(directory, -1, os.getegid())
        os.fchmod(directory, 0o750)
        no_acl(directory)
        key = os.open("server.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                      0o600, dir_fd=directory)
        try:
            os.fchmod(key, 0o600)
            os.fchown(key, -1, os.getegid())
            no_acl(key)
            cert = os.open("server.crt", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                           0o600, dir_fd=directory)
            try:
                os.fchown(cert, -1, os.getegid())
                no_acl(cert)
                subprocess.run(
                    ["openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256",
                     "-noenc", "-days", "30", "-subj", "/CN=127.0.0.1",
                     "-addext", "subjectAltName=IP:127.0.0.1",
                     "-addext", "basicConstraints=critical,CA:FALSE",
                     "-addext", "extendedKeyUsage=serverAuth",
                     "-keyout", f"/proc/self/fd/{key}", "-out", f"/proc/self/fd/{cert}"],
                    pass_fds=(key, cert), stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, check=True,
                )
                os.fchmod(cert, 0o640)
                os.fchmod(key, 0o640)
            finally:
                os.close(cert)
        finally:
            os.close(key)
        cert_read = os.open("server.crt", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        with os.fdopen(cert_read, "r", encoding="ascii") as stream:
            der = ssl.PEM_cert_to_DER_cert(stream.read())
        fingerprint = hashlib.sha256(der).hexdigest().upper()
        return ":".join(fingerprint[i:i + 2] for i in range(0, len(fingerprint), 2))
    except BaseException:
        if created:
            if directory is not None:
                for filename in ("server.key", "server.crt"):
                    try:
                        os.unlink(filename, dir_fd=directory)
                    except FileNotFoundError:
                        pass
            os.rmdir(name, dir_fd=parent)
        raise
    finally:
        if directory is not None:
            os.close(directory)
        os.close(parent)


def main():
    try:
        destination = os.environ.get("TLS_DEST", "")
        fingerprint = generate(destination)
    except (OSError, ValueError, subprocess.SubprocessError):
        print("Local TLS initialization failed; check destination, permissions and OpenSSL.", file=sys.stderr)
        return 1
    print("SHA-256 certificate fingerprint:", fingerprint)
    print("Do not trust an unverified certificate. Verify this fingerprint through a trusted channel.")
    print("Direct trust is only for explicitly configured test clients; no trust store was modified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
