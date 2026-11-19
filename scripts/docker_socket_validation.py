"""Filesystem validation for an explicitly selected local Docker socket."""

import errno
import os
import stat

from local_tls_init import no_acl


def validate_engine_socket(path):
    """Validate a local socket path; daemon identity is checked separately."""
    path = os.fspath(path)
    if (not isinstance(path, str) or not path.startswith("/") or path == "/" or
            os.path.normpath(path) != path or path.startswith("//") or
            any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in path)):
        raise ValueError("absolute normalized Docker socket path required")
    parts = path.split("/")[1:]
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in [None, *parts[:-1]]:
            if part is not None:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = child
            info = os.fstat(fd)
            if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
                raise ValueError("unsafe Docker socket directory ancestry")
            no_acl(fd)
        info = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid not in (0, os.geteuid()) or
                info.st_mode & 0o002):
            raise ValueError("Docker endpoint must be a trusted Unix socket")
        for attribute in ("system.posix_acl_access", "system.posix_acl_default"):
            try:
                os.getxattr(path, attribute, follow_symlinks=False)
            except OSError as exc:
                if exc.errno == errno.ENODATA:
                    continue
                raise
            raise ValueError("Docker socket ACLs are not supported")
        if not os.access(parts[-1], os.W_OK, dir_fd=fd, effective_ids=True, follow_symlinks=False):
            raise ValueError("Docker socket is not accessible to the operator")
    finally:
        os.close(fd)
