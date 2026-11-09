"""Fail-closed boundary for execution of host-installed MI code.

Distribution metadata is self-reported, and this process does not establish a
trusted import path or an immutable, independently verified source tree. This
gate authenticates neither the interpreter nor transitive dependencies.
"""


def require_verified_host_mi():
    """Refuse host MI execution until an independently verified path exists."""
    raise RuntimeError("host MI execution disabled: installed code and import path are not independently verified")
