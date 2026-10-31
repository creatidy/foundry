#!/usr/bin/env python3
"""Validate the interpolated TLS bind before the supported Compose startup."""

import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    try:
        result = subprocess.run(
            ["docker", "compose", "--env-file", ".env", "-f", "compose.yaml",
             "config", "--format", "json", "--no-path-resolution"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
        config = json.loads(result.stdout)
        mounts = [mount for mount in config["services"]["router"]["volumes"]
                  if mount.get("target") == "/run/foundry/tls"]
        if len(mounts) != 1 or mounts[0].get("type") != "bind":
            raise ValueError("TLS mount is not a unique bind")
        source = mounts[0]["source"]
        if not isinstance(source, str) or not os.path.isabs(source):
            raise ValueError("TLS source is not absolute")
        directory = Path(source)
        if not directory.is_dir():
            raise ValueError("TLS source is not an existing directory")
        for name in ("server.crt", "server.key"):
            path = directory / name
            if not path.is_file():
                raise ValueError("TLS file is missing or not a regular file")
            with path.open("rb"):
                pass
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        print("TLS preflight failed: check Compose configuration and the absolute "
              "TLS directory containing readable server.crt and server.key.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
