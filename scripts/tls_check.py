#!/usr/bin/env python3
"""Offline verification of the operator-provided router TLS identity."""

import json
import os
from pathlib import Path
import ssl
import subprocess
import sys


def router_identity(config):
    router = config["services"]["router"]
    mounts = [m for m in router["volumes"] if m.get("target") == "/run/foundry/tls"]
    if len(mounts) != 1 or mounts[0].get("type") != "bind":
        raise ValueError("ambiguous TLS bind")
    source = mounts[0]["source"]
    if not isinstance(source, str) or not os.path.isabs(source):
        raise ValueError("invalid TLS bind")
    command = router["command"]
    if not isinstance(command, list) or not all(isinstance(arg, str) for arg in command):
        raise ValueError("invalid command")
    # SR's argparse accepts abbreviated long options and split values.  Only
    # accept the complete, equals-form options in Foundry's known command;
    # otherwise an alias or a consumed value can change SR's effective args.
    allowed = {"--host", "--port", "--data-dir", "--tls-reload-hostname",
               "--tls-certfile", "--tls-keyfile"}
    values = {}
    for arg in command:
        name, separator, value = arg.partition("=")
        if not separator or name not in allowed or name in values or not value:
            raise ValueError("ambiguous TLS argument")
        values[name] = value
    if (values.keys() != allowed or
            values["--tls-certfile"] != "/run/foundry/tls/server.crt" or
            values["--tls-keyfile"] != "/run/foundry/tls/server.key"):
        raise ValueError("invalid TLS identity")
    return Path(source), values["--tls-reload-hostname"]


def verify(directory, hostname, client_context):
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    def reject_password():
        raise ValueError("encrypted private key")

    server_context.load_cert_chain(str(directory / "server.crt"),
                                   str(directory / "server.key"), password=reject_password)
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_context.wrap_bio(client_in, client_out, server_hostname=hostname)
    server = server_context.wrap_bio(server_in, server_out, server_side=True)
    completed = [False, False]
    transferred = 0
    for _ in range(100):
        for index, endpoint in enumerate((client, server)):
            if not completed[index]:
                try:
                    endpoint.do_handshake()
                    completed[index] = True
                except ssl.SSLWantReadError:
                    pass
        for outgoing, incoming in ((client_out, server_in), (server_out, client_in)):
            data = outgoing.read()
            transferred += len(data)
            if transferred > 1024 * 1024:
                raise ValueError("handshake too large")
            incoming.write(data)
        if all(completed):
            return
    raise ValueError("handshake did not complete")


def main():
    try:
        result = subprocess.run(
            ["docker", "compose", "--env-file", ".env", "-f", "compose.yaml",
             "config", "--format", "json", "--no-path-resolution"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30,
        )
        directory, hostname = router_identity(json.loads(result.stdout))
        # OpenSSL otherwise accepts these environment variables as trust overrides.
        os.environ.pop("SSL_CERT_FILE", None)
        os.environ.pop("SSL_CERT_DIR", None)
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        verify(directory, hostname, context)
    except Exception:
        print("TLS check failed: verify the Compose configuration and operator-provided TLS identity.",
              file=sys.stderr)
        return 1
    print("TLS check passed using host default trust.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
