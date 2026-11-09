"""Isolated Docker integration; set FOUNDRY_TEST_SR_IMAGE to a local compatible image."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_FILES = ("Makefile", "compose.yaml", "scripts/local_tls_init.py", "scripts/local_tls_up.py",
                 "scripts/docker_socket_validation.py")


class RuntimeFixtureTests(unittest.TestCase):
    def test_copied_startup_script_imports_without_docker(self):
        with tempfile.TemporaryDirectory(prefix="foundry-runtime-files-") as tmp:
            root = Path(tmp)
            for name in RUNTIME_FILES:
                destination = root / name
                destination.parent.mkdir(exist_ok=True, parents=True)
                shutil.copyfile(ROOT / name, destination)
            result = subprocess.run([sys.executable, "-I", "-c",
                                     "import sys; sys.path.insert(0, sys.argv[1]); import local_tls_up",
                                     str(root / "scripts")], capture_output=True, text=True, timeout=10)
            self.assertEqual(0, result.returncode, result.stderr)


@unittest.skipUnless(os.environ.get("FOUNDRY_TEST_SR_IMAGE"), "set FOUNDRY_TEST_SR_IMAGE for runtime tests")
class LocalTLSRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="foundry-runtime-")
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name)
        for name in RUNTIME_FILES:
            dest = self.project / name
            dest.parent.mkdir(exist_ok=True, parents=True)
            shutil.copyfile(ROOT / name, dest)
        (self.project / ".env").write_text("")
        self.dest = self.project / "tls"
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("FOUNDRY_", "COMPOSE_"))}
        self.env.update(FOUNDRY_ROUTER_IMAGE=os.environ["FOUNDRY_TEST_SR_IMAGE"],
                        FOUNDRY_ROUTER_HOST="127.0.0.1", FOUNDRY_ROUTER_PORT="0",
                        FOUNDRY_TLS_DIR=str(self.dest), TLS_DEST=str(self.dest),
                        COMPOSE_PROJECT_NAME="foundry-runtime-" + uuid.uuid4().hex[:12])
        self.env["LOCAL_TLS_PROJECT"] = self.env["COMPOSE_PROJECT_NAME"]
        self.addCleanup(self.cleanup_compose)
        result = self.run_cmd("make", "local-tls-init")
        self.assertEqual(result.returncode, 0, result.stderr)

    def run_cmd(self, *args, env=None, input=None):
        return subprocess.run(args, cwd=self.project, env=env or self.env, input=input,
                              text=True, capture_output=True, timeout=60)

    def cleanup_compose(self):
        result = self.run_cmd("docker", "compose", "--env-file", ".env", "-f", "compose.yaml", "down", "--volumes", "--remove-orphans")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_guarded_start_and_client_trust(self):
        bad = self.env.copy()
        bad["FOUNDRY_ROUTER_HOST"] = "wrong.example"
        self.assertNotEqual(self.run_cmd("make", "local-tls-up", env=bad).returncode, 0)
        bad = self.env.copy()
        bad["FOUNDRY_TLS_DIR"] = str(self.project / "other")
        self.assertNotEqual(self.run_cmd("make", "local-tls-up", env=bad).returncode, 0)
        (self.dest / "server.key").chmod(0o644)
        self.assertNotEqual(self.run_cmd("make", "local-tls-up").returncode, 0)
        (self.dest / "server.key").chmod(0o640)
        cert = self.dest / "server.crt"
        original = cert.read_bytes()
        ca = self.run_cmd("openssl", "req", "-new", "-x509", "-key", str(self.dest / "server.key"),
                          "-subj", "/CN=127.0.0.1", "-addext", "basicConstraints=critical,CA:TRUE",
                          "-out", str(cert))
        self.assertEqual(ca.returncode, 0, ca.stderr)
        self.assertNotEqual(self.run_cmd("make", "local-tls-up").returncode, 0)
        cert.write_bytes(original)
        result = self.run_cmd("make", "local-tls-up")
        self.assertEqual(result.returncode, 0, result.stderr)
        cid = self.run_cmd("docker", "compose", "--env-file", ".env", "-f", "compose.yaml", "ps", "-q", "router").stdout.strip()
        for _ in range(45):
            info = json.loads(self.run_cmd("docker", "inspect", cid).stdout)[0]
            state = info["State"]
            if not state["Running"] or state.get("Health", {}).get("Status") in ("healthy", "unhealthy"):
                break
            time.sleep(1)
        self.assertEqual(state.get("Health", {}).get("Status"), "healthy", str(state))
        access = self.run_cmd("docker", "exec", cid, "python", "-c",
                              "import os; print(os.getuid(), os.getgroups(), os.access('/run/foundry/tls/server.key', os.R_OK)); "
                              "\ntry: open('/run/foundry/tls/server.key', 'a')\nexcept OSError: print('read-only')")
        self.assertEqual(access.returncode, 0, access.stderr)
        self.assertIn("10001", access.stdout)
        self.assertIn("True", access.stdout)
        self.assertIn("read-only", access.stdout)
        port = self.run_cmd("docker", "port", cid, "8787/tcp").stdout.strip().rsplit(":", 1)[-1]
        for expected, options in [(0, ["-CAfile", str(self.dest / "server.crt"), "-verify_ip", "127.0.0.1"]),
                                  (1, ["-CAfile", str(self.dest / "server.crt"), "-verify_hostname", "wrong.example"]),
                                  (1, ["-no-CAfile", "-no-CApath", "-no-CAstore", "-verify_ip", "127.0.0.1"])]:
            client = self.run_cmd("openssl", "s_client", "-connect", "127.0.0.1:" + port,
                                  "-verify_return_error", *options, input="")
            self.assertEqual(client.returncode == 0, expected == 0, client.stderr)
        self.assertNotIn((self.dest / "server.key").read_text(), result.stdout + result.stderr)
        self.assertNotEqual(self.run_cmd("make", "local-tls-up").returncode, 0)
        adopt = self.env.copy()
        adopt["LOCAL_TLS_ADOPT_PROJECT"] = self.env["LOCAL_TLS_PROJECT"]
        self.assertEqual(self.run_cmd("make", "local-tls-up", env=adopt).returncode, 0)

    def test_existing_resources_are_not_adopted(self):
        project = self.env["LOCAL_TLS_PROJECT"]
        image = os.environ["FOUNDRY_TEST_SR_IMAGE"]
        fixtures = [
            ("container", ["create", "--name", project + "-orphan", "--label", "com.docker.compose.project=" + project, image], project + "-orphan"),
            ("network", ["create", "--label", "com.docker.compose.project=" + project, project + "-orphan"], project + "-orphan"),
            ("volume", ["create", "--label", "com.docker.compose.project=" + project, project + "-orphan"], project + "-orphan"),
            ("network", ["create", project + "_backend"], project + "_backend"),
            ("volume", ["create", project + "_router-data"], project + "_router-data"),
        ]
        for kind, create, name in fixtures:
            with self.subTest(kind=kind, name=name):
                self.assertNotEqual(self.run_cmd("docker", kind, "inspect", name).returncode, 0)
                created = self.run_cmd("docker", kind, *create)
                self.assertEqual(created.returncode, 0, created.stderr)
                try:
                    before = self.run_cmd("docker", kind, "inspect", name)
                    result = self.run_cmd("make", "local-tls-up")
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    after = self.run_cmd("docker", kind, "inspect", name)
                    self.assertEqual(before.returncode, 0, before.stderr)
                    self.assertEqual(after.returncode, 0, after.stderr)
                    self.assertEqual(json.loads(before.stdout), json.loads(after.stdout))
                    self.assertEqual(self.run_cmd("docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + project,
                                                  "--filter", "label=com.docker.compose.service=router").stdout.strip(), "")
                finally:
                    removed = self.run_cmd("docker", kind, "rm", name)
                    self.assertEqual(removed.returncode, 0, removed.stderr)

    def test_project_required_and_daemon_failure(self):
        missing = self.env.copy()
        missing.pop("LOCAL_TLS_PROJECT")
        self.assertNotEqual(self.run_cmd("make", "local-tls-up", env=missing).returncode, 0)
        mismatch = self.env.copy()
        mismatch["LOCAL_TLS_ADOPT_PROJECT"] = "another-project"
        self.assertNotEqual(self.run_cmd("make", "local-tls-up", env=mismatch).returncode, 0)
        unavailable = self.env.copy()
        unavailable["DOCKER_HOST"] = "unix:///nonexistent/foundry-test-docker.sock"
        self.assertNotEqual(self.run_cmd("make", "local-tls-up", env=unavailable).returncode, 0)

    def test_public_default_has_no_leaf_override(self):
        result = self.run_cmd("docker", "compose", "--env-file", ".env", "-f", "compose.yaml", "config", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        router = json.loads(result.stdout)["services"]["router"]
        self.assertNotIn("SR_HEALTHCHECK_CA", router["environment"])
        self.assertFalse(any(a.startswith("--tls-reload-ca-cert") for a in router["command"]))
        self.assertNotIn("group_add", router)
