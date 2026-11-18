"""Protected MI input and local startup override checks, without Docker."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import local_tls_up


class MIOptInTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "mi"
        self.directory.mkdir(mode=0o750)
        self.publication = self.directory / "publication.json"
        self.publication.write_bytes(b"synthetic publication")
        self.digest = hashlib.sha256(self.publication.read_bytes()).hexdigest()
        self.image_id = "sha256:" + "a" * 64
        self.trust = self.directory / "trust.json"
        self.trust.write_text(json.dumps({"publication": "/run/foundry/mi/publication.json",
                                          "reference": {"sha256": self.digest}}))
        self.publication.chmod(0o640)
        self.trust.chmod(0o640)
        self.tls = Path(self.temp.name) / "tls"
        self.tls.mkdir()
        for name in ("server.crt", "server.key"):
            (self.tls / name).write_bytes(b"offline readable fixture; validation is mocked")
        self.env = {"LOCAL_TLS_PROJECT": "test", "TLS_DEST": str(self.tls),
                    "FOUNDRY_TLS_DIR": str(self.tls), "FOUNDRY_ROUTER_HOST": "127.0.0.1"}
        self.enterContext(mock.patch.object(local_tls_up, "mount_group", return_value=str(os.getegid())))
        self.enterContext(mock.patch.object(local_tls_up, "tls_settings", side_effect=lambda base: {
            key: os.environ.get(key, "") for key in ("TLS_DEST", "FOUNDRY_TLS_DIR", "FOUNDRY_ROUTER_HOST")}))

    def check(self, digest=None):
        local_tls_up.validate_mi(str(self.directory), self.digest if digest is None else digest)

    def startup(self, *, enabled=True, image=None, entrypoint=None, wait="ok", health_override=False, changed=False):
        config = {"name": "test", "services": {"router": {"image": "candidate", "entrypoint": entrypoint}}}
        if health_override:
            config["services"]["router"]["healthcheck"] = {"disable": True}
        env = self.env.copy()
        if enabled:
            env.update(FOUNDRY_MI_DIR=str(self.directory), FOUNDRY_MI_SHA256=self.digest,
                       FOUNDRY_MI_IMAGE_ID=self.image_id)
        if image is None:
            image = {"Id": self.image_id, "Config": {"Healthcheck": {"Test": ["CMD", "probe"]}}}
        stages, overrides = [], []
        validate_mi = local_tls_up.validate_mi
        def validate_input(directory, digest):
            stages.append("validate_mi")
            self.assertEqual((str(self.directory), self.digest), (directory, digest))
            if changed and stages.count("validate_mi") == 2:
                raise ValueError("changed MI input")
            validate_mi(directory, digest)
        def check_project(project, rendered):
            stages.append("project")
            self.assertEqual(("test", config), (project, rendered))
            return False
        def run(args, **kwargs):
            if args[:2] == ["docker", "compose"] and args[-4:] == ["config", "--format", "json", "--no-path-resolution"]:
                stages.append("config")
                return subprocess.CompletedProcess(args, 0, stdout=json.dumps(config).encode())
            if args == ["docker", "image", "inspect", "candidate"]:
                stages.append("inspect")
                return subprocess.CompletedProcess(args, 0, stdout=json.dumps([image]).encode())
            if args[:2] == ["docker", "compose"] and "up" in args:
                stages.append("up")
                path = args[args.index("-f", args.index("-f") + 1) + 1]
                overrides.append(json.loads(Path(path).read_text()))
                self.assertEqual(["up", "-d", "--no-build", "--pull", "never"] +
                                 (["--force-recreate", "--wait", "--wait-timeout", "60"] if enabled else []),
                                 args[args.index("up"):])
                if enabled:
                    self.assertEqual(90, kwargs["timeout"])
                if wait == "timeout":
                    raise subprocess.TimeoutExpired(args, 90)
                return subprocess.CompletedProcess(args, 1 if wait == "failure" else 0)
            self.fail(f"unexpected subprocess: {args!r}")
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(local_tls_up, "validate"), \
             mock.patch.object(local_tls_up, "validate_mi", side_effect=validate_input), \
             mock.patch.object(local_tls_up, "check_project", side_effect=check_project), \
             mock.patch.object(local_tls_up.subprocess, "run", side_effect=run):
            result = local_tls_up.main()
        return result, stages, overrides

    def expected_override(self, enabled):
        router = {"command": ["--host=0.0.0.0", "--port=8787", "--data-dir=/data",
                  "--tls-certfile=/run/foundry/tls/server.crt", "--tls-keyfile=/run/foundry/tls/server.key",
                  "--tls-reload-hostname=127.0.0.1", "--worker-listen-host=0.0.0.0", "--worker-listen-port=8790",
                  "--worker-tls-certfile=/run/foundry/tls/server.crt", "--worker-tls-keyfile=/run/foundry/tls/server.key",
                  "--worker-tls-reload-hostname=127.0.0.1", "--tls-reload-ca-cert=/run/foundry/tls/server.crt",
                  "--worker-tls-reload-ca-cert=/run/foundry/tls/server.crt"],
                  "environment": {"SR_HEALTHCHECK_URL": "https://127.0.0.1:8787/healthz",
                                  "SR_HEALTHCHECK_CA": "/run/foundry/tls/server.crt"},
                  "extra_hosts": ["127.0.0.1:127.0.0.1"], "group_add": [str(os.getegid())],
                  "volumes": [{"type": "bind", "source": str(self.tls), "target": "/run/foundry/tls",
                               "read_only": True, "bind": {"create_host_path": False}}]}
        if enabled:
            router["command"].append("--mi-config=/run/foundry/mi/trust.json")
            router.update(image=self.image_id, restart="no")
            router["volumes"] += [{"type": "bind", "source": str(self.directory / name),
                                   "target": "/run/foundry/mi/" + name, "read_only": True,
                                   "bind": {"create_host_path": False}}
                                  for name in ("trust.json", "publication.json")]
        return {"services": {"router": router}}

    def test_reference_and_file_protection(self):
        self.check()
        with self.assertRaises(ValueError):
            self.check("0" * 64)
        self.publication.write_bytes(b"replacement")
        with self.assertRaises(ValueError):
            self.check()
        self.publication.write_bytes(b"synthetic publication")
        self.trust.chmod(0o644)
        with self.assertRaises(ValueError):
            self.check()
        self.trust.chmod(0o640)
        self.trust.unlink()
        self.trust.symlink_to(self.publication)
        with self.assertRaises(OSError):
            self.check()

    def test_duplicate_keys_and_external_publication_rejected(self):
        for body in ('{"publication":"/run/foundry/mi/publication.json","publication":"x"}',
                     json.dumps({"publication": "/tmp/publication.json", "reference": {"sha256": self.digest}})):
            self.trust.write_text(body)
            with self.assertRaises(ValueError):
                self.check()

    def test_hard_linked_publication_rejected(self):
        self.check()
        os.link(self.publication, Path(self.temp.name) / "publication-link")
        with self.assertRaises(ValueError):
            self.check()

    def test_trust_size_limit(self):
        body = self.trust.read_bytes()
        self.trust.write_bytes(body + b" " * (256 * 1024 - len(body)))
        self.check()
        with self.trust.open("ab") as stream:
            stream.write(b" ")
        with self.assertRaises(ValueError):
            self.check()

    def test_opt_in_override_only_and_default_unchanged(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                result, stages, overrides = self.startup(enabled=enabled)
                self.assertEqual(0, result)
                self.assertEqual((["validate_mi"] if enabled else []) + ["config"] +
                                 (["inspect", "validate_mi"] if enabled else []) + ["project", "up"], stages)
                self.assertEqual([self.expected_override(enabled)], overrides)

    def test_mi_wait_failure_and_timeout_refuse(self):
        for wait in ("ok", "failure", "timeout"):
            with self.subTest(wait=wait):
                result, stages, overrides = self.startup(wait=wait)
                self.assertEqual(0 if wait == "ok" else 1, result)
                self.assertEqual(["validate_mi", "config", "inspect", "validate_mi", "project", "up"], stages)
                self.assertEqual([self.expected_override(True)], overrides)

    def test_rejects_wrong_image_or_missing_healthcheck(self):
        for image in ({"Id": self.image_id, "Config": {"Healthcheck": {"Test": ["CMD", "probe"]}}},
                      {"Id": "sha256:" + "b" * 64, "Config": {"Healthcheck": {"Test": ["CMD", "probe"]}}},
                      {"Id": self.image_id, "Config": {}},
                      {"Id": self.image_id, "Config": {"Healthcheck": {"Test": []}}},
                      {"Id": self.image_id, "Config": {"Healthcheck": {"Test": ["NONE"]}}},
                      {"Id": self.image_id, "Config": {"Healthcheck": {"Test": "CMD probe"}}},
                      {"Id": self.image_id, "Config": {"Healthcheck": {"Test": ["CMD"]}}}):
            valid = image == {"Id": self.image_id, "Config": {"Healthcheck": {"Test": ["CMD", "probe"]}}}
            with self.subTest(image=image):
                result, stages, overrides = self.startup(image=image)
                self.assertEqual(0 if valid else 1, result)
                self.assertEqual(["validate_mi", "config", "inspect"] +
                                 (["validate_mi", "project", "up"] if valid else []), stages)
                self.assertEqual([self.expected_override(True)] if valid else [], overrides)

    def test_entrypoint_rejection(self):
        for entrypoint in (None, [], "", ["other"]):
            with self.subTest(entrypoint=entrypoint):
                result, stages, overrides = self.startup(entrypoint=entrypoint)
                self.assertEqual(0 if entrypoint is None else 1, result)
                self.assertEqual(["validate_mi", "config", "inspect"] +
                                 (["validate_mi", "project", "up"] if entrypoint is None else []), stages)
                self.assertEqual([self.expected_override(True)] if entrypoint is None else [], overrides)

    def test_health_override_and_changed_mi_refused(self):
        result, stages, overrides = self.startup(health_override=True)
        self.assertEqual(1, result)
        self.assertEqual(["validate_mi", "config", "inspect"], stages)
        self.assertEqual([], overrides)
        result, stages, overrides = self.startup(changed=True)
        self.assertEqual(1, result)
        self.assertEqual(["validate_mi", "config", "inspect", "validate_mi"], stages)
        self.assertEqual([], overrides)

    def require_compose(self, env):
        if not shutil.which("docker", path=env["PATH"]):
            self.skipTest("Docker CLI is unavailable")
        result = subprocess.run(["docker", "compose", "version"], env=env, capture_output=True, timeout=30)
        message = (result.stdout + result.stderr).decode(errors="replace").lower()
        if result.returncode and ("'compose' is not a docker command" in message or
                                  "unknown docker command: \"compose\"" in message or
                                  "unknown command: docker compose" in message):
            self.skipTest("Docker Compose plugin is unavailable in the isolated environment")
        self.assertEqual(0, result.returncode, message)

    def test_compose_gate_uses_invocation_environment(self):
        env = {"PATH": os.defpath, "HOME": self.temp.name}
        for code, output, exception in ((0, b"", None),
                                        (1, b"docker: 'compose' is not a docker command.", unittest.SkipTest),
                                        (1, b"unexpected error", AssertionError)):
            with self.subTest(output=output), mock.patch.object(shutil, "which", return_value="/usr/bin/docker") as which, \
                 mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], code, b"", output)) as run:
                if exception:
                    with self.assertRaises(exception):
                        self.require_compose(env)
                else:
                    self.require_compose(env)
                which.assert_called_once_with("docker", path=env["PATH"])
                run.assert_called_once_with(["docker", "compose", "version"], env=env, capture_output=True, timeout=30)

    def test_rendered_compose_null_entrypoint(self):
        root = Path(__file__).resolve().parents[1]
        env = {**self.env, "PATH": os.defpath, "HOME": self.temp.name,
               "FOUNDRY_ROUTER_IMAGE": "test-image", "FOUNDRY_ROUTER_HOST": "127.0.0.1",
               "FOUNDRY_TLS_DIR": str(self.tls), "LOCAL_TLS_PROJECT": "test", "TLS_DEST": str(self.tls),
               "FOUNDRY_MI_DIR": str(self.directory), "FOUNDRY_MI_SHA256": self.digest,
               "FOUNDRY_MI_IMAGE_ID": self.image_id}
        self.require_compose(env)
        rendered = subprocess.run(["docker", "compose", "-p", "test", "--env-file", "/dev/null",
                                   "-f", "compose.yaml", "config", "--format", "json", "--no-path-resolution"],
                                  cwd=root, env=env, capture_output=True, check=True, timeout=30)
        config = json.loads(rendered.stdout)
        router = config["services"]["router"]
        self.assertIsNone(router.get("entrypoint"))

    def test_compose_preserves_literal_dollar_bind_sources(self):
        root = Path(__file__).resolve().parents[1]
        for suffix in ("$NAME", "${NAME}"):
            mi_dir = str(self.directory / suffix)
            env = {**self.env, "PATH": os.defpath, "HOME": self.temp.name}
            env.update(FOUNDRY_ROUTER_IMAGE="test-image", FOUNDRY_ROUTER_HOST="127.0.0.1",
                        FOUNDRY_TLS_DIR=str(self.tls), LOCAL_TLS_PROJECT="test", TLS_DEST=str(self.tls),
                       FOUNDRY_MI_DIR=mi_dir, FOUNDRY_MI_SHA256=self.digest,
                       FOUNDRY_MI_IMAGE_ID=self.image_id, NAME="interpolated")
            if suffix == "$NAME":
                self.require_compose(env)
            rendered = subprocess.run(["docker", "compose", "-p", "test", "--env-file", "/dev/null",
                                       "-f", "compose.yaml", "config", "--format", "json", "--no-path-resolution"],
                                      cwd=root, env=env, capture_output=True, check=True, timeout=30)
            config = json.loads(rendered.stdout)
            overrides, stages = [], []
            def run(args, **kwargs):
                if args[:2] == ["docker", "compose"] and args[-4:] == ["config", "--format", "json", "--no-path-resolution"]:
                    stages.append("config")
                    return subprocess.CompletedProcess(args, 0, stdout=json.dumps(config).encode())
                if args == ["docker", "image", "inspect", config["services"]["router"]["image"]]:
                    stages.append("inspect")
                    return subprocess.CompletedProcess(args, 0, stdout=json.dumps([{"Id": self.image_id, "Config": {"Healthcheck": {"Test": ["CMD", "probe"]}}}]).encode())
                self.assertEqual(["docker", "compose"], args[:2])
                self.assertIn("up", args)
                self.assertEqual(["up", "-d", "--no-build", "--pull", "never", "--force-recreate", "--wait", "--wait-timeout", "60"], args[args.index("up"):])
                self.assertEqual(90, kwargs["timeout"])
                stages.append("up")
                override = args[args.index("-f", args.index("-f") + 1) + 1]
                overrides.append(Path(override).read_text())
                return subprocess.CompletedProcess(args, 0)
            with self.subTest(suffix=suffix), mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch.object(local_tls_up, "validate"), mock.patch.object(local_tls_up, "validate_mi"), \
                 mock.patch.object(local_tls_up, "check_project", return_value=False), \
                 mock.patch.object(local_tls_up.subprocess, "run", side_effect=run):
                self.assertEqual(0, local_tls_up.main())
            self.assertEqual(["config", "inspect", "up"], stages)
            self.assertEqual(1, len(overrides))
            with tempfile.TemporaryDirectory() as tmp:
                override = Path(tmp) / "override.json"
                override.write_text(overrides[0])
                merged = subprocess.run(["docker", "compose", "-p", "test", "--env-file", "/dev/null",
                                         "-f", "compose.yaml", "-f", str(override), "config", "--format", "json", "--no-path-resolution"],
                                        cwd=root, env=env, capture_output=True, check=True, timeout=30)
            mounts = json.loads(merged.stdout)["services"]["router"]["volumes"]
            sources = {m["target"]: m["source"] for m in mounts}
            for name in ("trust.json", "publication.json"):
                # Compose escapes literal dollars again when rendering its reusable config.
                rendered_source = sources["/run/foundry/mi/" + name]
                self.assertEqual(os.path.join(mi_dir, name).replace("$", "$$"), rendered_source)
                self.assertEqual(os.path.join(mi_dir, name), rendered_source.replace("$$", "$"))

    @unittest.skipUnless(shutil.which("make"), "GNU Make is unavailable")
    def test_make_exports_literal_dollar_paths(self):
        root = Path(__file__).resolve().parents[1]
        recipe = "mi-env-test: ; @python3 -c 'import os; print(os.environ[\"FOUNDRY_MI_DIR\"])'"
        env = {key: value for key, value in os.environ.items()
               if key not in ("FOUNDRY_MI_DIR", "MAKEFLAGS", "MFLAGS", "MAKEOVERRIDES")}
        env["NAME"] = "interpolated"
        for suffix in ("$NAME", "${NAME}"):
            literal = "/tmp/" + suffix
            for command_line in (False, True):
                run_env = env.copy()
                args = ["make", "--no-print-directory", "--eval", recipe, "mi-env-test"]
                if command_line:
                    args.append("FOUNDRY_MI_DIR=" + literal.replace("$", "$$"))
                else:
                    run_env["FOUNDRY_MI_DIR"] = literal
                with self.subTest(suffix=suffix, command_line=command_line):
                    result = subprocess.run(args, cwd=root, env=run_env, capture_output=True,
                                            text=True, check=True, timeout=30)
                    self.assertEqual(literal, result.stdout.strip())

if __name__ == "__main__":
    unittest.main()
