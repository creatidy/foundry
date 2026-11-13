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
        config = {"name": "test", "services": {"router": {
            "volumes": [{"type": "bind", "source": "/tls", "target": "/run/foundry/tls", "read_only": True}],
            "environment": {"SR_HEALTHCHECK_URL": "https://127.0.0.1:8787/healthz"},
            "image": "test-image", "command": ["--tls-reload-hostname=127.0.0.1"]}}}
        for enabled in (False, True):
            env = self.env.copy()
            if enabled:
                env.update(FOUNDRY_MI_DIR=str(self.directory), FOUNDRY_MI_SHA256=self.digest,
                           FOUNDRY_MI_IMAGE_ID=self.image_id)
            captured = []
            def run(args, **kwargs):
                if "config" in args:
                    return subprocess.CompletedProcess(args, 0, stdout=json.dumps(config).encode())
                if args[:3] == ["docker", "image", "inspect"]:
                    return subprocess.CompletedProcess(args, 0, stdout=json.dumps([{"Id": self.image_id, "Config": {"Healthcheck": {"Test": ["CMD", "probe"]}}}]).encode())
                path = args[args.index("-f", args.index("-f") + 1) + 1]
                captured.append(json.loads(Path(path).read_text()))
                return subprocess.CompletedProcess(args, 0)
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(local_tls_up, "validate"), \
                 mock.patch.object(local_tls_up, "check_project", return_value=False), \
                 mock.patch.object(local_tls_up.subprocess, "run", side_effect=run):
                self.assertEqual(0, local_tls_up.main())
            router = captured[0]["services"]["router"]
            self.assertEqual(enabled, "--mi-config=/run/foundry/mi/trust.json" in router["command"])
            self.assertEqual({"/run/foundry/tls"} | ({"/run/foundry/mi/trust.json", "/run/foundry/mi/publication.json"} if enabled else set()),
                             {mount["target"] for mount in router["volumes"]})
            if enabled:
                self.assertEqual(self.image_id, router["image"])
                self.assertEqual("no", router["restart"])
                self.assertEqual({"/run/foundry/tls", "/run/foundry/mi/trust.json", "/run/foundry/mi/publication.json"},
                                 {mount["target"] for mount in router["volumes"]})
                for mount in router["volumes"]:
                    self.assertTrue(mount["read_only"])
                    self.assertFalse(mount["bind"]["create_host_path"])

    def test_mi_wait_failure_and_timeout_refuse(self):
        config = {"name": "test", "services": {"router": {
            "volumes": [{"type": "bind", "source": "/tls", "target": "/run/foundry/tls", "read_only": True}],
            "environment": {"SR_HEALTHCHECK_URL": "https://127.0.0.1:8787/healthz"},
            "image": "test-image", "command": ["--tls-reload-hostname=127.0.0.1"]}}}
        env = {**self.env,
               "FOUNDRY_MI_DIR": str(self.directory), "FOUNDRY_MI_SHA256": self.digest,
               "FOUNDRY_MI_IMAGE_ID": self.image_id}
        for timeout in (False, True):
            def run(args, **kwargs):
                if "config" in args:
                    return subprocess.CompletedProcess(args, 0, stdout=json.dumps(config).encode())
                if args[:3] == ["docker", "image", "inspect"]:
                    return subprocess.CompletedProcess(args, 0, stdout=json.dumps([{"Id": self.image_id, "Config": {"Healthcheck": {"Test": ["CMD", "probe"]}}}]).encode())
                self.assertIn("--wait", args)
                self.assertIn("--force-recreate", args)
                self.assertEqual("60", args[args.index("--wait-timeout") + 1])
                self.assertEqual(90, kwargs["timeout"])
                if timeout:
                    raise subprocess.TimeoutExpired(args, 90)
                return subprocess.CompletedProcess(args, 1)
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(local_tls_up, "validate"), \
                 mock.patch.object(local_tls_up, "check_project", return_value=False), \
                 mock.patch.object(local_tls_up.subprocess, "run", side_effect=run):
                self.assertNotEqual(0, local_tls_up.main())

    def test_rejects_wrong_image_or_missing_healthcheck(self):
        config = {"name": "test", "services": {"router": {"image": "candidate"}}}
        env = {**self.env, "FOUNDRY_MI_DIR": str(self.directory),
               "FOUNDRY_MI_SHA256": self.digest, "FOUNDRY_MI_IMAGE_ID": self.image_id}
        for image in ({"Id": "sha256:" + "b" * 64, "Config": {"Healthcheck": {"Test": ["CMD", "probe"]}}},
                      {"Id": self.image_id, "Config": {}},
                      {"Id": self.image_id, "Config": {"Healthcheck": {"Test": []}}}):
            def run(args, **kwargs):
                output = config if "config" in args else [image]
                return subprocess.CompletedProcess(args, 0, stdout=json.dumps(output).encode())
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(local_tls_up, "validate"), \
                 mock.patch.object(local_tls_up.subprocess, "run", side_effect=run):
                self.assertNotEqual(0, local_tls_up.main())

    @unittest.skipUnless(shutil.which("docker"), "Docker Compose is unavailable")
    def test_rendered_compose_null_entrypoint_and_override_rejection(self):
        root = Path(__file__).resolve().parents[1]
        env = {**os.environ, "FOUNDRY_ROUTER_IMAGE": "test-image", "FOUNDRY_ROUTER_HOST": "127.0.0.1",
               "FOUNDRY_TLS_DIR": str(self.tls), "LOCAL_TLS_PROJECT": "test", "TLS_DEST": str(self.tls),
               "FOUNDRY_MI_DIR": str(self.directory), "FOUNDRY_MI_SHA256": self.digest,
               "FOUNDRY_MI_IMAGE_ID": self.image_id}
        rendered = subprocess.run(["docker", "compose", "-p", "test", "--env-file", "/dev/null",
                                   "-f", "compose.yaml", "config", "--format", "json", "--no-path-resolution"],
                                  cwd=root, env=env, capture_output=True, check=True, timeout=30)
        config = json.loads(rendered.stdout)
        router = config["services"]["router"]
        self.assertIsNone(router.get("entrypoint"))
        for entrypoint, expected in ((None, 0), ([], 1), ("", 1), (["other"], 1)):
            router["entrypoint"] = entrypoint
            def run(args, **kwargs):
                if "config" in args:
                    return subprocess.CompletedProcess(args, 0, stdout=json.dumps(config).encode())
                if args[:3] == ["docker", "image", "inspect"]:
                    return subprocess.CompletedProcess(args, 0, stdout=json.dumps([{"Id": self.image_id, "Config": {"Healthcheck": {"Test": ["CMD", "probe"]}}}]).encode())
                return subprocess.CompletedProcess(args, 0)
            with self.subTest(entrypoint=entrypoint), mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch.object(local_tls_up, "validate"), mock.patch.object(local_tls_up, "check_project", return_value=False), \
                 mock.patch.object(local_tls_up.subprocess, "run", side_effect=run):
                self.assertEqual(expected, local_tls_up.main())

    @unittest.skipUnless(shutil.which("docker"), "Docker Compose is unavailable")
    def test_compose_preserves_literal_dollar_bind_sources(self):
        root = Path(__file__).resolve().parents[1]
        for suffix in ("$NAME", "${NAME}"):
            mi_dir = str(self.directory / suffix)
            env = {key: value for key, value in os.environ.items() if not key.startswith("COMPOSE_")}
            env.update(FOUNDRY_ROUTER_IMAGE="test-image", FOUNDRY_ROUTER_HOST="127.0.0.1",
                        FOUNDRY_TLS_DIR=str(self.tls), LOCAL_TLS_PROJECT="test", TLS_DEST=str(self.tls),
                       FOUNDRY_MI_DIR=mi_dir, FOUNDRY_MI_SHA256=self.digest,
                       FOUNDRY_MI_IMAGE_ID=self.image_id, NAME="interpolated")
            rendered = subprocess.run(["docker", "compose", "-p", "test", "--env-file", "/dev/null",
                                       "-f", "compose.yaml", "config", "--format", "json", "--no-path-resolution"],
                                      cwd=root, env=env, capture_output=True, check=True, timeout=30)
            config = json.loads(rendered.stdout)
            overrides = []
            def run(args, **kwargs):
                if "config" in args:
                    return subprocess.CompletedProcess(args, 0, stdout=json.dumps(config).encode())
                if args[:3] == ["docker", "image", "inspect"]:
                    return subprocess.CompletedProcess(args, 0, stdout=json.dumps([{"Id": self.image_id, "Config": {"Healthcheck": {"Test": ["CMD", "probe"]}}}]).encode())
                override = args[args.index("-f", args.index("-f") + 1) + 1]
                overrides.append(Path(override).read_text())
                return subprocess.CompletedProcess(args, 0)
            with self.subTest(suffix=suffix), mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch.object(local_tls_up, "validate"), mock.patch.object(local_tls_up, "validate_mi"), \
                 mock.patch.object(local_tls_up, "check_project", return_value=False), \
                 mock.patch.object(local_tls_up.subprocess, "run", side_effect=run):
                self.assertEqual(0, local_tls_up.main())
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
