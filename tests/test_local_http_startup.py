"""Pure Python startup contract tests; every subprocess is mocked."""

import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import local_tls_up
import tls_check


LOCAL_COMMAND = ["--host=0.0.0.0", "--port=8787", "--data-dir=/data",
                 "--local-container-http", "--worker-listen-host=0.0.0.0",
                 "--worker-listen-port=8790"]
DEFAULT_IMAGE = "foundry-sr-mi:5bd4fa4-local"
IMAGE_ID = "sha256:" + "a" * 64
INFO_COMMAND = ["docker", "info", "--format", "{{json .SecurityOptions}}"]
TLS_KEYS = ("TLS_DEST", "FOUNDRY_TLS_DIR", "FOUNDRY_ROUTER_HOST")
TLS_LABELS = {"org.creatidy.foundry." + key.lower(): "${" + key + "-}" for key in TLS_KEYS}
CONFIG_TAIL = ["config", "--format", "json", "--no-path-resolution"]


def is_projection(args):
    return len(args) >= 6 and args[-6] == "-f" and Path(args[-5]).name == "settings.json" and args[-4:] == CONFIG_TAIL


def projection_result(args, values=None):
    if not is_projection(args) or json.loads(Path(args[-5]).read_text()) != {
            "services": {"router": {"labels": TLS_LABELS}}}:
        raise AssertionError("expected only three TLS projection labels")
    values = os.environ if values is None else values
    labels = {"org.creatidy.foundry." + key.lower(): values.get(key, "").replace("$", "$$") for key in TLS_KEYS}
    output = json.dumps({"services": {"router": {"labels": labels}}}).encode()
    return subprocess.CompletedProcess(args, 0, stdout=output)


class LocalHTTPStartupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "mi$literal"
        self.directory.mkdir(mode=0o750)
        self.publication = self.directory / "publication.json"
        self.publication.write_bytes(b"synthetic offline publication")
        self.digest = hashlib.sha256(self.publication.read_bytes()).hexdigest()
        self.trust = self.directory / "trust.json"
        self.trust.write_text(json.dumps({"publication": "/run/foundry/mi/publication.json",
                                          "reference": {"sha256": self.digest}}))
        for path in (self.publication, self.trust):
            path.chmod(0o640)
        self.config = {"name": "foundry", "services": {"router": {
            "image": DEFAULT_IMAGE, "command": LOCAL_COMMAND.copy()}}}
        self.images = [{"Id": IMAGE_ID, "Config": {
            "Healthcheck": {"Test": ["CMD", "probe"]}}}]
        self.base = ["docker", "compose", "-f", "compose.yaml"]
        self.overrides = []
        self.stages = []
        self.failure_stage = None
        self.failure = None
        self.after_inspect = None
        self.security_options = ["name=seccomp,profile=builtin"]
        self.projection_output = None
        self.settings_paths = []
        self.stderr = io.StringIO()
        patches = (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(local_tls_up.os.path, "isfile", return_value=False),
            mock.patch.object(local_tls_up, "validate", side_effect=AssertionError("TLS validation in HTTP mode")),
            mock.patch.object(subprocess, "Popen", side_effect=AssertionError("unmocked subprocess")),
            contextlib.redirect_stderr(self.stderr),
        )
        for patch in patches:
            patch.__enter__()
            self.addCleanup(patch.__exit__, None, None, None)
        self.run = self.enterContext(mock.patch.object(subprocess, "run", side_effect=self.fake_run))

    def fake_run(self, args, **kwargs):
        if is_projection(args):
            self.assertEqual(self.base + ["-f"], args[:-5])
            self.settings_paths.append(Path(args[-5]))
            stage = "environment"
            output = projection_result(args).stdout if self.projection_output is None else self.projection_output
            self.assertEqual({"check": True, "capture_output": True, "timeout": 30}, kwargs)
        elif args == self.base + ["config", "--format", "json"]:
            stage, output = "config", self.config
            self.assertEqual(30, kwargs["timeout"])
        elif args == self.base + ["build", "router"]:
            stage, output = "build", None
            self.assertEqual(900, kwargs["timeout"])
        elif args == ["docker", "image", "inspect", self.config["services"]["router"]["image"]]:
            stage, output = "inspect", self.images
            self.assertEqual(30, kwargs["timeout"])
            if self.after_inspect:
                self.after_inspect()
        elif args == INFO_COMMAND:
            stage, output = "info", self.security_options
            self.assertEqual(20, kwargs["timeout"])
            self.assertTrue(kwargs["capture_output"])
        else:
            self.assertEqual(self.base + ["-f"], args[:len(self.base) + 1])
            for path in self.settings_paths:
                self.assertNotIn(str(path), args)
                self.assertFalse(path.exists())
            expected = ["up", "-d", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "60"]
            if os.environ.get("FOUNDRY_MI_DIR"):
                expected.append("--force-recreate")
            self.assertEqual(expected, args[len(self.base) + 2:])
            self.assertEqual(90, kwargs["timeout"])
            self.overrides.append(json.loads(Path(args[len(self.base) + 1]).read_text()))
            stage, output = "up", None
        self.stages.append(stage)
        if stage == self.failure_stage:
            if isinstance(self.failure, BaseException):
                raise self.failure
            return subprocess.CompletedProcess(args, self.failure)
        if stage != "up":
            self.assertTrue(kwargs["check"])
        return subprocess.CompletedProcess(args, 0, stdout=output if isinstance(output, bytes)
                                           else json.dumps(output).encode())

    def enable_mi(self, *, image=True):
        os.environ.update(FOUNDRY_MI_DIR=str(self.directory), FOUNDRY_MI_SHA256=self.digest)
        if image:
            os.environ["FOUNDRY_MI_IMAGE_ID"] = IMAGE_ID

    def assert_refused(self):
        self.assertEqual(1, local_tls_up.local_http_main())
        self.assertNotIn("up", self.stages)
        self.assertEqual([], self.overrides)
        self.assertIn("Local HTTP startup not confirmed", self.stderr.getvalue())
        self.assertTrue(all(not path.exists() for path in self.settings_paths))

    def test_default_builds_once_and_resolves_id_without_manual_hash(self):
        self.assertEqual(0, local_tls_up.local_http_main())
        self.assertEqual(["environment", "config", "build", "inspect", "up"], self.stages)
        self.assertEqual({"services": {"router": {"image": IMAGE_ID}}}, self.overrides[0])
        self.assertEqual(LOCAL_COMMAND, self.config["services"]["router"]["command"])
        self.assertFalse(any(arg.startswith("--tls-") for arg in LOCAL_COMMAND))

    def test_custom_image_uses_inspected_id_without_build(self):
        self.config["services"]["router"]["image"] = "operator/router:custom"
        self.images[0]["Config"]["Healthcheck"]["Test"] = ["CMD-SHELL", "probe"]
        self.assertEqual(0, local_tls_up.local_http_main())
        self.assertEqual(["environment", "config", "inspect", "up"], self.stages)
        self.assertEqual(IMAGE_ID, self.overrides[0]["services"]["router"]["image"])

    def test_optional_env_file_is_passed_to_every_compose_command(self):
        self.base = ["docker", "compose", "--env-file", ".env", "-f", "compose.yaml"]
        with mock.patch.object(local_tls_up.os.path, "isfile", return_value=True):
            self.assertEqual(0, local_tls_up.local_http_main())
        self.assertEqual(["environment", "config", "build", "inspect", "up"], self.stages)

    def test_partial_mi_inputs_refuse_before_build_or_inspect(self):
        for env in ({"FOUNDRY_MI_DIR": str(self.directory)},
                    {"FOUNDRY_MI_SHA256": self.digest},
                    {"FOUNDRY_MI_IMAGE_ID": IMAGE_ID},
                    {"FOUNDRY_MI_DIR": str(self.directory), "FOUNDRY_MI_IMAGE_ID": IMAGE_ID},
                    {"FOUNDRY_MI_SHA256": self.digest, "FOUNDRY_MI_IMAGE_ID": IMAGE_ID}):
            with self.subTest(keys=sorted(env)), mock.patch.dict(os.environ, env, clear=True):
                self.stages.clear()
                self.assert_refused()
                self.assertEqual(["environment", "config"], self.stages)

    def test_mi_has_exactly_two_read_only_file_binds_and_no_restart(self):
        for independent_image, options, group in (
                (False, ["name=seccomp,profile=builtin"], str(os.getegid())),
                (True, ["name=seccomp,profile=builtin", "name=rootless"], "0")):
            with self.subTest(independent_image=independent_image, options=options):
                self.enable_mi(image=independent_image)
                self.security_options = options
                self.overrides.clear()
                self.stages.clear()
                with mock.patch.object(local_tls_up, "validate_mi", wraps=local_tls_up.validate_mi) as validate:
                    self.assertEqual(0, local_tls_up.local_http_main())
                self.assertEqual(["environment", "config", "build", "inspect", "info", "up"], self.stages)
                self.assertEqual([mock.call(str(self.directory), self.digest)] * 2, validate.call_args_list)
                router = self.overrides[0]["services"]["router"]
                self.assertEqual(IMAGE_ID, router["image"])
                self.assertEqual("no", router["restart"])
                self.assertEqual([group], router["group_add"])
                self.assertEqual(LOCAL_COMMAND + ["--mi-config=/run/foundry/mi/trust.json"], router["command"])
                self.assertEqual([
                    {"type": "bind", "source": str(self.directory / name).replace("$", "$$"),
                     "target": "/run/foundry/mi/" + name, "read_only": True,
                     "bind": {"create_host_path": False}}
                    for name in ("trust.json", "publication.json")], router["volumes"])
                self.assertEqual(LOCAL_COMMAND, self.config["services"]["router"]["command"])

    def test_mi_reference_failures_refuse_before_build(self):
        self.enable_mi()
        valid_trust = self.trust.read_text()
        for body in (
                {"publication": "/elsewhere/publication.json", "reference": {"sha256": self.digest}},
                {"publication": "/run/foundry/mi/publication.json", "reference": {"sha256": "b" * 64}},
                {"publication": "/run/foundry/mi/publication.json", "reference": {}},
        ):
            with self.subTest(trust=body):
                self.trust.write_text(json.dumps(body))
                self.stages.clear()
                self.assert_refused()
                self.assertEqual(["environment", "config"], self.stages)
        self.trust.write_text(valid_trust)
        self.publication.write_bytes(b"changed publication")
        self.stages.clear()
        self.assert_refused()
        self.assertEqual(["environment", "config"], self.stages)

    def test_mi_changed_before_mount_is_revalidated(self):
        self.enable_mi()
        self.after_inspect = lambda: self.publication.write_bytes(b"changed after image inspection")
        self.assert_refused()
        self.assertEqual(["environment", "config", "build", "inspect", "info"], self.stages)

    def test_mi_invalid_docker_security_options_refuse_before_mount(self):
        self.enable_mi()
        for options in (None, {}, "name=rootless", ["name=rootless", 0], b"not-json"):
            with self.subTest(options=options):
                self.security_options = options
                self.stages.clear()
                self.assert_refused()
                self.assertEqual(["environment", "config", "build", "inspect", "info"], self.stages)

    def test_mi_image_mismatch_refuses_without_startup(self):
        self.enable_mi()
        for expected in ("sha256:" + "b" * 64, "not-an-image-id"):
            with self.subTest(expected=expected):
                os.environ["FOUNDRY_MI_IMAGE_ID"] = expected
                self.stages.clear()
                self.assert_refused()

    def test_invalid_image_identity_refuses(self):
        valid = copy.deepcopy(self.images[0])
        for images in ([], [valid, valid], [{**valid, "Id": "tag:mutable"}],
                       [{**valid, "Id": "sha256:" + "A" * 64}], [{"Config": valid["Config"]}]):
            with self.subTest(images=images):
                self.images = images
                self.stages.clear()
                self.assert_refused()

    def test_image_health_contract_required(self):
        self.enable_mi()
        for health in (None, [], "probe", ["NONE"], ["CMD"], ["NONE", "probe"]):
            with self.subTest(health=health):
                self.images[0]["Config"] = {} if health is None else {"Healthcheck": {"Test": health}}
                self.stages.clear()
                self.assert_refused()

    def test_compose_health_or_entrypoint_override_refuses(self):
        for override in ({"healthcheck": {}}, {"healthcheck": {"disable": True}},
                         {"entrypoint": []}, {"entrypoint": ""}, {"entrypoint": ["other"]}):
            with self.subTest(override=override):
                router = self.config["services"]["router"]
                router.pop("healthcheck", None)
                router.pop("entrypoint", None)
                router.update(override)
                self.stages.clear()
                self.assert_refused()

    def test_tls_settings_refuse_http_before_any_subprocess(self):
        for key in ("TLS_DEST", "FOUNDRY_TLS_DIR", "FOUNDRY_ROUTER_HOST"):
            with self.subTest(key=key), mock.patch.dict(os.environ, {key: "explicit-tls"}):
                self.assert_refused()
        self.run.assert_not_called()

    def test_dotenv_only_tls_refuses_http_before_build_image_or_up(self):
        self.base = ["docker", "compose", "--env-file", ".env", "-f", "compose.yaml"]
        for key in ("TLS_DEST", "FOUNDRY_TLS_DIR", "FOUNDRY_ROUTER_HOST"):
            with self.subTest(key=key), mock.patch.object(local_tls_up.os.path, "isfile", return_value=True):
                self.assertNotIn(key, os.environ)
                self.projection_output = json.dumps({"services": {"router": {"labels": {
                    name: "dotenv-only-private-value" if name.endswith(key.lower()) else ""
                    for name in TLS_LABELS}}}}).encode()
                self.stages.clear()
                self.run.reset_mock()
                self.assert_refused()
                self.assertEqual(["environment"], self.stages)
                self.assertEqual(1, self.run.call_count)
                self.assertTrue(is_projection(self.run.call_args.args[0]))
                self.assertFalse(self.settings_paths[-1].exists())
                self.assertNotIn("dotenv-only-private-value", self.stderr.getvalue())

    def test_http_uses_compose_resolved_empty_tls_values(self):
        self.base = ["docker", "compose", "--env-file", ".env", "-f", "compose.yaml"]
        with mock.patch.object(local_tls_up.os.path, "isfile", return_value=True):
            self.assertEqual(0, local_tls_up.local_http_main())
        self.assertEqual(["environment", "config", "build", "inspect", "up"], self.stages)

    def test_unrelated_multiline_and_bash_function_environment_is_not_interpreted(self):
        ambient = {"UNRELATED": "first line\nFOUNDRY_TLS_DIR=not-a-setting\nthird=line",
                   "BASH_FUNC_foundry_probe%%": "() {  :;\n}\n"}
        with mock.patch.dict(os.environ, ambient):
            self.assertEqual(0, local_tls_up.local_http_main())
            self.assertEqual(ambient, dict(os.environ))
        self.assertEqual(["environment", "config", "build", "inspect", "up"], self.stages)

    def test_malformed_partial_or_nonstring_projection_refuses_http_without_disclosure(self):
        secret = "PRIVATE_COMPOSE_OUTPUT_123"
        labels = {name: "" for name in TLS_LABELS}
        outputs = (secret.encode(), json.dumps({"secret": secret}).encode(),
                   *[json.dumps({"secret": secret, "services": {"router": {"labels": value}}}).encode()
                     for value in (None, [], {}, {name: "" for name in labels if not name.endswith(".tls_dest")},
                                   {**labels, "org.creatidy.foundry.tls_dest": 7},
                                   {**labels, "org.creatidy.foundry.foundry_tls_dir": None})])
        for output in outputs:
            with self.subTest(output=output), contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.projection_output = output
                self.stages.clear()
                self.assert_refused()
                self.assertEqual(["environment"], self.stages)
                self.assertNotIn(secret, stdout.getvalue() + self.stderr.getvalue())

    def test_missing_local_mode_or_tls_command_refuses_without_fallback(self):
        for command in ([arg for arg in LOCAL_COMMAND if arg != "--local-container-http"],
                        LOCAL_COMMAND + ["--tls-certfile=/run/foundry/tls/server.crt"]):
            with self.subTest(command=command):
                self.config["services"]["router"]["command"] = command
                self.stages.clear()
                self.assert_refused()
                self.assertEqual(["environment", "config"], self.stages)

    def test_subprocess_failures_do_not_retry_or_fall_back(self):
        self.enable_mi()
        stages = ["environment", "config", "build", "inspect", "info", "up"]
        for stage in stages:
            for failure in (subprocess.CalledProcessError(1, "mock-command"),
                            subprocess.TimeoutExpired("mock-command", 30), OSError("mock failure")):
                with self.subTest(stage=stage, failure=type(failure).__name__):
                    self.failure_stage, self.failure = stage, failure
                    self.stages.clear()
                    self.overrides.clear()
                    self.assertEqual(1, local_tls_up.local_http_main())
                    self.assertEqual(stages[:stages.index(stage) + 1], self.stages)

    def test_wait_failure_return_code_is_not_success(self):
        self.failure_stage, self.failure = "up", 7
        self.assertEqual(7, local_tls_up.local_http_main())
        self.assertEqual(["environment", "config", "build", "inspect", "up"], self.stages)


class StartupDispatchAndTLSTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        # tls_override checks readability; cryptographic verification is a separate contract.
        for name in ("server.crt", "server.key"):
            (self.directory / name).write_text("synthetic, not a certificate")
        self.enterContext(mock.patch.dict(os.environ, {}, clear=True))
        self.enterContext(mock.patch.object(subprocess, "Popen", side_effect=AssertionError("unmocked subprocess")))
        self.run = self.enterContext(mock.patch.object(subprocess, "run", side_effect=self.fake_run))

    def fake_run(self, args, **kwargs):
        if is_projection(args):
            self.assertEqual({"check": True, "capture_output": True, "timeout": 30}, kwargs)
            return projection_result(args)
        raise AssertionError("unexpected subprocess: " + repr(args))

    def test_make_and_compose_select_local_http_without_tls(self):
        makefile = (ROOT / "Makefile").read_text()
        self.assertIn("up:\n\t@python3 scripts/local_tls_up.py --local-http\n", makefile)
        self.assertIn("tls-up:\n\t@python3 scripts/local_tls_up.py --tls\n", makefile)
        exports = {name for line in makefile.splitlines() if line.startswith("export ")
                   for name in line.split()[1:]}
        self.assertTrue(set(TLS_KEYS).isdisjoint(exports))
        compose = (ROOT / "compose.yaml").read_text()
        command = compose.split("    command:\n", 1)[1].split("    environment:\n", 1)[0]
        self.assertEqual(LOCAL_COMMAND, [line.strip()[2:] for line in command.splitlines()])
        self.assertIn("SR_HEALTHCHECK_URL: http://127.0.0.1:8787/healthz", compose)
        self.assertNotIn("/run/foundry/tls", compose)
        self.assertNotIn("--tls-", command)

    def test_local_http_dispatch_and_argparse_conflicts(self):
        with mock.patch.object(local_tls_up, "local_http_main", return_value=23) as local:
            self.assertEqual(23, local_tls_up.main(["--local-http"]))
            local.assert_called_once_with()
            local.reset_mock()
            for args in (["--local-http", "--tls"], ["--unknown"]):
                with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        local_tls_up.main(args)
                    self.assertEqual(2, error.exception.code)
            local.assert_not_called()
        self.run.assert_not_called()

    def test_tls_and_legacy_dispatch_never_fall_back_to_http(self):
        os.environ.update(LOCAL_TLS_PROJECT="test", TLS_DEST=str(self.directory),
                          FOUNDRY_TLS_DIR=str(self.directory), FOUNDRY_ROUTER_HOST="example.test")
        for args in ([], ["--tls"]):
            def run(command, **kwargs):
                if is_projection(command):
                    return projection_result(command)
                raise subprocess.CalledProcessError(1, "docker")

            with self.subTest(args=args), mock.patch.object(local_tls_up, "local_http_main") as local, \
                    mock.patch.object(local_tls_up, "validate", side_effect=ValueError("invalid TLS")) as validate, \
                    mock.patch.object(subprocess, "run", side_effect=run), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(1, local_tls_up.main(args))
                self.assertEqual(0 if args else 1, validate.call_count)
                local.assert_not_called()

    def test_advanced_tls_override_verifies_main_and_worker_without_local_mode(self):
        router = local_tls_up.tls_override(str(self.directory), "example.test")
        self.assertEqual([
            "--host=0.0.0.0", "--port=8787", "--data-dir=/data",
            "--tls-certfile=/run/foundry/tls/server.crt", "--tls-keyfile=/run/foundry/tls/server.key",
            "--tls-reload-hostname=example.test", "--worker-listen-host=0.0.0.0",
            "--worker-listen-port=8790", "--worker-tls-certfile=/run/foundry/tls/server.crt",
            "--worker-tls-keyfile=/run/foundry/tls/server.key", "--worker-tls-reload-hostname=example.test",
        ], router["command"])
        self.assertNotIn("--local-container-http", router["command"])
        self.assertEqual({"SR_HEALTHCHECK_URL": "https://example.test:8787/healthz"}, router["environment"])
        self.assertEqual([{"type": "bind", "source": str(self.directory), "target": "/run/foundry/tls",
                           "read_only": True, "bind": {"create_host_path": False}}], router["volumes"])
        self.assertEqual(["example.test:127.0.0.1"], router["extra_hosts"])
        self.assertEqual((self.directory, "example.test"), tls_check.router_identity({"services": {"router": router}}))
        self.run.assert_not_called()

    def test_local_leaf_tls_sets_both_reload_trust_anchors(self):
        router = local_tls_up.tls_override(str(self.directory), "127.0.0.1", leaf=True)
        for prefix in ("--tls-reload-ca-cert=", "--worker-tls-reload-ca-cert="):
            self.assertIn(prefix + "/run/foundry/tls/server.crt", router["command"])
        self.assertEqual("/run/foundry/tls/server.crt", router["environment"]["SR_HEALTHCHECK_CA"])
        self.assertNotIn("--local-container-http", router["command"])

    def test_mount_group_uses_only_exact_rootless_marker(self):
        for options, expected in (([], "4321"), (["name=seccomp,profile=builtin"], "4321"),
                                  (["name=rootless"], "0"), (["name=rootless-extra"], "4321")):
            with self.subTest(options=options), mock.patch.object(local_tls_up.os, "getegid", return_value=4321):
                self.run.side_effect = None
                self.run.return_value = subprocess.CompletedProcess(INFO_COMMAND, 0, stdout=json.dumps(options).encode())
                self.assertEqual(expected, local_tls_up.mount_group())
                self.run.assert_called_once_with(INFO_COMMAND, check=True, capture_output=True, timeout=20)
                self.run.reset_mock()

    def test_tls_startup_uses_detected_mount_group_after_offline_override(self):
        os.environ["LOCAL_TLS_PROJECT"] = "test"
        for argv in ([], ["--tls"]):
            for options, group in (([], "4321"), (["name=rootless"], "0")):
                with self.subTest(argv=argv, options=options):
                    hostname = "example.test" if argv else "127.0.0.1"
                    effective = {"TLS_DEST": str(self.directory), "FOUNDRY_TLS_DIR": str(self.directory),
                                 "FOUNDRY_ROUTER_HOST": hostname}
                    stages = []

                    def run(args, **kwargs):
                        if is_projection(args):
                            self.assertEqual(["docker", "compose", "-p", "test", "--env-file", ".env",
                                              "-f", "compose.yaml", "-f"], args[:-5])
                            stages.append("environment")
                            return projection_result(args, effective)
                        if "config" in args:
                            stages.append("config")
                            return subprocess.CompletedProcess(args, 0, stdout=b'{"name":"test","services":{"router":{}}}')
                        if args == INFO_COMMAND:
                            stages.append("info")
                            return subprocess.CompletedProcess(args, 0, stdout=json.dumps(options).encode())
                        self.assertIn("up", args)
                        stages.append("up")
                        path = args[args.index("-f", args.index("-f") + 1) + 1]
                        router = json.loads(Path(path).read_text())["services"]["router"]
                        self.assertEqual([group], router["group_add"])
                        self.assertNotIn("--local-container-http", router["command"])
                        return subprocess.CompletedProcess(args, 0)

                    with mock.patch.object(local_tls_up.os, "getegid", return_value=4321), \
                            mock.patch.object(local_tls_up, "validate") as validate, \
                            mock.patch.object(local_tls_up, "check_project", return_value=False), \
                            mock.patch.object(local_tls_up.os.path, "isfile", return_value=True), \
                            mock.patch.object(local_tls_up, "tls_override", wraps=local_tls_up.tls_override) as override:
                        def ordered_run(args, **kwargs):
                            if args == INFO_COMMAND:
                                override.assert_called_once()
                            return run(args, **kwargs)
                        self.run.side_effect = ordered_run
                        self.assertEqual(0, local_tls_up.main(argv))
                        override.assert_called_once_with(str(self.directory), hostname, leaf=not argv)
                        self.assertEqual([] if argv else [mock.call(str(self.directory))] * 2,
                                         validate.call_args_list)
                    self.assertEqual(["environment", "config", "info", "up"], stages)

    def test_tls_mount_group_failure_refuses_without_http_fallback(self):
        os.environ.update(LOCAL_TLS_PROJECT="test", FOUNDRY_TLS_DIR=str(self.directory),
                          FOUNDRY_ROUTER_HOST="example.test")
        failures = (None, {}, ["name=rootless", False], b"invalid-json",
                    subprocess.CalledProcessError(1, INFO_COMMAND),
                    subprocess.TimeoutExpired(INFO_COMMAND, 20), OSError("info unavailable"))
        for failure in failures:
            with self.subTest(failure=failure), mock.patch.object(local_tls_up, "local_http_main") as local, \
                    contextlib.redirect_stderr(io.StringIO()):
                calls = []

                def run(args, **kwargs):
                    calls.append(args)
                    if is_projection(args):
                        return projection_result(args)
                    if "config" in args:
                        return subprocess.CompletedProcess(args, 0, stdout=b'{"name":"test","services":{"router":{}}}')
                    self.assertEqual(INFO_COMMAND, args)
                    if isinstance(failure, BaseException):
                        raise failure
                    output = failure if isinstance(failure, bytes) else json.dumps(failure).encode()
                    return subprocess.CompletedProcess(args, 0, stdout=output)

                self.run.side_effect = run
                self.assertEqual(1, local_tls_up.main(["--tls"]))
                self.assertEqual(3, len(calls))
                local.assert_not_called()

    def test_offline_tls_config_does_not_query_mount_group(self):
        base = ["docker", "compose", "--env-file", ".env", "-f", "compose.yaml"]

        def run(args, **kwargs):
            if is_projection(args):
                self.assertEqual(base + ["-f"], args[:-5])
                return projection_result(args, {"FOUNDRY_TLS_DIR": str(self.directory),
                                                "FOUNDRY_ROUTER_HOST": "example.test"})
            self.assertEqual(base + ["-f"], args[:len(base) + 1])
            self.assertEqual(["config", "--format", "json", "--no-path-resolution"], args[len(base) + 2:])
            self.assertEqual(30, kwargs["timeout"])
            return subprocess.CompletedProcess(args, 0, stdout=Path(args[len(base) + 1]).read_bytes())

        self.run.side_effect = run
        with mock.patch.object(local_tls_up.os.path, "isfile", return_value=True), \
                mock.patch.object(local_tls_up, "mount_group", side_effect=AssertionError("offline group discovery")):
            config = local_tls_up.tls_config()
        self.assertEqual((self.directory, "example.test"), tls_check.router_identity(config))
        self.assertEqual(2, self.run.call_count)

    def test_tls_settings_delegates_precedence_to_compose_and_filters_values(self):
        os.environ.update(FOUNDRY_TLS_DIR="process-value", FOUNDRY_ROUTER_HOST="process.test")
        base = ["docker", "compose", "--env-file", ".env", "-f", "compose.yaml"]
        effective = {"TLS_DEST": "/effective/leaf", "FOUNDRY_TLS_DIR": "/effective/tls=literal",
                     "FOUNDRY_ROUTER_HOST": "effective.test", "UNRELATED": "not-returned"}
        paths = []

        def run(args, **kwargs):
            self.assertEqual(base + ["-f"], args[:-5])
            self.assertEqual({"check": True, "capture_output": True, "timeout": 30}, kwargs)
            paths.append(Path(args[-5]))
            return projection_result(args, effective)

        self.run.side_effect = run
        self.assertEqual({key: value for key, value in effective.items() if key != "UNRELATED"},
                         local_tls_up.tls_settings(base))
        self.assertEqual(1, self.run.call_count)
        self.assertEqual(1, len(paths))
        self.assertFalse(paths[0].exists())
        self.assertFalse(paths[0].parent.exists())
        self.assertEqual("process-value", os.environ["FOUNDRY_TLS_DIR"])

    def test_tls_projection_preserves_single_and_double_literal_dollars(self):
        for suffix in ("$NAME", "$$NAME"):
            with self.subTest(suffix=suffix):
                directory = self.directory / suffix
                directory.mkdir()
                for name in ("server.crt", "server.key"):
                    (directory / name).write_text("synthetic, not a certificate")
                effective = {"TLS_DEST": str(directory), "FOUNDRY_TLS_DIR": str(directory),
                             "FOUNDRY_ROUTER_HOST": "example.test"}
                paths = []

                def run(args, **kwargs):
                    paths.append(Path(args[-5]))
                    return projection_result(args, effective)

                self.run.side_effect = run
                settings = local_tls_up.tls_settings(["docker", "compose", "-f", "compose.yaml"])
                self.assertEqual(effective, settings)
                router = local_tls_up.tls_override(settings["FOUNDRY_TLS_DIR"], settings["FOUNDRY_ROUTER_HOST"])
                self.assertEqual(str(directory).replace("$", "$$"), router["volumes"][0]["source"])
                self.assertEqual(str(directory), router["volumes"][0]["source"].replace("$$", "$"))
                self.assertFalse(paths[0].exists())

    def test_malformed_partial_or_nonstring_projection_refuses_tls_without_disclosure(self):
        os.environ["LOCAL_TLS_PROJECT"] = "test"
        secret = "PRIVATE_COMPOSE_OUTPUT_456"
        for output in (secret.encode(), json.dumps({"secret": secret, "services": {"router": {"labels": {}}}}).encode(),
                       json.dumps({"secret": secret, "services": {"router": {"labels": {
                           name: [] for name in TLS_LABELS}}}}).encode()):
            for consumer in (lambda: local_tls_up.main([]), lambda: local_tls_up.main(["--tls"]), tls_check.main):
                with self.subTest(output=output, consumer=consumer), \
                        contextlib.redirect_stdout(io.StringIO()) as stdout, \
                        contextlib.redirect_stderr(io.StringIO()) as stderr, \
                        mock.patch.object(local_tls_up, "mount_group", side_effect=AssertionError("engine query")), \
                        mock.patch.object(local_tls_up, "validate", side_effect=AssertionError("TLS validation")):
                    self.run.reset_mock()
                    self.run.side_effect = None
                    self.run.return_value = subprocess.CompletedProcess([], 0, stdout=output)
                    self.assertEqual(1, consumer())
                    self.assertEqual(1, self.run.call_count)
                    self.assertTrue(is_projection(self.run.call_args.args[0]))
                    self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue())

    def test_router_identity_rejects_worker_conflicts_aliases_and_partial_options(self):
        router = local_tls_up.tls_override(str(self.directory), "example.test")
        base = router["command"].copy()
        worker_options = [arg for arg in base if arg.startswith("--worker-")]
        commands = [base + ["--local-container-http"], base + ["--worker-tls-cert=other"],
                    base + ["--worker-listen-port", "8790"]]
        for option in worker_options:
            name = option.split("=", 1)[0]
            commands.extend((base + [option], [arg for arg in base if arg != option],
                             [name + "=conflict" if arg == option else arg for arg in base]))
        for command in commands:
            with self.subTest(command=command):
                router["command"] = command
                with self.assertRaises(ValueError):
                    tls_check.router_identity({"services": {"router": router}})
        self.run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
