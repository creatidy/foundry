"""First-run trust and fail-closed preflight checks."""

import importlib.util
import hashlib
import json
from pathlib import Path
import sys
import subprocess
import unittest
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("windows_first_run", ROOT / "scripts/windows_first_run.py")
first_run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(first_run)


class FirstRunTests(unittest.TestCase):
    def setUp(self):
        self.args = ["isolated-project", "sha256:" + "a" * 64, "/home/user/private/tls",
                     "b" * 64, "desktop-engine", "-", "Ubuntu"]

    def test_invalid_tls_stops_before_docker(self):
        with patch.object(first_run.platform, "system", return_value="Linux"), \
             patch.object(first_run.platform, "release", return_value="5.15.0-microsoft-standard-WSL2"), \
             patch.object(first_run, "validate", side_effect=ValueError("bad TLS")) as validate, \
             patch("subprocess.run", side_effect=AssertionError("unexpected external process")):
            self.assertEqual(first_run.main(self.args), 1)
        validate.assert_called_once_with(self.args[2])

    def test_bad_inputs_and_non_wsl_refused_before_tls(self):
        for args in (["bad;project", *self.args[1:]], [self.args[0], "latest", *self.args[2:]],
                     [*self.args[:2], "/tmp/a;id", *self.args[3:]], self.args[:2], self.args):
            with self.subTest(args=args), patch.object(first_run, "validate") as validate, \
                 patch.object(first_run.platform, "system", return_value="Linux"), \
                 patch.object(first_run.platform, "release", return_value="ordinary-linux"):
                self.assertEqual(first_run.main(args), 1)
                validate.assert_not_called()

    def test_invalid_tls_fails_closed(self):
        with patch.object(first_run.platform, "system", return_value="Linux"), \
             patch.object(first_run.platform, "release", return_value="microsoft-standard-WSL2"), \
             patch.object(first_run, "validate", side_effect=ValueError("secret")):
            self.assertEqual(first_run.main(self.args), 1)

    def test_windows_entrypoint_uses_only_fixed_pipe_and_no_shell(self):
        source = (ROOT / "scripts/windows-first-run.ps1").read_text()
        self.assertIn("--exec python3", source)
        self.assertIn("npipe:////./pipe/dockerDesktopLinuxEngine", source)
        self.assertNotIn("Invoke-Expression", source)
        self.assertNotIn("-ExecutionPolicy", source)

    def test_remote_override_rejected_before_tls_or_docker(self):
        with patch.object(first_run.platform, "system", return_value="Linux"), \
             patch.object(first_run.platform, "release", return_value="microsoft-standard-WSL2"), \
             patch.dict(first_run.os.environ, {"DOCKER_HOST": "tcp://remote:2375"}), \
             patch.object(first_run, "validate") as validate, \
             patch.object(first_run, "run", side_effect=AssertionError("contacted Docker")):
            self.assertEqual(first_run.main(self.args), 1)
            validate.assert_not_called()

    def test_checkout_attribute_preserves_hashed_compose_lf(self):
        result = subprocess.run(["git", "-c", "core.autocrlf=true", "check-attr", "eol", "--", "compose.yaml"],
                                cwd=ROOT, check=True, capture_output=True, text=True)
        self.assertEqual(result.stdout.strip(), "compose.yaml: eol: lf")
        self.assertEqual(hashlib.sha256((ROOT / "compose.yaml").read_bytes()).hexdigest(), first_run.COMPOSE_SHA256)

    def test_compose_and_mi_environment_rejected_before_docker(self):
        for name in ("COMPOSE_FILE", "FOUNDRY_MI_DIR"):
            with self.subTest(name=name), patch.dict(first_run.os.environ, {name: "unsafe"}, clear=True), \
                 patch.object(first_run.platform, "system", return_value="Linux"), \
                 patch.object(first_run.platform, "release", return_value="microsoft-standard-WSL2"), \
                 patch.object(first_run, "validate") as validate, \
                 patch.object(first_run, "run", side_effect=AssertionError("Docker contacted")):
                self.assertEqual(first_run.main(self.args), 1)
                validate.assert_not_called()

    def test_changed_compose_rejected_before_docker(self):
        with patch.dict(first_run.os.environ, {}, clear=True), \
             patch.object(first_run.platform, "system", return_value="Linux"), \
             patch.object(first_run.platform, "release", return_value="microsoft-standard-WSL2"), \
             patch.object(first_run, "COMPOSE_SHA256", "0" * 64), \
             patch.object(first_run, "run", side_effect=AssertionError("Docker contacted")):
            self.assertEqual(first_run.main(self.args), 1)

    def test_consent_denial_eof_and_revalidation_refuse_claim(self):
        self.args[3] = hashlib.sha256(b"der").hexdigest()
        self.args[5] = self.args[0]
        project, image, _, _, engine, _, _ = self.args
        config = {"name": project, "services": {"router": {"image": image}}}
        output = [json.dumps([{"Endpoints": {"docker": {"Host": first_run.SOCKET}}}]),
                  json.dumps({"OSType": "linux", "ID": engine}),
                  json.dumps([{"Id": image, "Config": {}}]), json.dumps(config)]
        for choice in ("NO", EOFError(), "YES", None):
            with self.subTest(choice=choice), patch.dict(first_run.os.environ, {}, clear=True), \
                 patch.object(first_run.platform, "system", return_value="Linux"), \
                 patch.object(first_run.platform, "release", return_value="microsoft-standard-WSL2"), \
                 patch.object(first_run, "validate"), patch.object(first_run.os, "chdir"), \
                 patch.object(Path, "read_text", return_value="certificate"), \
                 patch.object(first_run.ssl, "PEM_cert_to_DER_cert", return_value=b"der"), \
                 patch.object(first_run, "run", side_effect=output), \
                 patch.object(first_run, "check_project", return_value=True), \
                 patch.object(first_run, "verify_project", side_effect=["a" * 64, "b" * 64]), \
                 patch.object(first_run, "request", side_effect=[(200, None, b'{"status":"ok"}'),
                                                                  (303, "/admin/onboarding", b"")]), \
                 patch.object(first_run.sys.stdin, "isatty", return_value=choice is not None), \
                 patch.object(first_run.sys.stdout, "isatty", return_value=True), \
                 patch("builtins.input", side_effect=choice if isinstance(choice, Exception) else None,
                       return_value=choice), \
                 patch.object(first_run.subprocess, "run", side_effect=AssertionError("claim attempted")):
                self.assertEqual(first_run.main(self.args), 1)

    def test_engine_mismatch_stops_before_image_or_startup(self):
        self.args[3] = hashlib.sha256(b"der").hexdigest()
        output = [json.dumps([{"Endpoints": {"docker": {"Host": first_run.SOCKET}}}]),
                  json.dumps({"OSType": "linux", "ID": "another-engine"})]
        with patch.dict(first_run.os.environ, {}, clear=True), \
             patch.object(first_run.platform, "system", return_value="Linux"), \
             patch.object(first_run.platform, "release", return_value="microsoft-standard-WSL2"), \
             patch.object(first_run, "validate"), patch.object(Path, "read_text", return_value="certificate"), \
             patch.object(first_run.ssl, "PEM_cert_to_DER_cert", return_value=b"der"), \
             patch.object(first_run, "run", side_effect=output) as docker, \
             patch.object(first_run.subprocess, "run", side_effect=AssertionError("startup attempted")):
            self.assertEqual(first_run.main(self.args), 1)
        self.assertEqual(docker.call_count, 2)

    def test_existing_admin_resume_never_starts_or_issues_claim(self):
        self.args[3] = hashlib.sha256(b"der").hexdigest()
        self.args[5] = self.args[0]
        project, image, _, _, engine, _, _ = self.args
        config = {"name": project, "services": {"router": {"image": image}}}
        output = [json.dumps([{"Endpoints": {"docker": {"Host": first_run.SOCKET}}}]),
                  json.dumps({"OSType": "linux", "ID": engine}),
                  json.dumps([{"Id": image, "Config": {}}]), json.dumps(config)]
        with patch.dict(first_run.os.environ, {}, clear=True), \
             patch.object(first_run.platform, "system", return_value="Linux"), \
             patch.object(first_run.platform, "release", return_value="microsoft-standard-WSL2"), \
             patch.object(first_run, "validate"), patch.object(first_run.os, "chdir"), \
             patch.object(Path, "read_text", return_value="certificate"), \
             patch.object(first_run.ssl, "PEM_cert_to_DER_cert", return_value=b"der"), \
             patch.object(first_run, "run", side_effect=output), \
             patch.object(first_run, "check_project", return_value=True), \
             patch.object(first_run, "verify_project", return_value="a" * 64), \
             patch.object(first_run, "request", side_effect=[(200, None, b'{"status":"ok"}'),
                                                              (303, "/admin/login", b"")]), \
             patch.object(first_run.subprocess, "run", side_effect=AssertionError("mutation attempted")):
            self.assertEqual(first_run.main(self.args), 0)

    def test_extra_project_container_refused(self):
        config = {"volumes": {"router-data": {"name": "p_router-data"}},
                  "networks": {"backend": {"name": "p_backend"}}}
        with patch.object(first_run, "run", side_effect=["a" * 64 + "\n" + "b" * 64,
                                                          "p_router-data", "network-id"]):
            with self.assertRaises(ValueError):
                first_run.verify_project("p", "image", "/tls", config, {}, "b" * 64, "Ubuntu")

    def test_unmatched_mounted_leaf_is_refused(self):
        with patch.object(first_run, "run", return_value="a" * 64) as run:
            with self.assertRaises(ValueError):
                first_run.attest_container_certificate("c" * 64, "b" * 64)
        self.assertEqual(run.call_args.args[:4], ("docker", "exec", "c" * 64, "python"))
        self.assertNotIn("server.key", run.call_args.args[-1])

    def test_wrong_live_tls_leaf_is_refused_before_http(self):
        conn = Mock()
        conn.sock.getpeercert.return_value = b"wrong certificate"
        with patch.object(first_run.ssl, "create_default_context"), \
             patch.object(first_run.http.client, "HTTPSConnection", return_value=conn):
            with self.assertRaises(ValueError):
                first_run.request("/healthz", "/tls/server.crt", "b" * 64)
        conn.request.assert_not_called()
        conn.close.assert_called_once()

    def test_changed_tls_or_mi_mount_refused(self):
        cid = "a" * 64
        config = {"volumes": {"router-data": {"name": "p_router-data"}},
                  "networks": {"backend": {"name": "p_backend"}},
                  "services": {"router": {"command": ["--data-dir=/data"]}}}
        container = {"Id": cid, "Image": "image", "State": {"Running": True},
                     "Config": {"Labels": {"com.docker.compose.project": "p",
                                            "com.docker.compose.service": "router",
                                            "com.docker.compose.container-number": "1"},
                                "Entrypoint": None, "User": "10001:10001",
                                "Env": ["SR_HEALTHCHECK_URL=https://127.0.0.1:8787/healthz",
                                        "SR_HEALTHCHECK_CA=/run/foundry/tls/server.crt"],
                                "Cmd": ["--data-dir=/data", "--tls-reload-ca-cert=/run/foundry/tls/server.crt"]},
                     "HostConfig": {"NetworkMode": "p_backend", "Privileged": False,
                                    "SecurityOpt": ["no-new-privileges:true"], "GroupAdd": [str(first_run.os.getegid())],
                                    "PortBindings": {"8787/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8787"}]}},
                     "NetworkSettings": {"Networks": {"p_backend": {}}},
                     "Mounts": [{"Destination": "/data", "Type": "volume", "RW": True, "Name": "p_router-data"},
                                {"Destination": "/run/foundry/tls", "Type": "bind", "Source": "/tls", "RW": False}]}
        for change in ("writable", "extra", "other-distribution", "traversal", "unrelated",
                       "user", "capability", "device", "pid", "seccomp"):
            with self.subTest(change=change):
                current = json.loads(json.dumps(container))
                if change == "writable":
                    current["Mounts"][1]["RW"] = True
                elif change == "extra":
                    current["Mounts"].append({"Destination": "/run/foundry/mi/trust.json"})
                elif change == "user":
                    current["Config"]["User"] = "0:0"
                elif change == "capability":
                    current["HostConfig"]["CapAdd"] = ["SYS_ADMIN"]
                elif change == "device":
                    current["HostConfig"]["Devices"] = [{"PathOnHost": "/dev/sda"}]
                elif change == "pid":
                    current["HostConfig"]["PidMode"] = "host"
                elif change == "seccomp":
                    current["HostConfig"]["SecurityOpt"] = ["no-new-privileges:true", "seccomp=unconfined"]
                else:
                    prefix = "/run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/"
                    current["Mounts"][1]["Source"] = {
                        "other-distribution": prefix + "Other/123456",
                        "traversal": prefix + "Ubuntu/../evil",
                        "unrelated": "/tmp/unrelated",
                    }[change]
                output = [cid, "p_router-data", "network-id", json.dumps([current])]
                with patch.object(first_run, "run", side_effect=output):
                    with self.assertRaises(ValueError):
                        first_run.verify_project("p", "image", "/tls", config, {"Entrypoint": None, "User": "10001:10001"}, "b" * 64, "Ubuntu")

    def test_translated_bind_same_inode_required(self):
        with self.assertRaises((OSError, ValueError)):
            first_run.verify_bind_source("/run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/Ubuntu/" + "a" * 64,
                                         "/tmp/nonexistent-foundry-private/tls", "Ubuntu")
        with self.assertRaises(ValueError):
            first_run.verify_bind_source("/run/desktop/mnt/host/wsl/docker-desktop-bind-mounts/Ubuntu/../bad",
                                         "/tls", "Ubuntu")

    def test_fresh_start_claim_is_not_captured(self):
        self.args[3] = hashlib.sha256(b"der").hexdigest()
        project, image, tls, _, engine, _, _ = self.args
        cid = "a" * 64
        network_name = project + "_backend"
        config = {"name": project, "services": {"router": {"image": image, "command": ["--data-dir=/data"]}},
                  "volumes": {"router-data": {"name": project + "_router-data"}},
                  "networks": {"backend": {"name": network_name}}}
        image_config = {"Env": [], "Entrypoint": None, "User": "10001:10001"}
        container = {"State": {"Running": True}, "Image": image,
                     "Id": cid,
                     "Config": {"Labels": {"com.docker.compose.project": project,
                                            "com.docker.compose.service": "router",
                                            "com.docker.compose.container-number": "1"},
                                "Entrypoint": None, "User": "10001:10001",
                                "Env": ["SR_HEALTHCHECK_URL=https://127.0.0.1:8787/healthz",
                                        "SR_HEALTHCHECK_CA=/run/foundry/tls/server.crt"],
                                "Cmd": ["--data-dir=/data", "--tls-reload-ca-cert=/run/foundry/tls/server.crt"]},
                     "HostConfig": {"Privileged": False, "NetworkMode": network_name,
                                    "SecurityOpt": ["no-new-privileges:true"], "GroupAdd": [str(first_run.os.getegid())],
                                    "PortBindings": {"8787/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8787"}]}},
                     "NetworkSettings": {"Networks": {network_name: {}}},
                     "Mounts": [{"Destination": "/data", "Type": "volume", "RW": True, "Name": project + "_router-data"},
                                {"Destination": "/run/foundry/tls", "Type": "bind", "RW": False,
                                 "Source": tls}]}
        volume = {"Name": project + "_router-data", "Driver": "local", "Options": None,
                  "Labels": {"com.docker.compose.project": project,
                                                                     "com.docker.compose.volume": "router-data"}}
        network = {"Name": network_name, "Labels": {"com.docker.compose.project": project,
                                                       "com.docker.compose.network": "backend"},
                   "Containers": {cid: {}}}
        output = [json.dumps([{"Endpoints": {"docker": {"Host": first_run.SOCKET}}}]),
                  json.dumps({"OSType": "linux", "ID": engine}), json.dumps([{"Id": image, "Config": image_config}]),
                  json.dumps(config), cid, project + "_router-data", "network-id", json.dumps([container]),
                  json.dumps([volume]), cid, json.dumps([network]), self.args[3]]
        output += output[4:]
        with patch.dict(first_run.os.environ, {}, clear=True), \
             patch.object(first_run.platform, "system", return_value="Linux"), \
             patch.object(first_run.platform, "release", return_value="microsoft-standard-WSL2"), \
             patch.object(first_run, "validate"), patch.object(first_run.os, "chdir"), \
             patch.object(Path, "read_text", return_value="certificate"), \
             patch.object(first_run.ssl, "PEM_cert_to_DER_cert", return_value=b"der"), \
             patch.object(first_run, "run", side_effect=output), \
             patch.object(first_run, "check_project", return_value=False), \
             patch.object(first_run, "request", side_effect=[(200, None, b'{"status":"ok"}'),
                                                              (303, "/admin/onboarding", b""),
                                                              (303, "/admin/onboarding", b"")]), \
             patch.object(first_run.sys.stdin, "isatty", return_value=True), \
             patch.object(first_run.sys.stdout, "isatty", return_value=True), \
             patch("builtins.input", return_value="YES"), \
             patch.object(first_run.subprocess, "run", return_value=Mock(returncode=0)) as process:
            self.assertEqual(first_run.main(self.args), 0)
        self.assertEqual(process.call_count, 2)
        claim = process.call_args_list[1]
        self.assertEqual(claim.args[0], ["docker", "exec", cid, "python", "-m",
                                        "scarcity_router.control_server", "--data-dir", "/data",
                                        "--issue-bootstrap-claim"])
        self.assertNotIn("stdout", claim.kwargs)
        self.assertNotIn("capture_output", claim.kwargs)
        for option in ("driver", "options", "consumer"):
            with self.subTest(option=option):
                bad_volume = dict(volume)
                if option == "driver":
                    bad_volume["Driver"] = "other"
                elif option == "options":
                    bad_volume["Options"] = {"device": "/other"}
                checks = [cid, project + "_router-data", "network-id", json.dumps([container]),
                          json.dumps([bad_volume]), cid + "\n" + "b" * 64]
                with patch.object(first_run, "run", side_effect=checks):
                    with self.assertRaises(ValueError):
                        first_run.verify_project(project, image, tls, config, image_config, self.args[3], "Ubuntu")


if __name__ == "__main__":
    unittest.main()
