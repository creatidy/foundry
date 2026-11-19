"""Isolated launcher argument tests; no SR process or network listener."""

from pathlib import Path
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "local-start.sh"


class LocalStartTests(unittest.TestCase):
    def native_mi_fixture(self, base):
        parent = Path(base) / "private parent"
        parent.mkdir(mode=0o700)
        mi = parent / "mi data"
        mi.mkdir(mode=0o750)
        mi.chmod(0o750)
        publication = b'{"synthetic":true}'
        digest = hashlib.sha256(publication).hexdigest()
        for name, content in (("publication.json", publication),
                              ("trust.json", json.dumps({"publication": str(mi / "publication.json"),
                                                         "reference": {"sha256": digest}}).encode())):
            path = mi / name
            path.write_bytes(content)
            path.chmod(0o640)
        package = Path(base) / "mi-test-site" / "model_intelligence"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("", encoding="utf-8")
        fake = Path(base) / "fake-python"
        fake.write_text('#!/bin/sh\nif [ "$1" = "-B" ]; then PYTHONPATH="$HOME/mi-test-site" exec ' +
                        shlex.quote(sys.executable) + ' -S "$@"; fi\nprintf "ARG:%s\\n" "$@"\n', encoding="utf-8")
        fake.chmod(0o700)
        env = {"HOME": str(base), "PATH": "/usr/bin:/bin", "FOUNDRY_MI_DIR": str(mi),
               "FOUNDRY_MI_SHA256": digest}
        return mi, fake, env

    def test_native_mi_validates_and_passes_path_with_spaces(self):
        with tempfile.TemporaryDirectory() as temp:
            mi, fake, env = self.native_mi_fixture(temp)
            result = subprocess.run(["/bin/sh", str(SCRIPT), str(fake)], env=env,
                                    text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("ARG:--mi-config\nARG:" + str(mi / "trust.json") + "\n", result.stdout)
            self.assertIn("ARG:127.0.0.1\nARG:--port\nARG:8787\n", result.stdout)

    def test_native_mi_preflight_supports_python_safe_path(self):
        with tempfile.TemporaryDirectory() as temp:
            mi, fake, env = self.native_mi_fixture(temp)
            result = subprocess.run(["/bin/sh", str(SCRIPT), str(fake)],
                                    env={**env, "PYTHONSAFEPATH": "1"},
                                    text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("ARG:--mi-config\nARG:" + str(mi / "trust.json") + "\n", result.stdout)

    def test_native_mi_refuses_partial_wrong_digest_and_image_id(self):
        with tempfile.TemporaryDirectory() as temp:
            mi, fake, env = self.native_mi_fixture(temp)
            for update in ({"FOUNDRY_MI_DIR": ""}, {"FOUNDRY_MI_SHA256": ""},
                           {"FOUNDRY_MI_SHA256": "0" * 64}, {"FOUNDRY_MI_IMAGE_ID": "sha256:" + "a" * 64}):
                with self.subTest(update=update):
                    result = subprocess.run(["/bin/sh", str(SCRIPT), str(fake)], env={**env, **update},
                                            text=True, capture_output=True, check=False)
                    self.assertEqual(result.returncode, 2)
                    self.assertNotIn("ARG:scarcity_router.control_server", result.stdout)

    def test_native_mi_requires_installed_optional_dependency(self):
        with tempfile.TemporaryDirectory() as temp:
            mi, fake, env = self.native_mi_fixture(temp)
            package = Path(temp) / "mi-test-site" / "model_intelligence"
            (package / "__init__.py").unlink()
            package.rmdir()
            result = subprocess.run(["/bin/sh", str(SCRIPT), str(fake)], env=env,
                                    text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertIn("lacks the optional MI dependency", result.stderr)
            self.assertNotIn("ARG:scarcity_router.control_server", result.stdout)

    def test_native_mi_rejects_duplicate_keys_links_and_modified_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            mi, fake, env = self.native_mi_fixture(temp)
            trust = mi / "trust.json"
            original = trust.read_bytes()
            trust.write_text('{"publication":"bad","publication":"bad"}')
            result = subprocess.run(["/bin/sh", str(SCRIPT), str(fake)], env=env, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b"ARG:scarcity_router.control_server", result.stdout)
            trust.write_bytes(original)
            publication = mi / "publication.json"
            publication.write_bytes(b"changed")
            result = subprocess.run(["/bin/sh", str(SCRIPT), str(fake)], env=env, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b"ARG:scarcity_router.control_server", result.stdout)
            publication.unlink()
            publication.symlink_to(trust)
            result = subprocess.run(["/bin/sh", str(SCRIPT), str(fake)], env=env, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b"ARG:scarcity_router.control_server", result.stdout)

    def test_native_mi_rejects_container_publication_path_and_unsafe_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            mi, fake, env = self.native_mi_fixture(temp)
            trust = mi / "trust.json"
            config = json.loads(trust.read_text())
            config["publication"] = "/run/foundry/mi/publication.json"
            trust.write_text(json.dumps(config))
            result = subprocess.run(["/bin/sh", str(SCRIPT), str(fake)], env=env, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b"ARG:scarcity_router.control_server", result.stdout)
            config["publication"] = str(mi / "publication.json")
            trust.write_text(json.dumps(config))
            trust.chmod(0o644)
            result = subprocess.run(["/bin/sh", str(SCRIPT), str(fake)], env=env, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b"ARG:scarcity_router.control_server", result.stdout)

    def test_native_mi_rejects_hardlinks_without_disclosing_config(self):
        with tempfile.TemporaryDirectory() as temp:
            mi, fake, env = self.native_mi_fixture(temp)
            publication = mi / "publication.json"
            os.link(publication, Path(temp) / "second-link")
            result = subprocess.run(["/bin/sh", str(SCRIPT), str(fake)], env=env,
                                    text=True, capture_output=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("ARG:scarcity_router.control_server", result.stdout)
            self.assertNotIn("synthetic", result.stderr)

    def test_xdg_data_directory_and_server_arguments(self):
        with tempfile.TemporaryDirectory() as temp:
            fake = Path(temp) / "fake-python"
            fake.write_text('#!/bin/sh\nprintf "ARG:%s\\n" "$@"\n', encoding="utf-8")
            fake.chmod(0o700)
            env = {"HOME": "/home/test user", "XDG_DATA_HOME": "/tmp/data with spaces"}
            result = subprocess.run(
                ["/bin/sh", str(SCRIPT), str(fake)], env=env,
                text=True, capture_output=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ARG:scarcity_router.control_server\n", result.stdout)
        self.assertIn("ARG:127.0.0.1\nARG:--port\nARG:8787\n", result.stdout)
        self.assertIn("ARG:--data-dir\nARG:/tmp/data with spaces/scarcity-router/server\n", result.stdout)
        self.assertNotIn("ARG:--issue-bootstrap-claim", result.stdout)
        self.assertNotIn("ARG:--mi-config", result.stdout)

    def test_relative_xdg_uses_home_and_bad_interpreters_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            fake = Path(temp) / "fake-python"
            fake.write_text('#!/bin/sh\nprintf "ARG:%s\\n" "$@"\n', encoding="utf-8")
            fake.chmod(0o700)
            env = {"HOME": "/home/test user", "XDG_DATA_HOME": "relative"}
            result = subprocess.run(
                ["/bin/sh", str(SCRIPT), str(fake)], env=env,
                text=True, capture_output=True, check=False,
            )
            self.assertIn("ARG:/home/test user/.local/share/scarcity-router/server\n", result.stdout)
            self.assertEqual(result.returncode, 0)
            bad = subprocess.run(
                ["/bin/sh", str(SCRIPT), "python"], env=env,
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(bad.returncode, 2)
            self.assertNotIn("ARG:", bad.stdout)


if __name__ == "__main__":
    unittest.main()
