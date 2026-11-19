"""Real Python/Git discovery fixtures; no SR server, user state or network."""

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import call, patch
import venv


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("local_runtime", ROOT / "scripts/local_runtime.py")
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class AcceptedRevisionsTests(unittest.TestCase):
    def test_merged_local_compose_revision_is_accepted(self):
        self.assertIn("5bd4fa4d65028b46455f63726c2dda7b8e3ca341", runtime.ACCEPTED)
        self.assertIn("dc74c0f015551f075bc45ee15bdb0cf0705c91b5", runtime.ACCEPTED)


class LocalRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="foundry-discovery-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "foundry"
        self.root.mkdir()
        self.checkout = self.base / "scarcity-router"
        package = self.checkout / "scarcity_router"
        package.mkdir(parents=True)
        for name in ("__init__.py", "control_server.py", "server_ownership.py"):
            (package / name).write_text("# isolated synthetic SR fixture\n")
        (self.checkout / "examples").mkdir()
        (self.checkout / "examples/selector-policy.json").write_text("{}\n")
        subprocess.run(["git", "init", "-q", str(self.checkout)], check=True)
        self.git("remote", "add", "origin", runtime.CANONICAL)
        self.git("add", "scarcity_router", "examples/selector-policy.json")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "Synthetic fixture")
        self.revision = self.git("rev-parse", "HEAD").strip()
        self.python = self.environment(self.checkout / ".venv", editable=True)
        self.addCleanup(patch.stopall)
        patch.object(runtime, "ROOT", self.root).start()
        patch.object(runtime, "ACCEPTED", {self.revision}).start()
        patch.object(runtime.shutil, "which", return_value=None).start()
        patch.dict(os.environ, {"HOME": str(self.base / "home"), "XDG_DATA_HOME": str(self.base / "data")}, clear=True).start()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.checkout), *args], text=True)

    def environment(self, destination, *, editable=False):
        # Keep standalone interpreters beside their shared-library installation.
        venv.EnvBuilder(with_pip=False, symlinks=True).create(destination)
        site = next((destination / "lib").glob("python*/site-packages"))
        if editable:
            (site / "fixture.pth").write_text(str(self.checkout) + "\n")
        else:
            shutil.copytree(self.checkout / "scarcity_router", site / "scarcity_router")
            shutil.copyfile(self.checkout / "examples/selector-policy.json",
                            site / "scarcity_router/default-selector-policy.json")
        metadata = site / "scarcity_router-0.1.0.dist-info"
        metadata.mkdir()
        (metadata / "METADATA").write_text("Metadata-Version: 2.1\nName: scarcity-router\nVersion: 0.1.0\n")
        (metadata / "direct_url.json").write_text(json.dumps({
            "url": self.checkout.as_uri(), "dir_info": {"editable": editable},
        }))
        return destination / "bin/python"

    def tool(self):
        tools = self.base / "tools"
        python = self.environment(tools / "scarcity-router")
        uv = self.base / "uv"
        uv.write_text(f'#!/bin/sh\n[ "$1 $2" = "tool dir" ] || exit 99\nprintf "%s\\n" "{tools}"\n')
        uv.chmod(0o700)
        patch.object(runtime.shutil, "which", return_value=str(uv)).start()
        return python

    def test_existing_checkout_selected_and_no_state_created(self):
        python, source, revision = runtime.discover()
        self.assertEqual((python, source, revision), (self.python, self.checkout, self.revision))
        self.assertFalse((self.base / "home").exists())
        self.assertFalse((self.base / "data").exists())

    def test_installed_uv_tool_verified_against_retained_source(self):
        python = self.tool()
        self.python.unlink()
        self.assertEqual(runtime.discover()[0], python)

    def test_two_compatible_environments_are_ambiguous(self):
        self.tool()
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            runtime.discover()
        with patch.dict(os.environ, {"FOUNDRY_SR_CHECKOUT": str(self.checkout)}):
            self.assertEqual(runtime.discover()[0], self.python)

    def test_stale_tool_does_not_prevent_reusing_compatible_checkout(self):
        python = self.tool()
        site = next((python.parent.parent / "lib").glob("python*/site-packages"))
        (site / "scarcity_router/server_ownership.py").unlink()
        with redirect_stderr(io.StringIO()) as error:
            self.assertEqual(runtime.discover()[0], self.python)
        self.assertIn("Rejected SR runtime", error.getvalue())

    def test_unaccepted_revision_and_modified_or_extra_code_refused(self):
        with patch.object(runtime, "ACCEPTED", set()):
            with self.assertRaisesRegex(ValueError, "compatibility set"):
                runtime.verify(self.python)
        module = self.checkout / "scarcity_router/control_server.py"
        module.write_text("# modified\n")
        with self.assertRaisesRegex(ValueError, "differs from source revision"):
            runtime.verify(self.python)
        module.write_text("# isolated synthetic SR fixture\n")
        (module.parent / "extra.py").write_text("# extra\n")
        with self.assertRaisesRegex(ValueError, "file set"):
            runtime.verify(self.python)

    def test_wrong_origin_and_import_overrides_refused(self):
        self.git("remote", "set-url", "origin", "https://example.invalid/SR.git")
        with self.assertRaisesRegex(ValueError, "canonical"):
            runtime.verify(self.python)
        for name in ("PYTHONPATH", "PYTHONHOME"):
            with patch.dict(os.environ, {name: "/tmp/not-sr"}):
                with self.assertRaisesRegex(ValueError, "unset PYTHONPATH"):
                    runtime.discover()
        with patch.dict(os.environ, {"FOUNDRY_SR_CHECKOUT": "relative"}):
            with self.assertRaisesRegex(ValueError, "absolute"):
                runtime.discover()

    def test_modified_or_missing_editable_default_policy_refused(self):
        policy = self.checkout / "examples/selector-policy.json"
        policy.write_text('{"modified": true}\n')
        with self.assertRaisesRegex(ValueError, "differs from source revision.*selector-policy"):
            runtime.verify(self.python)
        policy.unlink()
        with self.assertRaisesRegex(ValueError, "selector-policy source is missing"):
            runtime.verify(self.python)

    def test_missing_or_modified_packaged_default_policy_refused(self):
        python = self.tool()
        package = next((python.parent.parent / "lib").glob("python*/site-packages/scarcity_router"))
        policy = package / "default-selector-policy.json"
        policy.write_text('{"modified": true}\n')
        with self.assertRaisesRegex(ValueError, "differs from source revision.*selector-policy"):
            runtime.verify(python)
        policy.unlink()
        with self.assertRaisesRegex(ValueError, "file set"):
            runtime.verify(python)

    def test_installed_policy_source_precedence_is_also_verified(self):
        python = self.tool()
        site = next((python.parent.parent / "lib").glob("python*/site-packages"))
        (site / "examples").mkdir()
        (site / "examples/selector-policy.json").write_text('{"modified": true}\n')
        with self.assertRaisesRegex(ValueError, "differs from source revision.*selector-policy"):
            runtime.verify(python)

    def test_absence_has_explicit_install_guidance(self):
        self.python.unlink()
        with self.assertRaisesRegex(ValueError, "make install"):
            runtime.discover()

    def test_install_requires_tools_before_reserving_path(self):
        with self.assertRaisesRegex(ValueError, "requires Git and uv"):
            runtime.install()
        self.assertFalse((self.root / ".foundry-sr").exists())

    def test_install_exact_pin_and_private_path_no_state_or_standalone_changes(self):
        checkout = self.root / ".foundry-sr"
        python = checkout / ".venv/bin/python"
        pin = runtime.INSTALL_REVISION
        standalone = self.python.lstat()
        clean_env = dict(os.environ)
        with (patch.dict(os.environ, {"GIT_DIR": str(self.checkout / ".git"),
                                      "GIT_WORK_TREE": str(self.checkout), "GIT_INDEX_FILE": "/other-index"}),
              patch.object(runtime.shutil, "which", side_effect=lambda name: "/tools/" + name),
              patch.object(runtime.subprocess, "run") as execute,
              patch.object(runtime, "run", return_value=pin) as read_git,
              patch.object(runtime, "verify", return_value=(python.parent.parent, checkout, pin)) as verify):
            self.assertEqual(runtime.install(), (python, checkout, pin))
            self.assertEqual(runtime.discover(), (python, checkout, pin))
            self.assertEqual(runtime.install(), (python, checkout, pin))
        self.assertEqual(verify.call_args_list, [call(python)] * 3)
        read_git.assert_called_once_with(["/tools/git", "--no-replace-objects", "-C", str(checkout),
                                          "rev-parse", "HEAD"], env=clean_env)
        self.assertEqual(execute.call_args_list, [
            call(["/tools/git", "clone", "--no-checkout", runtime.CANONICAL, str(checkout)],
                 cwd=self.root, env=clean_env, check=True, timeout=300),
            call(["/tools/git", "--no-replace-objects", "-C", str(checkout), "checkout", "--detach", pin],
                 cwd=self.root, env=clean_env, check=True, timeout=300),
            call(["/tools/uv", "--no-config", "venv", "--python", "3.12", str(python.parent.parent)],
                 cwd=self.root, env=clean_env, check=True, timeout=300),
            call(["/tools/uv", "--no-config", "pip", "install", "--no-python-downloads", "--python", str(python), str(checkout)],
                 cwd=self.root, env=clean_env, check=True, timeout=300),
        ])
        self.assertEqual(checkout.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.python.lstat().st_ino, standalone.st_ino)
        self.assertFalse((self.base / "data").exists())

    def test_provenance_git_uses_the_retained_checkout_despite_inherited_context(self):
        with patch.dict(os.environ, {"GIT_DIR": "/does-not-exist", "GIT_WORK_TREE": "/wrong-checkout"}):
            self.assertEqual(runtime.discover(), (self.python, self.checkout, self.revision))

    def test_mismatched_checkout_stops_before_uv_and_is_not_reused(self):
        checkout = self.root / ".foundry-sr"
        with (patch.object(runtime.shutil, "which", side_effect=lambda name: "/tools/" + name),
              patch.object(runtime.subprocess, "run") as execute,
              patch.object(runtime, "run", return_value="wrong-pin")):
            with self.assertRaisesRegex(ValueError, "installation failed"):
                runtime.install()
            self.assertEqual(execute.call_count, 2)
        self.assertTrue(checkout.is_dir())
        with self.assertRaisesRegex(ValueError, "installation not verified"):
            runtime.discover()
        with patch.dict(os.environ, {"FOUNDRY_SR_CHECKOUT": str(self.checkout)}):
            self.assertEqual(runtime.discover()[0], self.python)
            with self.assertRaisesRegex(ValueError, "unset FOUNDRY_SR_CHECKOUT"):
                runtime.install()

    def test_probe_failure_timeout_and_old_python_are_rejected(self):
        for contents in ("#!/bin/sh\nexit 1\n", "#!/bin/sh\nprintf 'not json'\n"):
            fake = self.base / "bad-python"
            fake.write_text(contents)
            fake.chmod(0o700)
            with self.assertRaises((ValueError, subprocess.SubprocessError)):
                runtime.verify(fake)
        with patch.object(runtime, "verify", side_effect=subprocess.TimeoutExpired("probe", 10)):
            with redirect_stderr(io.StringIO()):
                with self.assertRaisesRegex(ValueError, "no verifiable"):
                    runtime.discover()
        probe = runtime.PROBE.replace("(3, 12)", "(99, 0)")
        with patch.object(runtime, "PROBE", probe):
            with self.assertRaises(subprocess.CalledProcessError):
                runtime.verify(self.python)

    def test_main_check_does_not_start_and_start_execs_existing_launcher(self):
        launcher = self.root / "scripts/local-start.sh"
        with patch.object(sys, "argv", ["local_runtime.py", "--check"]):
            with patch.object(runtime.os, "execv") as execute, redirect_stdout(io.StringIO()):
                self.assertEqual(runtime.main(), 0)
                execute.assert_not_called()
        with patch.object(sys, "argv", ["local_runtime.py"]):
            with patch.object(runtime.os, "execv") as execute, patch.object(runtime.os, "chdir") as chdir:
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(runtime.main(), 0)
                execute.assert_called_once_with(str(launcher), [str(launcher), str(self.python)])
                chdir.assert_called_once_with(self.root)
        with patch.object(sys, "argv", ["local_runtime.py", "--bootstrap"]):
            with patch.object(runtime.os, "execv") as execute, patch.object(runtime.os, "chdir"):
                runtime.main()
                execute.assert_called_once_with(str(launcher), [str(launcher), str(self.python), "--bootstrap"])


if __name__ == "__main__":
    unittest.main()
