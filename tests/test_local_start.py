"""Isolated launcher argument tests; no SR process or network listener."""

from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "local-start.sh"


class LocalStartTests(unittest.TestCase):
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
