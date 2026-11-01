"""Fail-closed Docker resource discovery tests without changing Docker resources."""

from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from local_tls_up import check_project


class ProjectChecksTests(unittest.TestCase):
    def test_each_docker_listing_failure_is_fatal(self):
        config = {"networks": {"default": {"name": "test_default"}},
                  "volumes": {"data": {"name": "test_data"}}}
        for failed_call in range(5):
            with self.subTest(failed_call=failed_call):
                with mock.patch("local_tls_up.subprocess.run") as run:
                    run.side_effect = [subprocess.CompletedProcess([], 0, stdout=b"" if i < 3 else "")
                                       for i in range(failed_call)] + [subprocess.CalledProcessError(1, "docker")]
                    with self.assertRaises(subprocess.CalledProcessError):
                        check_project("test", config)
                    if failed_call:
                        self.assertIn("--all", run.call_args_list[0].args[0])
