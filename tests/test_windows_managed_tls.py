"""Managed TLS primitive tests; the Windows first-run gate stays closed."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("windows_managed_tls", ROOT / "scripts/windows_managed_tls.py")
managed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(managed)


class ManagedTlsTests(unittest.TestCase):
    def setUp(self):
        self.project = "test-project"
        self.image = "sha256:" + "a" * 64
        self.nonce = "b" * 32
        self.name = "foundry-tls-" + self.nonce
        labels = {managed._LABEL: "1", managed._LABEL + ".project": self.project,
                  managed._LABEL + ".image": self.image, managed._LABEL + ".nonce": self.nonce}
        self.volume = {"Name": self.name, "Driver": "local", "Options": None, "Labels": labels}

    def test_initializer_uses_isolated_container_and_no_host_bind(self):
        args = managed._container(self.image, self.name, writable=True)
        self.assertEqual(args[args.index("--pull") + 1], "never")
        self.assertEqual(args[args.index("--network") + 1], "none")
        self.assertEqual(args[args.index("--cap-drop") + 1], "ALL")
        self.assertEqual(args[args.index("--cap-add") + 1], "CHOWN")
        self.assertIn("--read-only", args)
        self.assertIn("/data:rw,noexec,nosuid,size=1m", args)
        self.assertIn("type=volume,src=" + self.name + ",dst=/tls,volume-nocopy", args)
        self.assertNotIn("type=bind", " ".join(args))
        self.assertNotIn("server.key", args)

    def test_collision_never_creates_or_deletes(self):
        with patch.object(managed.secrets, "token_hex", return_value=self.nonce), \
             patch.object(managed, "_run", return_value=self.name + "\n") as run:
            with self.assertRaises(managed.ManagedTlsError):
                managed.initialize_tls_volume(self.project, self.image)
        self.assertEqual(run.call_count, 1)

    def test_wrong_driver_options_labels_or_consumers_refused(self):
        for case in ("driver", "options", "labels", "consumer"):
            with self.subTest(case=case):
                volume = json.loads(json.dumps(self.volume))
                if case == "driver":
                    volume["Driver"] = "other"
                elif case == "options":
                    volume["Options"] = {"device": "/other"}
                elif case == "labels":
                    volume["Labels"][managed._LABEL + ".nonce"] = "0" * 32
                with patch.object(managed, "_run", side_effect=[json.dumps([volume]), "container-id"]):
                    with self.assertRaises(ValueError):
                        managed._inspect(self.project, self.image, self.name, self.nonce)

    def test_failed_initialization_does_not_remove_volume(self):
        output = ["", self.name, json.dumps([self.volume]), ""]
        with patch.object(managed.secrets, "token_hex", return_value=self.nonce), \
             patch.object(managed, "_run", side_effect=output + [subprocess.CalledProcessError(1, "docker")]) as run:
            with self.assertRaises(managed.ManagedTlsError):
                managed.initialize_tls_volume(self.project, self.image)
        self.assertFalse(any(call.args[0][:3] == ["docker", "volume", "rm"] for call in run.call_args_list))

    def test_marker_mismatch_or_invalid_cert_refused(self):
        for data in ({"identity": {}, "certificate": "-----BEGIN CERTIFICATE-----"},
                     {"identity": {"project": self.project, "image": self.image, "nonce": self.nonce},
                      "certificate": "not a certificate"}):
            with self.subTest(data=data), patch.object(managed, "_inspect"), \
                 patch.object(managed, "_run", return_value=json.dumps(data)):
                with self.assertRaises(ValueError):
                    managed.verify_tls_volume(self.project, self.image, self.name, self.nonce)

    @unittest.skipUnless(os.environ.get("FOUNDRY_TEST_MANAGED_TLS_IMAGE"), "requires explicit isolated Docker test image")
    def test_real_isolated_volume(self):
        image = os.environ["FOUNDRY_TEST_MANAGED_TLS_IMAGE"]
        nonce = self.nonce
        name = self.name
        # This test uses a fixed, checked name and only removes the volume it creates.
        with patch.object(managed.secrets, "token_hex", return_value=nonce):
            result = managed.initialize_tls_volume(self.project, image)
        try:
            self.assertEqual(result[:2], (name, nonce))
            self.assertEqual(managed.verify_tls_volume(self.project, image, name, nonce), result[2])
            self.assertIn("-----BEGIN CERTIFICATE-----", result[2])
        finally:
            managed._inspect(self.project, image, name, nonce)
            subprocess.run(["docker", "volume", "rm", name], check=True, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()
