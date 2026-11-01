"""Host integration tests for the explicit local TLS generator."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class LocalTLSTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="foundry-leaf-")
        self.addCleanup(self.temp.cleanup)
        self.parent = Path(self.temp.name)
        self.dest = self.parent / "new tls"

    def run_init(self, destination=None):
        env = os.environ.copy()
        env["TLS_DEST"] = str(self.dest if destination is None else destination)
        return subprocess.run(["make", "local-tls-init"], cwd=ROOT, env=env,
                              capture_output=True, text=True, timeout=60)

    def openssl(self, *args):
        return subprocess.run(["openssl", *map(str, args)], check=True,
                              capture_output=True, timeout=30).stdout

    def test_leaf_and_no_overwrite(self):
        result = self.run_init()
        self.assertEqual(result.returncode, 0, result.stderr)
        key, cert = self.dest / "server.key", self.dest / "server.crt"
        self.assertEqual(self.dest.stat().st_mode & 0o777, 0o750)
        self.assertEqual(key.stat().st_mode & 0o777, 0o640)
        text = self.openssl("x509", "-in", cert, "-noout", "-text").decode()
        self.assertIn("IP Address:127.0.0.1", text)
        self.assertIn("CA:FALSE", text)
        self.openssl("verify", "-CAfile", cert, "-verify_ip", "127.0.0.1", cert)
        cert_pub = self.openssl("x509", "-in", cert, "-pubkey", "-noout")
        key_pub = self.openssl("pkey", "-in", key, "-pubout")
        self.assertEqual(cert_pub, key_pub)
        self.assertEqual(cert.read_text().count("BEGIN CERTIFICATE"), 1)
        fingerprint = self.openssl("x509", "-in", cert, "-noout", "-fingerprint", "-sha256").decode().strip().split("=", 1)[1]
        self.assertIn(fingerprint, result.stdout)
        self.assertIn("Do not trust an unverified certificate", result.stdout)
        self.assertNotIn(key.read_text(), result.stdout + result.stderr)
        original = key.read_bytes(), cert.read_bytes()
        failed = self.run_init()
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(original, (key.read_bytes(), cert.read_bytes()))
        self.assertNotIn(key.read_text(), failed.stdout + failed.stderr)

    def test_missing_destination_and_existing_directory(self):
        self.assertNotEqual(self.run_init("").returncode, 0)
        self.dest.mkdir()
        self.assertNotEqual(self.run_init().returncode, 0)
        self.assertEqual(list(self.dest.iterdir()), [])

    def test_symlinks_and_permissions(self):
        link = self.parent / "link"
        link.symlink_to(self.parent, target_is_directory=True)
        self.assertNotEqual(self.run_init(link / "child").returncode, 0)
        self.dest.symlink_to(self.parent, target_is_directory=True)
        self.assertNotEqual(self.run_init().returncode, 0)
        self.parent.chmod(0o755)
        self.addCleanup(self.parent.chmod, 0o700)
        self.assertNotEqual(self.run_init(self.parent / "other").returncode, 0)
        self.assertFalse((self.parent / "other").exists())

    def test_openssl_failure_rolls_back(self):
        env = os.environ.copy()
        env.update(TLS_DEST=str(self.dest), PATH="/nonexistent")
        result = subprocess.run(["/usr/bin/python3", str(ROOT / "scripts/local_tls_init.py")],
                                env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.dest.exists())
        self.assertNotIn("PRIVATE KEY", result.stdout + result.stderr)

    def test_fifo_files_are_rejected_without_blocking(self):
        for name in ("server.crt", "server.key"):
            with self.subTest(name=name):
                result = self.run_init()
                self.assertEqual(result.returncode, 0, result.stderr)
                path = self.dest / name
                path.unlink()
                os.mkfifo(path, 0o640)
                env = os.environ.copy()
                env.update(TLS_DEST=str(self.dest), LOCAL_TLS_PROJECT="fifo-regression")
                result = subprocess.run(["python3", str(ROOT / "scripts/local_tls_up.py")],
                                        env=env, capture_output=True, text=True, timeout=3)
                self.assertNotEqual(result.returncode, 0)
                path.unlink()
                for remaining in self.dest.iterdir():
                    remaining.unlink()
                self.dest.rmdir()


if __name__ == "__main__":
    unittest.main()
