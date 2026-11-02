"""Disabled managed bootstrap transaction; no real claims are issued."""

import contextlib
import hashlib
import io
import json
import os
import subprocess
import threading
import time
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import windows_first_run as first_run


class ManagedBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.cert = "test certificate"
        self.der = b"test der"
        self.fingerprint = hashlib.sha256(self.der).hexdigest()
        self.args = dict(project="project", image="image", engine="engine", distribution="Ubuntu",
                         config={}, image_config={}, volume="volume", nonce="nonce", cert=self.cert,
                         fingerprint=self.fingerprint, container_id="a" * 64, protocol=Mock(),
                         reservation=Mock(retain=False), deadline=time.monotonic() + 120)
        self.stream = lambda password="valid-password": io.BytesIO(json.dumps(
            {"password": password, "confirmation": password}).encode())

    def mocks(self):
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(first_run, "MANAGED_BOOTSTRAP_ENABLED", True))
        stack.enter_context(patch.dict(first_run.os.environ, {"DOCKER_HOST": first_run.SOCKET}, clear=True))
        stack.enter_context(patch.object(first_run.ssl, "PEM_cert_to_DER_cert", return_value=self.der))
        stack.enter_context(patch.object(first_run.ssl, "create_default_context"))
        stack.enter_context(patch.object(first_run, "read_bootstrap_input", side_effect=lambda stream, deadline: stream.read(4097)))
        stack.enter_context(patch.object(first_run.managed_tls, "verify_tls_volume", return_value=self.cert))
        stack.enter_context(patch.object(first_run, "verify_project", return_value=self.args["container_id"]))
        stack.enter_context(patch.object(first_run, "run", return_value='{"OSType":"linux","ID":"engine"}'))
        self.state = stack.enter_context(patch.object(first_run, "request", return_value=(302, "/admin/onboarding", b"")))
        self.issue = stack.enter_context(patch.object(first_run, "issue_bootstrap_claim", return_value="a" * 43))
        self.conn = Mock()
        self.conn.sock.getpeercert.return_value = self.der
        self.conn.getresponse.return_value.status = 200
        stack.enter_context(patch.object(first_run.http.client, "HTTPSConnection", return_value=self.conn))
        return stack

    def test_disabled_before_read_or_any_external_action(self):
        stream = Mock()
        with patch.object(first_run, "issue_bootstrap_claim") as issue:
            self.assertEqual(first_run.managed_bootstrap(stream, **self.args), "disabled")
        stream.read.assert_not_called()
        issue.assert_not_called()

    def test_invalid_input_rejected_before_issuance(self):
        values = [b"x" * 4097, b"not-json", b'{"password":"short","confirmation":"short"}',
                  b'{"password":"valid-password","confirmation":"other"}',
                  b'{"password":" valid-password","confirmation":" valid-password"}']
        with self.mocks():
            for data in values:
                with self.subTest(data=data):
                    self.assertEqual(first_run.managed_bootstrap(io.BytesIO(data), **self.args), "invalid-input")
            self.issue.assert_not_called()

    def test_submission_pins_peer_and_sends_once(self):
        with self.mocks():
            self.state.side_effect = [(302, "/admin/onboarding", b""), (302, "/admin/login", b"")]
            self.assertEqual(first_run.managed_bootstrap(self.stream(), **self.args), "submitted")
            self.assertTrue(self.args["reservation"].retain)
            self.issue.assert_called_once()
            self.conn.request.assert_called_once()
            args, kwargs = self.conn.request.call_args
            self.assertEqual(args, ("POST", "/control/bootstrap/admin"))
            self.assertEqual(json.loads(kwargs["body"]), {"claim": "a" * 43,
                             "password": "valid-password", "confirm": True})
            self.conn.close.assert_called_once()

    def test_pin_mismatch_never_sends_password(self):
        with self.mocks():
            self.conn.sock.getpeercert.return_value = b"wrong"
            self.assertEqual(first_run.managed_bootstrap(self.stream(), **self.args), "recovery-required")
            self.conn.request.assert_not_called()

    def test_changed_state_prevents_claim(self):
        with self.mocks():
            self.state.return_value = (302, "/admin/login", b"")
            self.assertEqual(first_run.managed_bootstrap(self.stream(), **self.args), "recovery-required")
            self.issue.assert_not_called()

    def test_ambiguous_response_checks_state_without_retry_or_secret_output(self):
        with self.mocks(), contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            self.conn.getresponse.side_effect = OSError("valid-password")
            self.state.side_effect = [(302, "/admin/onboarding", b""), (302, "/admin/login", b"")]
            self.assertEqual(first_run.managed_bootstrap(self.stream(), **self.args), "configured-recovery-required")
            self.issue.assert_called_once()
            self.conn.request.assert_called_once()
            self.assertEqual(out.getvalue() + err.getvalue(), "")

    def test_rejected_and_issuance_failure_never_retry(self):
        for status in (401, 409):
            with self.subTest(status=status), self.mocks():
                self.conn.getresponse.return_value.status = status
                self.assertEqual(first_run.managed_bootstrap(self.stream(), **self.args), "recovery-required")
                self.issue.assert_called_once()
        with self.mocks():
            self.issue.side_effect = TimeoutError("sensitive")
            self.assertEqual(first_run.managed_bootstrap(self.stream(), **self.args), "not-configured-recovery-required")
            self.issue.assert_called_once()
            self.conn.request.assert_not_called()
            self.assertTrue(self.args["reservation"].retain)

    def test_disconnect_before_issuance_and_before_post(self):
        with self.mocks():
            self.args["protocol"].check_parent.side_effect = BrokenPipeError()
            self.assertEqual(first_run.managed_bootstrap(self.stream(), **self.args), "recovery-required")
            self.issue.assert_not_called()
            self.assertFalse(self.args["reservation"].retain)
        self.args["protocol"].reset_mock(side_effect=True)
        with self.mocks():
            self.args["protocol"].check_parent.side_effect = [None, BrokenPipeError()]
            self.assertEqual(first_run.managed_bootstrap(self.stream(), **self.args), "not-configured-recovery-required")
            self.issue.assert_called_once()
            self.conn.request.assert_not_called()
            self.assertTrue(self.args["reservation"].retain)

    def test_pipe_disconnect_and_expired_deadline_detected(self):
        reader, writer = os.pipe()
        with os.fdopen(writer, "w") as output:
            protocol = first_run.ManagedProtocol(output, io.BytesIO())
            protocol.check_parent(time.monotonic() + 2)
            os.close(reader)
            with self.assertRaises(BrokenPipeError):
                protocol.check_parent(time.monotonic() + 2)
            with self.assertRaises(TimeoutError):
                protocol.check_parent(time.monotonic() - 1)

    def test_reservation_conflict_and_retention(self):
        with patch.object(first_run, "run", side_effect=["a" * 64, subprocess.CalledProcessError(1, "docker"), "removed"]) as run:
            first = first_run.BootstrapReservation("project", "image")
            with self.assertRaises(subprocess.CalledProcessError):
                first_run.BootstrapReservation("project", "image")
            self.assertEqual(run.call_args_list[0].args[5], run.call_args_list[1].args[5])
            first.retain = True
            first.close()
            self.assertEqual(run.call_count, 2)
            first.retain = False
            first.close()
            self.assertEqual(run.call_args.args, ("docker", "rm", "-v", "a" * 64))

    def test_simultaneous_reservations_have_one_winner(self):
        occupied = set()
        mutex = threading.Lock()
        barrier = threading.Barrier(2)
        results = []

        def docker(*args):
            name = args[5]
            with mutex:
                if name in occupied:
                    raise subprocess.CalledProcessError(1, "docker")
                occupied.add(name)
                return "a" * 64

        def attempt():
            barrier.wait()
            try:
                results.append(first_run.BootstrapReservation("project", "image"))
            except subprocess.CalledProcessError:
                results.append(None)

        with patch.object(first_run, "run", side_effect=docker):
            threads = [threading.Thread(target=attempt) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=2)
            self.assertEqual(sum(result is not None for result in results), 1)
            self.assertEqual(len(results), 2)

    def test_issuer_deadline_kills_local_cli(self):
        popen = subprocess.Popen
        with patch.object(first_run.subprocess, "Popen") as start:
            start.side_effect = lambda *args, **kwargs: popen([sys.executable, "-c", "import time; time.sleep(10)"], **kwargs)
            with self.assertRaises(TimeoutError):
                first_run.issue_bootstrap_claim("container", time.monotonic() + 0.1)

    def test_success_without_verified_admin_retains_reservation(self):
        with self.mocks():
            self.assertEqual(first_run.managed_bootstrap(self.stream(), **self.args), "recovery-required")
            self.assertTrue(self.args["reservation"].retain)

    def test_protocol_gate_precedes_preflight(self):
        with patch.object(first_run, "managed_main") as preflight:
            self.assertEqual(first_run.main(["managed-protocol"]), 1)
            preflight.assert_not_called()

    def test_claim_capture_is_bounded_and_closes_stdin(self):
        popen = subprocess.Popen
        for code, valid in [("import sys; print('a'*43)", True),
                            ("import sys; print('a'*10000)", False),
                            ("import sys; print(sys.stdin.read())", False)]:
            with self.subTest(code=code), patch.object(first_run.subprocess, "Popen") as start:
                start.side_effect = lambda *args, **kwargs: popen([sys.executable, "-c", code], **kwargs)
                if valid:
                    self.assertEqual(first_run.issue_bootstrap_claim("container", time.monotonic() + 10), "a" * 43)
                else:
                    with self.assertRaises(ValueError):
                        first_run.issue_bootstrap_claim("container", time.monotonic() + 10)
                self.assertEqual(start.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_protocol_frames_and_confirmation_are_bounded(self):
        output = io.StringIO()
        protocol = first_run.ManagedProtocol(output, io.BytesIO(b"YES\ncredentials"))
        self.assertTrue(protocol.confirm_certificate("project", "public cert", "a" * 64))
        self.assertEqual(json.loads(output.getvalue()), {"type": "certificate", "project": "project",
                                                        "certificate": "public cert", "sha256": "a" * 64})
        self.assertEqual(protocol.input.read(), b"credentials")
        with self.assertRaises(ValueError):
            protocol.send({"type": "x" * 8192})
        self.assertFalse(first_run.ManagedProtocol(io.StringIO(), io.BytesIO(b"YES!\n")).confirm_certificate("p", "c", "f"))

    def test_ambiguous_response_reports_onboarding_and_unknown_separately(self):
        for state, expected in [((302, "/admin/onboarding", b""), "not-configured-recovery-required"),
                                ((500, None, b""), "recovery-required")]:
            with self.subTest(state=state), self.mocks():
                self.conn.getresponse.side_effect = OSError("lost")
                self.state.side_effect = [(302, "/admin/onboarding", b""), state]
                self.assertEqual(first_run.managed_bootstrap(self.stream(), **self.args), expected)


if __name__ == "__main__":
    unittest.main()
