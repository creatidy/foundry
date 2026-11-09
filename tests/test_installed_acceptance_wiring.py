"""Offline-only tests for phase wiring, isolation and fail-closed entry."""

from types import SimpleNamespace
import json
import os
from pathlib import Path
import shutil
import ssl
import stat
import tempfile
import unittest
from unittest import mock

import run_installed_acceptance as entry


class WiringTests(unittest.TestCase):
    def test_prepare_fails_before_loading_unverified_host_mi(self):
        with mock.patch.object(entry, '_checked_file') as checked, \
             mock.patch.object(entry, 'verify_mi_metadata') as metadata, \
             mock.patch.object(entry, 'controlled_cuts') as cuts:
            with self.assertRaisesRegex(RuntimeError, 'host MI execution disabled'):
                entry._prepare(SimpleNamespace())
        checked.assert_not_called()
        metadata.assert_not_called()
        cuts.assert_not_called()

    def test_project_preserves_original_error_when_cleanup_is_blocked(self):
        args = SimpleNamespace(new_image_id='new', old_image_id='old', socket='/run/docker.sock', engine_id='engine')
        project = mock.Mock()
        project.cleanup.side_effect = ValueError('no retry')
        evidence = mock.Mock(data={'phases': {}})
        with mock.patch.object(entry, 'InstalledProject', return_value=project), \
             mock.patch.object(entry, 'InstalledLifecycleAdapter'):
            with self.assertRaisesRegex(ValueError, 'identity mismatch') as caught:
                with entry._project(args, phase='execution', evidence=evidence):
                    raise ValueError('identity mismatch')
        self.assertEqual('failed', evidence.data['phases']['execution']['cleanup'])
        self.assertEqual('failed', evidence.data['phases']['execution']['status'])
        self.assertNotIn('checks_passed', evidence.data['phases']['execution'])
        self.assertIn('cleanup also failed', caught.exception.__notes__[0])

    def test_successful_body_is_not_passed_when_cleanup_fails(self):
        args = SimpleNamespace(new_image_id='new', old_image_id='old', socket='/run/docker.sock', engine_id='engine')
        project = mock.Mock()
        project.cleanup.side_effect = ValueError('cleanup failed')
        evidence = mock.Mock(data={'phases': {}})
        with mock.patch.object(entry, 'InstalledProject', return_value=project), \
             mock.patch.object(entry, 'InstalledLifecycleAdapter'):
            with self.assertRaisesRegex(ValueError, 'cleanup failed'):
                with entry._project(args, phase='execution', evidence=evidence):
                    pass
        record = evidence.data['phases']['execution']
        self.assertEqual('cleanup_failed', record['status'])
        self.assertEqual('failed', record['cleanup'])
        self.assertNotIn('checks_passed', record)

    def test_discovery_does_not_contact_docker_for_invalid_socket(self):
        with mock.patch.object(entry, 'validate_engine_socket', side_effect=ValueError('unsafe')), \
             mock.patch.object(entry, 'InstalledProject') as project:
            with self.assertRaisesRegex(ValueError, 'unsafe'):
                entry._discover_engine(SimpleNamespace(socket='/run/docker.sock', engine_id=None))
        project.assert_not_called()

    def test_discovery_rejects_unexpected_daemon_identity(self):
        data = {'ID': 'another-engine-123', 'OSType': 'linux', 'CgroupDriver': 'cgroupfs',
                'MemoryLimit': True, 'SwapLimit': True, 'PidsLimit': True, 'CpuCfsQuota': True}
        with mock.patch.object(entry, 'validate_engine_socket'), \
             mock.patch.object(entry, 'InstalledProject') as project:
            project.return_value._run.return_value = json.dumps(data)
            with self.assertRaisesRegex(ValueError, 'identity differs'):
                entry._discover_engine(SimpleNamespace(socket='/run/docker.sock', engine_id='expected-engine-123'))

    def test_main_bounds_batch_and_restores_signal_handlers(self):
        argv = ['runner', '--socket', '/run/docker.sock', '--base-digest', 'sha256:' + 'a' * 64,
                '--sr-repo', '/sr', '--mi-repo', '/mi', '--worker-sha256', 'a' * 64,
                '--fake-appserver', '/fake', '--fake-sha256', 'b' * 64,
                '--evidence-dir', '/tmp/kilo/example']
        with mock.patch.object(entry.sys, 'argv', argv), mock.patch.object(entry, 'run', side_effect=RuntimeError('failed')):
            with mock.patch.object(entry.signal, 'signal', side_effect=['previous-alarm', 'previous-term', None, None]) as handlers:
                with mock.patch.object(entry.signal, 'alarm') as alarm:
                    with self.assertRaisesRegex(RuntimeError, 'failed'):
                        entry.main()
        self.assertEqual([mock.call(5400), mock.call(0)], alarm.call_args_list)
        self.assertEqual(mock.call(entry.signal.SIGALRM, 'previous-alarm'), handlers.call_args_list[2])
        self.assertEqual(mock.call(entry.signal.SIGTERM, 'previous-term'), handlers.call_args_list[3])

    def test_evidence_is_private_exclusive_and_tracks_pending_phases(self):
        directory = tempfile.mkdtemp(prefix='foundry-report-test-', dir='/tmp/kilo')
        os.rmdir(directory)
        try:
            report = entry.Evidence(directory)
            report.close()
            self.assertEqual(0o700, stat.S_IMODE(os.stat(directory).st_mode))
            path = Path(directory) / 'acceptance.json'
            self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
            document = json.loads(path.read_text())
            self.assertEqual('running', document['status'])
            self.assertEqual('synthetic_upgrade_candidate_installed_acceptance', document['scope'])
            self.assertEqual(entry.provenance.OLD_SR, document['foundry_image_sr_revision'])
            self.assertEqual(entry.provenance.NEW_SR, document['candidate_image_sr_revision'])
            self.assertEqual('not_established', document['foundry_image_upgrade_compatibility'])
            self.assertIn('sandbox not verified', document['worker_backend_scope'])
            self.assertTrue(all(item['status'] == 'pending' for item in document['phases'].values()))
            with self.assertRaises(FileExistsError):
                entry.Evidence(directory)
            with self.assertRaises(ValueError):
                entry.Evidence(directory + '/nested')
        finally:
            shutil.rmtree(directory)

    def test_phases_use_distinct_projects_and_live_controls(self):
        events, projects, controls = [], [], []
        cuts = {name: (name.encode(), (name + "-trust").encode()) for name in
                ("fresh", "stale", "withdrawn", "incompatible")}

        class Project:
            def __init__(self, **kwargs):
                self.number = len(projects)
                self.image_id = kwargs["image_id"]
                projects.append(self)
                events.append((self.number, "create"))

            def cleanup(self):
                events.append((self.number, "cleanup"))

        class Adapter:
            def __init__(self, project, old, new):
                self.project, self.old_image_id, self.new_image_id = project, old, new
                self.admin = object()

            def start_old(self):
                events.append((self.project.number, "start_old"))

            def start_new_with_cut(self, publication, trust, digest):
                self.assert_fresh = (publication, trust, digest)
                events.append((self.project.number, "start_fresh"))

            def stop(self):
                events.append((self.project.number, "stop"))

            def exchange(self, *args, **kwargs):
                return 200, {"retained": True}

        class Control:
            def __init__(self, adapter, verify_only):
                self.number, self.verify_only, self.closed = adapter.project.number, verify_only, False
                controls.append(self)
                events.append((self.number, "verifier" if verify_only else "worker"))

            def worker_ready(self):
                self.assert_open()
                return True

            def verify_cut(self, key, response, digest):
                self.assert_open()
                return True

            def assert_open(self):
                if self.closed:
                    raise AssertionError("worker control closed early")

            def close(self):
                self.closed = True
                events.append((self.number, "close"))

        def variant(adapter, key, supplied, ready, verify):
            self.assertIs(supplied, cuts)
            self.assertTrue(ready())
            self.assertTrue(verify(key, {}, "digest"))
            events.append((adapter.project.number, "variant"))
            return {}, {}

        def preactivation(adapter, trust, key, retained, verify):
            self.assertEqual(b"fresh-trust", trust)
            self.assertTrue(verify(key, retained, "digest"))
            events.append((adapter.project.number, "preactivation"))

        worker_archive = object()
        worker_control = object()

        def migration(adapter, publication, *, start_worker):
            self.assertEqual(b"fresh", publication)
            self.assertIs(worker_control, start_worker("resume", worker_archive))
            events.append((adapter.project.number, "migration"))

        args = SimpleNamespace(authorize_disposable_linux_engine=True, socket="/private/sock", engine_id="engine",
                               old_image_id="old", new_image_id="new", worker_sha256="a" * 64,
                               fake_appserver="fake", fake_sha256="b" * 64)
        with mock.patch.object(entry.host_mi_provenance, "require_verified_host_mi"), \
             mock.patch.object(entry, "_checked_file", return_value=b"fixture"), \
             mock.patch.object(entry, "verify_mi_metadata"), mock.patch.object(entry, "controlled_cuts", return_value=cuts), \
             mock.patch.object(entry, "InstalledProject", Project), mock.patch.object(entry, "InstalledLifecycleAdapter", Adapter), \
             mock.patch.object(entry, "_security_negatives", side_effect=lambda a: events.append((a.project.number, "security"))), \
             mock.patch.object(entry, "_client", return_value="key"), \
             mock.patch.object(entry, "_control", side_effect=lambda a, h, f, x, verify_only=False: Control(a, verify_only)), \
             mock.patch.object(entry, "assert_input_boundary", side_effect=lambda a, k, c, mi_enabled: events.append((a.project.number, "bound" if mi_enabled else "unbound"))), \
             mock.patch.object(entry, "_execution", side_effect=lambda a, h, f, x: events.append((a.project.number, "execution"))), \
             mock.patch.object(entry, "_bound_selection", return_value={"retained": True}), \
             mock.patch.object(entry, "run_variant_reload_acceptance", side_effect=variant), \
             mock.patch.object(entry, "run_stale_installed", side_effect=lambda a, *x, **kw: events.append((a.project.number, "stale"))), \
             mock.patch.object(entry, "run_preactivation_failure", side_effect=preactivation), \
             mock.patch.object(entry, "start_live_worker", return_value=worker_control) as start_worker, \
             mock.patch.object(entry, "run_lifecycle_acceptance", side_effect=migration):
            entry.run_draft(args)
        self.assertEqual('resume', start_worker.call_args.kwargs['migration'])
        self.assertIs(worker_archive, start_worker.call_args.kwargs['worker_archive'])
        self.assertEqual(6, len(projects))
        self.assertEqual("new", projects[0].image_id)
        self.assertTrue(all(project.image_id == "old" for project in projects[1:]))
        self.assertEqual([0, 1, 2, 3, 4, 5], [number for number, event in events if event == "cleanup"])
        self.assertTrue(all(control.closed for control in controls))
        self.assertLess(events.index((2, "variant")), events.index((2, "close")))
        for number, operation in enumerate(("unbound", "execution", "variant", "stale", "preactivation", "migration")):
            self.assertIn((number, operation), events)

    def test_full_entrypoint_requires_explicit_authorization(self):
        args = SimpleNamespace(authorize_disposable_linux_engine=False, authorize_image_build=False)
        with mock.patch.object(entry.build, "DockerExecutor") as executor:
            with self.assertRaisesRegex(ValueError, "authorization"):
                entry.run(args)
        executor.assert_not_called()

    def test_verified_images_live_through_phases_and_cleanup_on_failure(self):
        args = SimpleNamespace(authorize_disposable_linux_engine=True, authorize_image_build=True,
                               confirm_external_boundaries=True, sr_repo="/sr", mi_repo="/mi",
                               base_digest="sha256:" + "a" * 64, socket="/private/sock", engine_id="engine",
                               zai_python=None, zai_output_dir=None, authorize_zai_source_reads=False,
                               worker_sha256='a' * 64, fake_appserver='/fake', fake_sha256='b' * 64,
                               preflight_evidence='/tmp/kilo/preflight/acceptance.json',
                               evidence_dir="/tmp/kilo/test-report")
        events = []
        evidence = mock.Mock(data={'image_cleanup': {}, 'images': {}, 'preflight': {}})

        class Executor:
            def __init__(self, **kwargs):
                self.number = len([item for item in events if item == "enter"])
                self.probe_uncertain = False
                self.cleanup_failed = False

            def __enter__(self):
                events.append("enter")
                return self

            def __exit__(self, *exc):
                events.append("exit" + str(self.number))

            def preflight(self, *, base_digest):
                events.append("preflight" + str(self.number))

        def verified(executor, **kwargs):
            events.append(kwargs["revision"])
            return "image" + str(executor.number)

        def phases(received, *, prepared, evidence):
            self.assertEqual(("image0", "image1"), (received.old_image_id, received.new_image_id))
            self.assertEqual("prepared", prepared)
            self.assertNotIn("exit0", events)
            self.assertNotIn("exit1", events)
            raise RuntimeError("phase failure")

        with mock.patch.object(entry.Path, "is_dir", return_value=True), \
             mock.patch.object(entry.provenance, "dockerfile"), \
             mock.patch.object(entry, "_prepare", return_value="prepared"), \
             mock.patch.object(entry, "Evidence", return_value=evidence), \
             mock.patch.object(entry, "_read_preflight", return_value="engine"), \
             mock.patch.object(entry, "_discover_engine", return_value="engine"), \
             mock.patch.object(entry.build, "DockerExecutor", Executor), \
             mock.patch.object(entry.build, "build_verified", side_effect=verified), \
             mock.patch.object(entry, "run_draft", side_effect=phases):
            with self.assertRaisesRegex(RuntimeError, "phase failure"):
                entry.run(args)
        self.assertEqual(["enter", "preflight0", entry.provenance.OLD_SR, "enter", "preflight1", entry.provenance.NEW_SR,
                          "exit1", "exit0"], events)
        self.assertEqual({'old': 'passed', 'new': 'passed'}, evidence.data['image_cleanup'])
        self.assertEqual('failed', evidence.data['status'])

    def test_real_source_requires_all_separate_authorization_inputs(self):
        args = SimpleNamespace(authorize_disposable_linux_engine=True, authorize_image_build=True,
                               confirm_external_boundaries=True, sr_repo="/sr", mi_repo="/mi",
                               base_digest="sha256:" + "a" * 64, zai_python="/venv/bin/python",
                               zai_output_dir=None, authorize_zai_source_reads=False,
                               worker_sha256='a' * 64, fake_appserver='/fake', fake_sha256='b' * 64,
                               preflight_evidence='/tmp/kilo/preflight/acceptance.json', socket='/private/sock', engine_id=None)
        with mock.patch.object(entry.Path, "is_dir", return_value=True), \
             mock.patch.object(entry, "_read_preflight", return_value="engine"), \
             mock.patch.object(entry.provenance, "dockerfile"), \
             mock.patch.object(entry.subprocess, "run") as subprocess_run, \
             mock.patch.object(entry.build, "DockerExecutor") as executor:
            with self.assertRaisesRegex(ValueError, "separate authorization"):
                entry.run(args)
        subprocess_run.assert_not_called()
        executor.assert_not_called()

    def test_full_success_is_labeled_synthetic_acceptance(self):
        args = SimpleNamespace(authorize_disposable_linux_engine=True, authorize_image_build=True,
                               confirm_external_boundaries=True, sr_repo='/sr', mi_repo='/mi',
                               base_digest='sha256:' + 'a' * 64, socket='/sock', engine_id=None,
                               preflight_evidence='/tmp/kilo/probe/acceptance.json',
                               worker_sha256='a' * 64, fake_appserver='/fake', fake_sha256='b' * 64,
                               zai_python=None, zai_output_dir=None, authorize_zai_source_reads=False,
                               evidence_dir='/tmp/kilo/full')
        evidence = mock.Mock(data={'preflight': {}})
        with mock.patch.object(entry, '_read_preflight', return_value='verified-engine-id'), \
             mock.patch.object(entry.Path, 'is_dir', return_value=True), \
             mock.patch.object(entry.provenance, 'dockerfile'), \
             mock.patch.object(entry, '_prepare'), \
             mock.patch.object(entry, 'Evidence', return_value=evidence), \
             mock.patch.object(entry, '_run_authorized'):
            entry.run(args)
        self.assertEqual('synthetic_acceptance_passed', evidence.data['status'])

    def test_preflight_only_reports_probe_without_build_or_acceptance(self):
        args = SimpleNamespace(preflight_only=True, authorize_engine_preflight=True,
                               base_digest='sha256:' + 'a' * 64, socket='/run/docker.sock', engine_id=None,
                               evidence_dir='/tmp/kilo/probe', zai_python=None, zai_output_dir=None,
                               authorize_zai_source_reads=False)
        evidence = mock.Mock(data={'preflight': {}})
        executor = mock.MagicMock()
        executor.__enter__.return_value = executor
        executor.preflight.return_value = {'memory': '536870912', 'swap': '0', 'pids': '128',
                                          'cpu': '100000 100000', 'available': 11 * 1024**3,
                                          'untrusted_extra': 'do-not-copy'}
        with mock.patch.object(entry, 'Evidence', return_value=evidence) as evidence_factory, \
             mock.patch.object(entry, '_discover_engine', return_value='verified-engine-id'), \
             mock.patch.object(entry.build, 'DockerExecutor', return_value=executor), \
             mock.patch.object(entry.build, 'build_verified') as build, \
             mock.patch.object(entry, '_prepare') as prepare, \
             mock.patch.object(entry, '_run_authorized') as full_run, \
             mock.patch.object(entry.subprocess, 'run') as source:
            entry.run(args)
        evidence_factory.assert_called_once_with(args.evidence_dir, preflight_only=True)
        executor.preflight.assert_called_once_with(base_digest=args.base_digest)
        self.assertEqual('verified-engine-id', args.engine_id)
        self.assertEqual('preflight_passed', evidence.data['status'])
        self.assertEqual('passed', evidence.data['preflight']['probe']['cleanup'])
        self.assertNotIn('untrusted_extra', evidence.data['preflight']['probe'])
        build.assert_not_called()
        prepare.assert_not_called()
        full_run.assert_not_called()
        source.assert_not_called()

    def test_preflight_requires_its_own_authorization(self):
        args = SimpleNamespace(preflight_only=True, authorize_engine_preflight=False)
        with mock.patch.object(entry, '_discover_engine') as discover:
            with self.assertRaisesRegex(ValueError, 'preflight authorization'):
                entry.run(args)
        discover.assert_not_called()

    def test_preflight_failure_is_not_reported_as_cleanup_success(self):
        args = SimpleNamespace(preflight_only=True, authorize_engine_preflight=True,
                               base_digest='sha256:' + 'a' * 64, socket='/run/docker.sock', engine_id=None,
                               evidence_dir='/tmp/kilo/probe', zai_python=None, zai_output_dir=None,
                               authorize_zai_source_reads=False)
        evidence = mock.Mock(data={'preflight': {}})
        executor = mock.MagicMock()
        executor.__enter__.return_value = executor
        executor.preflight.side_effect = TimeoutError('probe')
        with mock.patch.object(entry, 'Evidence', return_value=evidence), \
             mock.patch.object(entry, '_discover_engine', return_value='verified-engine-id'), \
             mock.patch.object(entry.build, 'DockerExecutor', return_value=executor):
            with self.assertRaises(TimeoutError):
                entry.run(args)
        self.assertEqual('failed', evidence.data['status'])
        self.assertEqual({'status': 'failed', 'cleanup': 'unknown'}, evidence.data['preflight']['probe'])
        evidence.close.assert_called_once()

    def test_reviewed_preflight_is_bound_to_socket_base_and_engine(self):
        directory = tempfile.mkdtemp(prefix='foundry-preflight-test-', dir='/tmp/kilo')
        os.rmdir(directory)
        base = 'sha256:' + 'a' * 64
        try:
            evidence = entry.Evidence(directory, preflight_only=True)
            evidence.data.update(status='preflight_passed', socket='/run/docker.sock', base_digest=base,
                                 engine_id='verified-engine-id')
            evidence.data['preflight']['probe'] = {'status': 'passed', 'cleanup': 'passed'}
            evidence.save()
            evidence.close()
            path = directory + '/acceptance.json'
            document = json.loads(Path(path).read_text())
            self.assertFalse(document['synthetic_evidence'])
            self.assertEqual('not_established', document['daemon_host_isolation'])
            self.assertEqual('not_established', document['builder_storage_quota'])
            self.assertEqual('verified-engine-id', entry._read_preflight(path, '/run/docker.sock', base))
            with self.assertRaisesRegex(ValueError, 'does not match'):
                entry._read_preflight(path, '/different.sock', base)
            with self.assertRaisesRegex(ValueError, 'does not match'):
                entry._read_preflight(path, '/run/docker.sock', 'sha256:' + 'b' * 64)
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(ValueError, 'unprotected'):
                entry._read_preflight(path, '/run/docker.sock', base)
        finally:
            shutil.rmtree(directory)

    def test_worker_evidence_is_strictly_allowlisted(self):
        checks = ('both_sources_routable both_own_projections_valid cross_client_projection_rejected '
                  'modified_projections_rejected restricted_source_excluded_from_selection restricted_pin_non_200 '
                  'restricted_responses_exclude_preferred_source input_4097_no_solution both_gateway_executions_completed '
                  'preferred_backend_model_and_effort_observed both_audit_targets_match_selection '
                  'both_execution_and_projection_receipts_verified alternate_disconnect_and_recovery').split()
        def case(source):
            return {'source_id': source, 'resource_id': source + ':gpt-6-sol:high',
                    'model': {'provider': 'openai', 'model': 'gpt-6-sol', 'variant': 'high', 'reasoning_effort': 'high'},
                    'client_id': 'client-' + 'a' * 8, 'selection_decision_id': 'rd-' + 'b' * 32,
                    'projection_request_id': 'c' * 32, 'projection_binding_sha256': 'd' * 64,
                    'projection_receipt_sha256': 'e' * 64, 'gateway_request_id': 'chatcmpl-' + 'f' * 32,
                    'gateway_decision_id': 'rd-' + 'b' * 32, 'execution_receipt_sha256': 'a' * 64}
        result = {'schema_version': 1, 'synthetic': True, 'cut_sha256': entry.fixture.EXPECTED_SHA256,
                  'limitations': ['same_container_test_worker', 'fake_backend_and_spawner', 'sandbox_not_verified'],
                  'cases': [case('foundry-worker-a'), case('foundry-worker-b')],
                  'checks': dict.fromkeys(checks, True)}
        adapter = mock.Mock()
        adapter.project.token = 'a' * 32
        adapter.admin.cookie, adapter.admin.csrf = 'private-cookie', 'private-csrf'
        adapter.project.run_worker_bundle.return_value = json.dumps(result)
        args = SimpleNamespace(worker_sha256='a' * 64, fake_sha256='b' * 64)
        self.assertEqual(result, entry._execution(adapter, b'helper', b'fake', args))
        result['cases'][0]['secret'] = 'must-not-be-written'
        adapter.project.run_worker_bundle.return_value = json.dumps(result)
        with self.assertRaisesRegex(ValueError, 'worker evidence case'):
            entry._execution(adapter, b'helper', b'fake', args)

    def test_security_negatives_fail_closed_offline(self):
        adapter = mock.Mock()
        adapter.project.port = 12345
        adapter.admin = SimpleNamespace(assert_auth_boundaries=mock.Mock())
        adapter.exchange.return_value = (401, {})
        adapter.project.tls_context.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError("hostname")
        connection = mock.Mock()
        connection.request.side_effect = ssl.SSLCertVerificationError("untrusted")
        with mock.patch.object(entry.ssl, "create_default_context", return_value=mock.Mock()), \
             mock.patch.object(entry.http.client, "HTTPSConnection", return_value=connection), \
             mock.patch.object(entry.socket, "create_connection"):
            entry._security_negatives(adapter)
        self.assertEqual(2, adapter.exchange.call_count)
        adapter.admin.assert_auth_boundaries.assert_called_once_with()
        self.assertEqual({}, adapter.exchange.call_args_list[0].args[3])
        self.assertEqual("Bearer foundry-invalid-test-key", adapter.exchange.call_args_list[1].args[3]["Authorization"])
        adapter.exchange.return_value = (200, {})
        with self.assertRaisesRegex(AssertionError, "credentials"):
            entry._security_negatives(adapter)


if __name__ == "__main__":
    unittest.main()
