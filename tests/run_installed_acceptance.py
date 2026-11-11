"""Authorized test-only preflight and isolated installed-acceptance runner."""

import argparse
from contextlib import contextmanager
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile

import image_build_executor as build
import image_provenance as provenance
import host_mi_provenance
import mi_publication_fixture as fixture
import zai_real_source_check as zai
from installed_lifecycle_adapter import InstalledLifecycleAdapter
from installed_mi_lifecycle_scenario import (_bound_selection, run_lifecycle_acceptance,
                                             run_preactivation_failure, run_variant_reload_acceptance)
from installed_provisioning import CommandFailure, InstalledProject, ROOT, WORKER_DIAGNOSTIC_RE, validate_engine_socket
from installed_worker_control import assert_input_boundary, run_stale_installed, start_live_worker


RUNNER = b'''import json, sys
settings = json.load(sys.stdin)
nonce = settings.pop('_foundry_diagnostic_nonce')
try:
    from worker_mi_acceptance import run_in_container
    print(json.dumps(run_in_container(settings), separators=(',', ':')))
except Exception as exc:
    category = next((name for cls, name in ((AssertionError, 'assertion'), (TimeoutError, 'timeout'),
                    (ValueError, 'value'), (OSError, 'os'), (RuntimeError, 'runtime'))
                    if isinstance(exc, cls)), 'other')
    line = 0
    caller = 0
    status = 0
    error_type = 'other'
    error_code = 'other'
    tb = exc.__traceback__
    while tb:
        if tb.tb_frame.f_code.co_filename.endswith('/worker_mi_acceptance.py'):
            caller = line
            line = tb.tb_lineno
            if tb.tb_frame.f_code.co_name == '_assert_gateway_error':
                value = tb.tb_frame.f_locals.get('status')
                if type(value) is int and 100 <= value <= 599:
                    status = value
                payload = tb.tb_frame.f_locals.get('payload')
                error = payload.get('error') if isinstance(payload, dict) else None
                if isinstance(error, dict):
                    if error.get('type') in ('permission_error', 'not_found_error', 'api_error', 'invalid_request_error'):
                        error_type = error['type']
                    if error.get('code') in ('unauthorized_target', 'pin_target_not_found', 'target_unavailable',
                                             'adapter_unavailable', 'backend_failure', 'capability_unassessed'):
                        error_code = error['code']
        tb = tb.tb_next
    print(f'FOUNDRY_WORKER_FAILURE:{nonce}:{category}:{line}:{caller}:{status}:{error_type}:{error_code}', file=sys.stderr)
    raise SystemExit(1) from None
'''

PHASE_CHECKS = {
    'baseline': ['missing_and_invalid_credentials_rejected', 'admin_csrf_and_inference_separation', 'untrusted_and_wrong_hostname_tls_rejected', 'mi_disabled_4097_admitted'],
    'execution': ['worker_execution_scenario_completed'],
    'variant_reload': ['mi_enabled_4097_blocked', 'stale_reload_rejected', 'incompatible_reload_rejected', 'withdrawal_reload_blocks', 'retained_projection_verified'],
    'stale_startup': ['stale_cut_4096_no_solution', 'stale_projection_survives_restart',
                      'stale_cut_4096_no_solution_after_restart'],
    'preactivation': ['incompatible_activation_rejected', 'fresh_cut_and_projection_recovered'],
    'migration_backup_restore': ['old_worker_routes_and_executes', 'upgraded_worker_routes_and_executes', 'unauthorized_reload_rejected', 'invalid_reload_preserves_projection', 'restart_retains_projection', 'restored_worker_routes_and_executes', 'post_backup_client_rejected', 'rollback_worker_routes_and_executes'],
}

# Fixed allowlist only: never enumerate a checkout or include file contents/paths
# supplied by the operator in the report.
PROVENANCE_FILES = (
    'Dockerfile.mi', 'compose.yaml', 'scripts/docker_socket_validation.py',
    'scripts/local_tls_init.py', 'scripts/local_tls_up.py',
    'tests/host_mi_provenance.py', 'tests/image_build_executor.py',
    'tests/image_provenance.py', 'tests/installed_admin.py',
    'tests/installed_lifecycle_adapter.py', 'tests/installed_mi_lifecycle_scenario.py',
    'tests/installed_provisioning.py', 'tests/installed_worker_control.py',
    'tests/mi_publication_fixture.py', 'tests/run_installed_acceptance.py',
    'tests/verified_mi_child.py', 'tests/worker_mi_acceptance.py',
    'tests/zai_real_source_check.py',
)


def _file_manifest():
    result = {}
    for name in PROVENANCE_FILES:
        parent = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            parts = Path(name).parts
            if not parts or any(part in ('', '.', '..') for part in parts) or Path(name).is_absolute():
                raise ValueError('invalid provenance path')
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                old_parent, parent = parent, child
                os.close(old_parent)
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        finally:
            os.close(parent)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > 1024 * 1024:
                raise ValueError('invalid provenance file')
            with os.fdopen(os.dup(fd), 'rb') as stream:
                data = stream.read(1024 * 1024 + 1)
            after = os.fstat(fd)
            if (len(data) != before.st_size or len(data) > 1024 * 1024 or
                    (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise ValueError('provenance file changed while reading')
            result[name] = hashlib.sha256(data).hexdigest()
        finally:
            os.close(fd)
    return result


def _input_provenance(manifest, source, prepared, args):
    helper, fake, _ = prepared
    hashes = {'worker_sha256': hashlib.sha256(helper).hexdigest(),
              'fake_sha256': hashlib.sha256(fake).hexdigest()}
    if (any(not isinstance(value, str) or re.fullmatch(r'[0-9a-f]{64}', value) is None
            for value in (args.worker_sha256, args.fake_sha256)) or
            hashes['worker_sha256'] != args.worker_sha256 or hashes['fake_sha256'] != args.fake_sha256 or
            hashes['worker_sha256'] != manifest['tests/worker_mi_acceptance.py'] or
            hashlib.sha256(source).hexdigest() != manifest['Dockerfile.mi']):
        raise ValueError('verified inputs differ from provenance manifest')
    return {'source_commit': 'not_established', 'file_sha256': manifest,
            'verified_fixture_sha256': hashes,
            'limitations': ['file_contents_sampled_not_full_repository_identity',
                            'loaded_code_and_transient_changes_not_verified']}


class Evidence:
    """Exclusive, private report outside the disposable engine's volumes."""

    def __init__(self, directory, *, preflight_only=False):
        path = Path(directory)
        if not path.is_absolute() or path.parent != Path('/tmp/kilo') or path.name in ('', '.', '..'):
            raise ValueError('evidence directory must be a new direct child of /tmp/kilo')
        parent = os.open('/tmp/kilo', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(parent)
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise ValueError('evidence parent must be operator-owned and not writable by others')
            os.mkdir(path.name, 0o700, dir_fd=parent)
            directory_fd = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                os.fchmod(directory_fd, 0o700)
                self.fd = os.open('acceptance.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                  0o600, dir_fd=directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            os.close(parent)
        self.data = {'schema_version': 2, 'synthetic_evidence': not preflight_only, 'status': 'running',
                     'scope': 'preflight_only' if preflight_only else 'synthetic_upgrade_candidate_installed_acceptance',
                     'daemon_host_isolation': 'not_established', 'builder_storage_quota': 'not_established',
                     'images': {}, 'cuts': {} if preflight_only else {'fresh': fixture.EXPECTED_SHA256, **fixture.VARIANT_SHA256},
                     'phases': {} if preflight_only else {name: {'status': 'pending', 'cleanup': 'not_started'} for name in PHASE_CHECKS},
                     'preflight': {}, 'image_cleanup': {}}
        if not preflight_only:
            self.data['old_test_image_sr_revision'] = provenance.OLD_SR
            self.data['new_test_image_sr_revision'] = provenance.NEW_SR
            self.data['foundry_image_upgrade_compatibility'] = 'not_established'
            self.data['worker_backend_scope'] = 'synthetic; native worker sandbox not verified'
            self.data['host_https_path'] = 'test TCP proxy with end-to-end router TLS; direct Docker publication not verified'
        self.save()

    def save(self):
        data = (json.dumps(self.data, sort_keys=True, separators=(',', ':')) + '\n').encode()
        os.lseek(self.fd, 0, os.SEEK_SET)
        os.ftruncate(self.fd, 0)
        while data:
            data = data[os.write(self.fd, data):]
        os.fsync(self.fd)

    def close(self):
        os.close(self.fd)


def _checked_file(path, expected):
    if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("independently supplied file digest required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
            raise ValueError("invalid fixture file")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("fixture digest mismatch")
        return data
    finally:
        os.close(fd)


@contextmanager
def _project(args, *, baseline=False, phase=None, evidence=None, cuts=None):
    old, new = (args.new_image_id, args.old_image_id) if baseline else (args.old_image_id, args.new_image_id)
    project = InstalledProject(socket_path=args.socket, engine_id=args.engine_id, image_id=old,
                               authorization="disposable-linux-engine-approved", mi_cuts=cuts,
                               base_digest=args.base_digest)
    record = None
    if evidence is not None:
        record = evidence.data['phases'][phase] = {'status': 'running', 'cleanup': 'pending'}
        evidence.save()
    body_passed = False
    try:
        yield InstalledLifecycleAdapter(project, old, new)
        body_passed = True
    except BaseException:
        if record is not None:
            record['status'] = 'failed'
        raise
    finally:
        original_error = sys.exc_info()[1]
        try:
            project.cleanup()
        except BaseException:
            if record is not None:
                record['cleanup'] = 'failed'
                if body_passed:
                    record['status'] = 'cleanup_failed'
            if original_error is None:
                raise
            original_error.add_note('Test-project cleanup also failed; inspect retained resources.')
        else:
            if record is not None:
                record['cleanup'] = 'passed'
                if body_passed:
                    record['status'] = 'passed'
                    record['checks_passed'] = PHASE_CHECKS[phase]
        finally:
            if record is not None:
                evidence.save()


def _client(adapter, label):
    status, payload = adapter.exchange("POST", "/control/clients", {"label": label}, {}, admin=True)
    if status != 200 or not isinstance(payload, dict) or not isinstance(payload.get("api_key"), str) or not payload["api_key"]:
        raise AssertionError("test client issuance failed")
    return payload["api_key"]


def _security_negatives(adapter):
    request = {"requirement": {"task_level": "L0", "capability_minima": {}, "hard_constraints": {}}}
    for headers in ({}, {"Authorization": "Bearer foundry-invalid-test-key"}):
        status, _ = adapter.exchange("POST", "/v1/select", request, headers, admin=False)
        if status != 401:
            raise AssertionError("missing or invalid credentials were accepted")
    adapter.admin.assert_auth_boundaries()
    conn = http.client.HTTPSConnection("127.0.0.1", adapter.project.port, timeout=10,
                                       context=ssl.create_default_context())
    try:
        try:
            conn.request("GET", "/healthz")
        except ssl.SSLCertVerificationError:
            pass
        else:
            raise AssertionError("untrusted test certificate was accepted")
    finally:
        conn.close()
    context = adapter.project.tls_context()
    with socket.create_connection(("127.0.0.1", adapter.project.port), timeout=10) as raw:
        try:
            with context.wrap_socket(raw, server_hostname="wrong-host.example.invalid"):
                raise AssertionError("certificate hostname mismatch was accepted")
        except ssl.SSLCertVerificationError:
            pass


def _control(adapter, helper, fake, args, *, verify_only=False):
    return start_live_worker(adapter.project, adapter.admin, helper, fake,
                             helper_sha256=args.worker_sha256, fake_sha256=args.fake_sha256,
                             verify_only=verify_only)


def _execution(adapter, helper, fake, args):
    project = adapter.project
    target = "/tmp/foundry-worker-" + project.token
    settings = {"isolated": True, "admin_cookie": adapter.admin.cookie, "admin_csrf": adapter.admin.csrf,
                "http_port": 8787, "worker_port": 8788, "ca_file": "/run/foundry/tls/server.crt",
                "store_file": "/data/server-state.sqlite3", "scratch": target + "/scratch",
                "backend_file": target + "/codex_fake_appserver.py"}
    files = {"runner.py": RUNNER, "worker_mi_acceptance.py": helper, "codex_fake_appserver.py": fake}
    hashes = {"runner.py": hashlib.sha256(RUNNER).hexdigest(), "worker_mi_acceptance.py": args.worker_sha256,
              "codex_fake_appserver.py": args.fake_sha256}
    output = project.run_worker_bundle(files, hashes, stdin=json.dumps(settings).encode())
    if not isinstance(output, str) or len(output) > 8192:
        raise ValueError('invalid worker evidence output')
    result = json.loads(output)
    checks = {'both_sources_routable', 'both_own_projections_valid', 'cross_client_projection_rejected',
              'modified_projections_rejected', 'restricted_source_excluded_from_selection', 'restricted_pin_non_200',
              'restricted_responses_exclude_preferred_source', 'input_4097_no_solution',
              'both_gateway_executions_completed', 'preferred_backend_model_and_effort_observed',
              'both_audit_targets_match_selection', 'both_execution_and_projection_receipts_verified',
              'alternate_disconnect_and_recovery'}
    if (not isinstance(result, dict) or set(result) != {'schema_version', 'synthetic', 'cut_sha256', 'cases', 'checks', 'limitations'}
            or type(result['schema_version']) is not int or result['schema_version'] != 1 or result['synthetic'] is not True
            or result['limitations'] != ['same_container_test_worker', 'fake_backend_and_spawner', 'sandbox_not_verified']
            or result['cut_sha256'] != fixture.EXPECTED_SHA256 or not isinstance(result['checks'], dict)
            or set(result['checks']) != checks or any(value is not True for value in result['checks'].values())
            or not isinstance(result['cases'], list) or len(result['cases']) != 2):
        raise ValueError('invalid worker evidence schema')
    identifiers = {'client_id': r'client-[0-9a-f]{8}', 'selection_decision_id': r'rd-[0-9a-f]{32}',
                   'projection_request_id': r'[0-9a-f]{32}', 'projection_binding_sha256': r'[0-9a-f]{64}',
                   'projection_receipt_sha256': r'[0-9a-f]{64}', 'gateway_request_id': r'chatcmpl-[0-9a-f]{32}',
                   'gateway_decision_id': r'rd-[0-9a-f]{32}', 'execution_receipt_sha256': r'[0-9a-f]{64}'}
    sources = set()
    for case in result['cases']:
        if (not isinstance(case, dict) or set(case) != {'source_id', 'resource_id', 'model', *identifiers}
                or case['source_id'] not in ('foundry-worker-a', 'foundry-worker-b')
                or case['resource_id'] != case['source_id'] + ':gpt-6-sol:high'
                or case['model'] != {'provider': 'openai', 'model': 'gpt-6-sol', 'variant': 'high', 'reasoning_effort': 'high'}
                or any(not isinstance(case[key], str) or re.fullmatch(pattern, case[key]) is None
                       for key, pattern in identifiers.items())):
            raise ValueError('invalid worker evidence case')
        sources.add(case['source_id'])
    if len(sources) != 2:
        raise ValueError('worker evidence must identify both synthetic sources')
    return result


def _prepare(args):
    helper = _checked_file(ROOT / "tests" / "worker_mi_acceptance.py", args.worker_sha256)
    fake = _checked_file(args.fake_appserver, args.fake_sha256)
    cuts = host_mi_provenance.generate_cuts(args.mi_python, args.mi_wheel, args.mi_repo)
    _validate_cuts(cuts)
    return helper, fake, cuts


def _validate_cuts(cuts):
    expected = {"fresh": fixture.EXPECTED_SHA256, **fixture.VARIANT_SHA256}
    if not isinstance(cuts, dict) or set(cuts) != set(expected):
        raise ValueError("invalid verified MI cuts")
    configuration = {"reasoning_effort": "high", "variant": "high"}
    for kind, digest in expected.items():
        cut = cuts[kind]
        if (not isinstance(cut, tuple) or len(cut) != 2 or
                not all(isinstance(part, bytes) and len(part) <= fixture.MAX_BYTES for part in cut) or
                hashlib.sha256(cut[0]).hexdigest() != digest):
            raise ValueError("invalid verified MI publication")
        trust = {
            "schema_version": 1, "publication": "/run/foundry/mi/publication.json",
            "reference": {"format_version": 1, "payload_schema": fixture.PAYLOAD_SCHEMA, "sha256": digest},
            "scope": {"scope_id": "foundry-incompatible-fixture/1" if kind == "incompatible" else "foundry-controlled-fixture/1",
                      "channel": "worker_bridged", "configuration": configuration,
                      "source_ids": ["foundry-synthetic-source"]},
            "bindings": [{"identity": {"provider": "openai", "model": "gpt-6-sol", "variant": "high"},
                          "subject": {"model_id": "foundry-synthetic-id", "provider_id": "openai",
                                      "provider_model_id": "gpt-6-sol", "physical_model_id": None,
                                      "revision": "fixture-1", "channel": "worker_bridged",
                                      "interface_id": "foundry-synthetic-api", "interface_provider_id": "foundry-synthetic-provider",
                                      "interface_version": "1", "configuration": configuration},
                          "dimension": "foundry.input", "meaning": "input-allowance", "basis": "fixture-basis"}],
            "max_bytes": fixture.MAX_BYTES,
        }
        if cut[1] != json.dumps(trust, sort_keys=True, separators=(",", ":")).encode():
            raise ValueError("verified MI trust mismatch")


def _discover_engine(args):
    validate_engine_socket(args.socket)
    path = Path(args.socket)
    project = InstalledProject(socket_path=args.socket, engine_id='discovery-placeholder',
                               image_id='sha256:' + '0' * 64, authorization='disposable-linux-engine-approved')
    with tempfile.TemporaryDirectory(prefix='foundry-engine-discovery-') as tmp:
        project.root = Path(tmp)
        project.env = {'PATH': os.defpath, 'HOME': tmp, 'DOCKER_CONFIG': tmp + '/docker-config'}
        data = json.loads(project._run(['docker', '--host', 'unix://' + str(path), 'info', '--format', '{{json .}}'], timeout=20))
    identifier = data.get('ID') if isinstance(data, dict) else None
    if (not isinstance(identifier, str) or not re.fullmatch(r'[A-Za-z0-9:._-]{12,128}', identifier)
            or data.get('OSType') != 'linux' or not data.get('CgroupDriver') or data['CgroupDriver'] == 'none'
            or not all(data.get(key) is True for key in ('MemoryLimit', 'SwapLimit', 'PidsLimit', 'CpuCfsQuota'))):
        raise ValueError('engine identity or reported Linux resource controls unavailable')
    if args.engine_id is not None and identifier != args.engine_id:
        raise ValueError('discovered engine identity differs from expected identity')
    return identifier


def _read_preflight(path, socket_path, base_digest):
    path = Path(path)
    if path.name != 'acceptance.json' or path.parent.parent != Path('/tmp/kilo'):
        raise ValueError('protected preflight report required under /tmp/kilo')
    parent = os.open('/tmp/kilo', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_info = os.fstat(parent)
        if parent_info.st_uid != os.geteuid() or parent_info.st_mode & 0o022:
            raise ValueError('unprotected preflight parent')
        directory = os.open(path.parent.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(directory)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError('unprotected preflight directory')
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                        stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 16384):
                    raise ValueError('unprotected preflight report')
                with os.fdopen(os.dup(fd), 'rb') as stream:
                    document = json.load(stream)
            finally:
                os.close(fd)
        finally:
            os.close(directory)
    finally:
        os.close(parent)
    if (not isinstance(document, dict) or document.get('scope') != 'preflight_only' or
            document.get('status') != 'preflight_passed' or document.get('socket') != socket_path or
            document.get('base_digest') != base_digest or document.get('daemon_host_isolation') != 'not_established' or
            document.get('builder_storage_quota') != 'not_established' or
            not isinstance(document.get('preflight'), dict) or
            not isinstance(document['preflight'].get('probe'), dict) or
            document['preflight']['probe'].get('status') != 'passed' or
            document['preflight']['probe'].get('cleanup') != 'passed' or
            not isinstance(document.get('engine_id'), str) or
            not re.fullmatch(r'[A-Za-z0-9:._-]{12,128}', document['engine_id'])):
        raise ValueError('preflight evidence does not match this run')
    return document['engine_id']


@contextmanager
def _executor(args, evidence, name):
    executor = build.DockerExecutor(socket_path=args.socket, engine_id=args.engine_id,
                                    authorization='disposable-linux-engine-approved',
                                    build_authorization='disposable-linux-image-build-approved')
    executor.__enter__()
    try:
        evidence.data['image_cleanup'][name] = 'pending'
        evidence.save()
        yield executor
    finally:
        try:
            executor.__exit__(*sys.exc_info())
        except BaseException:
            evidence.data['image_cleanup'][name] = 'failed'
            raise
        else:
            evidence.data['image_cleanup'][name] = ('unknown' if executor.probe_uncertain is True else
                                                    'failed' if executor.cleanup_failed is True else 'passed')
            if executor.probe_uncertain is True:
                evidence.data.setdefault('retained_preflight_probes', {})[name] = executor.project.token
        finally:
            evidence.save()


def run(args):
    if getattr(args, 'preflight_only', False):
        if not getattr(args, 'authorize_engine_preflight', False):
            raise ValueError('explicit engine preflight authorization required')
        if not isinstance(args.base_digest, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', args.base_digest):
            raise ValueError('exact base digest required')
        if any((args.zai_python, args.zai_output_dir, args.authorize_zai_source_reads)):
            raise ValueError('real-source options are not permitted in preflight-only mode')
        evidence = Evidence(args.evidence_dir, preflight_only=True)
        try:
            args.engine_id = _discover_engine(args)
            evidence.data.update(engine_id=args.engine_id, base_digest=args.base_digest, socket=args.socket)
            evidence.data['preflight']['probe'] = {'status': 'running', 'cleanup': 'unknown'}
            evidence.save()
            with build.DockerExecutor(socket_path=args.socket, engine_id=args.engine_id,
                                      authorization='disposable-linux-engine-approved',
                                      build_authorization='disposable-linux-image-build-approved') as executor:
                result = executor.preflight(base_digest=args.base_digest)
                if (not isinstance(result, dict) or result.get('memory') != '536870912' or
                        result.get('swap') != '0' or result.get('pids') != '128' or
                        result.get('cpu') != '100000 100000' or type(result.get('available')) is not int or
                        result['available'] < 10 * 1024**3):
                    raise ValueError('invalid preflight result')
                evidence.data['preflight']['probe'] = {
                    'status': 'passed', 'cleanup': 'passed',
                    'visible_cgroup_memory_bytes': 536870912, 'visible_cgroup_swap_bytes': 0,
                    'visible_cgroup_pids': 128, 'visible_cgroup_cpu': '100000 100000',
                    'ancestor_cgroup_limits': 'not_established',
                    'container_root_available_bytes': result['available']}
                evidence.save()
            evidence.data['status'] = 'preflight_passed'
        except BaseException as exc:
            evidence.data['status'] = 'failed'
            if evidence.data['preflight'].get('probe', {}).get('status') == 'running':
                evidence.data['preflight']['probe']['status'] = 'failed'
            if 'executor' in locals() and executor.probe_uncertain is True:
                evidence.data['preflight']['probe']['retained_label'] = executor.project.token
            if isinstance(exc, build.ImageInspectionFailure):
                evidence.data['preflight']['image_inspection'] = exc.diagnostic
            elif isinstance(exc, CommandFailure):
                allowed = {'', 'Docker reported permission denied; details redacted',
                           'Docker reported daemon unavailable; details redacted',
                           'Docker stderr redacted: unrecognized diagnostic',
                           'Docker stderr redacted: oversized diagnostic'}
                evidence.data['preflight']['engine_command'] = {
                    'classification': 'engine_command_failed',
                    'exit_status': exc.returncode if type(exc.returncode) is int and -255 <= exc.returncode <= 255 else None,
                    'stderr': exc.stderr if exc.stderr in allowed else 'Docker stderr redacted: unrecognized diagnostic'}
            raise
        finally:
            try:
                evidence.save()
            finally:
                evidence.close()
        return
    if not args.authorize_disposable_linux_engine or not args.authorize_image_build:
        raise ValueError("explicit disposable engine and image build authorization required")
    if not args.confirm_external_boundaries:
        raise ValueError("external host isolation, storage and build network boundaries must be established")
    if not args.preflight_evidence:
        raise ValueError('reviewed preflight evidence required before full acceptance')
    expected_engine = _read_preflight(args.preflight_evidence, args.socket, args.base_digest)
    if args.engine_id is not None and args.engine_id != expected_engine:
        raise ValueError('expected engine differs from reviewed preflight')
    args.engine_id = expected_engine
    if not all((args.sr_repo, args.mi_repo, args.worker_sha256, args.fake_appserver, args.fake_sha256,
                args.mi_python, args.mi_wheel)):
        raise ValueError('full acceptance requires source repositories, verified MI wheel inputs and pinned worker fixtures')
    for path in (args.sr_repo, args.mi_repo):
        if not Path(path).is_absolute() or not Path(path).is_dir():
            raise ValueError("absolute existing authenticated source repositories required")
    manifest = _file_manifest()
    source = (ROOT / "Dockerfile.mi").read_bytes()
    product_revision = provenance.product_revision(source)
    for revision in (provenance.OLD_SR, provenance.NEW_SR):
        provenance.dockerfile(source, revision, args.base_digest)
    real_source = (args.zai_python, args.zai_output_dir, args.authorize_zai_source_reads)
    if any(real_source) and not all(real_source):
        raise ValueError("real-source check requires interpreter, output directory and separate authorization")
    if all(real_source):
        if not Path(args.zai_python).is_absolute() or not Path(args.zai_python).is_file():
            raise ValueError("absolute existing real-source Python required")
        zai.check_directory(args.zai_output_dir)
    def _run_phases():
        helper, fake, cuts = prepared
        _validate_cuts(cuts)
        fresh_publication, fresh_trust = cuts["fresh"]

        with _project(args, baseline=True, phase='baseline', evidence=evidence, cuts=cuts) as adapter:
            adapter.start_old()  # Baseline uses the new test image without MI.
            _security_negatives(adapter)
            key = _client(adapter, "MI-disabled baseline")
            control = _control(adapter, helper, fake, args)
            try:
                response = assert_input_boundary(adapter, key, control, mi_enabled=False)
                if evidence is not None:
                    resource = response['route']['target']['resource']['resource_id']
                    if resource not in ('foundry-worker-a:gpt-6-sol:high', 'foundry-worker-b:gpt-6-sol:high'):
                        raise ValueError('unexpected synthetic resource')
                    evidence.data['phases']['baseline']['selected_resource_id'] = resource
                    evidence.save()
            finally:
                control.close()

        with _project(args, phase='execution', evidence=evidence, cuts=cuts) as adapter:
            adapter.start_new_with_cut(fresh_publication, fresh_trust, fixture.EXPECTED_SHA256)
            result = _execution(adapter, helper, fake, args)
            if evidence is not None:
                evidence.data['phases']['execution']['worker'] = result
                evidence.save()

        with _project(args, phase='variant_reload', evidence=evidence, cuts=cuts) as adapter:
            adapter.start_new_with_cut(fresh_publication, fresh_trust, fixture.EXPECTED_SHA256)
            key = _client(adapter, "fresh variant reload")
            control = _control(adapter, helper, fake, args)
            try:
                assert_input_boundary(adapter, key, control, mi_enabled=True)
                retained, _ = run_variant_reload_acceptance(adapter, key, cuts, control.worker_ready, control.verify_cut)
                if evidence is not None:
                    resource = retained['route']['target']['resource']['resource_id']
                    if resource not in ('foundry-worker-a:gpt-6-sol:high', 'foundry-worker-b:gpt-6-sol:high'):
                        raise ValueError('unexpected synthetic resource')
                    evidence.data['phases']['variant_reload']['selected_resource_id'] = resource
                    evidence.save()
            finally:
                control.close()

        with _project(args, phase='stale_startup', evidence=evidence, cuts=cuts) as adapter:
            run_stale_installed(adapter, cuts, helper, fake,
                                helper_sha256=args.worker_sha256, fake_sha256=args.fake_sha256)

        with _project(args, phase='preactivation', evidence=evidence, cuts=cuts) as adapter:
            adapter.start_new_with_cut(fresh_publication, fresh_trust, fixture.EXPECTED_SHA256)
            key = _client(adapter, "preactivation retained client")
            control = _control(adapter, helper, fake, args)
            try:
                retained = _bound_selection(adapter, key, blocked=False, worker_ready=control.worker_ready,
                                            verify_cut=control.verify_cut, digest=fixture.EXPECTED_SHA256)
            finally:
                control.close()
            adapter.stop()

            def verify_cut(client_key, response, digest):
                verifier = _control(adapter, helper, fake, args, verify_only=True)
                try:
                    return verifier.verify_cut(client_key, response, digest)
                finally:
                    verifier.close()

            run_preactivation_failure(adapter, fresh_trust, key, retained, verify_cut)

        with _project(args, phase='migration_backup_restore', evidence=evidence, cuts=cuts) as adapter:
            run_lifecycle_acceptance(
                adapter, fresh_publication,
                start_worker=lambda mode, archive: start_live_worker(
                    adapter.project, adapter.admin, helper, fake, helper_sha256=args.worker_sha256,
                    fake_sha256=args.fake_sha256, migration=mode, worker_archive=archive))


    def _run_authorized():
        args.engine_id = _discover_engine(args)
        evidence.data['engine_id'] = args.engine_id
        evidence.save()
        if all(real_source):
            result = subprocess.run([args.zai_python, "-I", str(ROOT / "tests" / "zai_real_source_check.py"),
                                     "--output-dir", args.zai_output_dir, "--authorization", zai.AUTHORIZATION],
                                    env={"PATH": os.defpath, "HOME": args.zai_output_dir, "LANG": "C.UTF-8"},
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=zai.PROCESS_TIMEOUT + 15, check=False)
            if result.returncode or result.stderr or len(result.stdout) > 8192:
                raise RuntimeError("real-source applicability check failed")
            summary = json.loads(result.stdout)
            blocker_names = {'scope_channel', 'subject_channel', 'subject_configuration', 'reasoning_effort',
                             'configuration_mismatch', 'unknown_freshness'}
            if (not isinstance(summary, dict) or summary.get("source_revision") != zai.MI_REVISION or
                    summary.get("router_applicability") != "not-established" or
                    summary.get("router_binding") is not None or summary.get('integrity_not_authenticity') is not True or
                    summary.get('retrieved_sources') != len(zai.EXPECTED_SOURCES) or
                    not isinstance(summary.get('cut_sha256'), str) or not re.fullmatch(r'[0-9a-f]{64}', summary['cut_sha256']) or
                    type(summary.get('model_claims')) is not int or summary['model_claims'] < 1 or
                    not isinstance(summary.get('blockers'), dict) or set(summary['blockers']) != blocker_names or
                    any(type(value) is not int or value < 0 or value > summary['model_claims']
                        for value in summary['blockers'].values())):
                raise ValueError("invalid real-source applicability report")
            evidence.data['real_source'] = {key: summary[key] for key in ('source_revision', 'cut_sha256', 'retrieved_sources', 'router_applicability', 'router_binding', 'integrity_not_authenticity', 'model_claims', 'blockers')}
            evidence.data['real_source'].update(scope='separate_source_publication', installed_mi_revision=provenance.MI,
                                                installed_image_compatibility='not_tested')
            evidence.save()
        with _executor(args, evidence, 'old') as old_executor:
            evidence.data['preflight']['old'] = 'running'
            evidence.save()
            old_executor.preflight(base_digest=args.base_digest)
            evidence.data['preflight']['old'] = 'passed'
            evidence.save()
            args.old_image_id = build.build_verified(old_executor, source=source, revision=provenance.OLD_SR,
                                                     base_digest=args.base_digest, sr_repo=args.sr_repo, mi_repo=args.mi_repo)
            evidence.data['images']['old'] = {'id': args.old_image_id, 'sr_revision': provenance.OLD_SR, 'mi_revision': provenance.MI, 'base_digest': args.base_digest}
            evidence.save()
            with _executor(args, evidence, 'new') as new_executor:
                evidence.data['preflight']['new'] = 'running'
                evidence.save()
                new_executor.preflight(base_digest=args.base_digest)
                evidence.data['preflight']['new'] = 'passed'
                evidence.save()
                args.new_image_id = build.build_verified(new_executor, source=source, revision=provenance.NEW_SR,
                                                         base_digest=args.base_digest, sr_repo=args.sr_repo, mi_repo=args.mi_repo)
                evidence.data['images']['new'] = {'id': args.new_image_id, 'sr_revision': provenance.NEW_SR, 'mi_revision': provenance.MI, 'base_digest': args.base_digest}
                evidence.save()
                _run_phases()


    prepared = _prepare(args)
    input_provenance = _input_provenance(manifest, source, prepared, args)
    if _file_manifest() != manifest:
        raise ValueError('provenance files changed during preparation')
    evidence = Evidence(args.evidence_dir)
    try:
        evidence.data['foundry_provenance'] = input_provenance
        evidence.data['product_dockerfile_sr_revision'] = product_revision
        evidence.save()
        _run_authorized()
        if _file_manifest() != manifest:
            raise ValueError('provenance files changed during acceptance')
    except BaseException as exc:
        evidence.data['status'] = 'failed'
        if isinstance(exc, CommandFailure) and WORKER_DIAGNOSTIC_RE.fullmatch(exc.stderr):
            evidence.data['worker_diagnostic'] = exc.stderr
        for name, status in evidence.data['preflight'].items():
            if status == 'running':
                evidence.data['preflight'][name] = 'failed'
        raise
    else:
        evidence.data['status'] = 'synthetic_acceptance_passed'
    finally:
        try:
            evidence.save()
        finally:
            evidence.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authorize-disposable-linux-engine", action="store_true")
    parser.add_argument("--authorize-image-build", action="store_true")
    parser.add_argument("--authorize-engine-preflight", action="store_true")
    parser.add_argument("--preflight-only", action="store_true", help="run bounded engine probe only; never build or start SR")
    parser.add_argument("--preflight-evidence", help="reviewed preflight-only acceptance.json for this socket and base; required for full acceptance")
    parser.add_argument("--confirm-external-boundaries", action="store_true", help="confirm independently authenticated source/base and externally enforced host isolation, storage quotas and build network boundaries")
    parser.add_argument("--socket", required=True)
    parser.add_argument("--engine-id", help="optional independently expected engine ID; otherwise discovered during authorized preflight")
    parser.add_argument("--base-digest", required=True)
    parser.add_argument("--sr-repo")
    parser.add_argument("--mi-repo")
    parser.add_argument("--mi-python", help="absolute trusted Python used for the isolated synthetic MI producer")
    parser.add_argument("--mi-wheel", help="absolute path to the independently pinned synthetic MI wheel")
    parser.add_argument("--worker-sha256")
    parser.add_argument("--fake-appserver")
    parser.add_argument("--fake-sha256")
    parser.add_argument("--evidence-dir", required=True, help="new private direct child of /tmp/kilo")
    parser.add_argument("--zai-python")
    parser.add_argument("--zai-output-dir")
    parser.add_argument("--authorize-zai-source-reads", action="store_true")
    args = parser.parse_args()
    def expired(signum, _frame):
        raise TimeoutError(f"acceptance batch interrupted by signal {signum}")

    previous_alarm = signal.signal(signal.SIGALRM, expired)
    previous_term = signal.signal(signal.SIGTERM, expired)
    signal.alarm(5400)
    try:
        run(args)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_alarm)
        signal.signal(signal.SIGTERM, previous_term)


if __name__ == "__main__":
    main()
