# Issue 1 Host Acceptance Authorization

Status: proposed, conditional authorization request for PR #22. Writing or
reviewing this document does not authorize SSH, Docker, a listener, a build, a
daemon start, or a test. No host acceptance commands were executed to prepare it.
The coordinator must fill the execution manifest and freeze the combined source
before requesting approval. Each stage below has an explicit approval boundary;
success in one stage is not permission to proceed to the next. The existing
runner combines build and run in one process. That command requires advance
conditional approval for BOTH stages, or it must not be started.

## Scope And Source

Verify the smallest installed Foundry SR-MI composition on the designated R61
Linux test host using the existing test runner, not a new runner, product service,
proxy, topology monitor, or isolation framework. Production changes belong to
PR #25 at `857bfe3053124f2e734cd0990194e6b56641362b`; test changes belong to
PR #22. The final exact combined commit/tree, offline results and independent
review receipts are recorded on issue #1, not inferred from a mutable worktree.

| Input | Required identity |
| --- | --- |
| Combined Foundry commit/tree | Use the final issue #1 receipt's exact commit/tree and review references; base `0c95034e0344fd8d1d3680ba01bfb2fd335172b0` |
| Canonical Compose and startup implementation | Exact files from that combined tree, including the local HTTP and explicit TLS paths |
| New SR | `5bd4fa4d65028b46455f63726c2dda7b8e3ca341` |
| Historical migration/rollback SR | `f96d58e6d7d0fffdbe70476850d824efa5de2fb5` |
| MI in both images and synthetic producer | `d65891668b7e79f7b666c021f02a1b4bf8c4ca9c` |
| Independently expected MI wheel SHA-256 | `1ca0b6a0d0e99a5df4a75c66b625f9433553afda09f6b5928be574369a29d019` |
| Python base manifest | PENDING_REVALIDATION; historical candidate below is not current verification |
| Old/new image IDs | NOT_BUILT: obtain from the approved build and independently inspect before run authorization |
| Worker/fake-backend bytes | Exact SHA-256 values derived from authenticated frozen objects, recorded before execution |

Canonical SR develop is `dc74c0f015551f075bc45ee15bdb0cf0705c91b5` at
source inspection. Its difference from the selected functional merge `5bd4fa4`
is documentation only. MI develop `c65df369f674b82347a2e08a27d5315d935ac1a4`
is not SR's pinned dependency and must not silently replace `d658916`.

All commands use Linux executables. No Windows process, PowerShell, browser,
provider credential, paid inference, public-source acquisition, DNS change,
trust-store change, firewall change, VPN change, host networking, privileged
container, Docker socket mount, or blanket workspace mount is included.
Existing services, accounts, data, VPNs and daemon/global configuration remain
untouched. Do not use the ROG Docker Desktop engine as a substitute.

## Historical Evidence

These are historical reports, not renewed authorization or current host facts:

- [Issue #1 comment 21726](https://forgejo.creatidy.com/Creatidy/foundry/issues/1#issuecomment-21726)
  records a 2026-11-11 R61 Ubuntu 24.04 x86-64 synthetic run, old `f96` to
  candidate `8fc4f91`, through a test TCP proxy with end-to-end TLS. It did not
  verify direct production publication or the new `5bd` image.
- [Comment 21761](https://forgejo.creatidy.com/Creatidy/foundry/issues/1#issuecomment-21761)
  records rootless engine ID `526d5483-aeb2-43ac-bdbc-4c6afed4ad4e`, a
  test-owned 24 GiB ext4 loop-backed store, and a common user slice observed at
  1.5 CPU, 2 GiB RAM, zero swap and 512 tasks. That daemon was subsequently
  stopped. Complete daemon/host isolation and a quota on all build storage were
  explicitly not established.
- Its base manifest was
  `sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b`.
  The retained `8fc` image is not the requested new image and must not be relabeled.
- [Comments 21943](https://forgejo.creatidy.com/Creatidy/foundry/issues/1#issuecomment-21943)
  and [22040](https://forgejo.creatidy.com/Creatidy/foundry/issues/1#issuecomment-22040)
  preserve the failed R61 `unshare` isolation attempt and require a concrete
  post-failure plan. Do not repeat `unshare --user --map-root-user --net`, its
  `ip` setup, or any equivalent wrapper after `Operation not permitted`.
- [Comment 21731](https://forgejo.creatidy.com/Creatidy/foundry/issues/1#issuecomment-21731)
  qualifies the earlier report's exact-run source identity and stale-after-restart
  evidence. Neither gap is repaired retroactively by this document.

The saved issue output does not identify the R61 login account, Unix socket path,
slice name, or backing-store path. Mock `/run/user/1001/docker.sock` examples in
tests are not historical host observations. Those fields must be established from
the owner's existing authenticated host records, not guessed or discovered by
connecting to arbitrary sockets. Historical acceptance JSON SHA-256 is
`661ad05fe7db95283e21c19e8d10ba252cabd14f07c3c4c71e15b19fab6d162c`.

## Execution Manifest

Fill these values in the approval request before running the corresponding stage.
An unresolved field blocks that stage; it is not an instruction for the owner to
create a VM, reconfigure a daemon, or perform manual network setup.

| Field | Value and verification |
| --- | --- |
| `R61_HOST`, `R61_USER`, expected UID/GID | PENDING: authenticated SSH destination and exact non-root account |
| SSH client and host identity | Existing `/usr/bin/ssh`, verified known-host entry; `StrictHostKeyChecking=yes`; no TOFU |
| Remote Python, Git, Docker, uv, Make | PENDING: absolute Linux executable paths and versions; inspect before invoking Python test code |
| `R61_ROOT` | PENDING: protected, frozen combined-source directory on R61, not a live owner checkout |
| `R61_SOCKET`, `R61_ENGINE_ID` | PENDING: exact test-only Unix socket, validated ancestry/ownership and matching rootless engine |
| `R61_SLICE`, `R61_DATA_ROOT`, temp/cache paths | PENDING: existing daemon/build cgroup ancestry, actual data-root/backing filesystems and available capacity |
| `BASE_DIGEST` | PENDING: independently authenticated manifest, locally present; no implicit pull |
| `SR_OBJECTS`, `MI_OBJECTS` | PENDING: absolute authenticated object repositories; no dirty checkout imports or lazy network fetch |
| `MI_PYTHON`, `MI_WHEEL`, `FAKE_APPSERVER` | PENDING: absolute inspected inputs; wheel and fixture bytes checked independently |
| `WORKER_SHA256`, `FAKE_SHA256` | PENDING: exact frozen fixture hashes, not values sampled after the run |
| `PREFLIGHT_DIR`, `RUN_DIR` | PENDING: distinct previously absent private direct children of `/tmp/kilo` on R61; build record belongs in the run report |
| `OLD_IMAGE_ID`, `NEW_IMAGE_ID` | PENDING_BUILD_RECORD: complete `sha256:` IDs; never mutable tags or the old R61 IDs |
| Stage approvals | PENDING: exact stage, command manifest, limits, source identities, date and owner decision |

Record the exact commands, substituted argument values, source tree, expected
fixtures, executable identities and selected daemon in the approval request.
Record the final combined tree in that external request/run manifest after
freezing this document too; do not claim a self-referential in-file tree hash.
Do not include credentials. SSH credentials remain in the existing SSH agent or
protected store; test administrator/client/worker credentials are synthetic and
remain in private files or process pipes, never argv, tool output or reports.

## Bounds And Stops

Requested ceilings for this one batch, subject to independently demonstrated
existing enforcement:

| Boundary | Requested maximum and actual limitation |
| --- | --- |
| Read-only inspection | 5 minutes total; SSH connection timeout 10 seconds; each remote diagnostic at most 20 seconds |
| Container preflight | 5 minutes total; probe create/start/remove individually at most 30 seconds; no SR listener |
| Image builds | Serialized, one old and one new build, each at most 900 seconds; no retry or parallel build |
| Build inspection | At most 900 seconds per image; bounded archives, no installed-code execution during static package comparison |
| Whole runner | Existing runner alarm is 5400 seconds; stage-specific approval must not exceed this 90-minute ceiling |
| Workload container | 1 CPU, 512 MiB RAM, memory+swap 512 MiB (zero additional swap), 128 PIDs; private cgroup namespace |
| Preflight container | Same CPU/RAM/PID bounds, UID/GID 65534, read-only root, no network, no capabilities, no-new-privileges |
| Aggregate daemon/build/host children | Target 1.5 CPU, 2 GiB RAM, zero swap, 512 tasks; historical observations do not prove current enforcement |
| Storage | At least 10 GiB available on each relevant backing store; approved bounded test store at most 24 GiB, including declared temp/cache/backup paths |
| Evidence/output | Build diagnostics 1 MiB; static site archive 128 MiB; backup archive 16 MiB, content 12 MiB and 1024 entries; protected evidence only |

`image_build_executor.py` requests build `--memory 1g --memory-swap 1g
--cpu-period 100000 --cpu-quota 100000`. BuildKit may ignore these legacy
flags. They do not enforce an aggregate build PID or storage quota. A container
probe, `docker info`, `docker system df`, or filesystem free space alone does
not prove aggregate builder limits. A 24 GiB backing image does not bound cache,
logs or temporary files outside it. Read the actual existing cgroup ancestry and
storage paths; do not add infrastructure or change quotas to make the check pass.

If the existing daemon cannot demonstrate the approved aggregate CPU, RAM, PID,
storage and build-network boundary, stop before building and report the exact
missing control. The operator must make an explicit bounded disposition; this
document does not silently accept the gap, relax the runner's
`--confirm-external-boundaries` assertion, or require a new daemon/VM. No automatic
base-image pull, daemon restart or storage provisioning is included.

Stop immediately on isolation failure, wrong account/engine/image/source, an
unexplained launch failure, timeout, endpoint-protection/security-policy warning,
unexpected listener/mount/peer, unrelated resource change, exhausted limit, unsafe
ownership or cleanup uncertainty. Do not retry with another wrapper, path,
namespace, engine, socket, flag, encoding or elevated account. Killing a timed-out
Docker client does not prove its daemon-side operation stopped. Retain identities
and safe diagnostics; seek a separate inspection/cleanup authorization if fenced.
Do not prune shared caches, delete ambiguous resources, or alter global settings.

## Stage A: Inspection

Approval A1 permits only the explicit read-only SSH diagnostics below, after the
manifest is filled. The commands are templates with manifest variables, not
permission to execute with guessed values. Run from the existing trusted client;
no login/daemon bootstrap script, shell profile wrapper or remote code upload.

```sh
/usr/bin/ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 "${R61_USER}@${R61_HOST}" /usr/bin/id
/usr/bin/ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 "${R61_USER}@${R61_HOST}" /usr/bin/hostname
/usr/bin/ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 "${R61_USER}@${R61_HOST}" "/usr/bin/stat -c '%U %G %a %F %n' '${R61_ROOT}' /tmp/kilo '${R61_SOCKET}'"
/usr/bin/ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 "${R61_USER}@${R61_HOST}" /usr/bin/git -C "${R61_ROOT}" rev-parse HEAD 'HEAD^{tree}'
/usr/bin/ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 "${R61_USER}@${R61_HOST}" /usr/bin/readlink -e /usr/bin/python3 /usr/bin/git /usr/bin/docker /usr/bin/make
/usr/bin/ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 "${R61_USER}@${R61_HOST}" /usr/bin/systemctl --user show "${R61_SLICE}" -p ControlGroup -p CPUQuotaPerSecUSec -p MemoryMax -p MemorySwapMax -p TasksMax
/usr/bin/ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 "${R61_USER}@${R61_HOST}" /usr/bin/findmnt -T "${R61_DATA_ROOT}" -o TARGET,SOURCE,FSTYPE,OPTIONS
/usr/bin/ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 "${R61_USER}@${R61_HOST}" /usr/bin/df -B1 "${R61_DATA_ROOT}" /tmp/kilo
```

Each displayed SSH invocation has this exact approved outer time bound:
`/usr/bin/timeout --signal=TERM --kill-after=5s 20s`, followed by the shown
`/usr/bin/ssh` argument vector. This is an ordinary command deadline, not an
alternative isolation wrapper. A timeout ends the stage; no retry follows.
Freeze SSH manifest values to shell-safe host/account/path characters
`[A-Za-z0-9_./:@-]+` before approval; do not interpolate unreviewed shell syntax.

The final request must also enumerate the verified uv executable and actual
read-only cgroup files for the daemon, builder and all relevant ancestors,
including `cpu.max`, `memory.max`, `memory.swap.max` and `pids.max`, and
backing-store diagnostics and their exact paths. Read only those named files
with the verified Linux `/usr/bin/cat`; do not run `ip` or `unshare`. No
arbitrary `/proc` or owner-home collection. Under a separately listed A1 daemon
read authorization, use the verified Docker executable with the explicit socket:

```sh
/usr/bin/docker --host "unix://${R61_SOCKET}" info --format '{{json .}}'
/usr/bin/docker --host "unix://${R61_SOCKET}" image inspect "python:3.12-slim@${BASE_DIGEST}"
/usr/bin/docker --host "unix://${R61_SOCKET}" container ls --all --no-trunc
/usr/bin/docker --host "unix://${R61_SOCKET}" network ls --no-trunc
/usr/bin/docker --host "unix://${R61_SOCKET}" volume ls
```

These Docker commands run on R61 as the manifest user, not on the local ROG
machine. Record only safe resource identity/state fields for noninterference;
never collect unrelated container environments, credentials or logs. An absent or
stopped daemon ends A1: its historical startup authorization is not renewed here.

Approval A2 separately permits the existing bounded container preflight. On R61,
from `R61_ROOT`, with the verified Python executable and a sanitized environment:

```sh
/usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp/kilo TMPDIR=/tmp/kilo \
  PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/python3 -B "${R61_ROOT}/tests/run_installed_acceptance.py" \
  --preflight-only --authorize-engine-preflight \
  --socket "${R61_SOCKET}" --engine-id "${R61_ENGINE_ID}" \
  --base-digest "${BASE_DIGEST}" --evidence-dir "${PREFLIGHT_DIR}"
```

The absolute executable paths must match the A1 observations; substitute and
freeze an actual differing path before approval, not after launch failure.
The script imports its sibling helpers, so this invocation does not add `-I`,
`PYTHONSAFEPATH` or an alternate import wrapper. The sanitized environment is
not an OS isolation claim. This stage writes a private report and creates one
uniquely labeled disposable probe, starts its bounded Python cgroup/free-space
read, verifies exit and ownership, and removes that probe. It does not build an
image, start SR, issue a claim, create a model worker, or acquire public evidence.
The report intentionally leaves daemon/host isolation and builder storage quota
unestablished; A1 external evidence must cover them before Stage B approval.

## Stage B: Build Gate

Approval B covers builds and static image verification, not an unconditional
runtime start. Use the existing `tests/run_installed_acceptance.py` and
`image_build_executor.py`, with authenticated source objects, the verified MI
wheel, one pinned base and serialized builds. Do not create a new build wrapper.

The runner has no build-only or run-only CLI: `--authorize-image-build` proceeds
directly into runtime phases, and `image_build_executor.py` has no standalone
CLI. Do not invent such switches or a new wrapper. A build-only approval cannot
authorize the full command below. The operator may instead approve B and C as
one conditional sequence after reviewing Stage A, explicitly authorizing C only
if the frozen runner's build identity and resource gates pass. No human pause
between build and run is implemented or claimed.

The build record must include the combined tree and file manifest, base manifest
and observed layers, exact old/new Dockerfile bytes and whether each is the
unmodified product file or a test variant, old/new SR pins, MI source/wheel and
installed-package manifests, fixture digests, full resulting image IDs, engine
identity, effective controls, commands, elapsed times and cleanup disposition.
The runner must save each verified image ID and provenance in its private
`acceptance.json` build record before entering the run phases; run manifest
entries must refer to those exact IDs, not tags. Its existing executor contexts
hold the images during runtime and normally delete them on exit. This is a
same-process identity-checked handoff, not a promise of retained images for a
later run. Unmodified product-image identity must be distinguished from the
executor's instrumented test-image definition.

Build networking may reach the canonical Forgejo Git repositories and the exact
package/base origins required by the inspected Dockerfile. Enumerate those
destinations and the existing enforcement or explicit operator disposition
before approval. Unlocked apt/pip dependencies and mutable product base tags
prevent a reproducible-build claim. No real-source MI refresh, inference,
credentials, registry push or system package installation on R61 is authorized.

## Stage C: Run Gate

Approval C is conditional on the new build record and full image IDs passing
the already-reviewed identity gate, not on historical R61 image IDs. If the
operator requires personal review of actual IDs before C, the existing combined
runner cannot satisfy that pause and must not be invoked under a build-only
approval. Do not build an alternate runner to conceal this limitation.

After A1/A2 and BOTH B/C approvals, the exact combined command template, executed
on R61 as the manifest account, is:

```sh
/usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp/kilo TMPDIR=/tmp/kilo \
  PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/python3 -B "${R61_ROOT}/tests/run_installed_acceptance.py" \
  --authorize-disposable-linux-engine --authorize-image-build \
  --confirm-external-boundaries \
  --preflight-evidence "${PREFLIGHT_DIR}/acceptance.json" \
  --socket "${R61_SOCKET}" --engine-id "${R61_ENGINE_ID}" \
  --base-digest "${BASE_DIGEST}" \
  --sr-repo "${SR_OBJECTS}" --mi-repo "${MI_OBJECTS}" \
  --mi-python "${MI_PYTHON}" --mi-wheel "${MI_WHEEL}" \
  --worker-sha256 "${WORKER_SHA256}" \
  --fake-appserver "${FAKE_APPSERVER}" --fake-sha256 "${FAKE_SHA256}" \
  --evidence-dir "${RUN_DIR}"
```

All CLI options above exist in the inspected runner. Verify the exact combined
source against the issue #1 receipt before execution. This command is NOT
authorized or ready to execute until the missing host manifest, enforcement
evidence and approvals are supplied. Do not pass `--zai-python`,
`--zai-output-dir` or `--authorize-zai-source-reads`. Never set
`--confirm-external-boundaries` on the basis of Docker-reported capability flags
or historical comments alone. There are no known current new-image IDs to paste
into this document, and no implicit image reuse or rebuild after failure.

The run manifest must record each phase's project/token, actual container IDs,
image IDs, selected data volume, network, published ports, transport, test input
cut and expected source/fixture hashes before the relevant operation. Final
provenance must identify the actual combined tree, not just the files sampled
after a run. Historical R61 reports remain unchanged.

Required runtime topology and cases:

- Use the final canonical `compose.yaml` and real production startup entrypoint.
  The new SR local path has `--host=0.0.0.0 --port=8787 --data-dir=/data
  --local-container-http --worker-listen-host=0.0.0.0
  --worker-listen-port=8790`, one router and one ordinary owned Compose network.
  Publish HTTP and worker ports only on `127.0.0.1`; use the canonical internal
  ports. Verify actual bindings, not YAML alone. No proxy or host networking.
- Use host HTTP `http://127.0.0.1:PORT` and worker `srw://127.0.0.1:8790`
  inside the router container for the existing synthetic same-container worker.
  Verify the separate host-loopback worker publication too; an unpublished
  same-container connection alone does not prove that host ingress works.
  The HTTP Host guard accepts the internal bound port, not arbitrary remapped
  ports. Programmatic ephemeral-port phases preserve SR's accepted internal Host
  authority and record ordinary browser access as not established. Canonical
  port-8787 browser/platform acceptance is a separate still-unverified gate; do
  not bypass the check or claim browser access from a rewritten Host.
- Confirm health, protected synthetic onboarding/login, rejected missing/invalid
  keys, administrator/inference separation, origin/CSRF rejection, exact MI
  consumption, viable authorization-filtered selection and retained projection
  verification. Exercise both permitted resources, blocked preferred resource,
  tampering/cross-client refusal, fake-backend dispatch/audit linkage, disconnect
  and recovery. Never substitute mocked routing inputs for installed selection.
- Reuse the existing phase scenarios for MI-disabled versus enabled input bounds,
  invalid/stale/incompatible reload, accepted withdrawal, retained receipts,
  stale startup and a NEW selection after restart with the same worker identities.
  Record causal limitations honestly: `no_solution` alone is not proof which
  constraint excluded a model. No source acquisition or paid/live backend call.
- Exercise explicit advanced TLS directly on the router, with scoped disposable
  certificate trust, wrong-host/untrusted negatives and no proxy. It is a
  separately selected transport, not fallback from local HTTP. The historical
  `f96` image does not accept `--local-container-http`: migration and rollback
  stages must retain verified TLS for that image. Retain TLS for both sides of
  store-migration tests when preserving origin-bound worker identity; those tests
  prove the store/backup boundary, not a seamless TLS-to-HTTP credential migration.
  New-image local HTTP phases separately cover the default product transport.
  Do not silently skip cases or relabel TLS evidence as local HTTP acceptance.

The candidate removes the historical private-network/TCP-proxy topology and
selects `NEW_SR=5bd4fa4`, direct publication and worker port 8790. Offline
orchestration checks do not execute that topology. This document adds no runner
and authorizes no implementation shortcut or host experiment.

## Data And Cleanup

Use new per-phase `foundry-test-<32hex>` projects, generated run tokens, matching
test labels, private temp directories and exclusively test-owned named volumes.
Refuse collisions, foreign peers, symlinks, unsafe group access and ambiguous
resources. Bind only the exact read-only fixture MI/TLS files; do not mount host
workspaces, owner credentials, the engine socket, or existing application data.
Validate rootless UID/GID translation against the verified socket peer and
current mapping before mounting; do not chown an owner tree or relax permissions.

For migration, stop the old SR process and all worker writers, capture a
consistent protected backup and worker identity archive, and validate the bounded
archive manifest before upgrading the SAME test store. Capture identity, schema
and retained evidence checks. Preserve the pre-upgrade backup independently.
An image-only downgrade is not rollback: restore the identified old backup into
a distinct initially empty test-owned volume, restore the matching worker state,
then start the old image over verified TLS. Verify original client/worker use and
rejection of a post-backup client. Later writes are deliberately absent after
restoration; do not promise lossless rollback. No production data is touched.

Successful cleanup stops and removes only identity/label-verified test containers,
then their unused owned network/volumes and this batch's untagged unconsumed
images according to the approved build/run record. Preserve the independently
provisioned base, historical retained images, unrelated services, all unowned
resources and shared build caches. No `system prune`, global cache removal,
`down --volumes` on an existing project, or deletion by name alone. Verify the
owned resource set is absent and compare safe pre/post identity inventories.
Record leftover cache/temporary/build effects and unavailable observations rather
than declaring the host unchanged. On a fence or uncertain launch/timeout,
retain resources and request bounded diagnosis instead of automatic mutation.

## Result Boundaries

Report commands, exact source/image/input identities, observed limits, phases,
assertions, test counts, wall time, failures and cleanup. Separate installed
source/package provenance, direct local HTTP, direct advanced TLS, migration and
synthetic backend receipts. Health is liveness, not readiness or MI evidence.
No automatic merge, main promotion, release, deployment or issue closure follows.

Native Windows browser/Schannel/trust lifecycle, a Windows worker, native worker
sandbox, real provider execution, source-owner truth/authenticity, positive live
Z.ai applicability, Kernel/Console installed adoption, production data migration
and production renewal remain UNVERIFIED. The synthetic MI wheel and source
objects do not authenticate all transitive dependencies or establish OS isolation.

The approval request may authorize the filled conditional B/C sequence after an
explicit review pause following A, or stop at inspection/preflight only. It
must identify the exact release decision and conditions. A requested human
pause after building is not provided by the current combined runner and must
not be promised. No successful command, old approval, peer report, flag string,
or agent recommendation constitutes an authorization decision.
