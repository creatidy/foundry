# Foundry

**A single, integrated environment for Scarcity Router, Model Intelligence, Creatidy Kernel and Console.**

**Foundry** is the name of the integrated **product**, not another execution engine. Its first implementation milestone packages actual existing capabilities and preserves standalone operation of all components.

Foundry is the public **deployment and integration product**. It does not own routing, public model facts, task orchestration, or operator decisions. Each source product must keep a usable standalone installation and its own contracts, state, release process, and authority.

**Status: local Compose startup is implemented; full production and target-host acceptance remain UNPROVED.** The default builds the existing Scarcity Router composed server through `Dockerfile.mi`, publishes HTTP and the direct worker listener on host loopback, and requires no `.env`, certificates or manually supplied image hash. MI publication activation is opt-in. Foundry does not add an MI daemon/update job, Kernel runner or connected Console service.

Advanced and distributed deployments require explicitly selected verified TLS with operator-managed certificates; startup never silently falls back to HTTP. The experimental Windows certificate-import proposal in [PR #14](https://forgejo.creatidy.com/Creatidy/foundry/pulls/14) is superseded as default onboarding, not integrated. See the [deployment matrix and security conditions](docs/architecture.md#target-deployment-topology).

## Local Docker startup

From the Foundry checkout, with Docker Engine/Compose, GNU Make and Python 3 available:

```sh
make up
```

`make up` calls `python3 scripts/local_tls_up.py --local-http`. With the default image it builds `Dockerfile.mi`, resolves the local image ID automatically, and starts that ID using a generated temporary override of the one canonical `compose.yaml`. It waits for health with a 60-second Compose wait and a 90-second startup command bound; the separate build has a 900-second bound. No reverse proxy, host networking, certificate setup or manual image inspection step is required. An independently inspected custom `FOUNDRY_ROUTER_IMAGE` must already exist locally; it is not automatically built or pulled by this path. `.env` is optional, not an onboarding prerequisite. TLS selection uses Compose's environment/`.env` precedence: effective TLS settings refuse local HTTP, including settings retained in an older `.env`. Use the explicit advanced commands below to keep TLS. A deliberate switch to plaintext requires reviewing the project, backing up, and explicitly removing its TLS settings, not ignoring them.

Open `http://127.0.0.1:8787/admin`. The direct worker endpoint is `srw://127.0.0.1:8790`, not an HTTP route or proxy. Pairing and worker authorization remain SR-owned; a listening port does not pair a worker. The container listens on `0.0.0.0` with SR's explicit `--local-container-http` mode, while both published host ports bind `127.0.0.1`. `FOUNDRY_WORKER_PORT` can change the host worker port, which is part of its credential origin. Keep HTTP port 8787 for ordinary browser access: changing only `FOUNDRY_ROUTER_PORT` remaps Docker publication but does not change SR's accepted HTTP Host authority. Programmatic remapped-port tests use SR's explicitly accepted `Host: 127.0.0.1`, not evidence that a browser works at that port.

**Plaintext trust boundary:** attached Compose peers and operator-configured routes may reach these container listeners. Loopback publication does not prove that the container is inaccessible from every other network. HTTP and `srw` provide no transport confidentiality within this accepted single-host boundary; authentication and authorization remain required. Operators are responsible for topology changes. Connections across hosts, network segments or independently configured distributed Docker environments require verified TLS, not reuse of this plaintext profile.

### First administrator

For a fresh installation only, leave the server running and personally execute this command in a second trusted private terminal:

```sh
docker compose exec router python -m scarcity_router.control_server --data-dir /data --issue-bootstrap-claim
```

This is an **owner-only normal-use step, never an agent-executed or agent-captured command**. Paste the resulting one-time claim directly into SR's onboarding form, then set the administrator password there. Do not use a recorded/shared terminal, put the claim in a URL, argument, file or log, or disable required organizational monitoring. Claims expire after 15 minutes; issuing another invalidates the previous one until an administrator exists. Do not issue one on ordinary restarts. With a custom Compose project, select that same project for the command.

Health is liveness, not successful onboarding, authentication, inference or worker acceptance. Configure authorized resources and distinct client/worker credentials through SR's own supported surfaces. Useful lifecycle commands are `make ps`, `make logs` and `make down`; logs can contain sensitive operational metadata. `make down` retains the named data volume. Repeat `make up` to start again; the default path rebuilds the pinned source image, so it can need network access even on a later invocation. A failed build/start or timeout does not remove resources or roll back state: inspect before retrying. Back up before any upgrade as described below.

## Linux / WSL2 startup

From the Foundry checkout, start in the foreground with GNU Make, Python 3 and Git installed:

```sh
make start
```

Open exactly `http://127.0.0.1:8787/admin` after SR prints **server component listening**. A selected runtime and a "Starting SR" message are not readiness; failures remain visible and return nonzero. Ctrl-C stops the foreground server; repeat `make start` to restart. This does not install a service or promise automatic startup after reboot. The command invokes the full composed server, not the recommendation-only `scarcity-router-server`.

### Runtime discovery

`make runtime-check` performs the same discovery without starting a server or opening its store. Foundry checks only the sibling `../scarcity-router/.venv/bin/python` and, when `uv` is on PATH, `$(uv tool dir)/scarcity-router/bin/python`. It does not search your home, activate an environment, change PATH, download anything or replace installations. An incompatible candidate is reported and excluded; two compatible environments are ambiguous and refuse startup. To explicitly select a nonstandard checkout or disambiguate existing environments, use `FOUNDRY_SR_CHECKOUT=/absolute/inspected/scarcity-router make start`; this selects only that checkout's `.venv`, not an arbitrary Python argument.

Verification uses Python 3.12+, ordinary `scarcity_router.control_server` import resolution and installed `direct_url.json` checkout provenance, not the unchanged `0.1.0` version. The retained source must have canonical HTTPS origin `https://forgejo.creatidy.com/Creatidy/scarcity-router.git` and HEAD in the exact compatibility set in `scripts/local_runtime.py`: `925ec06681c7fa085edd5015f57663e85d735768` (minimum, SR #253 ownership fix), `c67900723cd6ec7430a36dd0357ee17061f811b6`, `8fc4f91ff1aa4c52f4738d436fc2ac12d0b8acb1`, `5bd4fa4d65028b46455f63726c2dda7b8e3ca341` or `dc74c0f015551f075bc45ee15bdb0cf0705c91b5`. Inclusion is a source compatibility decision, not live acceptance. Every imported package file and the effective default selector-policy asset must match that Git tree; non-editable installations must contain the packaged policy, and editable installations must retain the source example. Extra or modified code and missing/modified default assets are refused; existing user policy is not inspected or changed. Unrelated checkout docs/tests can be dirty. Non-editable `uv tool` copies are compared with the retained checkout, not assumed current from their local directory URL. Wheel-only, VCS-only metadata, uninspected revisions and other installation layouts are not yet auto-discovered.

This is an offline compatibility/provenance check under a trusted operator-controlled host, Git objects, Python/uv executables and environment, not publisher authentication or dependency auditing. `PYTHONPATH` and `PYTHONHOME` overrides are refused. Protect the runtime, dependencies, source checkout and import environment from modification, including between verification and execution. New SR revisions require explicit Foundry compatibility review and an update to `scripts/local_runtime.py`; startup never follows a mutable branch. Do not reset a checkout containing other work to satisfy this check.

### Install SR if absent

Reuse an already compatible environment first. SR is not on PyPI. If there is no SR checkout, the following prepares a new **absent** sibling path at the inspected immutable revision (do not run it over an existing checkout):

```sh
git clone --no-checkout https://forgejo.creatidy.com/Creatidy/scarcity-router.git ../scarcity-router
git -C ../scarcity-router checkout --detach 5bd4fa4d65028b46455f63726c2dda7b8e3ca341
```

Inspect that checkout's README, `pyproject.toml` and installation/dependency contract before the one supported installation step:

```sh
uv tool install --python 3.12 ../scarcity-router
make runtime-check
make start
```

This explicit SR-supported local-checkout installation can download Python/build/runtime dependencies; they are not a fully locked release. No installation was performed by Foundry. Keep the checkout at the installed revision for subsequent verification. An existing `uv tool` installation is not silently overwritten: do not add `--force` or run SR's install-or-upgrade target merely to start Foundry. If the tool or checkout is older, modified or unverifiable, startup explains the refusal; inspect and deliberately plan its upgrade and data backup first, especially if other commands or a worker use the environment. No automatic migration, downgrade or rollback is provided. A separately inspected wheel is supported by SR packaging, but lacks sufficient provenance for this discovery increment; use the retained-checkout installation path above.

### State and onboarding

The underlying `scripts/local-start.sh` remains available for explicitly prepared interpreter use. The printed data directory is SR's `$XDG_DATA_HOME/scarcity-router/server` when `XDG_DATA_HOME` is absolute, otherwise `$HOME/.local/share/scarcity-router/server`. Keep the same environment and user on restart; changing them can select different state. Foundry does not reset, copy or migrate administrator identity, resources, keys or configuration. SR owns normal store opening and schema behavior. Discovery does not open user data; running a server can modify it.

The historical duplicate-start producer-fencing defect at SR revision `c16cc1db29f3828b3f9e8d05b19e645cfb0c32b8` was fixed in [SR #253 / PR #254](https://forgejo.creatidy.com/Creatidy/scarcity-router/pulls/254), integrated at the minimum revision above. SR now acquires exclusive server ownership before opening the store or constructing the producer. A concurrent server using the same data directory is refused without fencing the running producer's snapshot/replay operations; ownership is released on shutdown or process death. Stop any pre-fix server before upgrading: it does not participate in this ownership protocol. This protection belongs to SR, not a Foundry lock, and does not block the separate administrator claim command below. A refused duplicate never adopts the existing listener. Other startup failures can still initialize or modify state; do not assume every failed start leaves durable state unchanged.

For a fresh installation only, leave the server running and open a second trusted private terminal. Use the **SR interpreter** printed by `make start` and replace the data-directory placeholder with the exact path printed at startup:

```sh
/absolute/path/to/sr-python -m scarcity_router.control_server --data-dir '/exact/path/printed/at/startup' --issue-bootstrap-claim
```

Paste the resulting one-time claim into SR's onboarding form and set the administrator password there. Do not run the claim command through an agent, a recorded terminal, or a shared channel; do not put the claim in a URL, argument, file or log. The claim expires after 15 minutes; issuing another invalidates the previous one until an administrator exists. Do not issue a claim on normal restarts.

The owner confirmed local startup, Windows browser UI access, first-admin onboarding/login and administrator persistence across restart on ROG Windows 11 / WSL2 Ubuntu with the prior launcher. Existing Linux Chromium/Playwright exercised administration, providers, resources, permissions, sessions and security protections; two SR-owned defects and a separate inference-evidence gap were handed to SR and are not re-tested or fixed here. That evidence is not clean-machine installation, negative external reachability or authenticated inference acceptance for this new command. Those and supported upgrade/recovery remain M0 requirements. Launcher PR #19 was not a complete installer; discovery removes the interpreter-path step, not the remaining installation gates.

### Optional native MI

Native `make start` also accepts `FOUNDRY_MI_DIR` and `FOUNDRY_MI_SHA256` together. Use the protected directory/file ownership and digest rules in [Opt-In MI](#opt-in-mi), but set `trust.json`'s `publication` to the exact absolute host path `FOUNDRY_MI_DIR/publication.json`, not `/run/foundry/mi/publication.json`. The launcher validates those inputs before starting SR and passes the host `trust.json` via `--mi-config`. `FOUNDRY_MI_IMAGE_ID` is Compose-only and is refused by the native launcher.

The selected SR interpreter must already have its optional MI dependency; an absent installation can explicitly use `uv tool install --python 3.12 '../scarcity-router[mi]'` instead of the base install above. Never overwrite an existing installation to enable the extra without planning its upgrade. Startup checks availability, not an independently authenticated MI package revision or source applicability. It does not install dependencies, create a cut, infer model bindings or fetch updates. Keep native and container trust documents separate because their publication paths differ. SR performs full activation validation; failure does not imply unchanged durable state. Omitting both variables leaves native MI off.

## Repositories and ownership

| Component | Canonical Forgejo repository | Foundry role |
| --- | --- | --- |
| Scarcity Router | `Creatidy/scarcity-router` | The first existing server; gateway, private source state, admission and capacity |
| Model Intelligence | `Creatidy/model-intelligence` | Existing library/public-evidence producer and immutable publication; no invented daemon |
| Creatidy Kernel | `Creatidy/creatidy-kernel` | One work-control core for cooperative pull and supported managed push; existing harnesses execute work |
| Creatidy Console | `Creatidy/creatidy-console` | Authenticated local application, Router observer foundation and optional read-only Kernel proposal view; not full cross-product control |
| Foundry | `Creatidy/foundry` | Product-level versions, configuration, Compose, integration acceptance and update procedure |

`Infrastructure/creatidy-onprem` remains the separate, private owner of deployment-specific hosts, proxying, TLS infrastructure and secrets. Foundry must not require that repository. GitHub is a read-only mirror, not a canonical dependency or publishing target.

Canonical source research on 2026-11-13 verified Kernel `develop` at `5e6f42906980fd42293e0dab1be3d7942532ff81` and Console at `8f68259e8353d5c480d79598c28687079ad8eb14`. Kernel's ordinary SDK and provider-qualified composition are integrated, not merely planned; [Kernel #60](https://forgejo.creatidy.com/Creatidy/creatidy-kernel/issues/60#issuecomment-22066) still leaves full installed acceptance unverified. Basic pull does not require strict Router gateway compatibility, a particular harness or Console. MI utilized-reference retention is delivered, while [#55](https://forgejo.creatidy.com/Creatidy/creatidy-kernel/issues/55) direct-content expansion is optional. Console has its own login/sessions, but no enabled Kernel commands; its optional proposal view uses a trusted Linux supervisor's inherited descriptor, not a Kernel HTTP server or active SQLite access. [Console #34](https://forgejo.creatidy.com/Creatidy/creatidy-console/issues/34) retains outstanding multi-producer/recovery acceptance. None of these source receipts establishes Foundry target-host integration. See [architecture](docs/architecture.md#verified-kernel-and-console-boundaries) for pinned sources and limits.

## Advanced verified TLS

Build explicitly first; advanced startup uses `--no-build --pull never`:

```sh
make build
make tls-up LOCAL_TLS_PROJECT=your-tls-project FOUNDRY_ROUTER_HOST=router.example.com FOUNDRY_TLS_DIR=/absolute/protected/tls
```

`make tls-up` calls `scripts/local_tls_up.py --tls` and generates an override of canonical Compose. Supply an existing publicly trusted hostname-matching chain and key as `server.crt` and `server.key` in that absolute directory, readable by the non-root container. `FOUNDRY_ROUTER_HOST` and `FOUNDRY_TLS_DIR` can come from the invoking environment/Make command line or `.env`, resolved by Compose with its normal precedence. Startup adds the operator's primary GID for ordinary Docker, or container group zero for the standard same-user rootless Docker mapping, based on the selected engine's security options. Remote daemons and custom user-namespace mappings are not validated by that choice. Protect directory ancestry and key custody; do not commit certificates, keys or credentials. No certificate issuance, renewal or trust-store modification is performed. A private CA requires a separately accepted trust-bootstrap path; do not bypass verification.

The override replaces local plaintext mode with TLS on both the HTTP and direct worker listeners, configures verified reload hostnames and an HTTPS healthcheck, and maps the certificate hostname to container loopback only for that probe. Client DNS and trust still need correct independent configuration. Both host publications remain loopback; this command does not itself expose a cross-host service. Distributed exposure requires an explicitly reviewed network/client configuration with hostname and chain verification, not a proxy added by default. There is no silent TLS-to-HTTP fallback.

Startup checks directory/file readability, not a full host-side chain/hostname validation or a target acceptance receipt. SR owns TLS initialization and verified reload; health is not authenticated operation. Without MI, advanced startup does not wait for health. Confirm actual listener health, authentication and secure failures separately. Protect files from concurrent changes between checking, mounting and reload.

For the existing public-CA files, optional checks use the same generated advanced TLS model:

```sh
make preflight FOUNDRY_ROUTER_HOST=router.example.com FOUNDRY_TLS_DIR=/absolute/protected/tls
make tls-check FOUNDRY_ROUTER_HOST=router.example.com FOUNDRY_TLS_DIR=/absolute/protected/tls
```

`preflight` checks file presence/readability only. `tls-check` checks the exact HTTP/worker TLS argument shape and performs a bounded in-memory handshake using host default trust roots, including key, chain, validity and hostname; encrypted keys refuse without a prompt. Neither starts a listener or runs automatically on `make up`/`make tls-up`. Host trust is not container/browser trust, and the check does not establish revocation status, future validity, container read access, authentication or target acceptance. Its handshake limits do not bound certificate loading or captured Compose output. Protect input files, environment and `.env` from disclosure or concurrent changes. This public-CA check is not the explicit-leaf validation used by `local-tls-up`. `make config` validates only the canonical base, not a generated TLS/MI override or a running service.

TLS commands require an explicit `LOCAL_TLS_PROJECT` and refuse existing project containers, networks or volumes unless the operator also supplies matching `LOCAL_TLS_ADOPT_PROJECT`. Adoption permits reuse, modification or recreation, not proof of ownership. Inspect state and back up before adoption; use `COMPOSE_PROJECT_NAME=your-tls-project make down` to stop that project without deleting its data volume. Direct Compose startup/restart omits the generated TLS and MI choices; repeat the appropriate guarded command with the same settings. Never replace a TLS project with `make up`, which selects plaintext.

## Windows Prerequisites

### Legacy guarded TLS entrypoint

**Deprecated, unverified legacy path, not current onboarding:** `scripts/windows-first-run.ps1` and its TLS helpers retain old-layout Compose/hash guards. They are not adapted to the new local HTTP topology; do not run them as a workaround or update guard hashes to bless it. The default local Docker path above needs no certificate import or manual image hash. Foundry automation never issues or captures an administrator claim.

Retain the legacy security lessons when assessing any future Windows integration: compare the actual selected WSL/Linux engine with the fixed Docker Desktop pipe, do not infer engine identity from a WSL2 marker, and treat matching engine/container identities as point-in-time evidence under a trusted host rather than a lock or protection against administrators. Unattached volumes remain ambiguous and require inspection, not automatic deletion/regeneration. Public certificate equality is not private-key custody or browser trust.

Docker Desktop can create a WSL bind alias whose ancestry bypasses the original `0700` parent. Matching device/inode at an alias does not prove the container still holds that mount; the alias may have been remounted after the container bound an older key. The legacy bind-mounted path therefore remains refused. A managed named volume avoids that particular host bind but does not establish an accepted Windows installation, safe adoption or browser trust. Never bypass browser warnings or silently modify trust stores, global settings or execution policy.

From native PowerShell on Windows, run `powershell.exe -NoProfile -File .\scripts\windows-prerequisites.ps1` from this repository. The diagnostic checks WSL status/version and the local Docker Compose CLI, suppressing their output. By default it skips the Docker engine probe and exits nonzero because engine access remains unverified. After independently reviewing the selected Docker context, explicitly run `powershell.exe -NoProfile -File .\scripts\windows-prerequisites.ps1 -CheckEngine` to query the configured engine. The selected endpoint may be remote: the script warns before the request and does not display the endpoint. Opt-in exit 0 means only that all commands returned successfully, not that Foundry is ready. The Compose version check is a local CLI operation for standard Docker, but executes `docker.exe` from `PATH` and its plugin: use trusted executables and configuration. Each started command has a 10-second wait limit, after which the diagnostic attempts to terminate it and waits up to two more seconds; termination of descendant processes is not guaranteed. Status queries may cause underlying Windows services to initialize. The diagnostic does not inspect the reported WSL version or verify a WSL 2 distribution, engine identity, location or OS, Docker Desktop identity, image provenance, TLS, authentication, or actual Foundry operation.

This is not an installer or start command: it creates or adopts no Foundry resources, makes no trust changes, generates no keys or certificates, and does not fetch or install software. Windows/WSL first-run and browser trust remain unverified and incomplete. The advanced Linux local-test workflow below requires its own Linux prerequisites, verified image and explicit client trust; the public-CA Compose path above requires independently provisioned certificates. Neither path is automatically configured by this diagnostic.

Windows PowerShell may refuse `-File` from a WSL-backed UNC path with `AuthorizationManager check failed`, even where a displayed execution policy appears permissive. This diagnostic does not change or bypass execution policy. Use a trusted, locally available checkout at a Windows path only when permitted by your organization's policy. On an unexplained native launch failure, timeout, endpoint-protection warning or policy refusal, stop and preserve the evidence; do not retry with encoded commands, alternative wrappers, execution-policy bypasses or security exclusions. Native testing requires a separately approved bounded plan. Prior mock results do not prove the normal `-File` invocation is allowed.

## Local test leaf

On Linux, an operator can explicitly run `make local-tls-init TLS_DEST=/absolute/private-parent/new-directory`. The existing parent must be operator-owned with mode `0700`; the destination must not exist. Directory ancestry is checked, symlinks and unsupported filesystem ACLs are rejected. The command requires Python 3, OpenSSL and `/proc/self/fd`, and creates `server.crt` and `server.key` with mode `0640` in a new mode `0750` directory, owned by the operator's primary group. The private parent prevents traversal by other host users. It prints the certificate's SHA-256 fingerprint. Verify that fingerprint through a trusted channel; **do not trust an unverified certificate**. The local filesystem and operator are assumed trusted, not an unauthenticated network.

This is a 30-day self-signed leaf for the numeric IP `127.0.0.1`, not a CA. Direct leaf trust is only for explicitly configured test clients; browser support is not claimed. Generation does not install trust, configure Compose, start a server, or renew certificates. The optional `make tls-check` uses host default trust and is not a prerequisite for this local self-signed leaf path.

For an explicit Linux test runtime, build first and select all leaf settings on the command line; `.env` is not required:

```sh
make build
make local-tls-up LOCAL_TLS_PROJECT=your-unique-test-project TLS_DEST=/absolute/private-parent/new-directory FOUNDRY_TLS_DIR=/absolute/private-parent/new-directory FOUNDRY_ROUTER_HOST=127.0.0.1
```

`TLS_DEST` and `FOUNDRY_TLS_DIR` must name the same protected leaf directory. The explicit project overrides Compose's default name. Existing project resources and resolved network/volume names refuse startup without matching adoption acknowledgment; Docker discovery failures also refuse. The generated override selects the standard local Docker/rootless readable group described above, TLS on both listeners and the leaf as each listener's reload trust; only the healthcheck receives `SR_HEALTHCHECK_CA`. No system trust store is changed, and other clients need their own verified explicit leaf trust. Use `COMPOSE_PROJECT_NAME=your-unique-test-project make down` to stop that project. This command does not perform onboarding or satisfy M0 acceptance. Normal `make up` remains certificate-free local HTTP; `make tls-up` is the separate existing public-CA path.

To rerun local startup against an existing project, an operator must first inspect its containers, networks, volumes and data and explicitly acknowledge adoption on that invocation by also setting `LOCAL_TLS_ADOPT_PROJECT=your-unique-test-project`. The acknowledgment must exactly match `LOCAL_TLS_PROJECT`. It authorizes Compose to reuse and potentially modify or recreate existing project resources, including persistent data volumes; the check does not prove ownership. Never use it for a project whose resources must not be touched. The local override is temporary, so normal `make up` is not a local-TLS restart procedure. Adopting an MI-enabled project without the MI variables can disable MI; check the configuration before adoption.

The SR container can read the key through the read-only mount; processes with the operator's group *inside that container* can also read it. Host root, Docker administrators, and other privileged actors are outside this isolation boundary. Neither project discovery nor the filesystem check is atomic with Docker startup: concurrent creation or modification can defeat the checks, so coordinate other Docker operators and protect the files from concurrent modification. Docker user-namespace remapping or a remote daemon may prevent access and are not validated. No automatic renewal or Windows/browser support is provided.

The HTTP listener serves admin/control and inference together; the worker protocol uses its separate direct listener. Only the explicit local HTTP profile permits their plaintext container binds. Authenticated onboarding and real inference must be validated separately. There is no automatic certificate bootstrap or background renewal in M0.

## Opt-In MI

The default `Dockerfile.mi` builds the composed server from canonical SR commit `5bd4fa4d65028b46455f63726c2dda7b8e3ca341` with SR's MI dependency pinned to canonical MI commit `d65891668b7e79f7b666c021f02a1b4bf8c4ca9c`. It checks both commit identities during the build. Installing the MI dependency does not activate a publication: `make up` needs no MI inputs for ordinary use. The base image, OS packages and other Python dependencies are not locked; this is not a reproducible or released image. The stock upstream SR Dockerfile does not install MI. Earlier `8fc4f91` image evidence does not establish acceptance for this pin.

Prepare a separate operator-owned absolute directory under an operator-owned mode `0700` parent, following the same protected ancestry rules as the local leaf. The MI directory must be mode `0750`, owned by the operator's UID and primary GID, with exactly named `trust.json` and `publication.json` regular, single-link files owned by that UID/GID and mode `0640`; symlinks and ACLs are refused. Create a valid SR `--mi-config` document with its `publication` set to `/run/foundry/mi/publication.json`, and independently review its reference, scope and exact model bindings against the actual publication and SR catalog. The complete strict schema is defined by SR's `scarcity_router/mi_server_config.py`; the upstream `tests/test_mi_server_config.py` and `tests/test_mi_consumer.py` provide synthetic examples, not real model facts. Do not derive trust merely from an unverified publication.

Opt in on any Compose startup path with `FOUNDRY_MI_DIR=/absolute/protected/mi` and `FOUNDRY_MI_SHA256=<independently-reviewed-lowercase-cut-sha256>` in the invoking environment or Make command line. Native MI uses the distinct host publication path documented above. For example:

```sh
make up FOUNDRY_MI_DIR=/absolute/protected/mi FOUNDRY_MI_SHA256='<reviewed-cut-sha256>'
```

Replace the digest placeholder before use. `FOUNDRY_MI_IMAGE_ID=sha256:<independently-verified-local-image-id>` is an optional assertion, not a mandatory manual step. Startup resolves the selected local image ID automatically and, if an assertion is supplied, requires equality. MI-enabled TLS startup also requires a declared image healthcheck. Identity equality and a healthcheck do not authenticate image provenance. The cut digest must match both `trust.json`'s `reference.sha256` and the exact publication bytes. Missing/partial MI inputs fail closed; omitting all MI variables leaves publication activation off.

The generated override binds only `trust.json` and `publication.json` read-only, adds `--mi-config`, selects the standard local Docker/rootless readable group described above and disables automatic restart. SR performs full schema/publication validation on activation; Foundry's preflight does not replace it. Local HTTP startup uses `up --wait --wait-timeout 60`; both MI-enabled startup transports also use `--force-recreate` so replacement file binds take effect. The startup command has a 90-second bound. A nonzero exit or timeout means startup was not confirmed, not that resources or state were rolled back. The image healthcheck proves liveness only. Keep MI settings on every restart; starting without them can disable MI.

GNU Make expands dollar signs in command-line variable assignments. For a literal `$NAME` or `${NAME}` in the MI directory name, quote the assignment against shell expansion and double the dollar for Make, for example `make local-tls-up 'FOUNDRY_MI_DIR=/absolute/private/$$NAME'` or `make local-tls-up 'FOUNDRY_MI_DIR=/absolute/private/$${NAME}'`, with the other required variables supplied separately. Alternatively, pass a shell-quoted inherited environment value, for example `FOUNDRY_MI_DIR='/absolute/private/$NAME' make local-tls-up`; do not double the dollar in that environment value. These are literal path examples, not suggested storage locations.

The independent digest check is a startup check, not publisher authentication or a continuous monitor. Manual `docker start` or `docker restart` bypasses it even though automatic restart is disabled; repeat the selected guarded startup path, with explicit project adoption for existing TLS projects. SR's administrator-only `/control/mi/reload` reads mounted files independently and does not repeat Foundry's external digest check. In-place writes can be visible to SR; atomic replacement of a host file does not update its existing file bind. Review and protect inputs before any reload, coordinate operators and recreate through guarded MI startup for replacement files. Checking and mounting are not atomic; a read-only container mount does not prevent host writes. The added container group can read these files; Docker administrators and host root remain outside the boundary. Authenticated utilization and execution on a target host still require separate acceptance; this adds no MI daemon, automatic updates or invented model bindings.

## Upgrade, backup and recovery

The default image uses SR server-store schema 6; the older `f96d58e` source uses schema 4. Opening old state with the new server can migrate it. SR opens/migrates its store before TLS initialization or listener binding, and can persist an MI cut during activation before serving requests. A failed startup or failed health wait is not evidence of unchanged data and does not trigger rollback.

1. Identify the exact project, old image and state volume, stop its router (`docker compose stop router`, selecting the same project when nondefault), and verify it is stopped before updating or rebuilding. Coordinate workers and unresolved execution; stopping is not rollback of external effects.
2. Make and verify an offline backup of the entire `/data` volume, not just one SQLite file, with permissions and all identity/configuration/worker state intact. Retain the old inspected image, exact settings and separately protected MI/TLS inputs and keys. Backups contain credentials/private data; do not upload or expose them. Foundry supplies no automated backup/restore command or proven recovery service.
3. Only after the backup is verified, update the selected source/image and use the appropriate startup path. Inspect migration, authentication, retained identity/configuration and actual operation. Neither Compose health nor synthetic migration fixtures establish a safe upgrade on the target host.
4. For rollback, stop the new server and preserve its data for investigation. Restore the verified pre-upgrade backup into a separate recovery volume/location and select the compatible old image/configuration; never point a schema-4 binary at schema-6 state or edit version markers. **Restoring the old backup loses writes made after that backup.** Reconcile external effects separately; no automatic downgrade, merge of histories or lossless rollback is promised.

Workers own separate credentials and runtime state; preserve those separately where installed. Worker credentials are bound to the exact `srw`/`srws` origin, including scheme and port. Changing TLS to local plaintext is not an automatic identity migration: follow SR's supported pairing procedure for the new origin, retaining the old state/settings for rollback. Never edit stored origins or transfer private credentials to make a transport change appear seamless.

Do not delete the named volume with `down -v` to repair startup. Native startup uses its own data path and explicit compatibility set; an image pin is not evidence of a compatible native installation, and no two controllers may share one live store. Production installation, schema-4-to-6 upgrade/restore and target-host acceptance remain UNPROVED until independently exercised for the exact deployment.

See [architecture](docs/architecture.md), [milestones](docs/milestones.md), and [repository migration](docs/repository-migration.md).

**Publishing status:** The bootstrap is published in canonical Forgejo at `Creatidy/foundry`. Publication does not establish integrated operation or production readiness.

## Principles

- One product-level install; **not four mandatory daemons** or four shared databases.
- Composed operations must not silently modify product policy or delegate user authority.
- Security boundaries do not follow Docker network labels; network and TLS assertions require evidence.
- Pin component versions and retained evidence independently; do not ship mutable `latest` as accepted release provenance.
- Standalone remains fully functional. Integration unlocks cross-component workflows only when exercised end-to-end.
- Avoid extra controllers, certificate authorities, reverse proxies, message brokers, Docker socket access and new credential stores absent a verified requirement.
