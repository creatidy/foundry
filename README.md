# Foundry

**A single, integrated environment for Scarcity Router, Model Intelligence, Creatidy Kernel and Console.**

**Foundry** is the name of the integrated **product**, not another execution engine. Its first implementation milestone packages actual existing capabilities and preserves standalone operation of all components.

Foundry is the public **deployment and integration product**. It does not own routing, public model facts, task orchestration, or operator decisions. Each source product must keep a usable standalone installation and its own contracts, state, release process, and authority.

**Status: M0 bootstrap — NOT a completed or production-ready integrated installation.** The current Compose file describes only the existing Scarcity Router server, with explicit pre-provisioned TLS and an explicitly supplied image. Apart from the separate local test leaf generator below, this repository does **not** implement certificate issuance or renewal, a MI update job, a Kernel runner, or a connected Console. No integrated end-to-end operation has been established.

The owner-selected default is a simple local HTTP installation without certificates or manual image IDs or network setup, for native Linux, Windows WSL2/Ubuntu and Docker. The native launcher below requires a separately prepared SR runtime; it is not a complete installer. Docker bridge HTTP requires a future verified SR security contract and is not supported by the current Compose. Advanced and distributed deployments retain verified TLS with operator-managed certificates. The experimental Windows certificate-import proposal in [PR #14](https://forgejo.creatidy.com/Creatidy/foundry/pulls/14) is superseded as the default onboarding direction; it has not been integrated. See the [deployment matrix and security conditions](docs/architecture.md#target-deployment-topology).

## Linux / WSL2 startup

From the Foundry checkout, start in the foreground with GNU Make, Python 3 and Git installed:

```sh
make start
```

Open exactly `http://127.0.0.1:8787/admin` after SR prints **server component listening**. A selected runtime and a "Starting SR" message are not readiness; failures remain visible and return nonzero. Ctrl-C stops the foreground server; repeat `make start` to restart. This does not install a service or promise automatic startup after reboot. The command invokes the full composed server, not the recommendation-only `scarcity-router-server`.

### Runtime discovery

`make runtime-check` performs the same discovery without starting a server or opening its store. Foundry checks only the sibling `../scarcity-router/.venv/bin/python` and, when `uv` is on PATH, `$(uv tool dir)/scarcity-router/bin/python`. It does not search your home, activate an environment, change PATH, download anything or replace installations. An incompatible candidate is reported and excluded; two compatible environments are ambiguous and refuse startup. To explicitly select a nonstandard checkout or disambiguate existing environments, use `FOUNDRY_SR_CHECKOUT=/absolute/inspected/scarcity-router make start`; this selects only that checkout's `.venv`, not an arbitrary Python argument.

Verification uses Python 3.12+, ordinary `scarcity_router.control_server` import resolution and installed `direct_url.json` checkout provenance, not the unchanged `0.1.0` version. The retained source must have canonical HTTPS origin `https://forgejo.creatidy.com/Creatidy/scarcity-router.git` and HEAD at an inspected exact revision: `925ec06681c7fa085edd5015f57663e85d735768` (minimum, SR #253 ownership fix), or `c67900723cd6ec7430a36dd0357ee17061f811b6` (also includes SR #255 browser onboarding fix). Every imported package file and the effective default selector-policy asset must match that Git tree; non-editable installations must contain the packaged policy, and editable installations must retain the source example. Extra or modified code and missing/modified default assets are refused; existing user policy is not inspected or changed. Unrelated checkout docs/tests can be dirty. Non-editable `uv tool` copies are compared with the retained checkout, not assumed current from their local directory URL. Wheel-only, VCS-only metadata, uninspected revisions and other installation layouts are not yet auto-discovered.

This is an offline compatibility/provenance check under a trusted operator-controlled host, Git objects, Python/uv executables and environment, not publisher authentication or dependency auditing. `PYTHONPATH` and `PYTHONHOME` overrides are refused. Protect the runtime, dependencies, source checkout and import environment from modification, including between verification and execution. New SR revisions require explicit Foundry compatibility review and an update to `scripts/local_runtime.py`; startup never follows a mutable branch. Do not reset a checkout containing other work to satisfy this check.

### Install SR if absent

Reuse an already compatible environment first. SR is not on PyPI. If there is no SR checkout, the following prepares a new **absent** sibling path at the inspected immutable revision (do not run it over an existing checkout):

```sh
git clone --no-checkout https://forgejo.creatidy.com/Creatidy/scarcity-router.git ../scarcity-router
git -C ../scarcity-router checkout --detach c67900723cd6ec7430a36dd0357ee17061f811b6
```

Inspect that checkout's README, `pyproject.toml` and installation/dependency contract before the one supported installation step:

```sh
uv tool install --python 3.12 ../scarcity-router
make runtime-check
make start
```

This explicit SR-supported local-checkout installation can download Python/build/runtime dependencies; they are not a fully locked release. No installation was performed by Foundry. Keep the checkout at the installed revision for subsequent verification. An existing `uv tool` installation is not silently overwritten: do not add `--force` or run SR's install-or-upgrade target merely to start Foundry. If the tool or checkout is older, modified or unverifiable, startup explains the refusal; inspect and deliberately plan its upgrade and data backup first, especially if other commands or a worker use the environment. No automatic migration, downgrade or rollback is provided. A separately inspected wheel is supported by SR packaging, but lacks sufficient provenance for this discovery increment; use the retained-checkout installation path above.

### State and onboarding

The unchanged underlying `scripts/local-start.sh` remains available for explicitly prepared interpreter use. The printed data directory is SR's `$XDG_DATA_HOME/scarcity-router/server` when `XDG_DATA_HOME` is absolute, otherwise `$HOME/.local/share/scarcity-router/server`. Keep the same environment and user on restart; changing them can select different state. Foundry does not reset, copy or migrate administrator identity, resources, keys or configuration. SR owns normal store opening and schema behavior. Discovery does not open user data; running a server can modify it.

The historical duplicate-start producer-fencing defect at SR revision `c16cc1db29f3828b3f9e8d05b19e645cfb0c32b8` was fixed in [SR #253 / PR #254](https://forgejo.creatidy.com/Creatidy/scarcity-router/pulls/254), integrated at the minimum revision above. SR now acquires exclusive server ownership before opening the store or constructing the producer. A concurrent server using the same data directory is refused without fencing the running producer's snapshot/replay operations; ownership is released on shutdown or process death. Stop any pre-fix server before upgrading: it does not participate in this ownership protocol. This protection belongs to SR, not a Foundry lock, and does not block the separate administrator claim command below. A refused duplicate never adopts the existing listener. Other startup failures can still initialize or modify state; do not assume every failed start leaves durable state unchanged.

For a fresh installation only, leave the server running and open a second trusted private terminal. Use the **SR interpreter** printed by `make start` and replace the data-directory placeholder with the exact path printed at startup:

```sh
/absolute/path/to/sr-python -m scarcity_router.control_server --data-dir '/exact/path/printed/at/startup' --issue-bootstrap-claim
```

Paste the resulting one-time claim into SR's onboarding form and set the administrator password there. Do not run the claim command through an agent, a recorded terminal, or a shared channel; do not put the claim in a URL, argument, file or log. The claim expires after 15 minutes; issuing another invalidates the previous one until an administrator exists. Do not issue a claim on normal restarts.

The owner confirmed local startup, Windows browser UI access, first-admin onboarding/login and administrator persistence across restart on ROG Windows 11 / WSL2 Ubuntu with the prior launcher. Existing Linux Chromium/Playwright exercised administration, providers, resources, permissions, sessions and security protections; two SR-owned defects and a separate inference-evidence gap were handed to SR and are not re-tested or fixed here. That evidence is not clean-machine installation, negative external reachability or authenticated inference acceptance for this new command. Those and supported upgrade/recovery remain M0 requirements. Launcher PR #19 was not a complete installer; discovery removes the interpreter-path step, not the remaining installation gates.

## Repositories and ownership

| Component | Canonical Forgejo repository | Foundry role |
| --- | --- | --- |
| Scarcity Router | `Creatidy/scarcity-router` | The first existing server; gateway, private source state, admission and capacity |
| Model Intelligence | `Creatidy/model-intelligence` | Existing library/public-evidence producer and immutable publication; no invented daemon |
| Creatidy Kernel | `Creatidy/creatidy-kernel` | Controller for existing harnesses and workspaces; native-host execution remains supported |
| Creatidy Console | `Creatidy/creatidy-console` | Future connected operator UI; current public code is a scaffold |
| Foundry | `Creatidy/foundry` | Product-level versions, configuration, Compose, integration acceptance and update procedure |

`Infrastructure/creatidy-onprem` remains the separate, private owner of deployment-specific hosts, proxying, TLS infrastructure and secrets. Foundry must not require that repository. GitHub is a read-only mirror, not a canonical dependency or publishing target.

## M0 compose — deliberately not zero-touch

The provisional [`compose.yaml`](compose.yaml), not the future local installer, requires **an existing SR image and a publicly trusted hostname-matching certificate/key**. The private-CA case requires a separately accepted trust-bootstrap path; it is not supported by this Compose path. Even when the host port is bound to `127.0.0.1`, Docker publication alone is NOT proof of LAN non-reachability; server-side TLS and authorization remain mandatory under the current SR contract.

1. Build an SR image from an inspected exact canonical Forgejo revision and supply its explicit reference in `.env` (`FOUNDRY_ROUTER_IMAGE`). The image must support `--tls-reload-hostname`: the inspected SR revision `209f7d39f3ecebbd1b98b11d7c44c63192fe50a4` supports it, while its first parent (the prior `develop` tip) does not. This is a source compatibility check, not an installation acceptance. No SR release was published as of 2026-10-31; this bootstrap does not clone, build or publish an image.
2. Provide an existing certificate chain and private key readable by SR's non-root container identity. Set `FOUNDRY_TLS_DIR` to the absolute directory containing `server.crt` and `server.key`. Do not add secrets to Git.
3. Set `FOUNDRY_ROUTER_HOST` to the certificate's validated DNS hostname. Inside the container this name is mapped to loopback solely for its HTTPS health probe. External clients still need valid DNS and trust.
4. The M0 verified TLS health probe uses platform trust roots. Do not assume arbitrary clients trust a private CA; that bootstrap is future work.
5. Run `make config` to verify the Compose definition. Use `make up` as the supported startup path: it checks Compose's interpolated TLS bind source is an existing absolute directory with readable `server.crt` and `server.key` before invoking Compose. Direct `docker compose up` bypasses this guard. `make up` is an **explicit deployment action** and requires Docker; do not run it against existing production environments without operator approval.

The preflight checks host-side file presence and readability only. It does not validate certificate trust or hostname, container read access, or authenticated SR startup. The source can also change between the check and Docker mounting it; protect the directory from concurrent modification.

`make tls-check` is an optional, offline host-side check of the existing files. It renders the same interpolated Compose model, identifies the router's TLS bind and hostname, and verifies a bounded in-memory TLS handshake, including the key, chain, validity and hostname, using Python/OpenSSL's host default trust roots. It does not contact the router, issue certificates, install trust, persist state, or run automatically on `make up`. Encrypted keys are rejected without prompting. Host trust is not container or browser trust, and a successful check establishes no independent trust in the host roots or the operator-provided files. It does not establish container readability, actual deployment, authentication, or future validity. Protect the TLS directory and its parent paths against replacement and concurrent changes: checking and mounting are separate operations. Compose interpolation inherits the invoking environment; protect environment variables and `.env` from disclosure. The check suppresses rendered configuration and diagnostic details, but cannot prevent exposure through other processes or tools.

The check accepts only the six full, `--option=value` router arguments in the current Compose command, each exactly once; additional options, abbreviations, and split forms fail closed. Changes to that command require reviewing and updating the check. The handshake limits do not bound certificate-file loading or captured Compose output, and the check does not establish revocation status.

The host port is bound to loopback, but this does not by itself prove the Docker/container port cannot be reached through another network. TLS plus authentication remain mandatory for the composed listener.

## Windows Prerequisites

### Guarded first-run entrypoint

**Experimental startup:** Foundry never issues or handles an administrator claim. The legacy bind-mounted path remains blocked before startup or adoption. The native entrypoint compares the Linux engine ID accessed through the selected WSL Unix socket with the Linux engine reached through Docker Desktop's fixed Windows pipe. Docker and Compose environment overrides are refused. Matching engine IDs are evidence under a trusted operator-controlled host and trusted Docker/WSL executables, not proof against a malicious socket proxy or host administrator.

The experimental managed-volume command is `powershell.exe -NoProfile -File .\scripts\windows-first-run.ps1 -Distribution Ubuntu -Project unique-test-project -ImageId sha256:<verified-image-id>`. It uses an explicit empty Compose environment file, not the checkout's `.env`. Public certificate confirmation uses observable input and output without requiring a TTY and issues no claim. It is based on the verified local Docker volume, not an HTTPS-observed fingerprint; it does not install browser trust. An unattached existing managed volume is treated as ambiguous and requires manual inspection, not automatic deletion or regeneration. Docker administrators and the trusted local host remain outside the custody boundary.

After verified HTTPS liveness and an onboarding redirect, the managed path prints `SERVER_RUNNING — ADMIN_ONBOARDING_INCOMPLETE`, a native Windows command with the inspected full container ID and the fixed Docker Desktop pipe, and exits `2`. The operator must personally execute that command in a trusted private terminal, not through an agent or recorded session. Do not disable or bypass required organizational monitoring. Copy the resulting 15-minute claim directly into `https://127.0.0.1:8787/admin/onboarding` and set the password in the browser form. Never put the claim in a URL, command argument, file, log or shared channel. The command and address contain no claim; Foundry neither issues nor captures one. A new claim invalidates the previous claim until an administrator exists.

Use the command promptly and coordinate Docker administrators: container and engine verification is a point-in-time check, not a lock against later changes. Docker administrators and the trusted host have administrative authority. The browser must already trust the independently verified certificate; do not bypass browser warnings. Onboarding and authenticated readiness are not established by displaying instructions. If an administrator exists, the entrypoint prints the login address and exits `0` without claim instructions. Other failures exit `1`; inspect resources before retrying, as failures may leave resources intact.

Provision a compatible SR image independently from inspected canonical revision `14580f629f123bd079e1aa80651a454e9b3e9ce7` and independently establish its local image ID; supplying the ID does not verify the image. The managed path requires a trusted Windows-local checkout whose path contains only ASCII letters, digits, spaces, `_`, `-`, `.`, and directory separators. The selected WSL Docker context must resolve to `unix:///var/run/docker.sock`; Python 3 and OpenSSL must already be installed in WSL. The WSL2 kernel marker is only an environment check. No Windows policy, trust store or global configuration is changed. Native browser trust and this manual onboarding workflow have not been verified on a target host.

The legacy bind-mounted startup and adoption remain guarded behind the custody blocker. No browser is opened and neither onboarding nor authenticated readiness is established by startup. Compose must support `config --no-path-resolution`.

Docker Desktop creates a WSL bind alias whose accessible ancestry can bypass the original `0700` parent. A matching device and inode at that alias also does not prove the container still holds that mount: the shared alias may have been remounted after the container bound an older key. Public-certificate fingerprint equality does not establish private-key custody. Consequently the legacy bind-mounted path refuses startup, adoption and claim issuance. The managed named-volume path does not expose the private key through that host bind; it does not modify a trust store.

From native PowerShell on Windows, run `powershell.exe -NoProfile -File .\scripts\windows-prerequisites.ps1` from this repository. The diagnostic checks WSL status/version and the local Docker Compose CLI, suppressing their output. By default it skips the Docker engine probe and exits nonzero because engine access remains unverified. After independently reviewing the selected Docker context, explicitly run `powershell.exe -NoProfile -File .\scripts\windows-prerequisites.ps1 -CheckEngine` to query the configured engine. The selected endpoint may be remote: the script warns before the request and does not display the endpoint. Opt-in exit 0 means only that all commands returned successfully, not that Foundry is ready. The Compose version check is a local CLI operation for standard Docker, but executes `docker.exe` from `PATH` and its plugin: use trusted executables and configuration. Each started command has a 10-second wait limit, after which the diagnostic attempts to terminate it and waits up to two more seconds; termination of descendant processes is not guaranteed. Status queries may cause underlying Windows services to initialize. The diagnostic does not inspect the reported WSL version or verify a WSL 2 distribution, engine identity, location or OS, Docker Desktop identity, image provenance, TLS, authentication, or actual Foundry operation.

This is not an installer or start command: it creates or adopts no Foundry resources, makes no trust changes, generates no keys or certificates, and does not fetch or install software. Windows/WSL first-run and browser trust remain unverified and incomplete. The advanced Linux local-test workflow below requires its own Linux prerequisites, verified image and explicit client trust; the public-CA Compose path above requires independently provisioned certificates. Neither path is automatically configured by this diagnostic.

Windows PowerShell may refuse `-File` from a WSL-backed UNC path with `AuthorizationManager check failed`, even where a displayed execution policy appears permissive. This diagnostic does not change or bypass execution policy. Use a trusted, locally available checkout at a Windows path when permitted by your organization's policy, and run the same command from its root. A local path is not guaranteed to resolve policy restrictions; if it is also refused, stop and consult the policy administrator. The automated mock tests can use a process-only encoded test command; their success does not establish that the normal `-File` invocation is allowed.

## Local test leaf

On Linux, an operator can explicitly run `make local-tls-init TLS_DEST=/absolute/private-parent/new-directory`. The existing parent must be operator-owned with mode `0700`; the destination must not exist. Directory ancestry is checked, symlinks and unsupported filesystem ACLs are rejected. The command requires Python 3, OpenSSL and `/proc/self/fd`, and creates `server.crt` and `server.key` with mode `0640` in a new mode `0750` directory, owned by the operator's primary group. The private parent prevents traversal by other host users. It prints the certificate's SHA-256 fingerprint. Verify that fingerprint through a trusted channel; **do not trust an unverified certificate**. The local filesystem and operator are assumed trusted, not an unauthenticated network.

This is a 30-day self-signed leaf for the numeric IP `127.0.0.1`, not a CA. Direct leaf trust is only for explicitly configured test clients; browser support is not claimed. Generation does not install trust, configure Compose, start a server, or renew certificates. The optional `make tls-check` uses host default trust and is not a prerequisite for this local self-signed leaf path.

For an explicit Linux test runtime, configure `.env` as above, but set `FOUNDRY_ROUTER_HOST=127.0.0.1` and `FOUNDRY_TLS_DIR` to the generated directory. Choose a unique Compose project name and run `make local-tls-up LOCAL_TLS_PROJECT=your-unique-test-project TLS_DEST=/absolute/private-parent/new-directory`. The project name is required and explicitly overrides Compose's default name. The command refuses projects with existing project-labeled containers (including stopped containers), networks or volumes, or existing networks/volumes with the resolved Compose names. Docker discovery failures also refuse startup. It validates the protected directory and leaf and invokes canonical Compose with a temporary override: SR receives the operator's numeric primary GID and the leaf as `--tls-reload-ca-cert`; only its healthcheck receives `SR_HEALTHCHECK_CA`. The image must support both settings. No system trust store is changed, and other clients need their own explicit leaf trust. Use `COMPOSE_PROJECT_NAME=your-unique-test-project make down` to stop that project. This command does not authorize a first admin, perform authenticated onboarding, or satisfy other M0 integration gates. The normal `make up` public-CA path is unchanged.

To rerun local startup against an existing project, an operator must first inspect its containers, networks, volumes and data and explicitly acknowledge adoption on that invocation by also setting `LOCAL_TLS_ADOPT_PROJECT=your-unique-test-project`. The acknowledgment must exactly match `LOCAL_TLS_PROJECT`. It authorizes Compose to reuse and potentially modify or recreate existing project resources, including persistent data volumes; the check does not prove ownership. Never use it for a project whose resources must not be touched. The local override is temporary, so normal `make up` is not a local-TLS restart procedure. Adopting an MI-enabled project without the MI variables can disable MI; check the configuration before adoption.

The SR container can read the key through the read-only mount; processes with the operator's group *inside that container* can also read it. Host root, Docker administrators, and other privileged actors are outside this isolation boundary. Neither project discovery nor the filesystem check is atomic with Docker startup: concurrent creation or modification can defeat the checks, so coordinate other Docker operators and protect the files from concurrent modification. Docker user-namespace remapping or a remote daemon may prevent access and are not validated. No automatic renewal or Windows/browser support is provided.

The main HTTP listener serves the admin/control and inference surfaces together. Plain HTTP to a non-loopback container listener is not enabled. Authenticated onboarding and real inference must be validated separately. There is no automatic certificate bootstrap or background renewal in M0.

## Opt-In MI

For an explicit Linux local-TLS test only, `Dockerfile.mi` builds the composed server from canonical SR commit `f96d58e6d7d0fffdbe70476850d824efa5de2fb5` with SR's MI extra pinned to canonical MI commit `d65891668b7e79f7b666c021f02a1b4bf8c4ca9c`. It checks both commit identities during the build. Run `docker build -f Dockerfile.mi -t foundry-sr-mi:f96d58e-local .` and set `FOUNDRY_ROUTER_IMAGE` to that local image. The base image, OS packages and other Python dependencies are not locked; this is not a reproducible or released image. The stock SR Dockerfile does not install MI.

Prepare a separate operator-owned absolute directory under an operator-owned mode `0700` parent, following the same protected ancestry rules as the local leaf. The MI directory must be mode `0750`, owned by the operator's UID and primary GID, with exactly named `trust.json` and `publication.json` regular, single-link files owned by that UID/GID and mode `0640`; symlinks and ACLs are refused. Create a valid SR `--mi-config` document with its `publication` set to `/run/foundry/mi/publication.json`, and independently review its reference, scope and exact model bindings against the actual publication and SR catalog. The complete strict schema is defined by SR's `scarcity_router/mi_server_config.py`; the upstream `tests/test_mi_server_config.py` and `tests/test_mi_consumer.py` provide synthetic examples, not real model facts. Do not derive trust merely from an unverified publication.

Invoke the existing startup path with `FOUNDRY_MI_DIR=/absolute/protected/mi`, `FOUNDRY_MI_SHA256=<independently-reviewed-lowercase-cut-sha256>` and `FOUNDRY_MI_IMAGE_ID=sha256:<independently-verified-local-image-id>` set in the invoking environment or on the `make` command line, alongside the required local TLS variables. The cut digest must match both `trust.json`'s `reference.sha256` and the exact publication bytes. The image selected by Compose must match the supplied local image ID and declare a healthcheck; the temporary override starts that ID, not the mutable tag. Independently verify the image and its healthcheck: an ID match and a declared healthcheck do not establish trustworthy provenance or behavior. The temporary override binds only the two named files read-only and adds `--mi-config`; canonical Compose and `make tls-check` remain unchanged. Omitting all three variables leaves the default path unchanged; partial settings fail closed. SR performs full schema and publication validation on activation, not Foundry's preflight. The opt-in disables automatic container restart and uses Compose `up --force-recreate --wait --wait-timeout 60` with a 90-second command bound, including on explicitly adopted projects. A nonzero exit or timeout means startup was not confirmed; inspect the project before retrying, since resources are not automatically removed. The healthcheck provided by `Dockerfile.mi` tests liveness, not authentication or inference.

GNU Make expands dollar signs in command-line variable assignments. For a literal `$NAME` or `${NAME}` in the MI directory name, quote the assignment against shell expansion and double the dollar for Make, for example `make local-tls-up 'FOUNDRY_MI_DIR=/absolute/private/$$NAME'` or `make local-tls-up 'FOUNDRY_MI_DIR=/absolute/private/$${NAME}'`, with the other required variables supplied separately. Alternatively, pass a shell-quoted inherited environment value, for example `FOUNDRY_MI_DIR='/absolute/private/$NAME' make local-tls-up`; do not double the dollar in that environment value. These are literal path examples, not suggested storage locations.

The independent digest check is a startup check, not publisher authentication or a continuous monitor. Manual `docker start` or `docker restart` bypasses it even though automatic restart is disabled; use the guarded `make local-tls-up` path with explicit project adoption to repeat it. SR's administrator-only `/control/mi/reload` also reads the mounted files independently and does not repeat Foundry's external digest check. In-place writes to the mounted files can be visible to SR; atomic replacement of a host file does not update its existing file bind, so recreate through the guarded startup path to use a replacement. Review and protect inputs and references before any reload, and coordinate operators: host files can change between checking and mounting, and a read-only container mount does not prevent host writes. The container's added operator GID can read these files; Docker administrators and host root remain outside the boundary. The script does not verify image provenance. Authenticated utilization, TLS and execution on a target host still require separate acceptance; this path adds no MI daemon, automatic updates, or model bindings.

SR activates and may persist the candidate MI cut in its durable store before it creates the TLS context or binds the HTTP listener. Consequently, a later TLS or bind failure can leave the candidate persisted even when startup fails; `--wait` does not roll back state. Inspect and back up the relevant project data before an adoption or retry, and do not infer that a failed startup left durable state unchanged.

See [architecture](docs/architecture.md), [milestones](docs/milestones.md), and [repository migration](docs/repository-migration.md).

**Publishing status:** The bootstrap is published in canonical Forgejo at `Creatidy/foundry`. Publication does not establish integrated operation or production readiness.

## Principles

- One product-level install; **not four mandatory daemons** or four shared databases.
- Composed operations must not silently modify product policy or delegate user authority.
- Security boundaries do not follow Docker network labels; network and TLS assertions require evidence.
- Pin component versions and retained evidence independently; do not ship mutable `latest` as accepted release provenance.
- Standalone remains fully functional. Integration unlocks cross-component workflows only when exercised end-to-end.
- Avoid extra controllers, certificate authorities, reverse proxies, message brokers, Docker socket access and new credential stores absent a verified requirement.
