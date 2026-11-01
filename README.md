# Foundry

**A single, integrated environment for Scarcity Router, Model Intelligence, Creatidy Kernel and Console.**

**Foundry** is the name of the integrated **product**, not another execution engine. Its first implementation milestone packages actual existing capabilities and preserves standalone operation of all components.

Foundry is the public **deployment and integration product**. It does not own routing, public model facts, task orchestration, or operator decisions. Each source product must keep a usable standalone installation and its own contracts, state, release process, and authority.

**Status: M0 bootstrap — NOT a completed or production-ready integrated installation.** The current Compose file describes only the existing Scarcity Router server, with explicit pre-provisioned TLS and an explicitly supplied image. Apart from the separate local test leaf generator below, this repository does **not** implement certificate issuance or renewal, a MI update job, a Kernel runner, or a connected Console. No integrated end-to-end operation has been established.

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

The provisional [`compose.yaml`](compose.yaml) requires **an existing SR image and a publicly trusted hostname-matching certificate/key**. The private-CA case requires a separately accepted trust-bootstrap path; it is not supported by the M0 Compose. This avoids reviving unsafe plaintext communication across Docker bridges. Even when the host port is bound to `127.0.0.1`, Docker publication alone is NOT proof of LAN non-reachability; server-side TLS and authorization remain mandatory.

1. Build an SR image from an inspected exact canonical Forgejo revision and supply its explicit reference in `.env` (`FOUNDRY_ROUTER_IMAGE`). The image must support `--tls-reload-hostname`: the inspected SR revision `209f7d39f3ecebbd1b98b11d7c44c63192fe50a4` supports it, while its first parent (the prior `develop` tip) does not. This is a source compatibility check, not an installation acceptance. No SR release was published as of 2026-10-31; this bootstrap does not clone, build or publish an image.
2. Provide an existing certificate chain and private key readable by SR's non-root container identity. Set `FOUNDRY_TLS_DIR` to the absolute directory containing `server.crt` and `server.key`. Do not add secrets to Git.
3. Set `FOUNDRY_ROUTER_HOST` to the certificate's validated DNS hostname. Inside the container this name is mapped to loopback solely for its HTTPS health probe. External clients still need valid DNS and trust.
4. The M0 verified TLS health probe uses platform trust roots. Do not assume arbitrary clients trust a private CA; that bootstrap is future work.
5. Run `make config` to verify the Compose definition. Use `make up` as the supported startup path: it checks Compose's interpolated TLS bind source is an existing absolute directory with readable `server.crt` and `server.key` before invoking Compose. Direct `docker compose up` bypasses this guard. `make up` is an **explicit deployment action** and requires Docker; do not run it against existing production environments without operator approval.

The preflight checks host-side file presence and readability only. It does not validate certificate trust or hostname, container read access, or authenticated SR startup. The source can also change between the check and Docker mounting it; protect the directory from concurrent modification.

The host port is bound to loopback, but this does not by itself prove the Docker/container port cannot be reached through another network. TLS plus authentication remain mandatory for the composed listener.

## Local test leaf

On Linux, an operator can explicitly run `make local-tls-init TLS_DEST=/absolute/private-parent/new-directory`. The existing parent must be operator-owned with mode `0700`; the destination must not exist. Directory ancestry is checked, symlinks and unsupported filesystem ACLs are rejected. The command requires Python 3, OpenSSL and `/proc/self/fd`, and creates `server.crt` and `server.key` with mode `0640` in a new mode `0750` directory, owned by the operator's primary group. The private parent prevents traversal by other host users. It prints the certificate's SHA-256 fingerprint. Verify that fingerprint through a trusted channel; **do not trust an unverified certificate**. The local filesystem and operator are assumed trusted, not an unauthenticated network.

This is a 30-day self-signed leaf for the numeric IP `127.0.0.1`, not a CA. Direct leaf trust is only for explicitly configured test clients; browser support is not claimed. Generation does not install trust, configure Compose, start a server, or renew certificates.

For an explicit Linux test runtime, configure `.env` as above, but set `FOUNDRY_ROUTER_HOST=127.0.0.1` and `FOUNDRY_TLS_DIR` to the generated directory. Choose a unique Compose project name and run `make local-tls-up LOCAL_TLS_PROJECT=your-unique-test-project TLS_DEST=/absolute/private-parent/new-directory`. The project name is required and explicitly overrides Compose's default name. The command refuses projects with existing project-labeled containers (including stopped containers), networks or volumes, or existing networks/volumes with the resolved Compose names. Docker discovery failures also refuse startup. It validates the protected directory and leaf and invokes canonical Compose with a temporary override: SR receives the operator's numeric primary GID and the leaf as `--tls-reload-ca-cert`; only its healthcheck receives `SR_HEALTHCHECK_CA`. The image must support both settings. No system trust store is changed, and other clients need their own explicit leaf trust. Use `COMPOSE_PROJECT_NAME=your-unique-test-project make down` to stop that project. This command does not authorize a first admin, perform authenticated onboarding, or satisfy other M0 integration gates. The normal `make up` public-CA path is unchanged.

To rerun local startup against an existing project, an operator must first inspect its containers, networks, volumes and data and explicitly acknowledge adoption on that invocation by also setting `LOCAL_TLS_ADOPT_PROJECT=your-unique-test-project`. The acknowledgment must exactly match `LOCAL_TLS_PROJECT`. It authorizes Compose to reuse and potentially modify or recreate existing project resources, including persistent data volumes; the check does not prove ownership. Never use it for a project whose resources must not be touched. The local override is temporary, so normal `make up` is not a local-TLS restart procedure.

The SR container can read the key through the read-only mount; processes with the operator's group *inside that container* can also read it. Host root, Docker administrators, and other privileged actors are outside this isolation boundary. Neither project discovery nor the filesystem check is atomic with Docker startup: concurrent creation or modification can defeat the checks, so coordinate other Docker operators and protect the files from concurrent modification. Docker user-namespace remapping or a remote daemon may prevent access and are not validated. No automatic renewal or Windows/browser support is provided.

The main HTTP listener serves the admin/control and inference surfaces together. Plain HTTP to a non-loopback container listener is not enabled. Authenticated onboarding and real inference must be validated separately. There is no automatic certificate bootstrap or background renewal in M0.

At inspected SR revision `209f7d39f3ecebbd1b98b11d7c44c63192fe50a4`, the composed control server has no MI consumer configuration and its Dockerfile does not install the MI extra. MI's explicit library consumer is not automatically connected to that server. MI revision `e8a6b81546994438038d22fd08fc041c6901d9cd` was its `develop` HEAD at the 2026-10-31 inspection and differs from SR's optional dependency pin `d65891668b7e79f7b666c021f02a1b4bf8c4ca9c`; these source revisions are inspection references, not an accepted or tested Foundry bill of materials. MI's retained artifact digest is not publisher authentication, and selected-source evidence must not be given invented model bindings or freshness.

See [architecture](docs/architecture.md), [milestones](docs/milestones.md), and [repository migration](docs/repository-migration.md).

**Publishing status:** The bootstrap is published in canonical Forgejo at `Creatidy/foundry`. Publication does not establish integrated operation or production readiness.

## Principles

- One product-level install; **not four mandatory daemons** or four shared databases.
- Composed operations must not silently modify product policy or delegate user authority.
- Security boundaries do not follow Docker network labels; network and TLS assertions require evidence.
- Pin component versions and retained evidence independently; do not ship mutable `latest` as accepted release provenance.
- Standalone remains fully functional. Integration unlocks cross-component workflows only when exercised end-to-end.
- Avoid extra controllers, certificate authorities, reverse proxies, message brokers, Docker socket access and new credential stores absent a verified requirement.
