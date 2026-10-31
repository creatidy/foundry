# Foundry

**A single, integrated environment for Scarcity Router, Model Intelligence, Creatidy Kernel and Console.**

**Foundry** is the name of the integrated **product**, not another execution engine. Its first implementation milestone packages actual existing capabilities and preserves standalone operation of all components.

Foundry is the public **deployment and integration product**. It does not own routing, public model facts, task orchestration, or operator decisions. Each source product must keep a usable standalone installation and its own contracts, state, release process, and authority.

**Status: M0 bootstrap — NOT a completed or production-ready integrated installation.** The current Compose file describes only the existing Scarcity Router server, with explicit pre-provisioned TLS and an explicitly supplied image. This repository does **not** yet implement certificate issuance/renewal, a MI update job, a Kernel runner, or a connected Console. No integrated end-to-end operation has been established.

## Repositories and ownership

| Component | Canonical Forgejo repository | Foundry role |
| --- | --- | --- |
| Scarcity Router | `Creatidy/scarcity-router` (owner-reported migration; verify canonical URL before integration) | The first existing server; gateway, private source state, admission and capacity |
| Model Intelligence | `Creatidy/model-intelligence` | Existing library/public-evidence producer and immutable publication; no invented daemon |
| Creatidy Kernel | `Creatidy/creatidy-kernel` | Controller for existing harnesses and workspaces; native-host execution remains supported |
| Creatidy Console | `Creatidy/creatidy-console` | Future connected operator UI; current public code is a scaffold |
| Foundry | **intended** `Creatidy/foundry` (not yet created/published by this package) | Product-level versions, configuration, Compose, integration acceptance and update procedure |

`Infrastructure/creatidy-onprem` remains the separate, private owner of deployment-specific hosts, proxying, TLS infrastructure and secrets. Foundry must not require that repository. GitHub is a read-only mirror, not a canonical dependency or publishing target.

## M0 compose — deliberately not zero-touch

The provisional [`compose.yaml`](compose.yaml) requires **an existing SR image and a publicly trusted hostname-matching certificate/key**. The private-CA case requires a separately accepted trust-bootstrap path; it is not supported by the M0 Compose. This avoids reviving unsafe plaintext communication across Docker bridges. Even when the host port is bound to `127.0.0.1`, Docker publication alone is NOT proof of LAN non-reachability; server-side TLS and authorization remain mandatory.

1. Build an SR image from an inspected exact canonical Forgejo revision, or choose an independently reviewed immutable released image. Supply its explicit reference in `.env` (`FOUNDRY_ROUTER_IMAGE`). This bootstrap does not clone, build or publish that image.
2. Provide an existing certificate chain and private key readable by SR's non-root container identity. Set `FOUNDRY_TLS_DIR` to the absolute directory containing `server.crt` and `server.key`. Do not add secrets to Git.
3. Set `FOUNDRY_ROUTER_HOST` to the certificate's validated DNS hostname. Inside the container this name is mapped to loopback solely for its HTTPS health probe. External clients still need valid DNS and trust.
4. The M0 verified TLS health probe uses platform trust roots. Do not assume arbitrary clients trust a private CA; that bootstrap is future work.
5. Run `make config` to verify the rendered Compose definition. `make up` is an **explicit deployment action** and requires Docker; do not run it against existing production environments without operator approval.

The host port is bound to loopback, but this does not by itself prove the Docker/container port cannot be reached through another network. TLS plus authentication remain mandatory for the composed listener.

The main HTTP listener serves the admin/control and inference surfaces together. Plain HTTP to a non-loopback container listener is not enabled. Authenticated onboarding and real inference must be validated separately. There is no automatic certificate bootstrap or background renewal in M0.

See [architecture](docs/architecture.md), [milestones](docs/milestones.md), and [repository migration](docs/repository-migration.md).

**Publishing status:** This directory is a local repository-ready seed, not a Forgejo commit or PR. Foundry creation in canonical Forgejo remains to be completed with authenticated access. No existing product repository has been changed.

## Principles

- One product-level install; **not four mandatory daemons** or four shared databases.
- Composed operations must not silently modify product policy or delegate user authority.
- Security boundaries do not follow Docker network labels; network and TLS assertions require evidence.
- Pin component versions and retained evidence independently; do not ship mutable `latest` as accepted release provenance.
- Standalone remains fully functional. Integration unlocks cross-component workflows only when exercised end-to-end.
- Avoid extra controllers, certificate authorities, reverse proxies, message brokers, Docker socket access and new credential stores absent a verified requirement.
