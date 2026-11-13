# Foundry integration architecture

**Status:** canonical Compose implements default single-host local HTTP and explicit advanced TLS overrides. Native foreground startup remains available. Source implementation, synthetic checks and historical receipts are not production or target-host acceptance. No release, deployment or host test is authorized by this documentation.

## Scope

Foundry is a distribution and compatibility boundary for four independent products. Its code should consist of Compose, operator-facing install/update configuration, version and contract records, and cross-product acceptance. It is not a task scheduler, a model router, an MI catalog, a browser authorization broker, or a second control plane.

The responsibility graph, not a requirement to run four services, is:

```text
Kernel approved work <-> existing pull client or supported managed harness
Route-enabled profile only: harness -> Scarcity Router authorized gateway -> execution source
Model Intelligence validated publication -> Scarcity Router evidence admission
Supported producer facts / separately authorized commands <-> Console
Foundry -> configure and validate installed component versions and transport
```

## Current evidence and deployment implications

| Component | Implementation and release consideration | Initial composition decision |
| --- | --- | --- |
| Scarcity Router | Existing composed HTTP/gateway/control server, durable state under `/data` and direct worker protocol. The pinned version supports explicit local-container plaintext mode and separately configured TLS. | The only Compose service; default source build, host-loopback HTTP/worker publications, named data volume. No default proxy. |
| Model Intelligence | Library and offline evidence/publication producer; SR's MI dependency is installed in the default image, but publication activation remains opt-in. No daemon or automatic refresh scheduler. | Validate an operator-selected retained cut through SR's actual consumer; keep digest, provenance, rights and policy distinct. |
| Creatidy Kernel | One work-control core for cooperative pull and supported managed push, ordinary SDK and independently bound provider drivers. SQLite requires validated native-local Linux topology; OverlayFS and network filesystems refuse. | Preserve native-host execution; do not invent a container, network daemon or generic harness guarantee for packaging symmetry. |
| Creatidy Console | Authenticated Node/TypeScript application server, React views, durable owner sessions, Router observer foundation and optional Linux read-only Kernel proposal channel. | Not shipped as a connected Foundry service. Adopt exact producer contracts and prove installed integration; no active producer database access. |

## Canonical Compose and startup

`compose.yaml` is the single base. `make up` calls `scripts/local_tls_up.py --local-http`, builds `Dockerfile.mi` for the default `foundry-sr-mi:5bd4fa4-local` image, resolves its local ID and starts that ID through a temporary generated override. No `.env`, certificates or manually entered image hash are required. The default source build checks canonical SR `5bd4fa4d65028b46455f63726c2dda7b8e3ca341` and SR's exact MI dependency `d65891668b7e79f7b666c021f02a1b4bf8c4ca9c`. Base images, OS packages and other dependencies remain unlocked; these pins are not a reproducible or published release.

The router explicitly receives `--local-container-http`, binds HTTP `0.0.0.0:8787` and direct worker `0.0.0.0:8790`, and publishes each on host `127.0.0.1`. Normal addresses are `http://127.0.0.1:8787/admin` and `srw://127.0.0.1:8790`. Worker pairing/authentication is still required; no worker, model or client key is created by Compose. The worker is not reached through an HTTP proxy.

`FOUNDRY_MI_DIR` and `FOUNDRY_MI_SHA256` opt into protected `trust.json` and `publication.json` mounts and `--mi-config`. Optional `FOUNDRY_MI_IMAGE_ID` asserts a known local image identity; omission does not require a manual hash step. Digest matching is not publisher authentication, full schema validation or a refresh service. SR owns activation and policy. The opt-in disables automatic restart; every deliberate restart/recreation must preserve its reviewed inputs. See [startup and MI details](../README.md#opt-in-mi).

`make build` explicitly builds before either advanced TLS startup. `make tls-up` calls the same script with `--tls`, requires `LOCAL_TLS_PROJECT`, `FOUNDRY_ROUTER_HOST` and an existing public-CA `FOUNDRY_TLS_DIR`, and replaces both listener transports with TLS. The existing Linux `make local-tls-up` instead validates a protected self-signed numeric-loopback leaf with `TLS_DEST`, matching `FOUNDRY_TLS_DIR`, `FOUNDRY_ROUTER_HOST=127.0.0.1` and an explicit project. Both use generated overrides, not a second Compose. Existing TLS projects require matching `LOCAL_TLS_ADOPT_PROJECT` after operator inspection; adoption is not ownership proof. Neither path falls back to HTTP or issues administrator claims.

The public-CA path uses normal trust verification; the protected test leaf requires independently verified explicit client trust and changes no trust store. The HTTPS healthcheck's hostname mapping is container-local, not external DNS. Host publications remain loopback even in TLS mode; cross-host exposure is a separate operator configuration and acceptance task. No default reverse proxy, host networking or global Docker change is needed.

## Product requirements

Default onboarding must not require manual image IDs, certificates or network setup. Local Compose now provides that startup path; native Linux and Windows WSL2/Ubuntu startup remain separate supported mechanisms with their documented runtime prerequisites. Actual clean-machine/platform acceptance is not inferred from implementation.

Advanced or distributed deployments retain verified HTTPS/TLS, operator-managed certificates, hostname verification and renewal using standard deployment practices. Local onboarding does not require Tailscale, a local CA, Windows certificate import, a new proxy or another daemon. A Kernel-local descriptor capability is its producer contract, not a new default Router transport requirement.

## Current implementation

`make start` discovers a provenance-checked existing native SR environment and delegates to the foreground launcher; absent environments need the documented inspected-checkout installation. Native HTTP binds `127.0.0.1`; `localhost` is not interchangeable for Host validation. Native MI uses protected host-local publication paths and the selected interpreter's optional MI dependency, not container paths or an image ID. Native and Compose state locations and accepted runtime versions are distinct.

The experimental Windows certificate-import direction in [Foundry PR #14](https://forgejo.creatidy.com/Creatidy/foundry/pulls/14) is superseded as default UX. Legacy Windows TLS helpers retain old-layout guards and are not a current installation path. Do not update a hash, encode commands or weaken policy to bypass a refusal. Windows-native tests require separate exact batch approval.

## Target deployment topology

These transports describe supplied mechanisms and intended deployment boundaries, not completed platform acceptance:

| Environment | Target transport | Target network |
| --- | --- | --- |
| Native Linux | HTTP | `127.0.0.1`, trusted local host |
| Windows WSL2 / Ubuntu | HTTP | Local loopback/browser reachability must be received on the exact host |
| Local Docker, Linux | Explicit local-container HTTP and `srw` | Bridge; host publications on `127.0.0.1`; peers/routes inside plaintext boundary |
| Local Docker Desktop | Same local-container profile | Target-host behavior and Windows/WSL boundary remain to verify |
| Advanced / distributed | Verified HTTPS and worker TLS | Operator-configured networking; hostname/chain verification; no fallback |

## Security and open acceptance

- Native/WSL acceptance must record actual local reachability and negative external access on the supported host. Forwarding or Host rejection alone does not prove isolation.
- The default Compose network is plaintext: attached peers and operator-configured routes may reach the listener. Host-loopback publication is not a promise of inaccessible container IPs, confidentiality from peers or continuous network isolation. Trust the host/Docker administrators and protect topology; do not add topology monitoring, host networking, a proxy or global Docker configuration as default prerequisites.
- Preserve authentication, authorization, Host validation, CSRF defenses and separate administrator, inference-client, worker and observer credentials. Protect private-terminal onboarding and persistent state. A successful healthcheck is not authenticated inference or worker execution.
- Cross-host, LAN/VPN, network-segment and independently configured distributed Docker connections require verified TLS on HTTP and worker transports. Preserve hostname and chain verification, operator-managed renewal and secure failure; no `verify=false`, TOFU or silent fallback.
- Each component owns its state and authority. Do not merge SQLite files or copy secrets across components.
- Never mount the Docker socket, owner home, Kilo session tokens or whole source workspaces into the Router server container.
- No blanket host networking, privileged containers, `verify=false`, TOFU, automatic external interface binding, implicit identity migration or silent model substitution.
- Clients inside the selected local plaintext boundary still authenticate; clients outside it require verified TLS. Network membership never grants authority.

## Verified Kernel and Console boundaries

Canonical Forgejo metadata and immutable source were read on 2026-11-13:

| Source | Exact `develop` revision | Foundry consequence |
| --- | --- | --- |
| [Kernel](https://forgejo.creatidy.com/Creatidy/creatidy-kernel/src/commit/5e6f42906980fd42293e0dab1be3d7942532ff81/README.md) | `5e6f42906980fd42293e0dab1be3d7942532ff81` | Ordinary SDK and provider-qualified composition ship; do not describe them as absent or require strict Router interception for basic pull. |
| [Console](https://forgejo.creatidy.com/Creatidy/creatidy-console/src/commit/8f68259e8353d5c480d79598c28687079ad8eb14/docs/contracts.md) | `8f68259e8353d5c480d79598c28687079ad8eb14` | Authenticated local application and read-only producer integrations are bounded, not a scaffold or complete task-control UI. |

[ADR0012](https://forgejo.creatidy.com/Creatidy/creatidy-kernel/src/commit/5e6f42906980fd42293e0dab1be3d7942532ff81/docs/adr/0012-unified-work-coordination-and-drivers.md) supersedes ADR0007's universal push/gateway interpretation. Kernel owns work, budgets, claims, review/acceptance and recovery; Router owns model/source selection/admission, quota and gateway facts. Basic cooperative pull can use an acknowledged harness configuration without intercepting internal inference. Strict routing, pin/admission, hard inference caps and no-hidden-call guarantees require exact-profile proof or refusal. #52 is retired wontfix, not implemented or required for initial acceptance. Neither Console, an IDE plugin nor a specific harness is mandatory.

The implemented `ScarcityRouterAllocator` consumes SR's `/v1/select` recommendation interface and Kernel checks its own runtime bindings. A recommendation is not a reservation or proof of dynamic inference through SR's execution gateway. Kernel #55 and #60 and Console #34 do not block independently executable Foundry #1 source work.

Kernel serves its own snapshots/events/commands through bounded trusted-local capabilities, not a general browser HTTP API. Its Linux supervisor launch passes an inherited descriptor to a backend, not attachment to an existing server; configured labels check pairing, not producer identity. Console login is not a Kernel grant. The current optional Console channel displays a digest-verified proposal only, with effective host policy unknown; all Kernel commands remain unavailable. No active Kernel SQLite reader, new Kernel network bridge or shared authority database is authorized.

Console owns same-origin browser authentication and durable sessions, not producer business authority. Router observer credentials are separately scoped; administration retains its own login. Its current observer adapter accepts configured literal-loopback origins only, so a Docker service hostname is not automatically a supported Console connection. MI's documented operator boundary is offline read-only `mi.operator-working/1`, not a daemon or replay service. Producer-scoped revisions, gaps, freshness, explicit unknowns and supported correlations must survive projections; no global event order or heuristic joins.

Kernel [#55](https://forgejo.creatidy.com/Creatidy/creatidy-kernel/issues/55) already retains immutable utilized MI references as local-only provenance; direct-content/harness-evidence expansion remains optional. The latest [#60 receipt](https://forgejo.creatidy.com/Creatidy/creatidy-kernel/issues/60#issuecomment-22066) records integrated #105 and #133/#134 and an installed synthetic four-provider ordinary journey. Earlier deferred/no-bridge claims are historical. Full #60 acceptance is still UNVERIFIED, with incomplete composed-matrix/review and unreceived live acceptance. [Console #34](https://forgejo.creatidy.com/Creatidy/creatidy-console/issues/34) similarly retains multi-producer/recovery and installed evidence gaps. Foundry must not turn component source receipts into cross-product acceptance.

## State, upgrades and recovery

The Compose pin uses SR server-store schema 6; historical SR `f96d58e` uses schema 4. Stop the exact controller and verify an offline backup of its complete `/data` volume before updating or rebuilding. Retain the old image/settings and separately protected MI/TLS inputs. Opening the new server can migrate state before listener or TLS initialization, and MI activation can persist a cut before requests are served. Failure/timeout is not unchanged state or automatic rollback.

An old binary refuses the newer schema. Rollback requires stopping the new server and restoring a verified pre-upgrade backup into a separate recovery location with the compatible old image/configuration; it loses writes after that backup. Preserve failed-upgrade state, do not edit markers/delete sidecars, and reconcile external effects separately. Foundry supplies no automated lossless downgrade, backup service or proven target-host recovery. See the [operator sequence](../README.md#upgrade-backup-and-recovery).

## Ownership boundaries

The canonical Forgejo repositories maintain each product's implementation, version tags, source-level CI and product contracts. Foundry references only accepted immutable artifacts and exact integration contracts. `Infrastructure/creatidy-onprem` may consume public Foundry releases for a specific hosted deployment; Foundry must not depend on that private repo.

The owner's completed transfer of Scarcity Router to `Creatidy/scarcity-router` must be verified on canonical Forgejo for consumers and automation, including redirects, branch protection, CI permissions, webhook references, clone/dependency URLs and links, before any automated release work. Do not force-push or recreate the historical repository.
