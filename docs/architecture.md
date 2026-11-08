# Foundry integration architecture — M0

**Status:** owner-approved product direction and target architecture; the native launcher requires a prepared SR runtime, and the complete local installer and Docker HTTP transport are not delivered. The existing Compose is a separate, unverified TLS candidate. This is not approval for live installation or a product release.

## Scope

Foundry is a distribution and compatibility boundary for four independent products. Its code should consist of Compose, operator-facing install/update configuration, version and contract records, and cross-product acceptance. It is not a task scheduler, a model router, an MI catalog, a browser authorization broker, or a second control plane.

The integration graph, once each existing producer contract is verified, is:

```text
Kernel -> existing harness -> Scarcity Router authorized gateway -> execution source
Model Intelligence validated publication -> Scarcity Router evidence admission
SR / MI / Kernel owner-served facts and commands -> Console (when implemented)
Foundry -> configure and validate installed component versions and transport
```

## Current evidence and deployment implications

| Component | Implementation and release consideration | Initial composition decision |
| --- | --- | --- |
| Scarcity Router | Existing Python composed HTTP/gateway/control server, SQLite under `/data`, separate native worker, TLS required off loopback; Docker image definition exists, no verified published release. | Only currently described Compose service. Explicit TLS, image and state. |
| Model Intelligence | Library and offline/public evidence producer, retained publication files; no live daemon or automatic refresh scheduler. | Integrate through existing verified SR consumer interface later, not a fake MI service. |
| Creatidy Kernel | Local harness/workspace authority, SQLite on specifically validated native local Linux filesystem; OverlayFS and network filesystems refused. | Keep native-host execution as supported path until container filesystem, harness and credential boundaries pass acceptance. |
| Creatidy Console | React/Vite scaffold, no implemented producer integrations or stable auth/reverse proxy contract. | No operational container until the owning project delivers and accepts integration. |

## Product requirements

The default target is a simple local install and startup using HTTP without certificates, accessible only from the local computer. Native Linux, Windows WSL2/Ubuntu and Docker are intended installation options. An ordinary user should not manually handle image IDs, certificates or network configuration. This is a target, not a claim of an available installer or platform acceptance.

Advanced or distributed deployments retain verified HTTPS/TLS, operator-managed certificates, hostname verification and renewal using standard deployment practices. Docker, remote servers, LAN/VPN and distributed deployments are intended options; additional operator configuration is acceptable. Local onboarding must not require Tailscale, a local CA, Windows certificate import, Unix sockets, a new proxy or another daemon. Host networking is not the Foundry default solution.

## Current implementation

SR supports genuine loopback HTTP without certificates (D-056 tier A), with a Host authority matching the bind; `localhost` is not interchangeable with a `127.0.0.1` bind. SR also supports verified TLS for non-loopback binds and externally managed certificate paths and verified reload. Its example Compose uses host networking for native Linux loopback, not evidence for Docker Desktop. A WSL loopback observation in [SR #224](https://forgejo.creatidy.com/Creatidy/scarcity-router/issues/224) is not complete installation or security acceptance.

Foundry's current `compose.yaml` binds SR to `0.0.0.0` inside a bridge container, requires an explicitly supplied image and certificate/key, and publishes a host loopback port. Its documented public-CA path and experimental local TLS/Windows workflows are not the target simple installer or proof of authenticated end-to-end operation. Docker bridge HTTP is not currently supported: SR rejects non-loopback plaintext listeners, and bridge-published traffic reaches a non-loopback container interface. The experimental Windows certificate-import workflow in [Foundry PR #14](https://forgejo.creatidy.com/Creatidy/foundry/pulls/14) is superseded as the default UX direction, not integrated; its history and unfinished work remain intact. Operator-managed TLS remains relevant for advanced use.

## Target deployment topology

These are acceptance targets, not claims of implemented Foundry installation modes:

| Environment | Target transport | Target network |
| --- | --- | --- |
| Native Linux | HTTP | `127.0.0.1` |
| Windows WSL2 / Ubuntu | HTTP | Verified local loopback access |
| Local Docker, Linux | HTTP | Bridge, host publication on `127.0.0.1` |
| Local Docker Desktop | HTTP | Bridge, host publication on `127.0.0.1` |
| Advanced / distributed | HTTPS/TLS | Operator-configured networking |

## Security and open acceptance

- Native and WSL paths must demonstrate local-only reachability on supported configurations, including actual Windows-to-WSL access and negative external access; forwarding and a Host rejection alone do not prove network isolation.
- Local Docker HTTP requires a future explicit, enforceable SR whole-listener contract. Host loopback publication alone does not prevent direct container-IP routes, access by bridge peers, daemon direct routing, firewall changes or later network attachment. A dedicated or internal network and startup-only inspection do not prove continuous isolation. Demonstrate the effective host publication, container and peer reachability, daemon routing and firewall boundaries over startup, restart and topology changes, with negative LAN/WAN and unintended-peer access checks on each supported platform. Define trusted host and Docker administrator assumptions and fail closed when the boundary cannot be established or maintained.
- Preserve authentication, authorization, Host validation, CSRF defenses and separation of administrator, inference-client, worker and other credentials in every tier. HTTP removes transport confidentiality within the accepted local boundary; local users and privileged host/Docker administrators are not automatically isolated. Protect onboarding and persistent state as well as ordinary requests.
- SR D-056 and D-085 and #224 currently retain a not-yet-implemented, explicitly selected whole-listener Tier B and require TLS on non-loopback binds today. The smallest upstream decision is for SR's owner to amend or formally reconcile #224 and D-085 with the desired ordinary bridge-local HTTP mode: specify the trusted boundary, continuously enforceable isolation and failure behavior, including topology changes, or explicitly decide an equivalent revised contract. A flag, label, unchecked `0.0.0.0` exception or Compose declaration is not that contract. No host-side mechanism is selected here. Until an accepted contract and implementation exist, retain TLS for bridge binds. SR #224 also records review-capacity constraints requiring a policy-consistent owner disposition before further consequential delivery.
- Foundry's existing `AGENTS.md` prohibits plaintext non-loopback listeners. The Docker target conflicts with that instruction until a separately authorized, reviewed policy amendment and SR contract exist; this documentation does not relax it. Native Linux/WSL installer work is independently actionable and does not wait for Docker Tier B.
- Cross-host, LAN, VPN and advanced connections require verified TLS to protect credentials and traffic and authenticate the endpoint across the host boundary. Preserve hostname and chain verification, operator-managed renewal and secure failure; no `verify=false`, TOFU or silent HTTPS-to-HTTP fallback. Worker transport has its own SR contract.

- Each component owns its state and authority. Do not merge SQLite files or copy secrets across components.
- Never mount the Docker socket, owner home, Kilo session tokens or whole source workspaces into the Router server container.
- No blanket host networking, privileged containers, `verify=false`, TOFU, automatic external interface binding, implicit identity migration or silent model substitution.
- A cross-container client must authenticate and, under the current SR contract, verify the correct TLS hostname and trust chain. Internal network membership alone is not an authentication or confidentiality boundary.

## Ownership boundaries

The canonical Forgejo repositories maintain each product's implementation, version tags, source-level CI and product contracts. Foundry references only accepted immutable artifacts and exact integration contracts. `Infrastructure/creatidy-onprem` may consume public Foundry releases for a specific hosted deployment; Foundry must not depend on that private repo.

The owner's completed transfer of Scarcity Router to `Creatidy/scarcity-router` must be verified on canonical Forgejo for consumers and automation, including redirects, branch protection, CI permissions, webhook references, clone/dependency URLs and links, before any automated release work. Do not force-push or recreate the historical repository.
