# Foundry integration architecture — M0

**Status:** owner-approved product direction and target architecture; `make start` discovers a verifiable existing native SR runtime and delegates to the foreground launcher. Absent runtimes use an explicit inspected-checkout `uv tool install` step. The complete local installer and Docker HTTP transport are not delivered. The existing Compose is a separate, unverified TLS candidate. This is not approval for live installation or a product release.

## Scope

Foundry is a distribution and compatibility boundary for four independent products. Its code should consist of Compose, operator-facing install/update configuration, version and contract records, and cross-product acceptance. It is not a task scheduler, a model router, an MI catalog, a browser authorization broker, or a second control plane.

The integration graph, once each existing producer contract is verified, is:

```text
Kernel -> SR /v1/select recommendation -> Kernel-bound existing harness
Optional execution client -> Scarcity Router authorized gateway -> execution source
Model Intelligence validated publication -> Scarcity Router evidence admission
SR / MI / Kernel owner-served facts and commands -> Console (when implemented)
Foundry -> configure and validate installed component versions and transport
```

CK's implemented SR allocator consumes recommendations from `/v1/select` and independently checks its runtime bindings; a recommendation is not a reservation or proof of execution. At inspected [CK revision `1bcb052`](https://forgejo.creatidy.com/Creatidy/creatidy-kernel/src/commit/1bcb052e527933b7b2f419ac76017f2d20e88a1e/README.md), its SR client accepts HTTP only for configured loopback hostnames and requires verified HTTPS otherwise. A Docker service name is not loopback to a client in another container. CK's own owner interface is a preconnected local descriptor, not an existing network server. These are current CK contracts, not a requirement to add a proxy or a claim that CK and the selected SR revision have been accepted together.

## Current evidence and deployment implications

| Component | Implementation and release consideration | Initial composition decision |
| --- | --- | --- |
| Scarcity Router | Existing Python composed HTTP/gateway/control server, SQLite under `/data`, separate native worker, explicit local-container HTTP mode and verified TLS for networked use; Docker image definition exists, no verified published release. | Only currently described Compose service. Foundry's current Compose uses explicit TLS, image and state. |
| Model Intelligence | Library and offline/public evidence producer, retained publication files; no live daemon or automatic refresh scheduler. | Integrate through existing verified SR consumer interface later, not a fake MI service. |
| Creatidy Kernel | Local harness/workspace authority with a preconnected local descriptor interface, and SQLite on a specifically validated native local Linux filesystem; OverlayFS and network filesystems refused. | Keep native-host execution as supported path until container filesystem, harness and credential boundaries pass acceptance. Do not invent a CK network daemon. |
| Creatidy Console | React/Vite scaffold, no implemented producer integrations or stable auth/reverse proxy contract. | No operational container until the owning project delivers and accepts integration. |

## Product requirements

The default target is a simple local install and startup using HTTP without certificates, accessible only from the local computer. Native Linux, Windows WSL2/Ubuntu and Docker are intended installation options. An ordinary user should not manually handle image IDs, certificates or network configuration. This is a target, not a claim of an available installer or platform acceptance.

Advanced or distributed deployments retain verified HTTPS/TLS, operator-managed certificates, hostname verification and renewal using standard deployment practices. Docker, remote servers, LAN/VPN and distributed deployments are intended options; additional operator configuration is acceptable. Local onboarding must not require Tailscale, a local CA, Windows certificate import, Unix sockets, a new proxy or another daemon. Host networking is not the Foundry default solution.

## Current implementation

SR supports genuine loopback HTTP without certificates, with a Host authority matching the bind; `localhost` is not interchangeable with a `127.0.0.1` bind. Since [SR PR #267](https://forgejo.creatidy.com/Creatidy/scarcity-router/pulls/267), its explicit `--local-container-http` mode also supports ordinary local bridge Compose with host-loopback publication. SR retains verified TLS for advanced networked deployments and externally managed certificate paths and reload. Upstream testing is not acceptance of a Foundry installation.

Foundry's current `compose.yaml` binds SR to `0.0.0.0` inside a bridge container, requires an explicitly supplied image and certificate/key, and publishes a host loopback port. Its documented public-CA path and experimental local TLS/Windows workflows are not the target simple installer or proof of authenticated end-to-end operation. SR's new explicit Docker HTTP mode is not yet integrated in Foundry: bridge-published traffic reaches a non-loopback container interface, and Foundry's current instructions prohibit plaintext listeners there. The experimental Windows certificate-import workflow in [Foundry PR #14](https://forgejo.creatidy.com/Creatidy/foundry/pulls/14) is superseded as the default UX direction, not integrated; its history and unfinished work remain intact. Operator-managed TLS remains relevant for advanced use.

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
- SR's explicit local Docker HTTP mode publishes ports to host loopback in its supplied Compose configuration, but HTTP is plaintext on the Compose network: other connected containers can reach the listener. Host-loopback publication alone does not establish isolation from direct container-IP routes or later network changes. The local deployment assumes a trusted host and Docker administrator; operators who alter the supplied topology are responsible for the resulting exposure. Continuous topology monitoring is not part of the owner's local deployment requirement.
- Preserve authentication, authorization, Host validation, CSRF defenses and separation of administrator, inference-client, worker and other credentials in every tier. HTTP removes transport confidentiality within the accepted local boundary; local users and privileged host/Docker administrators are not automatically isolated. Protect onboarding and persistent state as well as ordinary requests.
- The owner revised [SR #224](https://forgejo.creatidy.com/Creatidy/scarcity-router/issues/224), superseding the former continuous topology-enforcement requirement. Its local Docker mode was merged in SR PR #267; the issue is now closed. No topology watcher, new proxy or certificate-management service is required by that local SR scope.
- Foundry's existing `AGENTS.md` independently prohibits plaintext non-loopback listeners. The Docker HTTP target still conflicts with that instruction until a separately authorized, reviewed policy amendment; this documentation does not relax it. Native Linux/WSL installer work is independently actionable.
- Cross-host, LAN, VPN and advanced connections require verified TLS to protect credentials and traffic and authenticate the endpoint across the host boundary. Preserve hostname and chain verification, operator-managed renewal and secure failure; no `verify=false`, TOFU or silent HTTPS-to-HTTP fallback. Worker transport has its own SR contract.

- Each component owns its state and authority. Do not merge SQLite files or copy secrets across components.
- Never mount the Docker socket, owner home, Kilo session tokens or whole source workspaces into the Router server container.
- No blanket host networking, privileged containers, `verify=false`, TOFU, automatic external interface binding, implicit identity migration or silent model substitution.
- A cross-container client must authenticate. In SR's explicit local HTTP mode, traffic on the Compose network is plaintext; in advanced networked deployments the client must verify the TLS hostname and trust chain. Network membership alone is not an authentication or confidentiality boundary.

## Ownership boundaries

The canonical Forgejo repositories maintain each product's implementation, version tags, source-level CI and product contracts. Foundry references only accepted immutable artifacts and exact integration contracts. `Infrastructure/creatidy-onprem` may consume public Foundry releases for a specific hosted deployment; Foundry must not depend on that private repo.

The owner's completed transfer of Scarcity Router to `Creatidy/scarcity-router` must be verified on canonical Forgejo for consumers and automation, including redirects, branch protection, CI permissions, webhook references, clone/dependency URLs and links, before any automated release work. Do not force-push or recreate the historical repository.
