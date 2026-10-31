# Foundry integration architecture — M0

**Status:** proposed deployment architecture and unverified Compose candidate. Not approval for live installation, no product release.

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

## Isolation, credentials and network

- Each component owns its state and authority. Do not merge SQLite files or copy secrets across components.
- M0 publishes only the SR composed listener to host loopback and requires TLS inside the container (non-loopback bind). Do not claim the Docker publication isolates every possible direct route. Authorization and verified TLS remain mandatory.
- M0 uses an existing, publicly trusted operator-managed certificate, not a Foundry-generated CA. DNS hostname must match the certificate; the same hostname maps to container loopback for SR's verified HTTPS healthcheck. This is a liveness mechanism, not trust bootstrap for arbitrary clients.
- Never mount the Docker socket, owner home, Kilo session tokens or whole source workspaces into the Router server container.
- No blanket host networking, privileged containers, `verify=false`, TOFU, automatic external interface binding, implicit identity migration or silent model substitution.
- A future cross-container client must authenticate and verify the correct hostname and trust chain. Internal network membership alone is not an authentication or confidentiality boundary.

## Ownership boundaries

The canonical Forgejo repositories maintain each product's implementation, version tags, source-level CI and product contracts. Foundry references only accepted immutable artifacts and exact integration contracts. `Infrastructure/creatidy-onprem` may consume public Foundry releases for a specific hosted deployment; Foundry must not depend on that private repo.

The owner's completed transfer of Scarcity Router to `Creatidy/scarcity-router` must be verified on canonical Forgejo for consumers and automation, including redirects, branch protection, CI permissions, webhook references, clone/dependency URLs and links, before any automated release work. Do not force-push or recreate the historical repository.
