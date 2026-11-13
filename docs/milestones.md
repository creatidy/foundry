# Foundry delivery gates

Do not treat a documentation-only plan or synthetic fixture as a deployed integrated product.

## M0 — local installation and acceptance

- [x] Select product name **Foundry** and narrow repository ownership.
- [x] Supply one canonical Compose for the existing SR service, default `Dockerfile.mi` build, explicit local-container HTTP and direct worker port 8790 published on host `127.0.0.1`; no default proxy or invented MI/Kernel/Console daemons.
- [x] Document current functionality, external dependencies and trust boundaries.
- [x] Create `Creatidy/foundry` on canonical Forgejo and publish the bootstrap.
- [ ] Publish reviewed integration changes.
- [x] Add native foreground launcher (PR #19) and interpreter-free `make start` discovery with exact-source compatibility checks and explicit SR checkout installation guidance. These increments are not a complete installer; owner-confirmed ROG browser/onboarding/restart evidence does not close inference, fresh-install, isolation, update or recovery acceptance.
- [x] Implement `make up` through `scripts/local_tls_up.py --local-http`, with automatic default build/image-ID resolution and no required `.env`, certificates or manually supplied image hash. Source pins are SR `5bd4fa4d65028b46455f63726c2dda7b8e3ca341` and its MI dependency `d65891668b7e79f7b666c021f02a1b4bf8c4ca9c`; dependency installation is not publication activation.
- [x] Retain protected Linux `local-tls-up` and add explicit `make tls-up` through the script's `--tls` mode, using generated overrides only. Advanced paths require `make build` first, exact TLS settings/project and no silent HTTP fallback.
- [x] Document private manual first-admin claim issuance, optional MI cut/digest with optional image-ID assertion, and stop/backup/restore requirements for schema-4-to-6 upgrades. Documentation is not executed acceptance.
- [ ] **Local target acceptance:** on each supported native Linux, Windows WSL2/Ubuntu and Docker option, receive install/start, local UI, manual first-admin onboarding and authenticated functionality, including execution with an authorized resource, without mandatory certificates, image hashes or network setup. Implemented startup is not a completed clean-machine installer or target-host receipt.
- [ ] Verify first-run/restart, persistent identity/configuration/data, denied unauthorized access and actual supplied topology on each supported platform. Record that local Compose peers/routes are inside a plaintext trust boundary; do not claim inaccessible container IPs or require continuous topology monitoring as a default feature.
- [ ] Exercise stopped-state complete backup, schema-4-to-6 upgrade, failure inspection and restore with the compatible old image. Demonstrate that rollback restores the earlier state and loses later writes; no image-only downgrade, automatic rollback or preservation of post-backup writes is claimed.
- [ ] **Advanced TLS:** separately verify operator-managed certificates, hostname and chain validation, renewal/reload, authenticated operation and secure failures for supported remote, LAN/VPN and distributed deployments. Do not require this certificate lifecycle for basic local onboarding.

## M1 — evidence integration

- [x] Provide opt-in activation via `FOUNDRY_MI_DIR` and `FOUNDRY_MI_SHA256`, protected file mounts and exact-cut checks; a manually supplied `FOUNDRY_MI_IMAGE_ID` is optional. No MI daemon or automatic refresh follows.
- [ ] Receive the actual installed producer/consumer path at the exact SR/MI/artifact revisions. Build checks and synthetic fixtures are not authenticated target-host utilization or source applicability.
- [ ] Add an opted-in retained publication refresh/update mechanism only if necessary; define schedule, one-writer custody, rollback and failure semantics before adding a service.
- [ ] Prove MI publication is consumed by SR with exact version and decision-to-evidence binding. Outage/stale/withdrawal tests retain truthful known/unknown facts.
- [ ] Keep both components independently installable.

## M2 — Kernel composition

- [x] Revalidate canonical Kernel `develop` `5e6f42906980fd42293e0dab1be3d7942532ff81`: one pull/push core, ordinary SDK and provider-qualified composition are integrated. This source research is not Foundry acceptance.
- [ ] Receive installed ordinary pull-first work through the supported Kernel core, with optional evidenced managed push. Neither a specific harness, Console nor strict Router gateway interception is a basic prerequisite.
- [ ] For a requested strict routing/pin/admission/no-hidden-call profile, prove exact harness/Router/version compatibility or refuse it. Kernel #52 is retired wontfix, not completed or an initial acceptance gate.
- [ ] Preserve workspace ownership, scoped credentials, native filesystem SQLite constraints and non-root execution.
- [ ] Compose Kernel's existing trusted-local owner/worker capabilities without inventing an HTTP daemon, exposing trusted controller objects or opening active SQLite. A resident/container deployment requires an actual need and accepted producer/security contract, not symmetry.
- [ ] Prove approved work -> supported execution -> exact verification and independent review/remediation -> acceptance, with original budgets, explicit cost unknowns, STOP/settlement and recovery. Add route facts only where evidenced. Kernel #60 remains open despite integrated #105/#133; its complete composed matrix and live acceptance are not established.

## M3 — Console integration and user acceptance

- [x] Revalidate Console `develop` `8f68259e8353d5c480d79598c28687079ad8eb14`: authenticated local application/sessions, Router observer foundation and optional read-only Kernel proposal view exist; it is not merely a scaffold.
- [ ] Adopt actual source-owned interfaces and supported authorization; do not read producer databases. Kernel's inherited local descriptor and MI's offline read-only operator contract are not browser/network services.
- [ ] Receive Console multi-producer freshness, recovery, security and installed compatibility under Console #34. Preserve independent Router-only usefulness; all Kernel commands currently remain unavailable, and Console login grants no producer authority.
- [ ] Provide coherent onboarding/update guidance without copying credentials or conflating Console login, Router observer/admin/inference credentials and Kernel capabilities.
- [ ] Test on native Linux and standard Docker Desktop/Windows/WSL2 with no forced global settings.
- [ ] Define pinned release bill of materials, supported upgrades, rollbacks, back-ups and recovery.

Individual product issues are not made ineligible merely because a downstream Foundry acceptance milestone is unfinished. Explicit owner authorization and canonical producer evidence control acceptance.
