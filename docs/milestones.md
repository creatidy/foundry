# Foundry delivery gates

Do not treat a documentation-only plan or synthetic fixture as a deployed integrated product.

## M0 — bootstrap (this package)

- [x] Select product name **Foundry** and narrow repository ownership.
- [x] Prepare a single safe Compose **candidate** with an existing SR service; no invented MI/Kernel/Console daemons.
- [x] Document current functionality, external dependencies and trust boundaries.
- [x] Create `Creatidy/foundry` on canonical Forgejo and publish the bootstrap.
- [ ] Publish reviewed integration changes.
- [ ] **Local target:** on each supported native Linux, Windows WSL2/Ubuntu and Docker option, an ordinary user can install and start Foundry, open the local UI, complete first-administrator onboarding and use authenticated SR functionality, including execution with an authorized resource, without manually managing certificates, Docker image hashes or network settings. No such complete installer is delivered yet.
- [ ] Verify actual installation, first-run and restart, persistent identity/configuration/data, safe update and recovery, denied unauthorized access and local-only network boundaries on each supported platform. Docker bridge HTTP requires an accepted and verified SR #224 contract; native Linux/WSL work can proceed independently.
- [ ] **Advanced TLS:** separately verify operator-managed certificates, hostname and chain validation, renewal/reload, authenticated operation and secure failures for supported remote, LAN/VPN and distributed deployments. Do not require this certificate lifecycle for basic local onboarding.

## M1 — evidence integration

- [ ] Verify MI public artifact producer contract and SR's actual consumer path on exact source revisions.
- [ ] Add an opted-in retained publication refresh/update mechanism only if necessary; define schedule, one-writer custody, rollback and failure semantics before adding a service.
- [ ] Prove MI publication is consumed by SR with exact version and decision-to-evidence binding. Outage/stale/withdrawal tests retain truthful known/unknown facts.
- [ ] Keep both components independently installable.

## M2 — Kernel composition

- [ ] Verify the current supported Kernel adapter and SR gateway compatibility with a REAL local harness execution.
- [ ] Preserve workspace ownership, scoped credentials, native filesystem SQLite constraints and non-root execution.
- [ ] Decide whether Kernel needs a resident service or a native host process; do not introduce a container just for symmetry.
- [ ] Prove task -> model route -> execution -> independent review -> acceptance with exact provenance and no self-approval.

## M3 — Console integration and user acceptance

- [ ] Implement source-owned read/command APIs in each producer as needed; do not read their databases directly.
- [ ] Console owner implements auth, browser security, state freshness, commands and actual views.
- [ ] One onboarding flow, one update path, no unreviewed secrets transfer.
- [ ] Test on native Linux and standard Docker Desktop/Windows/WSL2 with no forced global settings.
- [ ] Define pinned release bill of materials, supported upgrades, rollbacks, back-ups and recovery.

Individual product issues are not made ineligible merely because a downstream Foundry acceptance milestone is unfinished. Explicit owner authorization and canonical producer evidence control acceptance.
