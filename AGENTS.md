# Foundry — repository instructions

Foundry is the public **integration and installation product** for Scarcity Router,
Model Intelligence, Creatidy Kernel and Creatidy Console. It is not an agent
orchestrator, model selector, facts producer or shared authority database.

## Source and authority

- Canonical development is Forgejo `Creatidy/foundry`. GitHub, if later created,
  is a read-only mirror, never a substitute for canonical operations.
- Revalidate source identities and exact upstream contracts before implementing an
  integration. The owner reports SR has moved to `Creatidy/scarcity-router`.
- Do not create, move or rewrite product repositories as a side effect.
- Record decisions in this repository only for Foundry packaging and integration;
  source components own their own APIs, behavior, tests, data and credentials.
- No `main` promotion, release, deployment, external credentials or DNS changes
  without explicit authority.

## Minimal implementation discipline

- Start from one smallest working composition and verify it on actual target hosts.
- Keep one canonical Compose; do not run invented daemons for MI, Kernel or Console.
- No Docker socket, privileged container, blanket shared workspace, plaintext
  non-loopback listener, `verify=false`, TOFU or unverifiable private-CA bootstrap.
- Product capabilities are not established by YAML alone: verify authenticated
  end-to-end execution, TLS, updates, isolation, storage and rollback.
- Use one independently reviewed PR per consequential change after scope and actual
  source are frozen. Exact review/CI/merge authority comes from current canonical
  repository policy, not this bootstrap.
