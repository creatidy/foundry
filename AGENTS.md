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
- Target ordinary feature PRs at `develop`; use `main` for controlled integration
  and promotions from `develop`.
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

## Host security and test execution

- The owner's Windows workstation is not disposable. Starting Windows-native
  processes from WSL affects the host even with mocks, synthetic data or temporary
  files. Read-only repository analysis does not authorize host-interacting tests.
- Do not execute generated, encoded, compressed, obfuscated or dynamically
  reconstructed PowerShell, or existing code containing such techniques, for any
  purpose until a separate owner-authorized remediation and validation plan exists.
  Examples include generated `-EncodedCommand` payloads, Base64/gzip loaders,
  dynamic `[scriptblock]::Create(...)` and in-memory execution used to bypass a
  restricted `-File` path. These patterns are not inherently malicious and may be
  inspected statically. Never use them to work around execution-policy or path
  restrictions, failed launches or endpoint-security detections.
- Obtain explicit advance owner approval for each batch of tests that starts native
  Windows processes, changes Windows state or may interact with endpoint protection.
  Describe exact commands and executables, affected machine and account, expected
  subprocesses and visible windows, security-sensitive behavior, time and resource
  bounds, cleanup and failure handling. Approval does not cover arbitrary retries or
  alternative wrappers.
- Stop immediately on an unexplained native launch failure, Windows subprocess
  timeout, antivirus or endpoint-protection warning, unexpected security-policy
  behavior or failure to establish isolation. Do not retry with different encoding,
  compression, flags, paths or wrappers; escalate the evidence and remaining
  verification need.
- Never disable endpoint protection, add exclusions, bypass execution policy,
  suppress detection or alter global Windows settings to make tests pass. Never
  silently change trust stores, credential stores, firewall, policy or security
  configuration.
- Prefer static analysis and pure Linux/Python unit tests for non-Windows logic; do
  not launch PowerShell merely to exercise a simulated certificate store when the
  logic can be validated without native Windows execution. Native acceptance still
  requires an explicitly authorized, isolated test plan where relevant; do not
  expand test infrastructure for hypothetical edge cases.
