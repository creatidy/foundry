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
- No Docker socket, privileged container, blanket shared workspace, `verify=false`,
  TOFU or unverifiable private-CA bootstrap.
- The default single-host Compose profile explicitly selects SR's
  `--local-container-http` mode, binds any published service ports to host
  loopback, and requires no certificates. This profile is the only permitted
  case for plaintext non-loopback listeners. Authentication and authorization
  remain required.
  HTTP is plaintext on the Compose network: attached peers or operator-configured
  routing may reach the listener, and host-loopback publication alone does not
  prove isolation. Operators are responsible for changes to the supplied topology.
  Do not require host networking, topology monitoring, an extra proxy or global
  Docker configuration for the local profile.
- Advanced deployments across machines, network segments or independently
  configured distributed Docker environments require verified TLS with hostname
  and chain validation; never silently fall back to HTTP.
- Product capabilities are not established by YAML alone: verify authenticated
  end-to-end execution, the appropriate transport, updates, isolation, storage
  and rollback.
- Use one independently reviewed PR per consequential change after scope and actual
  source are frozen. Exact review/CI/merge authority comes from current canonical
  repository policy, not this bootstrap.

## Architecture choices

- Check standard Linux, Docker, WSL and existing product capabilities first;
  compare the simplest feasible alternatives before choosing a design.
- Separate user requirements, security requirements and current implementation
  limitations. Identify the exact threat or contract justifying complexity, and
  assess installation steps and ongoing maintenance.
- Do not turn an incidental implementation constraint into a permanent product
  requirement; reject new infrastructure unless a concrete need is demonstrated.

## Test and evidence discipline

- During development run checks relevant to the change. Use CI for one full
  required verification of the exact commit or explicitly identified merge tree;
  repeat the full suite locally only when diagnosing a failure or when CI cannot
  provide required evidence. A CI result does not itself authorize host-interacting
  tests or replace acceptance on the actual target host.
- Avoid running the same scenario twice without a distinct evidentiary purpose.
  Preserve the combined assertions when consolidating duplicates; document distinct
  boundaries such as source checkout versus installed package. Define scenario
  cases once rather than maintaining manually copied matrices in separate runners.
- Build an identical artifact once per run and share it only after checking its
  identity and provenance. Artifacts from different versions or build paths, such
  as a checkout wheel and a wheel rebuilt from an sdist, may provide distinct
  evidence. Share artifacts, not mutable test state: isolate databases, workdirs,
  ports, process identifiers and test data unless sharing is itself under test.
- Parallelize only after establishing isolation, preferably in separate processes;
  serialize or actually isolate tests that use host-global state, shared containers,
  fixed markers or signals. Do not mask races with longer timeouts or retries. If
  the suite is split into phases or shards, automatically verify their collected
  test identities, including parameters, form a complete and disjoint partition;
  matching counts alone are insufficient.
- When testing an installed artifact, verify import or execution provenance in
  workers and representative child processes too, so checkout code cannot be
  mistaken for the artifact. Retain separate evidence that it works without
  undeclared runtime dependencies when that boundary is relevant.
- Before integration verify the actual checkout or explicitly identified merge
  tree, results of all required checks, and current HEAD and base. Independent
  review examines the code, assertions and evidence from the exact CI run; repeat
  checks only when needed to resolve a risk. Current canonical policy determines
  required review, CI and merge authority.
- When changing test execution or performance, measure before and after: total
  wall-clock time, major phases, test counts including skips, and runner conditions.
  Treat an individual measurement as an observation, not a future guarantee.
  Report missing tools, access, environments or evidence as UNPROVED, not success,
  especially for native, security, external integration and failure behavior.

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
