# Scarcity Router organization transfer — verification checklist

The owner has transferred Scarcity Router from `BioMedical-IT` to `Creatidy` in canonical Forgejo and updated the local Git `origin`. **Do not repeat that transfer** and do not rewrite existing history or close/recreate issues.

Before the first new PR involving SR, independently verify on canonical Forgejo:

1. The new repository path, canonical clone URL and full inherited branch/commit history, issue/PR identities and redirects. The owner supplied a `.git-url` display-link suffix; determine the actual canonical clone URL from Forgejo rather than treating that suffix as a Git transport URL.
2. Current HEAD of `develop`, active PRs, protections, required CI and review policy. Historical references are not current evidence.
3. Repository permission and Forgejo MCP repository owner filters, CLI aliases and Kilo routing/rules.
4. `pyproject.toml`, lockfiles, readmes, Docker/OCI source metadata, release workflows, webhooks and external consumers for old `BioMedical-IT/scarcity-router` references. Change only relevant references in owner-scoped PRs.
5. GitHub stays a read-only mirror; it must not become a canonical dependency URL, merge destination or release authority.
6. No changes to historical provenance bytes merely to make old URLs look new.

When current canonical access cannot be established, record UNVERIFIED and the exact missing read; do not treat the old mirror as an authority for remote mutations.
