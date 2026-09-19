# CI/CD identity scenario fixtures

Two fictional versions of the same small pipeline: a GitHub Actions
workflow that builds and publishes signed turbine controller config/firmware
bundles to a cloud OTA distribution bucket, using OIDC federation to assume
an AWS IAM role (no long-lived cloud credentials stored in GitHub).

- `vulnerable-workflow/` -- unpinned third-party actions, workflow-level
  `permissions: write-all`-equivalent, and an OIDC trust policy that trusts
  *any* branch or workflow in the whole `offshore-wind-ops` GitHub org
  (`sub: "repo:offshore-wind-ops/*:*"`, no `aud` check). The assumed role
  can also reach `wind-farm-fleet-management-api` -- the same role that's
  supposed to only publish firmware bundles can, per this trust policy,
  also touch the API that pushes commands out to individual turbines.
- `hardened-workflow/` -- pinned actions (commit SHA), no default token
  permissions with the minimum (`id-token: write`, `contents: read`)
  granted per-job instead, and a trust policy scoped to one specific
  repo+branch with an explicit `aud` (audience) restriction. The role's
  reachable resources are trimmed to just the OTA bucket it actually needs.

These are analysis fixtures for `scenarios/scenario_cicd_identity.py`, not
real infrastructure -- see that script and `docs/results.md` for the real,
computed before/after finding counts TrustGraph produces against them.
`offshore-wind-ops`, the account IDs, and the resource names are all
fictional.
