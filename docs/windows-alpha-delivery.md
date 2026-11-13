# Native Windows alpha delivery boundary

## Status

This is an internal delivery-preparation record for the native Windows alpha.
It does not itself create or publish an npm package, or authorize public
distribution, deployment, or announcement. The authorized candidate workflow
may generate internal Windows packages in a GitHub prerelease linked to the
pull request's immutable head SHA.

The native Windows runtime is supported only within the envelope defined by
the [Windows trust model](windows-trust-model.md) and the
[Windows installation and Codex setup](windows-codex-setup.md). A host that
does not meet every required runtime, filesystem, OpenSSH, Credential Manager,
and native-boundary condition must leave validation unavailable.

## Distribution decision

The current alpha has no npm publication or public package distribution. An
authorized candidate workflow may attach internal Windows package assets to a
GitHub prerelease bound to an immutable pull-request SHA; that prerelease is
not public distribution. Do not copy a build artifact into another environment
as a substitute for a trusted build.

No license is selected by this preparation work. Distribution beyond the
repository's existing access controls requires separate legal direction and a
reviewed license decision.

## Candidate packages

On an eligible release or hotfix pull request, an authorized exact
`/generate-candidate` comment can create a GitHub prerelease candidate bound
to that pull request's immutable head commit. It never publishes to npm,
creates a stable release, or distributes a public package.

Candidate assets are Windows x64 packages containing the compiled runtime and
only the production native addon. They are emitted separately for Node.js 22
and Node.js 24 because native addon ABIs are not interchangeable. A candidate
is suitable only for the documented native Windows envelope and the matching
Node.js major version.

Before packaging, the workflow revalidates that the pull request is still an
open same-repository `release/*` or `hotfix/*` pull request targeting `master`
and records its immutable head SHA. It then reads check-runs only for that
exact SHA and requires these four exact successful checks:

- `validate (22.x)`
- `validate (24.x)`
- `validate-windows-native (22.x)`
- `validate-windows-native (24.x)`

Missing, pending, cancelled, failed, or differently sourced checks block
packaging and publication. The marked pull-request comment lists the blocking
checks. The verifier loaded from the trusted default-branch revision also compares the blob SHA
and decoded contents of `.github/workflows/ci.yml` with the immutable source
SHA, blocking if the file is absent, unreadable, or changed. A check-run is
trusted only when its API provenance is
`app.slug == "github-actions"`; repeated trusted attempts use the newest
`started_at`, with `id` as the deterministic tie-breaker. A missing
`started_at` is itself a blocker. The workflow run must point to the canonical
`.github/workflows/ci.yml` workflow with the `pull_request` event, matching SHA,
canonical workflow id, same-repository head, and exact pull-request
association. The verifier itself is read from the trusted default-branch revision, while build
and packaging use the immutable source SHA. When the package gate passes, the
workflow runs only the Windows Node.js 22 and 24 native build, runtime build,
package-content inspection, and pack steps needed for the two ABI-specific
assets. It revalidates the pull request and canonical checks again immediately
before publishing and reuses an existing matching prerelease and assets
idempotently.

## Reproducible local build

On a supported x64 Windows host, use a clean checkout and an approved Node.js
22-or-newer executable. The native build additionally requires the Windows
C++ build prerequisites for Node.js addons.

```powershell
npm ci
npm run format:check
npm run lint
npm test
npm run build
npm run build:native
npm test
```

The second test run verifies the compiled native production and test addons.
The output must include both `build/Release/windows_trust.node` and
`build/Release/windows_trust_test.node`. A missing addon or any unsupported
runtime condition is a fail-closed result; do not use WSL, a copied binary,
or a PATH-selected executable as a workaround.

## Protected delivery flow

`master` is created from `develop` and uses the same protection baseline as
`develop`: current CI checks are required and up to date, administrators are
subject to protection, force-push and deletion are disabled, and conversation
resolution is required. Changes reach `master` only through a reviewed pull
request after the required checks pass.

This release boundary does not authorize package or binary publication.
