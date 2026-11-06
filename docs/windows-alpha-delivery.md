# Native Windows alpha delivery boundary

## Status

`v0.1.0` is the first internal, source-built pre-1.0 release. It is intended
for controlled production validation before any `v1.0.0` release. The release
tag identifies the reviewed source only; it does not authorize a deployment,
package publication, standalone executable, or binary artifact.

The native Windows runtime is supported only within the envelope defined by
the [Windows trust model](windows-trust-model.md) and the
[Windows installation and Codex setup](windows-codex-setup.md). A host that
does not meet every required runtime, filesystem, OpenSSH, Credential Manager,
and native-boundary condition must leave validation unavailable.

## Distribution decision

The current pre-1.0 release is available only as an internal source checkout
built by the operator. There is no published package, standalone executable,
or binary artifact. Do not copy a build artifact into another environment as
a substitute for a trusted build.

No license is selected by this preparation work. Distribution beyond the
repository's existing access controls requires separate legal direction and a
reviewed license decision.

## Candidate packages

On an eligible release or hotfix pull request, an authorized exact
`/generate-candidate` comment can create a GitHub prerelease candidate bound
to that pull request's immutable head commit. It never publishes to npm and
never creates a stable release.

Candidate assets are Windows x64 packages containing the compiled runtime and
only the production native addon. They are emitted separately for Node.js 22
and Node.js 24 because native addon ABIs are not interchangeable. A candidate
is suitable only for the documented native Windows envelope and the matching
Node.js major version.

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
