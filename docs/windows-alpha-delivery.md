# Native Windows alpha delivery boundary

## Status

This is an internal delivery-preparation record. It does not create, assign,
or publish a release version, and it does not authorize a tag, deployment,
announcement, or package publication.

The native Windows runtime is supported only within the envelope defined by
the [Windows trust model](windows-trust-model.md) and the
[Windows installation and Codex setup](windows-codex-setup.md). A host that
does not meet every required runtime, filesystem, OpenSSH, Credential Manager,
and native-boundary condition must leave validation unavailable.

## Distribution decision

The current alpha is available only as an internal source checkout built by
the operator. There is no published package, standalone executable, or binary
artifact. Do not copy a build artifact into another environment as a
substitute for a trusted build.

No license is selected by this preparation work. Distribution beyond the
repository's existing access controls requires separate legal direction and a
reviewed license decision.

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

This preparation does not merge any pull request or publish any artifact.
