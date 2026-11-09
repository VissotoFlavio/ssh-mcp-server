# Automated backports

The `backport-master-to-develop.yml` workflow runs when a `release/*` or
`hotfix/*` pull request is merged into `master`. It creates or reuses the
deterministic `backport/<type>-<version>` branch and pull request targeting
`develop`. Retries inspect open and closed pull requests so a merged backport
is recognized as complete instead of creating another pull request.

## Required repository secret

The workflow needs a repository-scoped fine-grained personal access token
stored as the Actions secret `BACKPORT_TOKEN`. Configure it in the repository
under **Settings → Secrets and variables → Actions → New repository secret**.
Choose **Repository access** for this repository only. Do not put the token in
the workflow file, an issue, a pull request, a commit, or a log.

Grant the token only these repository permissions:

- **Contents: Read and write** — required to create the deterministic Git ref.
- **Pull requests: Read and write** — required to inspect existing backports
  and create the pull request.

The token's default metadata permission is sufficient; no other repository or
organization permissions are required. Never paste the token value into a
command or expose it while testing the setup.

## Safe verification

Verify only that the secret name is present. In the repository settings, the
Actions secrets list should contain `BACKPORT_TOKEN`; the value is never
displayed. With GitHub CLI, this lists secret names and metadata without
reading secret values:

```sh
gh secret list --repo OWNER/REPOSITORY --app actions
```

Replace `OWNER/REPOSITORY` with the repository name. A qualifying merged pull
request is the end-to-end trigger. Before any GitHub API call, a non-mutating
preflight checks that `BACKPORT_TOKEN` is present. If it is unavailable, the
preflight fails closed with an actionable error instead of attempting any
branch, pull request, or read-only API operation. The next validation step
uses the read-only `github.token`; the mutation step uses `BACKPORT_TOKEN` only
after the preflight succeeds. An open matching pull request is reused only
when its deterministic branch and head SHA still match the source merge SHA. A
closed but unmerged matching pull request fails closed with guidance to resolve
it before retrying.

The workflow never prints the token value. Its logs and step summary contain
only source/merge identifiers, the deterministic branch, the action taken,
and (when reused or already complete) the existing pull request URL. A merged
backport is recorded in the summary and requires no mutation.
