import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';

const workflow = readFileSync(join(process.cwd(), '.github', 'workflows', 'backport-master-to-develop.yml'), 'utf8');
const validationStep = workflow.slice(
  workflow.indexOf('      - name: Validate source and existing backport'),
  workflow.indexOf('      - name: Create backport branch and pull request'),
);
const preflightStep = workflow.slice(
  workflow.indexOf('      - name: Validate BACKPORT_TOKEN'),
  workflow.indexOf('      - name: Validate source and existing backport'),
);
const creationStep = workflow.slice(workflow.indexOf('      - name: Create backport branch and pull request'));
const firstMutationApiCall = creationStep.indexOf('gh api --method POST');
const firstWorkflowApiCall = workflow.indexOf('gh api --method');

test('backport workflow keeps its merged release and hotfix trigger', () => {
  assert.match(workflow, /pull_request:\s+types:\s+- closed\s+branches:\s+- master/u);
  assert.match(workflow, /github\.event\.pull_request\.merged == true/u);
  assert.match(workflow, /startsWith\(github\.event\.pull_request\.head\.ref, 'release\/'\)/u);
  assert.match(workflow, /startsWith\(github\.event\.pull_request\.head\.ref, 'hotfix\/'\)/u);
});

test('validation uses the read-only github token and GET-only API calls', () => {
  assert.match(validationStep, /GH_TOKEN: \$\{\{ github\.token \}\}/u);
  assert.match(validationStep, /gh api --method GET/u);
  assert.doesNotMatch(validationStep, /gh api --method (?!GET\b)/u);
  assert.equal((validationStep.match(/-f state=all/gu) ?? []).length, 1);
  assert.match(workflow, /permissions:\s+contents: read\s+pull-requests: read/u);
});

test('creation uses BACKPORT_TOKEN and fails closed with actionable guidance', () => {
  assert.match(creationStep, /GH_TOKEN: \$\{\{ secrets\.BACKPORT_TOKEN \}\}/u);
  assert.doesNotMatch(creationStep, /BACKPORT_TOKEN Actions secret is not configured/u);
  assert.match(preflightStep, /BACKPORT_TOKEN: \$\{\{ secrets\.BACKPORT_TOKEN \}\}/u);
  assert.match(preflightStep, /echo "::error::The BACKPORT_TOKEN Actions secret is not configured\."/u);
  assert.match(preflightStep, /exit 1/u);
});

test('backport branch and pull request behavior remains deterministic', () => {
  assert.match(workflow, /backport_branch="backport\/\$\{source_type\}-\$\{version_segment\}"/u);
  assert.match(workflow, /head="\$\{REPOSITORY_OWNER\}:\$\{backport_branch\}"/u);
  assert.match(creationStep, /-f head="\$BACKPORT_BRANCH"/u);
  assert.match(creationStep, /-f base=develop/u);
  assert.match(creationStep, /pr_base.*develop|pr_base.*== "develop"/u);
  assert.match(creationStep, /pr_head_sha.*MERGE_SHA/u);
});

test('retries recognize merged completion and closed-unmerged conflicts', () => {
  assert.equal((workflow.match(/-f state=all/gu) ?? []).length, 2);
  assert.doesNotMatch(workflow, /-f state=open/u);
  assert.match(workflow, /pr_merged_at=.*merged_at \/\/ ""/u);
  assert.match(workflow, /action="complete"/u);
  assert.match(workflow, /Completion: the existing backport pull request is merged; no mutation is required\./u);
  assert.match(workflow, /A closed, unmerged backport pull request already exists.*resolve it before retrying\./u);
  assert.match(workflow, /Existing backport pull request is merged[\s\S]*No mutation is required\./u);
  assert.match(
    validationStep,
    /elif \[\[ "\$pr_state" == "open" \]\]; then[\s\S]*?if \[\[ -z "\$branch_sha" \]\]; then[\s\S]*?fail "An open backport pull request exists but its deterministic branch is missing\."[\s\S]*?if \[\[ "\$pr_base" != "develop" \|\| "\$pr_head_sha" != "\$MERGE_SHA" \]\]; then[\s\S]*?action="reuse"/u,
  );
  assert.match(
    creationStep,
    /if \[\[ "\$pr_state" == "open" && -z "\$branch_sha" \]\]; then[\s\S]*?fail "An open backport pull request exists but its deterministic branch is missing\."/u,
  );
  assert.match(
    creationStep,
    /if \[\[ "\$pr_state" == "open" && "\$branch_sha" == "\$MERGE_SHA" && "\$pr_base" == "develop" && "\$pr_head_sha" == "\$MERGE_SHA" \]\]; then[\s\S]*?echo "Backport pull request already exists: \$\{pr_url\}"[\s\S]*?exit 0/u,
  );
});

test('mutation is gated to creation actions and preserves trust boundaries', () => {
  assert.match(workflow, /if: steps\.validate\.outputs\.action == 'create_branch_and_pr' \|\| steps\.validate\.outputs\.action == 'create_pr'/u);
  assert.match(validationStep, /BASE_REPOSITORY.*REPOSITORY/u);
  assert.match(validationStep, /SOURCE_REPOSITORY.*REPOSITORY/u);
  assert.match(validationStep, /\[\[:xdigit:\]\]\{40\}/u);
  assert.match(validationStep, /\^\(release\|hotfix\)\//u);
  assert.match(validationStep, /pr_head_repo=.*head\.repo\.full_name \/\/ ""/u);
  assert.match(validationStep, /pr_head_ref=.*head\.ref \/\/ ""/u);
  assert.match(
    validationStep,
    /if \[\[ "\$pr_head_repo" != "\$REPOSITORY" \|\| "\$pr_head_ref" != "\$backport_branch" \]\]; then[\s\S]*?fail "The existing backport pull request head provenance does not match the repository and deterministic branch\."/u,
  );
  assert.match(creationStep, /pr_head_repo=.*head\.repo\.full_name \/\/ ""/u);
  assert.match(creationStep, /pr_head_ref=.*head\.ref \/\/ ""/u);
  assert.match(
    creationStep,
    /if \[\[ "\$pr_head_repo" != "\$REPOSITORY" \|\| "\$pr_head_ref" != "\$BACKPORT_BRANCH" \]\]; then[\s\S]*?fail "The existing backport pull request head provenance does not match the repository and deterministic branch\."/u,
  );
  assert.doesNotMatch(workflow, /- uses: actions\/checkout/u);
  assert.equal((workflow.match(/secrets\.BACKPORT_TOKEN/gu) ?? []).length, 2);
  assert.equal((preflightStep.match(/secrets\.BACKPORT_TOKEN/gu) ?? []).length, 1);
  assert.equal((creationStep.match(/secrets\.BACKPORT_TOKEN/gu) ?? []).length, 1);
  assert.doesNotMatch(validationStep, /secrets\.BACKPORT_TOKEN/u);
  assert.doesNotMatch(validationStep, /gh api --method POST/u);
  assert.doesNotMatch(preflightStep, /gh api|POST/u);
  assert.ok(workflow.indexOf('      - name: Validate BACKPORT_TOKEN') < firstWorkflowApiCall);
  assert.ok(workflow.indexOf('      - name: Validate source and existing backport') < firstWorkflowApiCall);
  assert.ok(creationStep.indexOf('-f state=all') < firstMutationApiCall);
  assert.ok(creationStep.indexOf('More than one matching backport pull request exists') < firstMutationApiCall);
  assert.ok(creationStep.indexOf('A closed, unmerged backport pull request already exists') < firstMutationApiCall);
});

test('workflow does not log token material', () => {
  assert.equal((workflow.match(/secrets\.BACKPORT_TOKEN/gu) ?? []).length, 2);
  assert.doesNotMatch(workflow, /(?:echo|printf)[^\n]*(?:\$\{?GH_TOKEN|\$\{?BACKPORT_TOKEN|secrets\.BACKPORT_TOKEN)/iu);
  assert.doesNotMatch(workflow, /GITHUB_STEP_SUMMARY[^\n]*(?:GH_TOKEN|BACKPORT_TOKEN)/iu);
});
