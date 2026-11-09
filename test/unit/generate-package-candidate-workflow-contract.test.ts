import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import test from 'node:test';

const workflow = readFileSync(join(process.cwd(), '.github', 'workflows', 'generate-package-candidate.yml'), 'utf8');
const helper = readFileSync(join(process.cwd(), 'scripts', 'verify-candidate-checks.sh'), 'utf8');
const packageGate = workflow.slice(workflow.indexOf('  package-gate:'), workflow.indexOf('  package-windows:'));
const packaging = workflow.slice(workflow.indexOf('  package-windows:'), workflow.indexOf('  publish:'));
const publish = workflow.slice(workflow.indexOf('  publish:'), workflow.indexOf('  report:'));
const report = workflow.slice(workflow.indexOf('  report:'));
const sourceSha = 'a'.repeat(40);
const trustedRef = 'b'.repeat(40);
const requiredChecks = ['validate (22.x)', 'validate (24.x)', 'validate-windows-native (22.x)', 'validate-windows-native (24.x)'];

type VerifierFixtureData = {
  metadata: string;
  trustedWorkflow: string;
  sourceWorkflow: string;
  checks: string;
  suite: string;
  runs: string;
};

const createVerifierFixtures = (
  mutateChecks: (checks: Array<Record<string, unknown>>) => void = () => undefined,
  mutateData: (data: VerifierFixtureData) => void = () => undefined,
): VerifierFixtureData => {
  const checks = requiredChecks.map((name, index) => ({
    id: 1000 + index,
    name,
    head_sha: sourceSha,
    started_at: '2026-11-08T22:41:19Z',
    status: 'completed',
    conclusion: 'success',
    app: { slug: 'github-actions' },
    check_suite: { id: 2000 + index },
  }));
  mutateChecks(checks);
  const workflowRuns = checks.map((check, index) => ({
    id: 3000 + index,
    name: 'CI',
    path: '.github/workflows/ci.yml',
    event: 'pull_request',
    head_sha: sourceSha,
    head_repository: { full_name: 'VissotoFlavio/ssh-mcp-server' },
    workflow_id: 4000,
    check_suite_id: 2000 + index,
    run_attempt: 1,
    run_started_at: '2026-11-08T22:41:19Z',
    pull_requests: [{ number: 79, head: { sha: sourceSha } }],
  }));
  const data: VerifierFixtureData = {
    metadata: JSON.stringify({ path: '.github/workflows/ci.yml', id: 4000 }),
    trustedWorkflow: JSON.stringify({
      path: '.github/workflows/ci.yml',
      sha: 'workflow-blob',
      content: Buffer.from('name: CI\n').toString('base64'),
    }),
    sourceWorkflow: JSON.stringify({ path: '.github/workflows/ci.yml', sha: 'workflow-blob', content: Buffer.from('name: CI\n').toString('base64') }),
    checks: JSON.stringify([{ check_runs: checks }]),
    suite: JSON.stringify({ head_sha: sourceSha, app: { slug: 'github-actions' } }),
    runs: JSON.stringify([{ workflow_runs: workflowRuns }]),
  };
  mutateData(data);
  return data;
};

const runVerifier = (mutateChecks?: (checks: Array<Record<string, unknown>>) => void, mutateData?: (data: VerifierFixtureData) => void) => {
  const root = mkdtempSync(join(tmpdir(), 'ssh-mcp-candidate-checks-'));
  const bin = join(root, 'bin');
  const fixtures = join(root, 'fixtures');
  mkdirSync(bin);
  mkdirSync(fixtures);
  const output = join(root, 'output');
  const verifierPath = join(process.cwd(), 'scripts', 'verify-candidate-checks.sh');
  const data = createVerifierFixtures(mutateChecks, mutateData);
  const fixtureGh = String.raw`#!/usr/bin/env bash
set -euo pipefail
args="$*"
case "$args" in
  *"contents/.github/workflows/ci.yml?ref="*)
    if [[ "$args" == *"ref=$TRUSTED_REF"* ]]; then cat "$FIXTURES_DIR/trusted-workflow.json"; else cat "$FIXTURES_DIR/source-workflow.json"; fi
    ;;
  *"actions/workflows/ci.yml"*) cat "$FIXTURES_DIR/metadata.json" ;;
  *"check-runs?per_page=100"*) cat "$FIXTURES_DIR/checks.json" ;;
  *"check-suites/"*) cat "$FIXTURES_DIR/suite.json" ;;
  *"actions/runs?head_sha="*) cat "$FIXTURES_DIR/runs.json" ;;
  *) echo "unexpected gh fixture request: $args" >&2; exit 1 ;;
esac
`;
  writeFileSync(join(fixtures, 'metadata.json'), data.metadata);
  writeFileSync(join(fixtures, 'trusted-workflow.json'), data.trustedWorkflow);
  writeFileSync(join(fixtures, 'source-workflow.json'), data.sourceWorkflow);
  writeFileSync(join(fixtures, 'checks.json'), data.checks);
  writeFileSync(join(fixtures, 'suite.json'), data.suite);
  writeFileSync(join(fixtures, 'runs.json'), data.runs);
  writeFileSync(join(bin, 'gh'), fixtureGh);
  chmodSync(join(bin, 'gh'), 0o755);
  const result = spawnSync('bash', [verifierPath], {
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: `${bin}${delimiter}${process.env.PATH ?? ''}`,
      FIXTURES_DIR: fixtures,
      GH_TOKEN: 'fixture-token',
      REPOSITORY: 'VissotoFlavio/ssh-mcp-server',
      PULL_REQUEST_NUMBER: '79',
      SOURCE_SHA: sourceSha,
      TRUSTED_REF: trustedRef,
      GITHUB_OUTPUT: output,
    },
  });
  const outputText = readFileSync(output, 'utf8');
  rmSync(root, { recursive: true, force: true });
  return { result, outputText };
};

test('candidate helper requires the exact source checks and canonical workflow provenance', () => {
  assert.match(helper, /: "\$\{GH_TOKEN:\?GH_TOKEN is required\}"/u);
  assert.match(helper, /: "\$\{REPOSITORY:\?REPOSITORY is required\}"/u);
  assert.match(helper, /: "\$\{PULL_REQUEST_NUMBER:\?PULL_REQUEST_NUMBER is required\}"/u);
  assert.match(helper, /: "\$\{SOURCE_SHA:\?SOURCE_SHA is required\}"/u);
  assert.match(helper, /: "\$\{TRUSTED_REF:\?TRUSTED_REF is required\}"/u);
  assert.deepEqual(
    [...helper.matchAll(/'([^']+ \((?:22|24)\.x\))'/gu)].map((match) => match[1]),
    ['validate (22.x)', 'validate (24.x)', 'validate-windows-native (22.x)', 'validate-windows-native (24.x)'],
  );
  assert.match(helper, /contents\/\.github\/workflows\/ci\.yml\?ref=\$TRUSTED_REF/u);
  assert.match(helper, /contents\/\.github\/workflows\/ci\.yml\?ref=\$SOURCE_SHA/u);
  assert.match(helper, /trusted_workflow_blob_sha.*\.sha/u);
  assert.match(helper, /source_workflow_blob_sha.*\.sha/u);
  assert.match(helper, /trusted_workflow_content.*base64 --decode/u);
  assert.match(helper, /trusted_workflow_blob_sha.*source_workflow_blob_sha/u);
  assert.match(helper, /gh api --paginate --slurp\s+\\\s+"repos\/\$REPOSITORY\/commits\/\$SOURCE_SHA\/check-runs\?per_page=100"/u);
  assert.match(helper, /select\(\.name == \$name and \.head_sha == \$source_sha\)/u);
  assert.match(helper, /\.app\.slug \/\/ empty/u);
  assert.match(helper, /app_slug.*github-actions/u);
  assert.match(helper, /check-suites\/\$suite_id/u);
  assert.match(helper, /actions\/workflows\/ci\.yml/u);
  assert.match(helper, /canonical_workflow_path.*\.github\/workflows\/ci\.yml/u);
  assert.match(helper, /actions\/runs\?head_sha=\$SOURCE_SHA&event=pull_request/u);
  assert.match(helper, /\.check_suite_id.*suite_id/u);
  assert.match(helper, /run_started_at.*\.id/u);
  assert.match(helper, /workflow run start time missing or ambiguous/u);
  assert.match(helper, /workflow_path.*\.github\/workflows\/ci\.yml/u);
  assert.match(helper, /workflow_event.*pull_request/u);
  assert.match(helper, /workflow_head_sha.*SOURCE_SHA/u);
  assert.match(helper, /workflow_head_repository.*REPOSITORY/u);
  assert.match(helper, /workflow_pr_matches[\s\S]*PULL_REQUEST_NUMBER/u);
  assert.match(helper, /workflow_run_id_from_run.*canonical_workflow_id/u);
  assert.match(helper, /workflow_suite_id.*suite_id/u);
});

test('candidate helper chooses the newest started attempt and fails closed on ambiguity', () => {
  assert.match(helper, /sort_by\(\[\(\.started_at \/\/ ""\), \(\.id \/\/ 0\)\]\)\s+\| last \/\/ empty/u);
  assert.doesNotMatch(helper, /completed_at|created_at/u);
  assert.match(helper, /check_id.*\^\[1-9\]\[0-9\]\*\$/u);
  assert.match(helper, /timestamp missing or ambiguous \(started_at/u);
  assert.match(helper, /timestamp invalid \(started_at=/u);
  assert.match(helper, /untrusted check-run provenance/u);
  assert.match(helper, /non-canonical workflow provenance/u);
  assert.match(helper, /write_output blockers/u);
  assert.match(helper, /write_output error/u);
  assert.match(helper, /write_output verified false/u);
  assert.match(helper, /write_output verified true/u);
  assert.match(helper, /exit 1/u);
});

test('package-gate validates identity, exposes errors, and invokes the trusted helper', () => {
  assert.match(packageGate, /runs-on: ubuntu-latest/u);
  assert.match(packageGate, /checks: read\s+actions: read/u);
  assert.match(packageGate, /Revalidate candidate pull request identity/u);
  assert.match(packageGate, /echo "error=\$error" >> "\$GITHUB_OUTPUT"/u);
  assert.match(packageGate, /actions\/checkout@v4/u);
  assert.match(packageGate, /ref: \$\{\{ github\.sha \}\}[\s\S]*?path: verifier/u);
  assert.match(packageGate, /sparse-checkout: scripts\/verify-candidate-checks\.sh/u);
  assert.match(packageGate, /- id: checks/u);
  assert.match(packageGate, /run: bash verifier\/scripts\/verify-candidate-checks\.sh/u);
  assert.match(packageGate, /PULL_REQUEST_NUMBER: \$\{\{ needs\.resolve\.outputs\.pull_request_number \}\}/u);
  assert.match(packageGate, /TRUSTED_REF: \$\{\{ github\.sha \}\}/u);
  assert.match(packageGate, /blockers: \$\{\{ steps\.checks\.outputs\.blockers \}\}/u);
  assert.match(packageGate, /error: \$\{\{ steps\.identity\.outputs\.error \|\| steps\.checks\.outputs\.error \}\}/u);
  assert.doesNotMatch(packageGate, /ref: \$\{\{ needs\.resolve\.outputs\.source_sha \}\}/u);
});

test('packaging is only the candidate build and pack matrix', () => {
  assert.match(packaging, /needs:\s*-\s+resolve\s*-\s+package-gate/u);
  assert.match(packaging, /if: needs\.package-gate\.result == 'success'/u);
  assert.match(packaging, /runs-on: windows-latest/u);
  assert.match(packaging, /node-major: \[22, 24\]/u);
  assert.match(packaging, /permissions:\s+contents: read/u);
  assert.match(packaging, /ref: \$\{\{ needs\.resolve\.outputs\.source_sha \}\}/u);
  assert.doesNotMatch(packaging, /path: verifier|verify-candidate-checks|outputs:|checks: read|actions: read/u);
  assert.match(packaging, /npm run build:native/u);
  assert.match(packaging, /npm pack --json/u);
  assert.doesNotMatch(packaging, /npm run format:check|npm run lint|npm test/u);
  assert.doesNotMatch(workflow, /^\s{2}validate-linux:|^\s{2}validate-windows:/mu);
});

test('publication rechecks immediately before release and exposes late errors', () => {
  assert.match(publish, /needs:\s+[\s\S]*- package-gate[\s\S]*- package-windows/u);
  assert.match(publish, /permissions:\s+contents: write\s+checks: read\s+actions: read\s+pull-requests: read/u);
  assert.match(publish, /outputs:\s+blockers: \$\{\{ steps\.checks\.outputs\.blockers \}\}/u);
  assert.match(publish, /error: \$\{\{ steps\.release\.outputs\.error \|\| steps\.checks\.outputs\.error \}\}/u);
  assert.ok(publish.indexOf('- id: checks') < publish.indexOf('- id: release'));
  assert.match(publish, /ref: \$\{\{ github\.sha \}\}[\s\S]*?path: verifier/u);
  assert.match(publish, /run: bash verifier\/scripts\/verify-candidate-checks\.sh/u);
  assert.match(publish, /PULL_REQUEST_NUMBER: \$\{\{ needs\.resolve\.outputs\.pull_request_number \}\}/u);
  assert.match(publish, /TRUSTED_REF: \$\{\{ github\.sha \}\}/u);
  assert.match(publish, /emit_error/u);
  assert.match(publish, /\.head\.repo\.full_name == \$repository and \.head\.sha == \$source_sha/u);
  assert.match(publish, /gh release create "\$tag"/u);
  assert.match(publish, /gh release upload "\$tag"/u);
  assert.match(publish, /release_status.*404/u);
  assert.match(publish, /Unable to determine whether candidate release/u);
  assert.match(publish, /git\/ref\/tags\/\$tag/u);
  assert.match(publish, /resolve_tag_commit_sha/u);
  assert.match(publish, /Existing tag.*immutable source SHA/u);
  assert.match(publish, /Candidate tag.*after release handling/u);
  assert.match(publish, /sha256sum.*candidate\//u);
  assert.match(publish, /existing_digest.*sha256:/u);
  assert.match(publish, /final_digest.*sha256:/u);
  assert.doesNotMatch(publish, /ref: \$\{\{ needs\.resolve\.outputs\.source_sha \}\}/u);
});

test('report prefers gate and publication blockers or errors', () => {
  assert.match(report, /PACKAGE_GATE_BLOCKERS: \$\{\{ needs\.package-gate\.outputs\.blockers \}\}/u);
  assert.match(report, /PACKAGE_GATE_ERROR: \$\{\{ needs\.package-gate\.outputs\.error \}\}/u);
  assert.match(report, /PUBLISH_BLOCKERS: \$\{\{ needs\.publish\.outputs\.blockers \}\}/u);
  assert.match(report, /PUBLISH_ERROR: \$\{\{ needs\.publish\.outputs\.error \}\}/u);
  assert.match(report, /reason="\$\{PACKAGE_GATE_BLOCKERS:-\$\{PACKAGE_GATE_ERROR/u);
  assert.match(report, /reason="\$\{PUBLISH_BLOCKERS:-\$PUBLISH_ERROR\}"/u);
  assert.match(report, /ssh-mcp-server:candidate:/u);
  assert.equal((workflow.match(/run: bash verifier\/scripts\/verify-candidate-checks\.sh/gu) ?? []).length, 2);
  assert.doesNotMatch(workflow, /passed:/u);
  assert.doesNotMatch(workflow, /(?:echo|printf)[^\n]*(?:GH_TOKEN|github\.token)/u);
});

test('candidate helper accepts only four canonical successful checks', (context) => {
  if (process.platform === 'win32') {
    context.skip('Bash fixture execution is covered by the Ubuntu CI job.');
    return;
  }
  const { result, outputText } = runVerifier();
  assert.equal(result.status, 0, result.stderr);
  assert.match(outputText, /verified=true/u);
});

test('candidate helper blocks pending, failed, newest, and untrusted attempts', (context) => {
  if (process.platform === 'win32') {
    context.skip('Bash fixture execution is covered by the Ubuntu CI job.');
    return;
  }
  for (const mutate of [
    (checks: Array<Record<string, unknown>>) => Object.assign(checks[0], { status: 'in_progress', conclusion: null }),
    (checks: Array<Record<string, unknown>>) => Object.assign(checks[1], { conclusion: 'failure' }),
    (checks: Array<Record<string, unknown>>) =>
      checks.push({ ...checks[2], id: 9999, started_at: '2026-11-08T23:41:19Z', status: 'in_progress', conclusion: null }),
    (checks: Array<Record<string, unknown>>) => Object.assign(checks[3], { app: { slug: 'untrusted-app' } }),
  ]) {
    const { result, outputText } = runVerifier(mutate);
    assert.notEqual(result.status, 0);
    assert.match(outputText, /blockers=/u);
  }
});

test('candidate helper blocks trusted/source workflow and PR provenance mismatches', (context) => {
  if (process.platform === 'win32') {
    context.skip('Bash fixture execution is covered by the Ubuntu CI job.');
    return;
  }
  const mutations = [
    (data: VerifierFixtureData) => {
      const sourceWorkflow = JSON.parse(data.sourceWorkflow) as { sha: string };
      sourceWorkflow.sha = 'different-source-workflow-blob';
      data.sourceWorkflow = JSON.stringify(sourceWorkflow);
    },
    (data: VerifierFixtureData) => {
      const runs = JSON.parse(data.runs) as { workflow_runs: Array<{ path: string }> }[];
      runs[0].workflow_runs[0].path = '.github/workflows/other.yml';
      data.runs = JSON.stringify(runs);
    },
    (data: VerifierFixtureData) => {
      const runs = JSON.parse(data.runs) as { workflow_runs: Array<{ pull_requests: Array<{ number: number }> }> }[];
      runs[0].workflow_runs[0].pull_requests[0].number = 999;
      data.runs = JSON.stringify(runs);
    },
    (data: VerifierFixtureData) => {
      const suite = JSON.parse(data.suite) as { app: { slug: string } };
      suite.app.slug = 'untrusted-app';
      data.suite = JSON.stringify(suite);
    },
  ];
  for (const mutateData of mutations) {
    const { result, outputText } = runVerifier(undefined, mutateData);
    assert.notEqual(result.status, 0);
    assert.match(outputText, /blockers=/u);
    assert.match(outputText, /error=/u);
    assert.match(outputText, /verified=false/u);
  }
});
