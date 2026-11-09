#!/usr/bin/env bash

set -euo pipefail

: "${GH_TOKEN:?GH_TOKEN is required}"
: "${REPOSITORY:?REPOSITORY is required}"
: "${PULL_REQUEST_NUMBER:?PULL_REQUEST_NUMBER is required}"
: "${SOURCE_SHA:?SOURCE_SHA is required}"
: "${TRUSTED_REF:?TRUSTED_REF is required}"

required_checks=(
  'validate (22.x)'
  'validate (24.x)'
  'validate-windows-native (22.x)'
  'validate-windows-native (24.x)'
)
blockers=()

write_output() {
  local name="$1"
  local value="$2"

  if [[ -z "${GITHUB_OUTPUT:-}" ]]; then
    return
  fi
  if [[ "$value" == *$'\n'* ]]; then
    {
      echo "$name<<CANDIDATE_CHECKS_EOF"
      printf '%s\n' "$value"
      echo CANDIDATE_CHECKS_EOF
    } >> "$GITHUB_OUTPUT"
  else
    echo "$name=$value" >> "$GITHUB_OUTPUT"
  fi
}

finish_failure() {
  local error="$1"
  local blockers_text

  if (( ${#blockers[@]} == 0 )); then
    blockers+=("$error")
  fi
  blockers_text="$(printf '%s\n' "${blockers[@]}")"
  write_output blockers "$blockers_text"
  write_output error "$error"
  write_output verified false
  echo "::error::$error"
  printf '::error::%s\n' "${blockers[@]}"
  exit 1
}

unexpected_error() {
  local status="$?"
  local error='Candidate check verification failed closed because the API response could not be inspected.'

  if (( ${#blockers[@]} == 0 )); then
    blockers+=("API response inspection failed for source SHA $SOURCE_SHA")
  fi
  write_output blockers "$(printf '%s\n' "${blockers[@]}")"
  write_output error "$error"
  write_output verified false
  echo "::error::$error"
  printf '::error::%s\n' "${blockers[@]}"
  return "$status"
}

trap unexpected_error ERR

write_output blockers ''
write_output error ''
write_output verified false

if [[ ! "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  blockers+=("Invalid source SHA: $SOURCE_SHA")
  finish_failure 'Candidate check verification requires a 40-character immutable source SHA.'
fi

if [[ ! "$PULL_REQUEST_NUMBER" =~ ^[1-9][0-9]*$ ]]; then
  blockers+=("Invalid pull request number: $PULL_REQUEST_NUMBER")
  finish_failure 'Candidate check verification requires an immutable pull request number.'
fi

if ! trusted_workflow_file="$(gh api "repos/$REPOSITORY/contents/.github/workflows/ci.yml?ref=$TRUSTED_REF")"; then
  blockers+=("Trusted canonical CI workflow unavailable (ref=$TRUSTED_REF)")
  finish_failure 'Unable to read the canonical CI workflow from the trusted workflow revision.'
fi
if ! source_workflow_file="$(gh api "repos/$REPOSITORY/contents/.github/workflows/ci.yml?ref=$SOURCE_SHA")"; then
  blockers+=("Canonical CI workflow unavailable for source SHA $SOURCE_SHA")
  finish_failure 'Unable to read the canonical CI workflow for the immutable source SHA.'
fi

trusted_workflow_blob_sha="$(jq --raw-output '.sha // empty' <<<"$trusted_workflow_file")"
source_workflow_blob_sha="$(jq --raw-output '.sha // empty' <<<"$source_workflow_file")"
trusted_workflow_base64="$(jq --raw-output '.content // empty' <<<"$trusted_workflow_file" | tr -d '\r\n')"
source_workflow_base64="$(jq --raw-output '.content // empty' <<<"$source_workflow_file" | tr -d '\r\n')"
if [[ -z "$trusted_workflow_blob_sha" || -z "$source_workflow_blob_sha" ||
  -z "$trusted_workflow_base64" || -z "$source_workflow_base64" ]]; then
  blockers+=("Canonical CI workflow blob or content is missing (trusted SHA=$trusted_workflow_blob_sha, source SHA=$source_workflow_blob_sha)")
  finish_failure 'The canonical CI workflow contents could not be established on the trusted workflow revision and source SHA.'
fi
if [[ "$trusted_workflow_blob_sha" != "$source_workflow_blob_sha" ]]; then
  blockers+=("Canonical CI workflow blob differs from trusted revision (trusted blob=$trusted_workflow_blob_sha, source blob=$source_workflow_blob_sha)")
  finish_failure 'The source pull request changes the canonical CI workflow from the trusted revision.'
fi
if ! trusted_workflow_content="$(printf '%s' "$trusted_workflow_base64" | base64 --decode 2>/dev/null)" ||
  ! source_workflow_content="$(printf '%s' "$source_workflow_base64" | base64 --decode 2>/dev/null)"; then
  blockers+=("Canonical CI workflow content could not be decoded for comparison (SHA=$SOURCE_SHA)")
  finish_failure 'The canonical CI workflow content could not be decoded safely.'
fi
if [[ "$trusted_workflow_content" != "$source_workflow_content" ]]; then
  blockers+=("Canonical CI workflow content differs from trusted revision (trusted SHA=$trusted_workflow_blob_sha, source SHA=$source_workflow_blob_sha)")
  finish_failure 'The source canonical CI workflow content differs from the trusted workflow revision.'
fi

if ! workflow_metadata="$(gh api "repos/$REPOSITORY/actions/workflows/ci.yml")"; then
  blockers+=("Canonical CI workflow metadata unavailable for source SHA $SOURCE_SHA")
  finish_failure 'Unable to verify the canonical CI workflow.'
fi
canonical_workflow_path="$(jq --raw-output '.path // empty' <<<"$workflow_metadata")"
canonical_workflow_id="$(jq --raw-output 'if .id == null then "" else (.id | tostring) end' <<<"$workflow_metadata")"
if [[ "$canonical_workflow_path" != .github/workflows/ci.yml ||
  ! "$canonical_workflow_id" =~ ^[1-9][0-9]*$ ]]; then
  blockers+=("Canonical CI workflow path or id is invalid (path=$canonical_workflow_path, workflow_id=$canonical_workflow_id, SHA=$SOURCE_SHA)")
  finish_failure 'The canonical CI workflow identity could not be established.'
fi

if ! check_pages="$(gh api --paginate --slurp \
  "repos/$REPOSITORY/commits/$SOURCE_SHA/check-runs?per_page=100")"; then
  blockers+=("Required CI checks unavailable for source SHA $SOURCE_SHA")
  finish_failure 'Unable to read candidate check-runs for the immutable source SHA.'
fi
if ! check_runs="$(jq -c '[.[].check_runs[]] // []' <<<"$check_pages")"; then
  blockers+=("Required CI checks could not be inspected for source SHA $SOURCE_SHA")
  finish_failure 'Unable to inspect candidate check-runs for the immutable source SHA.'
fi

for check_name in "${required_checks[@]}"; do
  check_matches="$(jq -c \
    --arg name "$check_name" \
    --arg source_sha "$SOURCE_SHA" \
    '[.[] | select(.name == $name and .head_sha == $source_sha)]' <<<"$check_runs")"
  if [[ "$(jq 'length' <<<"$check_matches")" -eq 0 ]]; then
    blockers+=("$check_name: missing for SHA $SOURCE_SHA")
    continue
  fi

  trusted_runs=()
  while IFS= read -r check_run; do
    check_id="$(jq --raw-output 'if .id == null then "" else (.id | tostring) end' <<<"$check_run")"
    app_slug="$(jq --raw-output '.app.slug // empty' <<<"$check_run")"
    started_at="$(jq --raw-output '.started_at // empty' <<<"$check_run")"
    suite_id="$(jq --raw-output 'if .check_suite.id == null then "" else (.check_suite.id | tostring) end' <<<"$check_run")"

    if [[ ! "$check_id" =~ ^[1-9][0-9]*$ ]]; then
      blockers+=("$check_name: check-run id missing or invalid (SHA=$SOURCE_SHA)")
      continue
    fi
    if [[ -z "$started_at" ]]; then
      blockers+=("$check_name: timestamp missing or ambiguous (started_at, check-run $check_id, SHA=$SOURCE_SHA)")
    elif [[ ! "$started_at" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] ||
      ! date -u -d "$started_at" +%s >/dev/null 2>&1; then
      blockers+=("$check_name: timestamp invalid (started_at=$started_at, check-run $check_id, SHA=$SOURCE_SHA)")
      continue
    fi
    if [[ "$app_slug" != github-actions ]]; then
      blockers+=("$check_name: untrusted check-run provenance (app.slug=$app_slug, check-run $check_id, SHA=$SOURCE_SHA)")
      continue
    fi
    if [[ -z "$suite_id" ]]; then
      blockers+=("$check_name: canonical check suite missing (check-run $check_id, SHA=$SOURCE_SHA)")
      continue
    fi
    if [[ ! "$suite_id" =~ ^[1-9][0-9]*$ ]]; then
      blockers+=("$check_name: check suite id missing or invalid (check-run $check_id, SHA=$SOURCE_SHA)")
      continue
    fi

    if ! check_suite="$(gh api "repos/$REPOSITORY/check-suites/$suite_id")"; then
      blockers+=("$check_name: check suite $suite_id unavailable for canonical provenance (SHA=$SOURCE_SHA)")
      continue
    fi
    suite_head_sha="$(jq --raw-output '.head_sha // empty' <<<"$check_suite")"
    suite_app_slug="$(jq --raw-output '.app.slug // empty' <<<"$check_suite")"
    if [[ "$suite_head_sha" != "$SOURCE_SHA" || "$suite_app_slug" != github-actions ]]; then
      blockers+=("$check_name: check suite provenance is not canonical (head_sha=$suite_head_sha, app.slug=$suite_app_slug, check_suite_id=$suite_id, SHA=$SOURCE_SHA)")
      continue
    fi
    if ! workflow_run_pages="$(gh api --paginate --slurp \
      "repos/$REPOSITORY/actions/runs?head_sha=$SOURCE_SHA&event=pull_request&per_page=100")"; then
      blockers+=("$check_name: workflow runs unavailable for check suite $suite_id (SHA=$SOURCE_SHA)")
      continue
    fi
    workflow_run="$(jq -c \
      --arg suite_id "$suite_id" \
      --arg source_sha "$SOURCE_SHA" \
      '[.[].workflow_runs[] | select((.check_suite_id // "" | tostring) == $suite_id and .head_sha == $source_sha)]
       | sort_by([(.run_started_at // ""), (.run_attempt // 0), (.id // 0)])
       | last // empty' <<<"$workflow_run_pages")"
    if [[ -z "$workflow_run" || "$workflow_run" == null ]]; then
      blockers+=("$check_name: canonical workflow run missing from check suite $suite_id (SHA=$SOURCE_SHA)")
      continue
    fi

    workflow_run_id="$(jq --raw-output 'if .id == null then "" else (.id | tostring) end' <<<"$workflow_run")"
    if [[ ! "$workflow_run_id" =~ ^[1-9][0-9]*$ ]]; then
      blockers+=("$check_name: workflow run id missing or invalid (check_suite_id=$suite_id, SHA=$SOURCE_SHA)")
      continue
    fi
    workflow_run_started_at="$(jq --raw-output '.run_started_at // empty' <<<"$workflow_run")"
    if [[ -z "$workflow_run_started_at" ]]; then
      blockers+=("$check_name: workflow run start time missing or ambiguous (workflow run $workflow_run_id, SHA=$SOURCE_SHA)")
      continue
    fi
    workflow_path="$(jq --raw-output '.path // empty' <<<"$workflow_run")"
    workflow_path="${workflow_path%@*}"
    workflow_event="$(jq --raw-output '.event // empty' <<<"$workflow_run")"
    workflow_head_sha="$(jq --raw-output '.head_sha // empty' <<<"$workflow_run")"
    workflow_head_repository="$(jq --raw-output '.head_repository.full_name // empty' <<<"$workflow_run")"
    workflow_pr_matches="$(jq -r \
      --arg pull_request_number "$PULL_REQUEST_NUMBER" \
      --arg source_sha "$SOURCE_SHA" \
      'any(.pull_requests[]?; ((.number // "") | tostring) == $pull_request_number and (.head.sha // "") == $source_sha)' \
      <<<"$workflow_run")"
    workflow_run_id_from_run="$(jq --raw-output 'if .workflow_id == null then "" else (.workflow_id | tostring) end' <<<"$workflow_run")"
    workflow_suite_id="$(jq --raw-output 'if .check_suite_id == null then "" else (.check_suite_id | tostring) end' <<<"$workflow_run")"
    if [[ ! "$workflow_run_id_from_run" =~ ^[1-9][0-9]*$ ||
      ! "$workflow_suite_id" =~ ^[1-9][0-9]*$ ]]; then
      blockers+=("$check_name: workflow or suite id missing or invalid (workflow_id=$workflow_run_id_from_run, check_suite_id=$workflow_suite_id, SHA=$SOURCE_SHA)")
      continue
    fi
    if [[ "$workflow_path" != .github/workflows/ci.yml ||
      "$workflow_event" != pull_request ||
      "$workflow_head_sha" != "$SOURCE_SHA" ||
      "$workflow_head_repository" != "$REPOSITORY" ||
      "$workflow_pr_matches" != true ||
      "$workflow_run_id_from_run" != "$canonical_workflow_id" ||
      "$workflow_suite_id" != "$suite_id" ]]; then
      blockers+=("$check_name: non-canonical workflow provenance (path=$workflow_path, event=$workflow_event, workflow_id=$workflow_run_id_from_run, SHA=$workflow_head_sha, repository=$workflow_head_repository, pull_request=$workflow_pr_matches, check_suite_id=$workflow_suite_id)")
      continue
    fi

    if [[ -z "$started_at" ]]; then
      continue
    fi
    trusted_runs+=("$check_run")
  done < <(jq -c '.[]' <<<"$check_matches")

  if (( ${#trusted_runs[@]} == 0 )); then
    continue
  fi

  newest_check="$(printf '%s\n' "${trusted_runs[@]}" | jq -s -c \
    'sort_by([(.started_at // ""), (.id // 0)]) | last // empty')"
  status="$(jq --raw-output '.status // empty' <<<"$newest_check")"
  conclusion="$(jq --raw-output '.conclusion // empty' <<<"$newest_check")"
  check_id="$(jq --raw-output 'if .id == null then "" else (.id | tostring) end' <<<"$newest_check")"
  if [[ "$status" != completed ]]; then
    blockers+=("$check_name: pending (status=$status, check-run $check_id, SHA=$SOURCE_SHA)")
  elif [[ "$conclusion" != success ]]; then
    blockers+=("$check_name: failed (conclusion=$conclusion, check-run $check_id, SHA=$SOURCE_SHA)")
  fi
done

if (( ${#blockers[@]} > 0 )); then
  finish_failure 'Required CI checks are not complete, successful, canonical, and unambiguous.'
fi

write_output blockers ''
write_output error ''
write_output verified true
