#!/usr/bin/env bash
set -euo pipefail

incidents="$(npm run --silent exhausted)"
gh label create scanner-operations --color B60205 --description "TavernKeeper operational incidents" --force
gh label create scanner-unscannable --color 5319E7 --description "Removed from automatic TavernKeeper scans" --force
issues="$(gh issue list --state all --label scanner-operations --limit 100 --json number,state,body,createdAt,labels)"
cooling_target_keys="$(jq -r '.chronic_failures[].target_incident_key' <<< "$incidents")"
terminal_target_keys="$(jq -r '.unscannable_targets[].target_incident_key' <<< "$incidents")"
active_target_keys="$(printf '%s\n%s\n' "$cooling_target_keys" "$terminal_target_keys" | sed '/^$/d')"

jq -c '.chronic_failures[]' <<< "$incidents" | while read -r failure; do
  incident_key="$(jq -r '.target_incident_key' <<< "$failure")"
  repository_id="$(jq -r '.repository_id' <<< "$failure")"
  repository="$(jq -r '.repository' <<< "$failure")"
  target="$(jq -r '.target_sha' <<< "$failure")"
  count="$(jq -r '.consecutive_failures' <<< "$failure")"
  domain="$(jq -r '.last_failure.domain' <<< "$failure")"
  code="$(jq -r '.last_failure.code' <<< "$failure")"
  component="$(jq -r '.last_failure.component' <<< "$failure")"
  diagnostic="$(jq -r '.last_failure.diagnostic // "none"' <<< "$failure")"
  history="$(jq -c '.failure_history | map({failed_at, domain: .failure.domain, code: .failure.code, component: .failure.component, diagnostic: (.failure.diagnostic // null)})' <<< "$failure")"
  next_retry="$(jq -r '.not_before // "due"' <<< "$failure")"
  existing="$(jq -r --arg needle "Target incident key: \`$incident_key\`" 'map(select(.body | contains($needle))) | sort_by(.createdAt) | .[0].number // empty' <<< "$issues")"
  if [[ -z "$existing" ]]; then
    existing="$(jq -r --arg repository_id "Repository ID: \`$repository_id\`" --arg target "Target commit: \`$target\`" 'map(select((.body | contains($repository_id)) and (.body | contains($target)))) | sort_by(.createdAt) | .[0].number // empty' <<< "$issues")"
    if [[ -n "$existing" ]]; then
      legacy_body="$(jq -r --argjson number "$existing" '.[] | select(.number == $number) | .body' <<< "$issues")"
      updated_body="${legacy_body}"$'\n\n'"Target incident key: \`$incident_key\`"
      gh issue edit "$existing" --body "$updated_body"
    fi
  fi
  if [[ -z "$existing" ]]; then
    gh issue create \
      --label scanner-operations \
      --title "[scanner-operations] target cooling down" \
      --body "TavernKeeper's immediate retry also failed, so this target is cooling down for seven days. One final automatic attempt remains.\n\nTarget incident key: \`$incident_key\`\nRepository: \`$repository\`\nRepository ID: \`$repository_id\`\nTarget commit: \`$target\`\nConsecutive failures: \`$count\`\nDomain: \`$domain\`\nCode: \`$code\`\nComponent: \`$component\`\nDiagnostic: \`$diagnostic\`\nFinal attempt after: \`$next_retry\`\nFailure history (latest four): \`$history\`\n\nIf that final attempt fails, TavernKeeper will remove the repository from automatic scans until protected \`add-back\`."
  else
    existing_state="$(jq -r --argjson number "$existing" '.[] | select(.number == $number) | .state' <<< "$issues")"
    was_terminal="$(jq -r --argjson number "$existing" '.[] | select(.number == $number) | [.labels[].name] | index("scanner-unscannable") != null' <<< "$issues")"
    if [[ "$was_terminal" == "true" ]]; then
      gh issue edit "$existing" --remove-label scanner-unscannable
    fi
    if [[ "$existing_state" == "CLOSED" ]]; then
      gh issue reopen "$existing"
    fi
    gh issue comment "$existing" --body "The immediate retry failed after $count consecutive attempts. One final automatic attempt remains after \`$next_retry\`. Latest category: \`$domain/$code/$component/$diagnostic\`. Failure history (latest four): \`$history\`."
  fi
done

jq -c '.unscannable_targets[]' <<< "$incidents" | while read -r terminal; do
  incident_key="$(jq -r '.target_incident_key' <<< "$terminal")"
  repository_id="$(jq -r '.repository_id' <<< "$terminal")"
  target="$(jq -r '.target_sha' <<< "$terminal")"
  existing="$(jq -r --arg needle "Target incident key: \`$incident_key\`" 'map(select(.body | contains($needle))) | sort_by(.createdAt) | .[0].number // empty' <<< "$issues")"
  if [[ -z "$existing" ]]; then
    existing="$(jq -r --arg repository_id "Repository ID: \`$repository_id\`" --arg target "Target commit: \`$target\`" 'map(select((.body | contains($repository_id)) and (.body | contains($target)))) | sort_by(.createdAt) | .[0].number // empty' <<< "$issues")"
    if [[ -n "$existing" ]]; then
      legacy_body="$(jq -r --argjson number "$existing" '.[] | select(.number == $number) | .body' <<< "$issues")"
      updated_body="${legacy_body}"$'\n\n'"Target incident key: \`$incident_key\`"
      gh issue edit "$existing" --body "$updated_body"
    fi
  fi
  if [[ -n "$existing" ]]; then
    already_terminal="$(jq -r --argjson number "$existing" '.[] | select(.number == $number) | [.labels[].name] | index("scanner-unscannable") != null' <<< "$issues")"
    existing_state="$(jq -r --argjson number "$existing" '.[] | select(.number == $number) | .state' <<< "$issues")"
    if [[ "$already_terminal" == "true" && "$existing_state" == "CLOSED" ]]; then
      continue
    fi
    terminal_comment='TavernKeeper removed this repository from automatic scans after its final failed attempt. It is marked unscannable until a staff member uses protected `add-back`.'
    if [[ "$already_terminal" != "true" ]]; then
      gh issue edit "$existing" --add-label scanner-unscannable
    fi
    if [[ "$existing_state" == "OPEN" ]]; then
      gh issue close "$existing" --comment "$terminal_comment"
    else
      gh issue comment "$existing" --body "$terminal_comment"
    fi
  fi
done

jq -c '.[] | select(.state == "OPEN") | select(.body | test("Target incident key: `[0-9a-f]{64}`"))' <<< "$issues" | while read -r issue; do
  issue_number="$(jq -r '.number' <<< "$issue")"
  incident_key="$(jq -r '.body | capture("Target incident key: `(?<key>[0-9a-f]{64})`").key' <<< "$issue")"
  if ! grep -Fxq "$incident_key" <<< "$active_target_keys"; then
    gh issue close "$issue_number" --comment "This exact repository commit is no longer a chronic queued failure."
  fi
done

jq -c '.automatic_holds[] | select(.chronic)' <<< "$incidents" | while read -r hold; do
  fingerprint="$(jq -r '.error_fingerprint' <<< "$hold")"
  count="$(jq -r '.consecutive_failures' <<< "$hold")"
  code="$(jq -r '.failure.code' <<< "$hold")"
  component="$(jq -r '.failure.component' <<< "$hold")"
  domain="$(jq -r '.failure.domain' <<< "$hold")"
  next_probe="$(jq -r '.next_probe_at' <<< "$hold")"
  existing="$(gh issue list --state open --label scanner-operations --search "$fingerprint in:body" --json number --jq '.[0].number // empty')"
  if [[ -z "$existing" ]]; then
    gh issue create \
      --label scanner-operations \
      --title "[scanner-operations] chronic automatic recovery circuit" \
      --body "TavernKeeper is automatically probing a repeatedly failing shared boundary.\n\nFingerprint: \`$fingerprint\`\nDomain: \`$domain\`\nCode: \`$code\`\nComponent: \`$component\`\nConsecutive failures: \`$count\`\nNext probe: \`$next_probe\`\n\nThis circuit is time-bounded and will probe again automatically; no manual resume is required."
  else
    gh issue comment "$existing" --body "Automatic recovery remains active after $count consecutive failures. Next probe: \`$next_probe\`."
  fi
done
