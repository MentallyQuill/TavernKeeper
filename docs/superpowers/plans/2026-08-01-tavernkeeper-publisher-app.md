# TavernKeeper Publisher App Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give TavernKeeper one fail-closed, least-privilege direct-write identity for validated reports and operational state while enforcing pull-request and CI protection for every ordinary actor.

**Architecture:** Three single-repository GitHub Apps keep Actions wake authority separate from TavernKeeper contents publication. Ten protected mutation jobs mint short-lived Publisher installation tokens, while repository-local `GITHUB_TOKEN` retains contents-read and performs only local issue or continuation operations. A main-branch ruleset requires pull requests and CI except for the dedicated Publisher App Integration actor.

**Tech Stack:** GitHub Apps, GitHub Actions YAML, pinned `actions/create-github-app-token`, GitHub Rulesets REST API, TypeScript, Vitest, YAML parser, PowerShell, GitHub CLI.

## Global Constraints

- `Tavernary Wake TavernKeeper` is installed only on `MentallyQuill/TavernKeeper` with Actions write and metadata read.
- `TavernKeeper Wake Tavernary` is installed only on `MentallyQuill/Tavernary` with Actions write and metadata read.
- `TavernKeeper Publisher` is installed only on `MentallyQuill/TavernKeeper` with Contents write and metadata read.
- The Publisher Client ID variable and private-key secret exist only in `tavernkeeper-scanner` and `tavernkeeper-staff`.
- No mutation job may fall back to `GITHUB_TOKEN` for contents writes.
- Scans remain staff-controlled, exact-SHA, complete-or-nothing, and limited to at most five repositories per batch and two concurrent repository jobs.
- The initial staff pause remains active until both approved canary scans and their live Tavernary imports are verified.

---

## File map

- `.github/workflows/coverage-campaign.yml`: protected coverage-campaign mutation.
- `.github/workflows/reconcile.yml`: durable claim and provider-probe mutations, automatic child dispatch.
- `.github/workflows/release-holds.yml`: protected automatic-hold release.
- `.github/workflows/scan-and-publish.yml`: exact-target scan and serialized publication.
- `.github/workflows/targeted-scan.yml`: wake-App-authorized targeted queue mutation.
- `.github/workflows/policy-rescan.yml`: staff policy-campaign state mutation and local reconcile dispatch.
- `.github/workflows/staff-operations.yml`: staff pause/resume/retry state mutation and local reconcile dispatch.
- `.github/workflows/publisher-verification.yml`: owner-only scanner/staff protected-main canary.
- `scripts/check-workflow-policy.mjs`: static allowlist and secret/token placement enforcement.
- `tests/workflows.test.ts`: parsed workflow behavior and negative policy tests.
- `docs/architecture.md`, `docs/operations.md`, `README.md`: operator and public architecture documentation.

### Task 1: Create and constrain the three GitHub Apps

**Interfaces:**

- Produces: four source-side bridge secrets, two environment-scoped Publisher Client ID variable copies, two environment-scoped Publisher private-key secret copies, three single-repository installations, and the numeric Publisher integration ID needed by Task 4.

- [ ] **Step 1: Create the Tavernary-to-TavernKeeper wake App**

Create `Tavernary Wake TavernKeeper` under the MentallyQuill account with webhook disabled, account-only installation, Actions read/write, and mandatory metadata read. Install it with `Only select repositories: TavernKeeper`.

- [ ] **Step 2: Store its source-side credentials without printing the key**

```powershell
$wakeAppId = '4457487'
gh secret set TAVERNKEEPER_WAKE_APP_ID --repo MentallyQuill/Tavernary --body $wakeAppId
$wakeKeyFiles = @(Get-ChildItem -LiteralPath 'C:\Users\Keptin\Downloads' -Filter 'tavernary-wake-tavernkeeper.*.private-key.pem')
if ($wakeKeyFiles.Count -ne 1) { throw "Expected exactly one Tavernary wake private key download." }
$privateKey = Get-Content -Raw -LiteralPath $wakeKeyFiles[0].FullName
$privateKey | gh secret set TAVERNKEEPER_WAKE_APP_PRIVATE_KEY --repo MentallyQuill/Tavernary
```

Verify `gh secret list --repo MentallyQuill/Tavernary` names the two secrets, then delete only the exact downloaded PEM after resolving that it is under `C:\Users\Keptin\Downloads`.

- [ ] **Step 3: Create the TavernKeeper-to-Tavernary wake App**

Create `TavernKeeper Wake Tavernary` with webhook disabled, account-only installation, Actions read/write, and mandatory metadata read. Install it with `Only select repositories: Tavernary`. Store its source-side credentials without printing the key:

```powershell
$returnWakeAppId = '4457552'
gh secret set TAVERNARY_WAKE_APP_ID --repo MentallyQuill/TavernKeeper --body $returnWakeAppId
$returnWakeKeyFiles = @(Get-ChildItem -LiteralPath 'C:\Users\Keptin\Downloads' -Filter 'tavernkeeper-wake-tavernary.*.private-key.pem')
if ($returnWakeKeyFiles.Count -ne 1) { throw "Expected exactly one TavernKeeper wake private key download." }
$returnWakeKey = Get-Content -Raw -LiteralPath $returnWakeKeyFiles[0].FullName
$returnWakeKey | gh secret set TAVERNARY_WAKE_APP_PRIVATE_KEY --repo MentallyQuill/TavernKeeper
```

Verify `gh secret list --repo MentallyQuill/TavernKeeper` names both wake secrets before removing only the resolved PEM under `C:\Users\Keptin\Downloads`.

- [ ] **Step 4: Create the Publisher App, environment variables, and secrets**

Create `TavernKeeper Publisher` with webhook disabled, account-only installation, Contents read/write, mandatory metadata read, and no Actions permission. Install it with `Only select repositories: TavernKeeper`. Store the Client ID as a variable and the private key as a secret in both environments:

```powershell
$publisherClientId = 'Iv23lijroYAkNgXRcxdW'
gh variable set TAVERNKEEPER_PUBLISHER_CLIENT_ID --repo MentallyQuill/TavernKeeper --env tavernkeeper-scanner --body $publisherClientId
gh variable set TAVERNKEEPER_PUBLISHER_CLIENT_ID --repo MentallyQuill/TavernKeeper --env tavernkeeper-staff --body $publisherClientId
$publisherKeyFiles = @(Get-ChildItem -LiteralPath 'C:\Users\Keptin\Downloads' -Filter 'tavernkeeper-publisher.*.private-key.pem')
if ($publisherKeyFiles.Count -ne 1) { throw "Expected exactly one Publisher private key download." }
$publisherKey = Get-Content -Raw -LiteralPath $publisherKeyFiles[0].FullName
$publisherKey | gh secret set TAVERNKEEPER_PUBLISHER_APP_PRIVATE_KEY --repo MentallyQuill/TavernKeeper --env tavernkeeper-scanner
$publisherKey | gh secret set TAVERNKEEPER_PUBLISHER_APP_PRIVATE_KEY --repo MentallyQuill/TavernKeeper --env tavernkeeper-staff
```

Verify the environment variable with `gh variable list --repo MentallyQuill/TavernKeeper --env {environment_name}` and the private-key secret name with `gh api repos/MentallyQuill/TavernKeeper/environments/{environment_name}/secrets`. Verify each App installation visually names exactly one selected repository, and remove the exact downloaded PEM files.

### Task 2: Enforce Publisher authentication in workflow policy

**Files:**

- Modify: `tests/workflows.test.ts`
- Modify: `scripts/check-workflow-policy.mjs`

**Interfaces:**

- Consumes: token step ID `publisher-token` and Client ID/private-key names from Task 1.
- Produces: a policy that rejects untrusted contents-write permissions, misplaced Publisher secrets, persisted checkout credentials, and direct pushes without the Publisher token.

- [ ] **Step 1: Write the failing workflow tests**

Add assertions that every mutation workflow exposes `contents: read`, that each mutation job contains one `Create TavernKeeper Publisher token` step using the pinned action, exact Client ID variable, and private-key secret, that every checkout has `persist-credentials: false`, and that each step containing `git push origin HEAD:main` has `GH_TOKEN: ${{ steps.publisher-token.outputs.token }}` and contains `gh auth setup-git`. Reject legacy Publisher `app-id` inputs and App ID secrets.

Add a negative policy test that replaces `GH_TOKEN: ${{ steps.publisher-token.outputs.token }}` with `GH_TOKEN: ${{ github.token }}` in `reconcile.yml` and expects `/direct push does not use the Publisher App token/u`.

- [ ] **Step 2: Run the targeted tests and observe Red**

Run: `npm test -- tests/workflows.test.ts`

Expected: FAIL because current mutation workflows still expose contents write and push with the repository-local token.

- [ ] **Step 3: Add the minimal policy implementation**

Update `reviewedPermissionProfiles` so every mutation workflow and job uses `contents: read`. Add constants for the exact Publisher action pin, Client ID variable, private-key secret, mutation workflows, and mutation job names. Walk parsed steps and fail when the token step, protected environment, checkout flag, credential placement, or push-step token contract differs from the approved design.

- [ ] **Step 4: Run the targeted tests**

Run: `npm test -- tests/workflows.test.ts`

Expected: still FAIL only on the unchanged workflow YAML, proving the policy implementation is active.

- [ ] **Step 5: Commit the Red policy contract**

```powershell
git add tests/workflows.test.ts scripts/check-workflow-policy.mjs
git commit -m "test: require Publisher App writes"
```

### Task 3: Migrate all five mutation workflows

**Files:**

- Modify: `.github/workflows/reconcile.yml`
- Modify: `.github/workflows/deep-scan.yml`
- Modify: `.github/workflows/adjudicate.yml`
- Modify: `.github/workflows/policy-rescan.yml`
- Modify: `.github/workflows/staff-operations.yml`
- Test: `tests/workflows.test.ts`

**Interfaces:**

- Consumes: Publisher environment secrets and policy contract from Tasks 1-2.
- Produces: five fail-closed protected workflows using a short-lived Publisher token for direct pushes.

- [ ] **Step 1: Make workflow contents permissions read-only**

Set root and mutation-job `contents` permissions to `read`. Preserve `issues: write` only where staff incident creation needs it, `actions: write` only on separate local dispatch jobs/steps, and Pages/id-token permissions only on deployment workflows.

- [ ] **Step 2: Add the protected environment and token step to each mutation job**

Use this exact step before each commit step:

```yaml
- name: Create TavernKeeper Publisher token
  id: publisher-token
  uses: actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349
  with:
    client-id: ${{ vars.TAVERNKEEPER_PUBLISHER_CLIENT_ID }}
    private-key: ${{ secrets.TAVERNKEEPER_PUBLISHER_APP_PRIVATE_KEY }}
    owner: MentallyQuill
    repositories: TavernKeeper
    permission-contents: write
```

Add `environment: tavernkeeper-scanner` to `reconcile.yml`'s `publish` job; retain `tavernkeeper-staff` on all manual mutation jobs.

- [ ] **Step 3: Remove implicit checkout credentials and authenticate pushes explicitly**

Set `persist-credentials: false` on every mutation-job checkout. Set each commit step environment to:

```yaml
env:
  GH_TOKEN: ${{ steps.publisher-token.outputs.token }}
```

Run `gh auth setup-git` immediately before Git configuration and retain ordinary `git push origin HEAD:main` without force flags.

- [ ] **Step 4: Separate contents publication from Actions dispatch**

In `policy-rescan.yml` and `staff-operations.yml`, end the Publisher-authenticated commit step after `git push`. Add a later `Dispatch reconcile` step with `GH_TOKEN: ${{ github.token }}`. Give the job `actions: write` while keeping `contents: read`; keep the existing `operation != pause` condition in `staff-operations.yml`.

- [ ] **Step 5: Run the targeted tests and policy checker**

Run: `npm test -- tests/workflows.test.ts`

Run: `npm run workflows:check`

Expected: PASS and `Workflow policy passed for 8 workflows.`

- [ ] **Step 6: Commit the Green implementation**

```powershell
git add .github/workflows tests/workflows.test.ts scripts/check-workflow-policy.mjs
git commit -m "feat: publish with scoped GitHub App"
```

### Task 4: Document, publish, and protect main

**Files:**

- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/operations.md`
- Create: `docs/superpowers/specs/2026-08-01-tavernkeeper-publisher-app-design.md`
- Create: `docs/superpowers/plans/2026-08-01-tavernkeeper-publisher-app.md`

**Interfaces:**

- Consumes: verified workflows from Task 3 and numeric Publisher App ID from Task 1.
- Produces: deployed Publisher workflow and active main-branch protection.

- [ ] **Step 1: Update operator documentation**

Document all three App permission/install boundaries, both Publisher environment secret locations, fail-closed behavior, key rotation, the ruleset bypass, and the fact that `GITHUB_TOKEN` remains contents-read.

- [ ] **Step 2: Run the full local gate**

Run: `npm run check`

Expected: formatter, linter, typecheck, workflow policy, 152-or-more tests, package validation, and build all PASS.

- [ ] **Step 3: Commit documentation and push the feature branch**

```powershell
git add README.md docs
git commit -m "docs: define Publisher App boundary"
git push origin feature/tavernkeeper-v1
```

Open a pull request into `main`, wait for the `check` job, inspect its conclusion, merge only the verified head SHA, and confirm `main` contains the merge.

- [ ] **Step 4: Create the exact main ruleset**

Resolve the Publisher App integration ID from GitHub and construct this exact body in memory:

```json
{
  "name": "Protect main; allow TavernKeeper Publisher",
  "target": "branch",
  "enforcement": "active",
  "bypass_actors": [
    {
      "actor_id": "$publisherAppId",
      "actor_type": "Integration",
      "bypass_mode": "always"
    }
  ],
  "conditions": {
    "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] }
  },
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    {
      "type": "pull_request",
      "parameters": {
        "allowed_merge_methods": ["merge", "squash", "rebase"],
        "dismiss_stale_reviews_on_push": false,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_approving_review_count": 0,
        "required_review_thread_resolution": false
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "do_not_enforce_on_create": false,
        "required_status_checks": [
          { "context": "check", "integration_id": 15368 }
        ],
        "strict_required_status_checks_policy": true
      }
    }
  ]
}
```

In PowerShell, assign `$publisherAppId = [int]4457566`, construct the shown object with `$publisherAppId` as the numeric `actor_id`, serialize it with `ConvertTo-Json -Depth 10 -Compress`, and pipe it to `gh api --method POST repos/MentallyQuill/TavernKeeper/rulesets --input -`. Verify the response has `enforcement: active`, only one bypass actor of type `Integration`, `~DEFAULT_BRANCH`, and the four exact rules.

- [ ] **Step 5: Prove ordinary direct pushes are blocked**

From a clean, disposable test branch based on `main`, create a documentation-only commit and attempt `git push origin HEAD:main` with ordinary user authentication. Expected: rejected by repository rules. Push the branch normally and remove only that remote test branch after verification.

### Task 5: Run canary scans and prove the complete handshake

**Interfaces:**

- Consumes: protected Publisher path, both wake Apps, live Tavernary target manifest.
- Produces: verified Wandlight and Recursion exact-SHA reports, live TavernKeeper Pages entries, and live Tavernary card summaries.

- [ ] **Step 1: Resume scanning through the protected staff workflow**

Dispatch `staff-operations.yml` with `operation=resume`, approve the `tavernkeeper-staff` deployment, and verify the Publisher App commits the resulting `operations/state.json` update through the active ruleset.

- [ ] **Step 2: Run Wandlight as the first deep-scan canary**

Dispatch `deep-scan.yml` with `repository_id=1254077407`, approve the protected environment, and wait through completion. The target must resolve to `MentallyQuill/Wandlight` at the SHA currently published by Tavernary. If the provider or quota fails, allow the defined three retries over three hours; publish no degraded report and notify only TavernKeeper staff after exhaustion.

- [ ] **Step 3: Verify the complete Wandlight publication path**

Verify the workflow push actor is the Publisher App, the TavernKeeper report/index is immutable and live on Pages, the TavernKeeper-to-Tavernary App dispatches the input-free importer, Tavernary validates the summary, and the live Wandlight card shows the scan icon and concise exact-SHA result.

- [ ] **Step 4: Repeat for Recursion**

Dispatch `deep-scan.yml` with `repository_id=1285208664` and repeat every workflow, Pages, report-integrity, wake, import, deploy, and live-card check for `MentallyQuill/Recursion`.

- [ ] **Step 5: Capture final evidence**

Record both repository IDs, target SHAs, immutable report IDs and URLs, TavernKeeper publication commit SHAs, workflow run URLs, Tavernary import/deploy SHA, ruleset ID, App installation scopes, and live card states. Confirm no non-MentallyQuill repository was scanned and the initial rollout pause is cleared only after both canaries pass.
