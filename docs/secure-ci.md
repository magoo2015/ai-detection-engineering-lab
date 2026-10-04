# Secure CI

## Purpose

Secure CI holds security controls that run on every change to the
repository. Its goal is to detect and block changes containing likely
credentials, tokens, private keys, and similar secrets from being merged
into protected branches through normal development and pull-request
workflows.

Workflow: `.github/workflows/security-ci.yml`

## Separation from Detection CI

| Workflow | Purpose |
| --- | --- |
| Detection CI (`detection-ci.yml`) | Detection metadata validation and tests |
| Security CI (`security-ci.yml`) | Repository security controls |

Each workflow can fail on its own. A failed security check is never hidden
by a passing test run, and the reverse is also true. Security controls can
change without touching the detection pipeline.

## Current control: Gitleaks secret scanning

The `secret-scan` job runs on pushes to `main` and on pull requests that
target `main`. It:

1. Checks out the full git history (`fetch-depth: 0`) with read-only
   permissions (`contents: read`) and does not keep checkout credentials
   (`persist-credentials: false`).
2. Downloads a pinned Gitleaks release (`GITLEAKS_VERSION`) from the
   official GitHub release, checks the tarball's SHA-256 against the
   official checksum file, and extracts the binary into `RUNNER_TEMP`,
   outside the repository.
3. Runs `gitleaks git` with the default Gitleaks ruleset, plus:
   - `--redact`, which keeps secret values out of public CI logs.
   - `--ignore-gitleaks-allow`, which means inline `gitleaks:allow`
     comments cannot suppress findings.
   - `--exit-code 1`, which makes any finding fail the job.

The CLI is called directly instead of through `gitleaks/gitleaks-action`.
That keeps the scanned commit range, the exit-code behavior, and the
scanner version visible in the workflow file. It also means no extra
token permissions or third-party action are needed.

### Why scan the full history

Every run scans the entire git history, not only the commits in a pull
request. The repository is small, so this costs very little. It also
avoids the gaps that commit-range and shallow-clone scanning can leave:
if Gitleaks identifies a supported secret pattern anywhere in reachable history, the check fails.

## Pass/fail behavior

| Situation | Result |
| --- | --- |
| Scan completes, no findings | PASS |
| Secret finding | FAIL |
| Suspected false positive | FAIL until investigated |
| Gitleaks download fails | FAIL |
| Checksum mismatch | FAIL |
| Scanner configuration or runtime error | FAIL |
| Job exceeds 10 minutes | FAIL |

A scanner failure is never treated as a clean scan. Both workflow steps
use `set -euo pipefail`. The workflow has no `continue-on-error`, no
`|| true`, and does not pipe scanner output into another command.

## False positives and exceptions

Suspected false positives fail the build like any other finding. To
investigate one:

1. Read the redacted finding in the CI log: the rule, file, line, and
   commit.
2. Decide whether the value is a real secret. If there is any doubt,
   treat it as real.
3. If the value is not a secret and the content can be changed, change the
   content. Prefer this over adding an exception.

If an exception really is required, it must be:

- **Narrow:** a single finding fingerprint in `.gitleaksignore`, not a
  rule-wide, path-wide, or regex allowlist.
- **Documented:** a written reason in the same change.
- **Reviewed:** added through a pull request like any other code.

**No exceptions are currently configured.** The repository has no
`.gitleaks.toml`, no `.gitleaksignore`, and no custom rules. Any pull
request that adds one changes this control's behavior and needs explicit
review.

## If a real credential is committed

1. **Treat it as exposed.** Once a commit is pushed to GitHub, assume the
   secret has been seen, even if the push was to a branch or the commit
   was later removed.
2. **Rotate or revoke it first**, at the issuing provider. Removing it from
   the repository does not make it safe again.
3. Check the provider's logs for any use of the credential.
4. Remove the secret from the code. Rewrite history if appropriate, while
   remembering that forks, clones, and pull-request refs may still hold
   copies.
5. Record what happened and what changed.

## Limitations

Secure CI runs **after** a push. It detects secrets that have already
reached GitHub; it does not prevent the first push. Prevention would
need controls that run before or during the push.

## Intentionally deferred controls

These controls are out of scope for now and will be considered
separately:

- SAST (static application security testing)
- SCA / dependency vulnerability scanning
- GitHub Secret Scanning and push protection
- Pre-commit secret scanning
- SBOM generation
- Pinning GitHub Actions to commit SHAs
- Branch protection / required status checks
