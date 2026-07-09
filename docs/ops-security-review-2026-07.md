# Operational & Security Review — static-site-infra

**Date:** 2026-07-09 (Revision 3 — remediation status added; see the table at the end)
**Scope:** `specter_static_site/static_site_stack.py` (CDK stack), `specter_static_site/auth/` (Lambda@Edge Cognito OIDC handler, token client, JWT validator), `.github/workflows/` (CI/CD), packaging (`pyproject.toml`, requirements files), documentation (`README.md`, `CLAUDE.md`, `SECURITY.md`), and tests.
**Package version reviewed:** 2.4.0 (commit `b34df11`)

This is a review-only document; no code changes accompany it. Findings are prioritized P0 (critical) through P3 (low), each with location, impact, and a concrete recommendation.

**Revision 2:** a second independent review pass re-verified all findings from the first pass against the code (all 22 stand; none retracted) and extended coverage to the complete test suite, which the first pass had only skimmed. It adds three findings — P2-11 (sign-out does not revoke the refresh token), P3-6 (OAuth error responses cause a silent redirect loop), and P3-7 (test gap for redirect-validation edge cases) — and refines P2-2, P2-3, and the positive observations.

---

## Summary

The project is in good shape overall: origin access is OAC-based, all buckets block public access and enforce SSL, the auth handler fails closed and uses constant-time comparisons, and the CI pipeline includes linting with security rules, dependency auditing, secret scanning, and IAM Access Analyzer checks. The critical gaps are **secret handling for the Cognito client secret** and **alarms that notify no one**. The high-priority items cluster around supply-chain pinning and deploy-time footguns (region, bucket names, removal policy).

| Priority | Count | Theme |
|---|---|---|
| P0 | 2 | Plaintext client secret in Lambda package; alarms with no actions |
| P1 | 5 | Unpinned bundling deps; mutable CI refs; region validation; edge log retention; destructive removal policy |
| P2 | 11 | OIDC hardening, redirect edge case, token rotation, sign-out revocation, JWKS amplification, bucket-name overflow, CSP, lockfile, temp-dir secret |
| P3 | 7 | Doc drift, DNS records, cookie prefix, metric semantics, construct-ID collision, error-param loop, redirect test gap |

---

## P0 — Critical

### P0-1. Cognito client secret stored in plaintext inside the Lambda@Edge deployment package

**Location:** `specter_static_site/static_site_stack.py:170-189`, `specter_static_site/auth/handler.py:13-17`

The stack writes the raw `cognito_client_secret` into `config.json` and bundles it into the Lambda@Edge asset zip. As a result the secret is readable, in plaintext, in every one of these places:

- the local/CI staging directory and `cdk.out/` asset output;
- the CDK bootstrap S3 assets bucket (anyone with read access to that bucket);
- the deployed function package (anyone with `lambda:GetFunction` in the account can download the code);
- the consuming application's configuration, since the secret is a plain constructor argument (typically threaded through CI environment variables or CDK context).

Lambda@Edge does not support environment variables, but that does not force baking secrets into code. The standard pattern is:

1. Accept a **Secrets Manager secret ARN** (or SSM SecureString parameter name) as the constructor parameter instead of the raw secret.
2. In the handler, fetch the secret at cold start from Secrets Manager in `us-east-1` and cache it at module level (edge replicas can call regional endpoints; a ~50 ms cold-start cost, zero warm cost).
3. Grant the function's execution role `secretsmanager:GetSecretValue` on that one ARN.

This also removes the secret from the CDK asset hash and from P2-10 (temp-dir residue) entirely.

**Recommendation:** Change the API to `cognito_client_secret_arn`, fetch + cache at cold start, and treat the current parameter as deprecated. Rotate the client secret after migrating, since existing packages and asset buckets already contain it.

### P0-2. CloudWatch alarms have no notification actions

**Location:** `specter_static_site/static_site_stack.py:261-294` (comment: "console only, no SNS")

The 5xx (>5%) and 4xx (>10%) alarms have no `alarm_actions`. When they fire, the state change is visible only to someone who happens to be looking at the CloudWatch console — operationally, outages are discovered by end users, not by the team.

**Recommendation:** Create an SNS topic in the stack and wire it via `alarm.add_alarm_action(cw_actions.SnsAction(topic))`. Expose either `alarm_topic_arn` (import an existing topic) or `alarm_email` (create a topic + email subscription) as constructor parameters. Even a default topic with no subscription is better than none — it can be subscribed to after the fact without a redeploy. Consider `ok_actions` as well so recoveries are announced.

---

## P1 — High

### P1-1. Unpinned dependencies in the Lambda bundling command

**Location:** `specter_static_site/static_site_stack.py:211`

The bundling step runs `pip install PyJWT cryptography urllib3` with no version pins and no hashes. Every synth pulls the latest release of each — the code that gates every authenticated request is rebuilt from whatever PyPI serves that day. This is both a reproducibility problem (two synths of the same commit can produce different assets, so CDK asset hashes churn) and a supply-chain exposure (a compromised release of any of the three lands directly in the auth path).

`specter_static_site/auth/requirements.txt` exists with version floors, but the bundling command doesn't use it.

**Recommendation:** Pin exact versions in `auth/requirements.txt`, generate hashes (`pip-compile --generate-hashes` or `uv pip compile`), and change the bundling command to `pip install -r /asset-input/requirements.txt --require-hashes ...`. Dependabot already covers the repo, so pins won't rot silently.

### P1-2. CI reusable workflows and actions pinned to mutable refs, with `secrets: inherit`

**Location:** `.github/workflows/pr.yml`, `backup.yml`, `security.yml`, `validate-buckets.yml`

All four org-level reusable workflows and the composite action are referenced as `Specter099/.github/...@main`, and `pr.yml`/`backup.yml` pass `secrets: inherit`. A compromise (or simply a bad merge) on the `.github` repository's `main` branch immediately executes in this repo's context with **all** of its secrets, and — via `security.yml` and `backup.yml` — the AWS OIDC role. Marketplace actions (`actions/checkout@v6`, `aws-actions/configure-aws-credentials@v6`, etc.) are pinned to major tags, which are also mutable.

**Recommendation:**
- Pin reusable workflows and actions to full commit SHAs (with a tag comment for readability); Dependabot's `github-actions` ecosystem updates SHA pins automatically.
- Replace `secrets: inherit` with an explicit `secrets:` block listing only what each reusable workflow needs.
- The `environment: production` gate on `security.yml` is good — keep it, and confirm the environment requires approval for runs from forks.

### P1-3. No us-east-1 region validation despite hard regional requirements

**Location:** `specter_static_site/static_site_stack.py` (constructor)

Two resources in this stack only work in `us-east-1`: Lambda@Edge functions must be created there, and ACM certificates attached to CloudFront must live there. The stack accepts any `env.region` and fails only at deploy time — or worse, successfully creates a DNS-validated certificate in the wrong region that CloudFront can never use, leaving an orphaned cert and a confusing error.

**Recommendation:** At synth time, when `enable_auth` is true or a certificate is being created (`hosted_zone_id` path), raise a clear `ValueError` if `self.region` is set and is not `us-east-1`. (When the region is environment-agnostic/unresolved, emit a warning annotation instead.)

### P1-4. Lambda@Edge log retention is ineffective outside us-east-1

**Location:** `specter_static_site/static_site_stack.py:191-196`

The explicit `auth_log_group` (two-week retention) only receives logs from executions in `us-east-1`. Lambda@Edge replicas write to auto-created log groups named `/aws/lambda/<edge-region>.<function-name>` in **each region where the function executes**, and those groups are created with **no retention policy**. Consequences:

- unbounded CloudWatch Logs storage cost accumulating across many regions;
- unmanaged retention of request data (the handler logs the URI of every authenticated request at INFO), which matters for privacy/retention policy compliance.

**Recommendation:** Document the caveat prominently. Mitigations, in increasing effort: reduce handler logging to warnings/errors only; run a small scheduled Lambda (or org-level automation) that sets retention on `/aws/lambda/*.AuthEdgeFunction*` groups in all regions; or accept and document the cost/retention tradeoff explicitly.

### P1-5. Site bucket uses `RemovalPolicy.DESTROY` + `auto_delete_objects=True`

**Location:** `specter_static_site/static_site_stack.py:106-107`

A stack deletion — accidental or via a bad pipeline action — irreversibly deletes the production site bucket **including all object versions** (the auto-delete custom resource removes versions too, so bucket versioning offers no protection against this path). The README example suggests `termination_protection=True`, but that is opt-in and outside the construct.

**Recommendation:** Add a `removal_policy` parameter to the construct, defaulting to `RETAIN` (with `auto_delete_objects=False`); keep `DESTROY` available for dev/test stacks. Assets are redeployable from CI, so the cost of RETAIN is only an orphaned bucket to clean up manually — the safer default for a construct advertised for production use.

---

## P2 — Medium

### P2-1. OIDC flow lacks PKCE and `nonce` validation

**Location:** `specter_static_site/auth/handler.py:56-66`

The flow uses a confidential client (secret-authenticated token exchange) and a CSRF `state` cookie with constant-time comparison — good. PKCE (`code_challenge`/`code_verifier`) and an OIDC `nonce` (generated alongside `state`, validated against the `nonce` claim in the returned `id_token`) are cheap, standards-recommended defense-in-depth against authorization-code injection and token replay. Cognito supports both.

**Recommendation:** Generate a PKCE verifier + nonce with the state, store them in the short-lived state cookie (or an HMAC-signed composite value), send `code_challenge`/`nonce` on the authorize redirect, pass the verifier to the token exchange, and require the `nonce` claim to match on the first validation of the received `id_token`.

### P2-2. Open-redirect edge case in `_safe_redirect_path`

**Location:** `specter_static_site/auth/handler.py:94-106`

The validator rejects `//`-prefixed paths and anything with a scheme/netloc, but a path like `/\evil.com` passes: `urllib.parse.urlparse` does not treat `\` as an authority separator, yet some browsers normalize backslashes to slashes in the `Location` header, turning it into protocol-relative `//evil.com`. Exploitability is limited — the path only flows into a redirect after a *successful* token refresh, so the victim must already be authenticated and the attacker must control the requested URI — but the fix is one line.

**Recommendation:** Reject any candidate path containing `\` or ASCII control characters before the existing checks. Note that `test_safe_redirect_path` in `tests/test_auth_handler.py` covers `//`, absolute URLs, and `javascript:` but not these variants — add the missing cases alongside the fix (see P3-7).

### P2-3. Refresh-token rotation not handled

**Location:** `specter_static_site/auth/handler.py:214-236`

`_try_refresh` sets only the new `id_token` cookie. If the Cognito app client enables refresh-token rotation, the token endpoint returns a **new** refresh token and invalidates the old one — the handler drops it, so the stale cookie fails on the next refresh and the user is silently logged out hourly.

**Recommendation:** When the refresh response contains `refresh_token`, set it as a cookie (same pattern as `_handle_callback` lines 189-195). The surrounding error handling is otherwise sound: `refresh_tokens` returns `{}` on non-200 (vs. `exchange_code` raising), and the caller checks both cases with cookie-clearing fallbacks — that asymmetry is tested and handled; only the rotation gap needs fixing.

### P2-11. Sign-out does not revoke the refresh token

**Location:** `specter_static_site/auth/handler.py:200-211`

`_handle_signout` clears the cookies (a client-side-only action) and redirects to Cognito's `/logout` endpoint, which ends the hosted-UI session — but it does **not** revoke the refresh token. A refresh token that was exfiltrated (malware, device theft, backup leakage) remains valid for up to its full 30-day lifetime even after the user explicitly signs out, and can mint fresh id tokens the whole time.

**Recommendation:** During sign-out, when a `refresh_token` cookie is present, call Cognito's `/oauth2/revoke` endpoint (client-secret-authenticated, same pattern as `cognito_client.py`) before redirecting to `/logout`; treat revocation failures as non-fatal (still clear cookies and redirect). Requires "token revocation" enabled on the app client (the Cognito default). Also worth documenting: the cleared `id_token` remains cryptographically valid until its `exp` (≤1 h) — anyone holding a copy passes validation until then. That is inherent to stateless JWT auth at the edge and acceptable, but it should be a stated assumption.

### P2-4. JWKS force-refresh amplification

**Location:** `specter_static_site/auth/jwt_validator.py:60-67`

Any request bearing a token whose `kid` isn't in the cached JWKS triggers a forced re-fetch from Cognito. An attacker sending garbage tokens with random `kid`s makes every such request perform a network round trip — added latency, and potential throttling of the JWKS endpoint that then degrades legitimate key-rotation refreshes.

**Recommendation:** Rate-limit forced refreshes (e.g., allow at most one forced fetch per N seconds per container, treating unknown `kid`s as invalid in between). The legitimate use case — mid-TTL key rotation — is rare and tolerates a short delay.

### P2-5. Bucket names can exceed S3's 63-character limit

**Location:** `specter_static_site/static_site_stack.py:85,102`

`{domain_slug}-s3-logs-{account}-{region}-an` carries ~39 characters of fixed overhead (12-digit account, region up to 14 chars, literals). Any domain slug longer than ~24 characters produces an invalid bucket name and the deploy fails with a CloudFormation error far removed from the actual cause. `my-marketing-site.example-company.com` already overflows.

**Recommendation:** Validate the computed names at synth time and raise a clear error; or truncate the slug and append a short stable hash of the full domain to preserve uniqueness.

### P2-6. No CloudFront access logs (accepted tradeoff — document it)

**Location:** nag suppression `AwsSolutions-CFR3`, `static_site_stack.py:364-372`

CloudFront standard logging is disabled because it's incompatible with the Free pricing plan — a legitimate, documented tradeoff. Note the operational consequence: S3 server access logs only record **origin fetches (cache misses)**, so there is no edge-level record of who requested what. That limits incident forensics, WAF rule tuning, and investigation of auth abuse against the Lambda@Edge handler.

**Recommendation:** State the limitation in the README. Revisit if the distribution moves off the Free plan; CloudWatch Logs delivery for CloudFront (v2 standard logging) is an alternative worth evaluating.

### P2-7. No Content-Security-Policy header

**Location:** `specter_static_site/static_site_stack.py:241`

The managed `ResponseHeadersPolicy.SECURITY_HEADERS` provides HSTS, `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy`, but no CSP. For static sites (especially SPAs), CSP is the main mitigation against XSS turning into token/cookie theft or content injection.

**Recommendation:** Add an optional `csp` constructor parameter that, when set, builds a custom `ResponseHeadersPolicy` (inheriting the other security headers) with the given CSP string. CSP is site-specific, so a parameter — not a hardcoded value — is right.

### P2-8. Post-login deep link is lost

**Location:** `specter_static_site/auth/handler.py:150-197`

`_handle_callback` always redirects to `/`, so a user who opened `https://site/reports/q2?id=7` lands on the homepage after login. (The refresh path already preserves the target via `_safe_redirect_path` — the behavior is inconsistent.)

**Recommendation:** Store the originally requested path (validated through `_safe_redirect_path`) in the state cookie alongside the CSRF value at login-redirect time, and redirect to it in the callback.

### P2-9. No lockfile — CI dependencies float

**Location:** `requirements.txt` (just `-e .`), `requirements-dev.txt`, `pyproject.toml`

CI installs whatever the version ranges resolve to on a given day. A bad upstream release breaks CI unrelated to the commit under test, and "green last week, red today" costs debugging time. `pip-audit` results are likewise non-reproducible.

**Recommendation:** Add a compiled lockfile (`uv pip compile` or `pip-compile`) used by CI, refreshed by Dependabot/scheduled job. Keep the ranges in `pyproject.toml` for library consumers.

### P2-10. Secret-bearing temp directory is never cleaned up

**Location:** `specter_static_site/static_site_stack.py:173`

`tempfile.mkdtemp(prefix="static-site-auth-")` writes `config.json` — containing the client secret — and the directory is never deleted. Every synth leaves a plaintext copy of the secret in the temp dir of the CI runner or developer laptop. (Ephemeral CI runners bound the exposure; laptops do not.)

**Recommendation:** Delete the staging directory after `Code.from_asset` has consumed it (asset staging copies the content), or at process exit via `atexit`. Fully subsumed by P0-1 if the raw secret leaves the construct API.

---

## P3 — Low / documentation

### P3-1. Documentation drift

- `README.md` claims "S3 buckets for S3 and CloudFront access logs (180-day retention)" and `CLAUDE.md` says "Three buckets per site" — the stack creates **two** buckets, CloudFront logging is disabled, and the 180-day lifecycle applies only to the S3-access-logs bucket (the site bucket expires noncurrent versions at 30 days).
- The README install example pins `@v1.0.0`; the package is at 2.4.0.
- The README parameter table omits `cognito_*`, `deploy_role_arns`, `skip_deployment`, `exclude_patterns`, `deployment_memory_limit`.

**Recommendation:** Reconcile README/CLAUDE.md with the actual resources and parameters.

### P3-2. No Route 53 alias records; imported cert not validated for `www`

The distribution answers for the apex and `www.{domain}`, and auto-created certs cover both, but no A/AAAA alias records are created even when `hosted_zone_id` is provided — consumers wire DNS manually and `www` is easy to miss. Separately, an imported `certificate_arn` is never checked to cover `www.{domain}`; a cert without that SAN fails at deploy.

**Recommendation:** Optionally create alias records when a hosted zone is available (behind a `create_dns_records` flag), and document the `www` SAN requirement for imported certs.

### P3-3. Cookies could use the `__Host-` prefix

Cookies are `Secure; HttpOnly; SameSite=Lax` with `Path=/` — good. Renaming to `__Host-id_token` etc. adds browser-enforced guarantees (Secure, no Domain attribute, Path=/) at near-zero cost.

### P3-4. 4xxErrorRate semantics with SPA rewrite

Because 404s are rewritten to `200 /index.html`, real 404s never count toward the 4xx alarm — it effectively measures 403s (and 4xx from the auth Lambda). Worth a note in the alarm description so an operator doesn't misread a quiet 4xx metric as "no broken links."

### P3-5. Construct-ID collision in `deploy_role_arns`

**Location:** `specter_static_site/static_site_stack.py:119-125`

The construct ID is derived from the last ARN segment (`role_arn.split('/')[-1]`). Two roles with the same name in different accounts or IAM paths collide at synth with a duplicate-construct error. Use a hash of the full ARN (or the list index) in the ID.

### P3-6. OAuth error responses cause a silent redirect loop

**Location:** `specter_static_site/auth/handler.py:150-156`

When Cognito redirects back to `/_callback` with an `error` parameter instead of a `code` (e.g. `error=access_denied` when a user cancels login, or a misconfigured app client), `_handle_callback` redirects to `/` — which, with no token present, immediately bounces back to the Cognito authorize page. The user cycles between Cognito and the site and never sees an explanation. Bounded by user interaction, so it's an annoyance rather than a vulnerability.

**Recommendation:** Detect the `error` query parameter in the callback and return a small static 403/error response (and log the `error`/`error_description` values) instead of redirecting to `/`.

### P3-7. Test gap: redirect-validation edge cases not covered

**Location:** `tests/test_auth_handler.py` (`test_safe_redirect_path` parametrize cases)

The existing cases cover `//`-prefixed, absolute-URL, empty, and `javascript:` inputs — good — but not backslash variants (`/\evil.com`, `/\\evil.com`) or paths with control characters, which are exactly the inputs P2-2 identifies as risky. Add them (expected result `/`) together with the code fix so the regression stays pinned.

---

## Positive observations

- **Origin security:** OAC-based CloudFront→S3 access, `BLOCK_ALL` public access, SSL enforced, SSE on all buckets, versioning + sensible lifecycle rules.
- **Auth handler quality:** constant-time state comparison, fail-closed on invalid tokens (with cookie clearing), refresh attempted only on `ExpiredSignatureError`, algorithm allowlist plus `kid`/issuer/audience/`exp` enforcement in `jwt_validator.py`, HttpOnly/Secure/SameSite cookies, no secret values in logs, timeouts on all outbound HTTP.
- **Deliberate 403 handling:** only 404 is rewritten for SPA routing, so auth/OAC failures remain visible in metrics — with the reasoning documented inline.
- **CI hygiene:** matrix tests on 3.11/3.12, ruff with the security (`S`) ruleset, `pip-audit`, gitleaks, IAM Access Analyzer against synthesized templates, Dependabot for both pip and Actions, and default-restrictive `permissions: contents: read` on workflows.
- **cdk-nag** enabled with narrowly-scoped, individually-justified suppressions.
- **Good test coverage** for a construct library: synth assertions per parameter combination plus real unit tests for the auth handler, JWT validator, and Cognito client. The security-relevant behaviors are explicitly pinned by tests: invalid tokens must *not* trigger a refresh attempt (fail-closed), HS256 algorithm-downgrade tokens are rejected, the JWKS kid-miss path retries exactly once, the authorization code is URL-encoded in the token exchange, 403 is asserted *not* to be rewritten to `index.html`, and a regression test guards against reintroducing an unused CloudFront logs bucket. The JWT validator tests sign real RS256 tokens with a locally generated keypair rather than mocking the crypto.

---

## Suggested remediation order

1. **P0-1** — move the client secret to Secrets Manager; rotate the existing secret afterward.
2. **P0-2** — add SNS alarm actions (small, immediate operational win).
3. **P1-1 / P1-2** — pin Lambda bundling deps and CI refs (quick, high-leverage supply-chain fixes).
4. **P1-3 / P2-5** — synth-time validation (region, bucket-name length): cheap guards against confusing deploy failures.
5. **P1-5** — `removal_policy` parameter defaulting to RETAIN.
6. **P1-4, P2-1…P2-4, P2-11** — auth/logging hardening batch (edge log retention, PKCE/nonce, backslash-path rejection + tests, refresh rotation, JWKS rate limit, sign-out revocation).
7. Remaining P2/P3 as maintenance (CSP param, deep-link return, lockfile, docs, DNS records).

---

## Remediation status (v3.0.0, this branch)

All findings were remediated in commits `bf83b4c` (P0 + secret handling), `94197ba` (supply chain + synth guardrails), `3eedae3` (redirect/cookie/UX hardening), `e1115d4` (OIDC protocol hardening + CSP), and the docs/DNS commit following them. Breaking changes are documented in README "Breaking changes in v3".

| Finding | Status | Notes |
|---|---|---|
| P0-1 secret in Lambda package | **Fixed** | `cognito_client_secret_arn` (Secrets Manager, cold-start fetch + cache); rotate the old secret after upgrading |
| P0-2 alarms notify no one | **Fixed** | SNS topic (created or imported) with alarm + OK actions on both alarms |
| P1-1 unpinned bundling deps | **Fixed** | Hash-pinned `auth/requirements.txt` compiled from `requirements.in`, installed with `--require-hashes` |
| P1-2 mutable CI refs / `secrets: inherit` | **Fixed** | All workflows/actions SHA-pinned; explicit `AWS_ROLE_ARN` pass in pr.yml; backup.yml relies on its Environment secret (verify the `backup` Environment has `AWS_ROLE_ARN` configured — one-time settings check) |
| P1-3 no us-east-1 validation | **Fixed** | Synth-time error (resolved region) or warning (env-agnostic) |
| P1-4 edge log retention | **Mitigated + documented** | Per-request logging downgraded to DEBUG; per-region replica log groups are outside CDK's control — README caveat; full fix needs org-level automation |
| P1-5 site bucket DESTROY default | **Fixed** | Defaults to RETAIN; DESTROY is opt-in via `removal_policy` |
| P2-1 no PKCE/nonce | **Fixed** | S256 PKCE + nonce minted at login, verifier passed to exchange, nonce claim enforced on the validated id_token |
| P2-2 backslash open redirect | **Fixed** | `_safe_redirect_path` rejects `\\` and control chars |
| P2-3 refresh rotation dropped | **Fixed** | Rotated refresh token persisted as a cookie |
| P2-4 JWKS force-refresh amplification | **Fixed** | Forced refresh rate-limited to one per 30s per container |
| P2-5 bucket-name overflow | **Fixed** | Synth-time validation with worst-case token lengths; `bucket_name_prefix` escape hatch |
| P2-6 no CloudFront access logs | **Documented** | Deliberate Free-plan tradeoff; forensic limitation spelled out in README |
| P2-7 no CSP | **Fixed** | Optional `csp` param builds a custom ResponseHeadersPolicy mirroring the managed one |
| P2-8 deep link lost | **Fixed** | `__Host-auth_redirect` cookie round-trips the validated path+query |
| P2-9 no lockfile | **Fixed** | `requirements-lock.txt` (pip-compile) drives CI installs |
| P2-10 secret-bearing tempdir | **Fixed** | Staging dir removed after asset staging (and no longer contains the secret) |
| P2-11 sign-out doesn't revoke | **Fixed** | Best-effort `/oauth2/revoke` before the logout redirect |
| P3-1 doc drift | **Fixed** | README/CLAUDE.md reconciled (bucket count, retention, version pin, full param table) |
| P3-2 no DNS records / www SAN | **Fixed (DNS) / documented (SAN)** | `create_dns_records` creates apex+www A/AAAA aliases; imported-cert SAN coverage can't be checked at credential-free synth — documented |
| P3-3 `__Host-` prefix | **Fixed** | All auth cookies prefixed; legacy names actively cleared |
| P3-4 4xx metric semantics | **Fixed** | Alarm description carries the SPA-rewrite caveat |
| P3-5 construct-ID collision | **Fixed** | IDs use index + full-ARN hash |
| P3-6 OAuth error loop | **Fixed** | Static 403 page; IdP values logged, never reflected |
| P3-7 redirect test gap | **Fixed** | Backslash/control-char cases added to `test_safe_redirect_path` |
