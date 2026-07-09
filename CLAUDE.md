# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Reusable AWS CDK (Python) construct (`StaticSiteStack`) for hosting static sites on AWS. Provisions S3 + CloudFront with OAC, ACM certificates, CloudWatch dashboards/alarms, optional Cognito authentication via Lambda@Edge, and optional WAF integration. Packaged as an installable Python library (`specter-static-site`).

## Setup

```
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-lock.txt && pip install -e . --no-deps
```

Dependency locking: `requirements-lock.txt` (CI/dev environment) and
`specter_static_site/auth/requirements.txt` (Lambda bundle, hash-pinned) are
`pip-compile` outputs — edit the corresponding `.in` file and recompile
(`pip-compile requirements-lock.in -o requirements-lock.txt`;
`pip-compile --generate-hashes specter_static_site/auth/requirements.in
--output-file specter_static_site/auth/requirements.txt`).

## Common Commands

```
# Synthesize (validate templates)
.venv/bin/cdk synth

# Diff before deploy
.venv/bin/cdk diff StaticSiteStack

# Deploy
.venv/bin/cdk deploy StaticSiteStack

# Run tests
.venv/bin/pytest tests/ -v

# Lint
.venv/bin/ruff check .

# Security audit
.venv/bin/pip-audit
```

## Directory Structure

```
app.py                              # CDK app entry point (synth-only example)
specter_static_site/
  __init__.py                       # Exports StaticSiteStack
  static_site_stack.py              # Main construct: S3, CloudFront, ACM, CloudWatch
  auth/
    handler.py                      # Lambda@Edge viewer-request (Cognito OIDC flow)
    cognito_client.py               # Token exchange / refresh helpers
    jwt_validator.py                # JWT validation against Cognito JWKS
tests/
  test_static_site_stack.py         # Synth-level tests for all parameter combinations
```

## Architecture

- **S3 buckets**: Two buckets per site — site assets and S3 access logs (CloudFront standard logging is disabled; incompatible with the Free pricing plan). Names follow `{domain-slug}-{purpose}-{account}-{region}-an` convention, validated against S3's 63-char limit at synth.
- **CloudFront**: OAC-based origin access, HTTPS redirect, security response headers (optional CSP via custom policy). Only 404 rewrites to `/index.html` (SPA support); 403 surfaces as-is so auth/OAC failures stay visible.
- **Cognito auth** (optional): All four Cognito params must be provided together or omitted. Lambda@Edge handles the OIDC authorization code flow with PKCE + nonce, CSRF state cookies (`__Host-`-prefixed), JWT validation, refresh-token rotation, and sign-out revocation. The client secret is fetched from Secrets Manager (us-east-1) at cold start. Requires the stack in us-east-1 (validated at synth).
- **CloudWatch**: Dashboard with error rate and request graphs. Alarms on 5xx (>5%) and 4xx (>10%) error rates, wired to an SNS topic (alarm + OK actions).
- **cdk-nag**: Suppressions are documented inline for CDK-managed resources (BucketDeployment Lambda, logging circularity, SNS topic encryption).

## Breaking changes in v3

Do not reintroduce pre-v3 assumptions: `cognito_client_secret` is now
`cognito_client_secret_arn` (Secrets Manager ARN, never the raw secret); the
site bucket defaults to `RemovalPolicy.RETAIN` (DESTROY is opt-in); auth
cookies are `__Host-`-prefixed; `deploy_role_arns` construct IDs hash the full
ARN; synth validates us-east-1 and bucket-name length. See README "Breaking
changes in v3".

## Key Constructor Parameters

| Parameter | Purpose |
|---|---|
| `domain_name` | Site domain (used for bucket names, cert, CloudFront aliases) |
| `dist_path` | Path to static site build output |
| `certificate_arn` | Existing ACM cert ARN (or omit with `hosted_zone_id` to auto-create) |
| `hosted_zone_id` | Route 53 zone for DNS validation (required if no `certificate_arn`) |
| `web_acl_id` | WAF Web ACL ARN to attach to CloudFront |
| `cognito_*` | All four required together to enable Lambda@Edge auth. `cognito_client_secret_arn` is a full Secrets Manager ARN in us-east-1; the secret value is fetched at Lambda cold start, never baked into the package |
| `alarm_topic_arn` / `alarm_email` | Alarm notifications: import an existing SNS topic, or auto-create one (optionally with an email subscription) |
| `skip_deployment` | Skip S3 asset deployment (for CI/CD-managed deploys) |
| `deploy_role_arns` | IAM role ARNs granted read/write on the site bucket |
| `removal_policy` | Site bucket removal policy; defaults to RETAIN (pass DESTROY for dev/test) |
| `bucket_name_prefix` | Overrides the domain slug in bucket names (S3's 63-char limit) |
| `csp` | Content-Security-Policy value (builds a custom response headers policy) |
| `create_dns_records` | Create Route 53 alias records for apex + www (requires `hosted_zone_id`) |

## Testing

Tests use pytest and validate CDK synth succeeds for each parameter combination. No cloud resources are created.

```
.venv/bin/pytest tests/ -v
```

## Code Style

- Linter: ruff (default config)
- Python: >=3.11
