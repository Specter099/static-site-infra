# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Reusable AWS CDK (Python) construct (`StaticSiteStack`) for hosting static sites on AWS. Provisions S3 + CloudFront with OAC, ACM certificates, CloudWatch dashboards/alarms, optional Cognito authentication via Lambda@Edge, and optional WAF integration. Packaged as an installable Python library (`specter-static-site`).

## Setup

```
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

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

- **S3 buckets**: Three buckets per site — site assets, S3 access logs, CloudFront logs. Names follow `{domain-slug}-{purpose}-{account}-{region}-an` convention.
- **CloudFront**: OAC-based origin access, HTTPS redirect, security response headers. 403/404 errors rewrite to `/index.html` (SPA support).
- **Cognito auth** (optional): All four Cognito params must be provided together or omitted. Lambda@Edge handles OIDC authorization code flow with CSRF state cookies, JWT validation, and token refresh.
- **CloudWatch**: Dashboard with error rate and request graphs. Alarms on 5xx (>5%) and 4xx (>10%) error rates.
- **cdk-nag**: Suppressions are documented inline for CDK-managed resources (BucketDeployment Lambda, logging circularity).

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

## Testing

Tests use pytest and validate CDK synth succeeds for each parameter combination. No cloud resources are created.

```
.venv/bin/pytest tests/ -v
```

## Code Style

- Linter: ruff (default config)
- Python: >=3.11
