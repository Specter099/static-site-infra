# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Reusable AWS CDK (Python) construct for static site hosting on AWS. Deploys an S3-backed CloudFront distribution with optional Cognito authentication (Lambda@Edge), Route 53 DNS, ACM certificates, CloudWatch monitoring, and S3 access logging. Designed to be consumed by other CDK apps as a construct library.

## Setup

```
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## Common Commands

```
# Synthesize the test stack
.venv/bin/cdk synth

# Diff before deploy
.venv/bin/cdk diff StaticSiteStack

# Deploy
.venv/bin/cdk deploy StaticSiteStack

# Run tests
.venv/bin/pytest tests/

# Lint
.venv/bin/ruff check .
```

## Directory Structure

```
app.py                                    # CDK app entry point (CI synth test harness)
specter_static_site/
  __init__.py                             # Package exports (StaticSiteStack)
  static_site_stack.py                    # Main construct: S3, CloudFront, Route 53, monitoring
  auth/
    handler.py                            # Lambda@Edge viewer-request handler for Cognito auth
    cognito_client.py                     # Cognito OAuth2 token exchange client
    jwt_validator.py                      # JWT validation for Cognito tokens
    requirements.txt                      # Lambda@Edge dependencies
tests/
  test_static_site_stack.py               # Stack tests
```

## Architecture

Single reusable CDK stack (`StaticSiteStack`) with configurable parameters:

- **S3** -- Site bucket (versioned, encrypted, auto-delete), S3 access logs bucket, and CloudFront logs bucket. Bucket names follow the pattern `{domain-slug}-{purpose}-{account}-{region}-an`.
- **CloudFront** -- Distribution with OAC for S3 origin, HTTPS redirect, security headers, custom error responses (403/404 to index.html for SPA routing). Optional WAF integration via `web_acl_id`.
- **Authentication** -- Optional Cognito-based auth via Lambda@Edge (viewer-request). Requires all four Cognito parameters together: `cognito_user_pool_id`, `cognito_client_id`, `cognito_client_secret`, `cognito_domain`. Handles OAuth2 code flow with JWT validation.
- **DNS** -- Optional Route 53 hosted zone for automatic DNS records and ACM certificate creation. Alternatively accepts a pre-existing `certificate_arn`.
- **Monitoring** -- CloudWatch dashboard with error rate and request graphs. Alarms for 4xx (>10%) and 5xx (>5%) error rates.
- **Deployment** -- `BucketDeployment` from a local `dist_path` with CloudFront invalidation. Skippable via `skip_deployment=True` for CI/CD-managed deployments.
- **Compliance** -- cdk-nag suppressions for CDK-managed construct internals.

## Construct Parameters

| Parameter | Required | Description |
|---|---|---|
| `domain_name` | Yes | Primary domain name |
| `dist_path` | Yes | Path to static site build output |
| `certificate_arn` | Conditional | ACM cert ARN (required if no `hosted_zone_id`) |
| `hosted_zone_id` | Conditional | Route 53 zone (required if no `certificate_arn`) |
| `cognito_*` | No | Four Cognito params for auth (all or none) |
| `web_acl_id` | No | WAF Web ACL ID |
| `skip_deployment` | No | Skip S3 deployment (default: false) |
| `deploy_role_arns` | No | External roles granted S3 read/write |

## Code Style

Ruff for linting. cdk-nag runs at synth time.
