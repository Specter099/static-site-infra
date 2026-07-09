# static-site-infra

Reusable AWS CDK construct for hosting static websites on S3 + CloudFront.

## What it provisions

- S3 bucket for site assets (versioned, access-logged, retained on stack delete by default)
- S3 bucket for S3 server access logs (180-day retention)
- CloudFront distribution (HTTPS-only, SPA routing for 404s, security headers, optional CSP)
- ACM certificate (imported or DNS-validated via Route 53)
- Optional Route 53 alias records for apex + `www`
- Optional Cognito authentication at the edge (Lambda@Edge OIDC with PKCE, nonce, and refresh-token rotation/revocation)
- CloudWatch alarms (5xx >5%, 4xx >10%) wired to an SNS topic, plus a dashboard
- Optional WAFv2 Web ACL attachment

## Usage

### Install

In your `infra/requirements.txt`:

```
git+https://github.com/Specter099/static-site-infra.git@v3.0.0
```

### Example `app.py`

```python
#!/usr/bin/env python3
import os
import aws_cdk as cdk
from cdk_nag import AwsSolutionsChecks
from specter_static_site import StaticSiteStack

app = cdk.App()

StaticSiteStack(
    app,
    "MyStack",
    domain_name=app.node.try_get_context("domainName"),
    hosted_zone_id=app.node.try_get_context("hostedZoneId"),
    certificate_arn=app.node.try_get_context("certificateArn"),
    web_acl_id=app.node.try_get_context("webAclId"),   # optional
    dist_path=os.path.join(os.path.dirname(__file__), "..", "dist"),
    dashboard_name="MySiteDashboard",                   # optional, defaults to domain_name
    alarm_email="ops@example.com",                      # optional, see Alarms
    termination_protection=True,
    env=cdk.Environment(
        account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
        region="us-east-1",
    ),
)

cdk.Tags.of(app).add("Project", "MySite")
cdk.Tags.of(app).add("Environment", "Production")
cdk.Tags.of(app).add("ManagedBy", "CDK")
cdk.Aspects.of(app).add(AwsSolutionsChecks())

app.synth()
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `domain_name` | `str` | Yes | Apex domain (e.g. `example.com`) |
| `dist_path` | `str` | Yes | Absolute path to built frontend `dist/` directory |
| `hosted_zone_id` | `str` | No* | Route 53 hosted zone ID for cert DNS validation |
| `certificate_arn` | `str` | No* | ARN of existing ACM certificate to import (must be in us-east-1 and cover `www.{domain}` too) |
| `web_acl_id` | `str` | No | WAFv2 Web ACL ARN to attach to CloudFront |
| `dashboard_name` | `str` | No | CloudWatch dashboard name (defaults to `domain_name`) |
| `alarm_topic_arn` | `str` | No | Existing SNS topic for alarm notifications (otherwise one is created) |
| `alarm_email` | `str` | No | Email subscription added to the created alarm topic |
| `removal_policy` | `RemovalPolicy` | No | Site bucket policy; defaults to `RETAIN`. Pass `DESTROY` for dev/test stacks |
| `bucket_name_prefix` | `str` | No | Overrides the domain slug in bucket names (S3 caps names at 63 chars) |
| `csp` | `str` | No | `Content-Security-Policy` value; builds a custom response headers policy |
| `create_dns_records` | `bool` | No | Create Route 53 alias records (apex + `www`) pointing at the distribution; requires `hosted_zone_id` |
| `cognito_user_pool_id` | `str` | No** | Cognito user pool for edge authentication |
| `cognito_client_id` | `str` | No** | Cognito app client ID |
| `cognito_client_secret_arn` | `str` | No** | **Full** Secrets Manager ARN (us-east-1) holding the app client secret |
| `cognito_domain` | `str` | No** | Cognito hosted UI domain |
| `cognito_region` | `str` | No | Override region derived from the user pool ID |
| `skip_deployment` | `bool` | No | Skip the S3 asset deployment (CI/CD-managed deploys) |
| `exclude_patterns` | `list[str]` | No | Glob patterns excluded from the asset deployment |
| `deployment_memory_limit` | `int` | No | Memory (MB) for the BucketDeployment Lambda (default 512) |
| `deploy_role_arns` | `list[str]` | No | IAM role ARNs granted read/write on the site bucket |

\* One of `hosted_zone_id` or `certificate_arn` is required.
\*\* All four `cognito_*` parameters (except `cognito_region`) must be provided together to enable authentication.

### Cognito authentication setup

The app client secret lives in **Secrets Manager in us-east-1** — store the
secret string there and pass its full ARN (including the random suffix) as
`cognito_client_secret_arn`. The Lambda@Edge handler fetches it at cold start;
it is never baked into the Lambda package. The construct grants the function
`secretsmanager:GetSecretValue` on exactly that ARN.

Sign-out revokes the refresh token via Cognito's `/oauth2/revoke`, which
requires **token revocation** enabled on the app client (the default).

### Alarms

Both error-rate alarms notify an SNS topic. Pass `alarm_topic_arn` to use an
existing topic, `alarm_email` to create a topic with an email subscription, or
neither — a bare topic is still created (its ARN is a stack output) so you can
subscribe later without a redeploy. Note the 4xx alarm mostly measures 403s:
404s are rewritten to `200 /index.html` for SPA routing.

## Operational caveats

- **us-east-1 required** when auth is enabled or a certificate is created;
  the stack fails at synth otherwise (Lambda@Edge / CloudFront-cert constraint).
- **No CloudFront access logs**: standard logging is incompatible with the
  CloudFront Free pricing plan. S3 server access logs cover origin fetches
  (cache misses) only — there is no edge-level request log for forensics or
  WAF tuning. Revisit if the distribution moves off the Free plan.
- **Lambda@Edge log retention**: the stack sets two-week retention on the
  us-east-1 log group, but edge replicas write to auto-created
  `/aws/lambda/<region>.<function>` groups in each execution region with **no
  retention policy**. The handler logs at WARNING+ in routine operation to
  keep those small; managing their retention requires out-of-band automation.
- **Retained buckets**: with the default `removal_policy`, deleting the stack
  orphans the site bucket; its fixed name must be freed manually before the
  same stack can be recreated.
- **Upgrading to v3**: see below.

## Breaking changes in v3

1. **`cognito_client_secret` → `cognito_client_secret_arn`.** Store the secret
   in Secrets Manager (us-east-1) and pass the full ARN. Rotate the old secret
   value after migrating — pre-v3 Lambda packages and CDK asset buckets
   contain it in plaintext.
2. **Site bucket defaults to `RemovalPolicy.RETAIN`.** Pass
   `removal_policy=RemovalPolicy.DESTROY` to keep the old dev/test behavior.
3. **Auth cookies renamed** to `__Host-`-prefixed names. Users sign in again
   once after the upgrade; legacy cookies are cleared automatically.
4. **Synth-time validation added** for region (us-east-1, see above) and
   bucket-name length (63-char S3 limit; use `bucket_name_prefix`).
5. **`deploy_role_arns` construct IDs changed** (full-ARN hash). The generated
   IAM policies are recreated on upgrade — a brief permission gap for those
   roles; avoid running deploys through them concurrently with the upgrade.

## Versioning

```bash
# Release a new version
git tag v3.0.0 && git push origin v3.0.0

# Update a site to use the new version
# In infra/requirements.txt: change @v2.x.y → @v3.0.0
```
