# static-site-infra

Reusable AWS CDK construct for hosting static websites on S3 + CloudFront.

## What it provisions

- S3 bucket for site assets (versioned, access-logged)
- S3 buckets for S3 and CloudFront access logs (180-day retention)
- CloudFront distribution (HTTPS-only, SPA routing, security headers)
- ACM certificate (imported or DNS-validated via Route53)
- Route53 A + AAAA records for apex and `www` (optional)
- CloudWatch alarms: 5xx >5%, 4xx >10%
- CloudWatch dashboard
- Optional WAFv2 Web ACL attachment

## Usage

### Install

In your `infra/requirements.txt`:

```
git+https://github.com/Specter099/static-site-infra.git@v1.0.0
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
| `hosted_zone_id` | `str` | No* | Route53 hosted zone ID for DNS records + cert validation |
| `certificate_arn` | `str` | No* | ARN of existing ACM certificate to import |
| `web_acl_id` | `str` | No | WAFv2 Web ACL ARN to attach to CloudFront |
| `dashboard_name` | `str` | No | CloudWatch dashboard name (defaults to `domain_name`) |

\* One of `hosted_zone_id` or `certificate_arn` is required.

## Versioning

```bash
# Release a new version
git tag v1.1.0 && git push origin v1.1.0

# Update a site to use the new version
# In infra/requirements.txt: change @v1.0.0 → @v1.1.0
```
