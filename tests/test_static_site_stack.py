import shutil
import subprocess

import aws_cdk as cdk
import pytest
from aws_cdk import assertions

from specter_static_site import StaticSiteStack


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(
            ["docker", "info"],
            check=True,
            capture_output=True,
            timeout=5,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return False
    return True


_HAS_DOCKER = _docker_available()


def make_dist(tmp_path):
    """Create a minimal dist directory with an index.html."""
    (tmp_path / "index.html").write_text("<html></html>")
    return str(tmp_path)


def _synth(tmp_path, **kwargs):
    app = cdk.App()
    stack = StaticSiteStack(
        app,
        "TestStack",
        domain_name=kwargs.pop("domain_name", "example.com"),
        dist_path=make_dist(tmp_path),
        **kwargs,
    )
    return stack, app.synth()


def test_synth_with_certificate_arn(tmp_path):
    stack, _ = _synth(
        tmp_path,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
    )
    template = assertions.Template.from_stack(stack)

    # Site bucket: SSE, block public, versioning.
    template.has_resource_properties(
        "AWS::S3::Bucket",
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True,
            },
            "VersioningConfiguration": {"Status": "Enabled"},
        },
    )

    # CloudFront distribution: HTTPS redirect, only 404 rewritten, OAC origin.
    template.has_resource_properties(
        "AWS::CloudFront::Distribution",
        assertions.Match.object_like(
            {
                "DistributionConfig": assertions.Match.object_like(
                    {
                        "CustomErrorResponses": [
                            {
                                "ErrorCode": 404,
                                "ResponseCode": 200,
                                "ResponsePagePath": "/index.html",
                            }
                        ],
                        "DefaultCacheBehavior": assertions.Match.object_like(
                            {"ViewerProtocolPolicy": "redirect-to-https"}
                        ),
                    }
                )
            }
        ),
    )


def test_synth_with_hosted_zone(tmp_path):
    _, assembly = _synth(
        tmp_path,
        hosted_zone_id="Z1234567890",
        env=cdk.Environment(account="123456789012", region="us-east-1"),
    )
    assert assembly is not None


def test_synth_with_web_acl(tmp_path):
    stack, _ = _synth(
        tmp_path,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
        web_acl_id="arn:aws:wafv2:us-east-1:123456789012:global/webacl/test/abc123",
    )
    template = assertions.Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::CloudFront::Distribution",
        assertions.Match.object_like(
            {
                "DistributionConfig": assertions.Match.object_like(
                    {
                        "WebACLId": "arn:aws:wafv2:us-east-1:123456789012:"
                        "global/webacl/test/abc123"
                    }
                )
            }
        ),
    )


def test_synth_with_dashboard_name(tmp_path):
    _, assembly = _synth(
        tmp_path,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
        dashboard_name="MyCustomDashboard",
    )
    assert assembly is not None


def test_synth_with_deploy_role_arns(tmp_path):
    _, assembly = _synth(
        tmp_path,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
        deploy_role_arns=["arn:aws:iam::123456789012:role/github-actions-role"],
    )
    assert assembly is not None


def test_synth_alarms_present(tmp_path):
    stack, _ = _synth(
        tmp_path,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
    )
    template = assertions.Template.from_stack(stack)
    template.resource_count_is("AWS::CloudWatch::Alarm", 2)
    template.has_resource_properties(
        "AWS::CloudWatch::Alarm",
        {"MetricName": "5xxErrorRate", "Threshold": 5},
    )
    template.has_resource_properties(
        "AWS::CloudWatch::Alarm",
        {"MetricName": "4xxErrorRate", "Threshold": 10},
    )


def test_synth_no_unused_cloudfront_logs_bucket(tmp_path):
    stack, _ = _synth(
        tmp_path,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
    )
    template = assertions.Template.from_stack(stack)
    # S3 access logs bucket only — no separate (unused) CF logs bucket.
    buckets = template.find_resources("AWS::S3::Bucket")
    assert len(buckets) == 2  # site + s3 access logs


def test_synth_error_responses_do_not_mask_403(tmp_path):
    stack, _ = _synth(
        tmp_path,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
    )
    template = assertions.Template.from_stack(stack)
    distributions = template.find_resources("AWS::CloudFront::Distribution")
    (dist,) = distributions.values()
    error_responses = dist["Properties"]["DistributionConfig"].get(
        "CustomErrorResponses", []
    )
    codes = {e["ErrorCode"] for e in error_responses}
    assert 403 not in codes, "403 should surface as real 403, not be rewritten"
    assert 404 in codes


@pytest.mark.skipif(
    not _HAS_DOCKER, reason="Lambda@Edge bundling requires a local Docker daemon"
)
def test_synth_with_cognito_auth(tmp_path):
    _, assembly = _synth(
        tmp_path,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
        cognito_user_pool_id="us-east-1_TestPool",
        cognito_client_id="testclientid",
        cognito_client_secret="testclientsecret",
        cognito_domain="myapp.auth.us-east-1.amazoncognito.com",
    )
    assert assembly is not None


def test_synth_with_skip_deployment(tmp_path):
    _, assembly = _synth(
        tmp_path,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
        skip_deployment=True,
    )
    assert assembly is not None


def test_partial_cognito_params_raises(tmp_path):
    app = cdk.App()
    with pytest.raises(ValueError, match="All Cognito parameters"):
        StaticSiteStack(
            app,
            "TestStack",
            domain_name="example.com",
            dist_path=make_dist(tmp_path),
            certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
            cognito_user_pool_id="us-east-1_TestPool",
        )


def test_raises_without_cert_or_zone(tmp_path):
    app = cdk.App()
    with pytest.raises(ValueError, match="certificate_arn or hosted_zone_id"):
        StaticSiteStack(
            app,
            "TestStack",
            domain_name="example.com",
            dist_path=make_dist(tmp_path),
        )


def test_malformed_cognito_user_pool_id_requires_explicit_region(tmp_path):
    app = cdk.App()
    with pytest.raises(ValueError, match="cognito_region"):
        StaticSiteStack(
            app,
            "TestStack",
            domain_name="example.com",
            dist_path=make_dist(tmp_path),
            certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
            cognito_user_pool_id="not-a-valid-pool-id",
            cognito_client_id="c",
            cognito_client_secret="s",
            cognito_domain="d.auth.us-east-1.amazoncognito.com",
        )
