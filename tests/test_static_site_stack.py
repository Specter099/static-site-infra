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


def test_deploy_role_arns_same_name_different_accounts(tmp_path):
    """Same role name in two accounts must not collide on construct IDs."""
    _, assembly = _synth(
        tmp_path,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
        deploy_role_arns=[
            "arn:aws:iam::111111111111:role/deploy",
            "arn:aws:iam::222222222222:role/deploy",
        ],
    )
    assert assembly is not None


def test_non_us_east_1_with_cert_creation_raises(tmp_path):
    app = cdk.App()
    with pytest.raises(ValueError, match="us-east-1"):
        StaticSiteStack(
            app,
            "TestStack",
            domain_name="example.com",
            dist_path=make_dist(tmp_path),
            hosted_zone_id="Z1234567890",
            env=cdk.Environment(account="123456789012", region="eu-west-1"),
        )


def test_non_us_east_1_with_cognito_raises(tmp_path):
    app = cdk.App()
    with pytest.raises(ValueError, match="us-east-1"):
        StaticSiteStack(
            app,
            "TestStack",
            domain_name="example.com",
            dist_path=make_dist(tmp_path),
            certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
            cognito_user_pool_id="us-east-1_TestPool",
            cognito_client_id="c",
            cognito_client_secret_arn=_TEST_SECRET_ARN,
            cognito_domain="d.auth.us-east-1.amazoncognito.com",
            env=cdk.Environment(account="123456789012", region="eu-west-1"),
        )


def test_env_agnostic_cert_creation_warns_not_raises(tmp_path):
    stack, _ = _synth(tmp_path, hosted_zone_id="Z1234567890")
    assertions.Annotations.from_stack(stack).has_warning(
        "*",
        assertions.Match.string_like_regexp(".*us-east-1.*"),
    )


def test_bucket_name_overflow_raises(tmp_path):
    app = cdk.App()
    long_domain = "a-very-long-marketing-site.example-company.com"
    with pytest.raises(ValueError, match="bucket_name_prefix"):
        StaticSiteStack(
            app,
            "TestStack",
            domain_name=long_domain,
            dist_path=make_dist(tmp_path),
            certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
        )


def test_bucket_name_prefix_escape_hatch(tmp_path):
    stack, _ = _synth(
        tmp_path,
        domain_name="a-very-long-marketing-site.example-company.com",
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
        bucket_name_prefix="mktg-site",
        env=cdk.Environment(account="123456789012", region="us-east-1"),
    )
    template = assertions.Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::S3::Bucket",
        {"BucketName": "mktg-site-site-123456789012-us-east-1-an"},
    )


def test_site_bucket_retained_by_default(tmp_path):
    stack, _ = _synth(
        tmp_path,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
    )
    template = assertions.Template.from_stack(stack)
    for bucket in template.find_resources("AWS::S3::Bucket").values():
        assert bucket["DeletionPolicy"] == "Retain"
    # No auto-delete custom resource when the bucket is retained.
    assert not template.find_resources("Custom::S3AutoDeleteObjects")


def test_csp_param_creates_custom_headers_policy(tmp_path):
    stack, _ = _synth(
        tmp_path,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
        csp="default-src 'self'",
    )
    template = assertions.Template.from_stack(stack)
    template.resource_count_is("AWS::CloudFront::ResponseHeadersPolicy", 1)
    template.has_resource_properties(
        "AWS::CloudFront::ResponseHeadersPolicy",
        assertions.Match.object_like(
            {
                "ResponseHeadersPolicyConfig": assertions.Match.object_like(
                    {
                        "SecurityHeadersConfig": assertions.Match.object_like(
                            {
                                "ContentSecurityPolicy": {
                                    "ContentSecurityPolicy": "default-src 'self'",
                                    "Override": True,
                                },
                                "StrictTransportSecurity": assertions.Match.object_like(
                                    {"AccessControlMaxAgeSec": 31536000}
                                ),
                            }
                        )
                    }
                )
            }
        ),
    )


def test_no_csp_uses_managed_security_headers_policy(tmp_path):
    stack, _ = _synth(
        tmp_path,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
    )
    template = assertions.Template.from_stack(stack)
    template.resource_count_is("AWS::CloudFront::ResponseHeadersPolicy", 0)


def test_site_bucket_destroy_opt_in(tmp_path):
    stack, _ = _synth(
        tmp_path,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
        removal_policy=cdk.RemovalPolicy.DESTROY,
    )
    template = assertions.Template.from_stack(stack)
    assert template.find_resources("Custom::S3AutoDeleteObjects")


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


_TEST_SECRET_ARN = (
    "arn:aws:secretsmanager:us-east-1:123456789012:secret:cognito-client-secret-AbCdEf"
)


@pytest.mark.skipif(
    not _HAS_DOCKER, reason="Lambda@Edge bundling requires a local Docker daemon"
)
def test_synth_with_cognito_auth(tmp_path):
    stack, assembly = _synth(
        tmp_path,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
        cognito_user_pool_id="us-east-1_TestPool",
        cognito_client_id="testclientid",
        cognito_client_secret_arn=_TEST_SECRET_ARN,
        cognito_domain="myapp.auth.us-east-1.amazoncognito.com",
    )
    assert assembly is not None
    # The edge function role must be able to read the client secret.
    template = assertions.Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::IAM::Policy",
        assertions.Match.object_like(
            {
                "PolicyDocument": assertions.Match.object_like(
                    {
                        "Statement": assertions.Match.array_with(
                            [
                                assertions.Match.object_like(
                                    {
                                        "Action": assertions.Match.array_with(
                                            ["secretsmanager:GetSecretValue"]
                                        ),
                                        "Resource": _TEST_SECRET_ARN,
                                    }
                                )
                            ]
                        )
                    }
                )
            }
        ),
    )


def test_invalid_cognito_secret_arn_raises(tmp_path):
    app = cdk.App()
    with pytest.raises(ValueError, match="Secrets Manager ARN"):
        StaticSiteStack(
            app,
            "TestStack",
            domain_name="example.com",
            dist_path=make_dist(tmp_path),
            certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
            cognito_user_pool_id="us-east-1_TestPool",
            cognito_client_id="testclientid",
            cognito_client_secret_arn="testclientsecret",  # raw secret, not an ARN
            cognito_domain="myapp.auth.us-east-1.amazoncognito.com",
        )


def test_alarms_have_sns_actions_default_topic(tmp_path):
    stack, _ = _synth(
        tmp_path,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
    )
    template = assertions.Template.from_stack(stack)
    template.resource_count_is("AWS::SNS::Topic", 1)
    alarms = template.find_resources("AWS::CloudWatch::Alarm")
    assert len(alarms) == 2
    for alarm in alarms.values():
        props = alarm["Properties"]
        assert props.get("AlarmActions"), "alarm must have an alarm action"
        assert props.get("OKActions"), "alarm must have an OK action"


def test_alarm_email_creates_subscription(tmp_path):
    stack, _ = _synth(
        tmp_path,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
        alarm_email="ops@example.com",
    )
    template = assertions.Template.from_stack(stack)
    template.has_resource_properties(
        "AWS::SNS::Subscription",
        {"Protocol": "email", "Endpoint": "ops@example.com"},
    )


def test_alarm_topic_arn_imports_existing_topic(tmp_path):
    topic_arn = "arn:aws:sns:us-east-1:123456789012:existing-alarms"
    stack, _ = _synth(
        tmp_path,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
        alarm_topic_arn=topic_arn,
    )
    template = assertions.Template.from_stack(stack)
    # Imported, not created.
    template.resource_count_is("AWS::SNS::Topic", 0)
    for alarm in template.find_resources("AWS::CloudWatch::Alarm").values():
        assert alarm["Properties"]["AlarmActions"] == [topic_arn]


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
            cognito_client_secret_arn=_TEST_SECRET_ARN,
            cognito_domain="d.auth.us-east-1.amazoncognito.com",
        )
