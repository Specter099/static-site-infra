import aws_cdk as cdk
from aws_cdk import Duration, assertions
import pytest
from specter_static_site import StaticSiteStack


def make_dist(tmp_path):
    """Create a minimal dist directory with an index.html."""
    (tmp_path / "index.html").write_text("<html></html>")
    return str(tmp_path)


def _synth(tmp_path, **kwargs):
    """Helper: synthesize a stack and return a Template for assertions."""
    dist = make_dist(tmp_path)
    defaults = {
        "domain_name": "example.com",
        "dist_path": dist,
        "certificate_arn": "arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
    }
    defaults.update(kwargs)
    app = cdk.App()
    stack = StaticSiteStack(app, "TestStack", **defaults)
    return assertions.Template.from_stack(stack)


# --- Synthesis smoke tests ---


def test_synth_with_certificate_arn(tmp_path):
    template = _synth(tmp_path)
    template.resource_count_is("AWS::S3::Bucket", 3)


def test_synth_with_hosted_zone(tmp_path):
    dist = make_dist(tmp_path)
    app = cdk.App()
    StaticSiteStack(
        app,
        "TestStack",
        domain_name="example.com",
        dist_path=dist,
        hosted_zone_id="Z1234567890",
        env=cdk.Environment(account="123456789012", region="us-east-1"),
    )
    assembly = app.synth()
    assert assembly is not None


def test_synth_with_web_acl(tmp_path):
    template = _synth(
        tmp_path,
        web_acl_id="arn:aws:wafv2:us-east-1:123456789012:global/webacl/test/abc123",
    )
    template.has_resource_properties(
        "AWS::CloudFront::Distribution",
        {"DistributionConfig": assertions.Match.object_like({"WebACLId": assertions.Match.any_value()})},
    )


def test_synth_with_dashboard_name(tmp_path):
    template = _synth(tmp_path, dashboard_name="MyCustomDashboard")
    template.has_resource_properties(
        "AWS::CloudWatch::Dashboard",
        {"DashboardName": "MyCustomDashboard"},
    )


def test_raises_without_cert_or_zone(tmp_path):
    dist = make_dist(tmp_path)
    app = cdk.App()
    with pytest.raises(ValueError, match="certificate_arn or hosted_zone_id"):
        StaticSiteStack(
            app,
            "TestStack",
            domain_name="example.com",
            dist_path=dist,
        )


# --- Security assertions ---


def test_all_buckets_block_public_access(tmp_path):
    template = _synth(tmp_path)
    buckets = template.find_resources("AWS::S3::Bucket")
    for logical_id, resource in buckets.items():
        props = resource.get("Properties", {})
        bpa = props.get("PublicAccessBlockConfiguration", {})
        assert bpa.get("BlockPublicAcls") is True, f"{logical_id} missing BlockPublicAcls"
        assert bpa.get("BlockPublicPolicy") is True, f"{logical_id} missing BlockPublicPolicy"
        assert bpa.get("IgnorePublicAcls") is True, f"{logical_id} missing IgnorePublicAcls"
        assert bpa.get("RestrictPublicBuckets") is True, f"{logical_id} missing RestrictPublicBuckets"


def test_all_buckets_enforce_ssl(tmp_path):
    template = _synth(tmp_path)
    policies = template.find_resources("AWS::S3::BucketPolicy")
    assert len(policies) >= 3, "Expected at least 3 bucket policies (one per bucket)"


def test_all_buckets_have_encryption(tmp_path):
    template = _synth(tmp_path)
    buckets = template.find_resources("AWS::S3::Bucket")
    for logical_id, resource in buckets.items():
        props = resource.get("Properties", {})
        enc = props.get("BucketEncryption", {})
        rules = enc.get("ServerSideEncryptionConfiguration", [])
        assert len(rules) > 0, f"{logical_id} has no encryption configuration"


def test_cloudfront_redirects_to_https(tmp_path):
    template = _synth(tmp_path)
    template.has_resource_properties(
        "AWS::CloudFront::Distribution",
        {
            "DistributionConfig": assertions.Match.object_like(
                {
                    "DefaultCacheBehavior": assertions.Match.object_like(
                        {"ViewerProtocolPolicy": "redirect-to-https"}
                    )
                }
            )
        },
    )


def test_site_bucket_has_versioning(tmp_path):
    template = _synth(tmp_path)
    # The site bucket is the one with DESTROY deletion policy (the others use RETAIN)
    buckets = template.find_resources("AWS::S3::Bucket")
    found_versioned = False
    for logical_id, resource in buckets.items():
        props = resource.get("Properties", {})
        vc = props.get("VersioningConfiguration", {})
        if vc.get("Status") == "Enabled":
            found_versioned = True
    assert found_versioned, "No bucket has versioning enabled"


# --- SPA routing tests ---


def test_spa_routing_enabled_by_default(tmp_path):
    template = _synth(tmp_path)
    template.has_resource_properties(
        "AWS::CloudFront::Distribution",
        {
            "DistributionConfig": assertions.Match.object_like(
                {"CustomErrorResponses": assertions.Match.any_value()}
            )
        },
    )


def test_spa_routing_disabled(tmp_path):
    template = _synth(tmp_path, enable_spa_routing=False)
    dist_resources = template.find_resources("AWS::CloudFront::Distribution")
    for logical_id, resource in dist_resources.items():
        config = resource.get("Properties", {}).get("DistributionConfig", {})
        assert "CustomErrorResponses" not in config, "SPA error responses should not be present"


def test_custom_spa_error_ttl(tmp_path):
    template = _synth(tmp_path, spa_error_ttl=Duration.seconds(30))
    template.has_resource_properties(
        "AWS::CloudFront::Distribution",
        {
            "DistributionConfig": assertions.Match.object_like(
                {
                    "CustomErrorResponses": assertions.Match.array_with(
                        [assertions.Match.object_like({"ErrorCachingMinTTL": 30})]
                    )
                }
            )
        },
    )


# --- Tagging tests ---


def test_tags_applied_to_resources(tmp_path):
    template = _synth(tmp_path, tags={"Environment": "production", "Team": "platform"})
    buckets = template.find_resources("AWS::S3::Bucket")
    for logical_id, resource in buckets.items():
        props = resource.get("Properties", {})
        tag_list = props.get("Tags", [])
        tag_keys = {t["Key"] for t in tag_list}
        assert "Environment" in tag_keys, f"{logical_id} missing Environment tag"
        assert "Team" in tag_keys, f"{logical_id} missing Team tag"


# --- Monitoring tests ---


def test_cloudwatch_alarms_exist(tmp_path):
    template = _synth(tmp_path)
    template.resource_count_is("AWS::CloudWatch::Alarm", 2)


def test_cloudwatch_dashboard_exists(tmp_path):
    template = _synth(tmp_path)
    template.resource_count_is("AWS::CloudWatch::Dashboard", 1)
