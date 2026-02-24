import os
import tempfile
import aws_cdk as cdk
import pytest
from specter_static_site import StaticSiteStack


def make_dist(tmp_path):
    """Create a minimal dist directory with an index.html."""
    (tmp_path / "index.html").write_text("<html></html>")
    return str(tmp_path)


def test_synth_with_certificate_arn(tmp_path):
    dist = make_dist(tmp_path)
    app = cdk.App()
    stack = StaticSiteStack(
        app,
        "TestStack",
        domain_name="example.com",
        dist_path=dist,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
    )
    assembly = app.synth()
    assert assembly is not None


def test_synth_with_hosted_zone(tmp_path):
    dist = make_dist(tmp_path)
    app = cdk.App()
    stack = StaticSiteStack(
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
    dist = make_dist(tmp_path)
    app = cdk.App()
    stack = StaticSiteStack(
        app,
        "TestStack",
        domain_name="example.com",
        dist_path=dist,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
        web_acl_id="arn:aws:wafv2:us-east-1:123456789012:global/webacl/test/abc123",
    )
    assembly = app.synth()
    assert assembly is not None


def test_synth_with_dashboard_name(tmp_path):
    dist = make_dist(tmp_path)
    app = cdk.App()
    stack = StaticSiteStack(
        app,
        "TestStack",
        domain_name="example.com",
        dist_path=dist,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
        dashboard_name="MyCustomDashboard",
    )
    assembly = app.synth()
    assert assembly is not None


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
