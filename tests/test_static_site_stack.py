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
    StaticSiteStack(
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
    dist = make_dist(tmp_path)
    app = cdk.App()
    StaticSiteStack(
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
    StaticSiteStack(
        app,
        "TestStack",
        domain_name="example.com",
        dist_path=dist,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
        dashboard_name="MyCustomDashboard",
    )
    assembly = app.synth()
    assert assembly is not None


def test_synth_with_deploy_role_arns(tmp_path):
    dist = make_dist(tmp_path)
    app = cdk.App()
    StaticSiteStack(
        app,
        "TestStack",
        domain_name="example.com",
        dist_path=dist,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
        deploy_role_arns=["arn:aws:iam::123456789012:role/github-actions-role"],
    )
    assembly = app.synth()
    assert assembly is not None


def test_synth_with_cognito_auth(tmp_path):
    dist = make_dist(tmp_path)
    app = cdk.App()
    StaticSiteStack(
        app,
        "TestStack",
        domain_name="example.com",
        dist_path=dist,
        certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
        cognito_user_pool_id="us-east-1_TestPool",
        cognito_client_id="testclientid",
        cognito_client_secret="testclientsecret",
        cognito_domain="myapp.auth.us-east-1.amazoncognito.com",
    )
    assembly = app.synth()
    assert assembly is not None


def test_partial_cognito_params_raises(tmp_path):
    dist = make_dist(tmp_path)
    app = cdk.App()
    with pytest.raises(ValueError, match="All Cognito parameters"):
        StaticSiteStack(
            app,
            "TestStack",
            domain_name="example.com",
            dist_path=dist,
            certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/test-cert",
            cognito_user_pool_id="us-east-1_TestPool",
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
