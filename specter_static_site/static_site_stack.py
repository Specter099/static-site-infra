import json
import re
import shutil
import tempfile
from pathlib import Path

from aws_cdk import (  # noqa: I001
    BundlingOptions,
    CfnOutput,
    Duration,
    RemovalPolicy,
    Stack,
    aws_certificatemanager as acm,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_cloudwatch as cloudwatch,
    aws_iam as iam,
    aws_lambda as _lambda,
    aws_logs as logs,
    aws_route53 as route53,
    aws_s3 as s3,
    aws_s3_deployment as s3deploy,
)
from cdk_nag import NagSuppressions
from constructs import Construct

_AUTH_DIR = Path(__file__).parent / "auth"
_COGNITO_POOL_ID_RE = re.compile(r"^(?P<region>[a-z]{2}-[a-z]+-\d)_[A-Za-z0-9]+$")


class StaticSiteStack(Stack):
    def __init__(  # noqa: PLR0913
        self,
        scope: Construct,
        construct_id: str,
        *,
        domain_name: str,
        dist_path: str,
        hosted_zone_id: str | None = None,
        certificate_arn: str | None = None,
        web_acl_id: str | None = None,
        dashboard_name: str | None = None,
        deploy_role_arns: list[str] | None = None,
        cognito_user_pool_id: str | None = None,
        cognito_client_id: str | None = None,
        cognito_client_secret: str | None = None,
        cognito_domain: str | None = None,
        cognito_region: str | None = None,
        skip_deployment: bool = False,
        exclude_patterns: list[str] | None = None,
        deployment_memory_limit: int = 512,
        **kwargs,
    ) -> None:
        super().__init__(
            scope,
            construct_id,
            description=f"Static site hosting for {domain_name}",
            **kwargs,
        )

        # Validate Cognito parameters: all or none.
        cognito_params = [
            cognito_user_pool_id,
            cognito_client_id,
            cognito_client_secret,
            cognito_domain,
        ]
        enable_auth = all(p is not None for p in cognito_params)
        if any(p is not None for p in cognito_params) and not enable_auth:
            raise ValueError(
                "All Cognito parameters (cognito_user_pool_id, cognito_client_id, "
                "cognito_client_secret, cognito_domain) must be provided together."
            )

        # CloudWatch dashboard names allow only alphanumerics, dashes, and underscores.
        resolved_dashboard_name = (dashboard_name or domain_name).replace(".", "-")

        # Sanitize domain name for use in bucket names (replace dots with hyphens).
        domain_slug = domain_name.replace(".", "-")

        # S3 access logs bucket
        s3_access_logs_bucket = s3.Bucket(
            self,
            "S3AccessLogsBucket",
            bucket_name=f"{domain_slug}-s3-logs-{self.account}-{self.region}-an",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.RETAIN,
            auto_delete_objects=False,
            lifecycle_rules=[
                s3.LifecycleRule(
                    expiration=Duration.days(180),
                ),
            ],
        )

        # S3 bucket for site assets
        site_bucket = s3.Bucket(
            self,
            "SiteBucket",
            bucket_name=f"{domain_slug}-site-{self.account}-{self.region}-an",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            server_access_logs_bucket=s3_access_logs_bucket,
            versioned=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    abort_incomplete_multipart_upload_after=Duration.days(1),
                    noncurrent_version_expiration=Duration.days(30),
                )
            ],
        )

        # Grant external roles read/write access to the site bucket (e.g. CI/CD pipelines).
        for role_arn in deploy_role_arns or []:
            role = iam.Role.from_role_arn(
                self,
                f"DeployRole{role_arn.split('/')[-1]}",
                role_arn,
            )
            site_bucket.grant_read_write(role)

        # Look up Route 53 hosted zone if provided
        hosted_zone = None
        if hosted_zone_id:
            hosted_zone = route53.HostedZone.from_hosted_zone_attributes(
                self,
                "Zone",
                hosted_zone_id=hosted_zone_id,
                zone_name=domain_name,
            )

        # Resolve SSL certificate
        if certificate_arn:
            certificate = acm.Certificate.from_certificate_arn(
                self, "Cert", certificate_arn
            )
        elif hosted_zone:
            certificate = acm.Certificate(
                self,
                "SiteCertificate",
                domain_name=domain_name,
                subject_alternative_names=[f"www.{domain_name}"],
                validation=acm.CertificateValidation.from_dns(hosted_zone),
            )
        else:
            raise ValueError(
                "You must provide either certificate_arn or hosted_zone_id "
                "so a certificate can be created."
            )

        # Lambda@Edge for Cognito authentication (optional).
        edge_lambdas = []
        if enable_auth:
            if cognito_region:
                region = cognito_region
            else:
                match = _COGNITO_POOL_ID_RE.match(cognito_user_pool_id or "")
                if not match:
                    raise ValueError(
                        "Could not derive region from cognito_user_pool_id "
                        f"{cognito_user_pool_id!r}; pass cognito_region explicitly."
                    )
                region = match.group("region")

            # Stage auth source + config.json into a tempdir so the client secret
            # is passed as a file (never interpolated into a shell command) and
            # the asset hash covers the config.
            staging = Path(tempfile.mkdtemp(prefix="static-site-auth-"))
            for src in _AUTH_DIR.glob("*.py"):
                shutil.copy2(src, staging / src.name)
            (staging / "config.json").write_text(
                json.dumps(
                    {
                        "user_pool_id": cognito_user_pool_id,
                        "client_id": cognito_client_id,
                        "client_secret": cognito_client_secret,
                        "cognito_domain": cognito_domain,
                        "redirect_uri": f"https://{domain_name}/_callback",
                        "callback_path": "/_callback",
                        "signout_path": "/_signout",
                        "region": region,
                    }
                )
            )

            auth_log_group = logs.LogGroup(
                self,
                "AuthEdgeFunctionLogs",
                retention=logs.RetentionDays.TWO_WEEKS,
                removal_policy=RemovalPolicy.DESTROY,
            )

            auth_function = _lambda.Function(
                self,
                "AuthEdgeFunction",
                runtime=_lambda.Runtime.PYTHON_3_12,
                handler="handler.handler",
                code=_lambda.Code.from_asset(
                    str(staging),
                    bundling=BundlingOptions(
                        image=_lambda.Runtime.PYTHON_3_12.bundling_image,
                        platform="linux/amd64",
                        command=[
                            "bash",
                            "-c",
                            "pip install PyJWT cryptography urllib3"
                            " --platform manylinux2014_x86_64"
                            " --implementation cp"
                            " --python-version 3.12"
                            " --only-binary=:all:"
                            " -t /asset-output"
                            " && cp /asset-input/*.py /asset-input/config.json"
                            " /asset-output/",
                        ],
                    ),
                ),
                timeout=Duration.seconds(5),
                memory_size=128,
                log_group=auth_log_group,
            )

            edge_lambdas.append(
                cloudfront.EdgeLambda(
                    function_version=auth_function.current_version,
                    event_type=cloudfront.LambdaEdgeEventType.VIEWER_REQUEST,
                )
            )

        # CloudFront distribution
        distribution = cloudfront.Distribution(
            self,
            "SiteDistribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(site_bucket),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                response_headers_policy=cloudfront.ResponseHeadersPolicy.SECURITY_HEADERS,
                edge_lambdas=edge_lambdas or None,
            ),
            domain_names=[domain_name, f"www.{domain_name}"],
            certificate=certificate,
            default_root_object="index.html",
            # Only rewrite 404 to index.html (SPA routing). Surface 403 as-is so
            # real auth/OAC failures are visible in CloudFront 4xx alarms rather
            # than masked behind a 200 OK on /index.html.
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=404,
                    response_http_status=200,
                    response_page_path="/index.html",
                    ttl=Duration.minutes(5),
                ),
            ],
            web_acl_id=web_acl_id,
        )

        # CloudWatch alarms — console only, no SNS
        cloudwatch.Alarm(
            self,
            "High5xxErrorRate",
            metric=cloudwatch.Metric(
                namespace="AWS/CloudFront",
                metric_name="5xxErrorRate",
                dimensions_map={"DistributionId": distribution.distribution_id},
                statistic="Average",
                period=Duration.minutes(5),
            ),
            threshold=5,
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="CloudFront 5xx error rate exceeded 5%",
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        cloudwatch.Alarm(
            self,
            "High4xxErrorRate",
            metric=cloudwatch.Metric(
                namespace="AWS/CloudFront",
                metric_name="4xxErrorRate",
                dimensions_map={"DistributionId": distribution.distribution_id},
                statistic="Average",
                period=Duration.minutes(5),
            ),
            threshold=10,
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="CloudFront 4xx error rate exceeded 10%",
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING,
        )

        cloudwatch.Dashboard(
            self,
            "SiteDashboard",
            dashboard_name=resolved_dashboard_name,
            widgets=[
                [
                    cloudwatch.GraphWidget(
                        title="CloudFront Error Rates",
                        width=12,
                        left=[
                            cloudwatch.Metric(
                                namespace="AWS/CloudFront",
                                metric_name="5xxErrorRate",
                                dimensions_map={
                                    "DistributionId": distribution.distribution_id
                                },
                                statistic="Average",
                                period=Duration.minutes(5),
                                label="5xx Error Rate",
                            ),
                            cloudwatch.Metric(
                                namespace="AWS/CloudFront",
                                metric_name="4xxErrorRate",
                                dimensions_map={
                                    "DistributionId": distribution.distribution_id
                                },
                                statistic="Average",
                                period=Duration.minutes(5),
                                label="4xx Error Rate",
                            ),
                        ],
                    ),
                    cloudwatch.GraphWidget(
                        title="CloudFront Requests",
                        width=12,
                        left=[
                            cloudwatch.Metric(
                                namespace="AWS/CloudFront",
                                metric_name="Requests",
                                dimensions_map={
                                    "DistributionId": distribution.distribution_id
                                },
                                statistic="Sum",
                                period=Duration.minutes(5),
                                label="Total Requests",
                            ),
                        ],
                    ),
                ],
            ],
        )

        # Deploy site assets from dist/ (skip when CI/CD handles deployment separately).
        if not skip_deployment:
            s3deploy.BucketDeployment(
                self,
                "DeploySite",
                sources=[
                    s3deploy.Source.asset(dist_path, exclude=exclude_patterns or [])
                ],
                destination_bucket=site_bucket,
                distribution=distribution,
                distribution_paths=["/*"],
                memory_limit=deployment_memory_limit,
                exclude=exclude_patterns or [],
            )

        # cdk-nag suppressions for accepted deviations
        NagSuppressions.add_resource_suppressions(
            distribution,
            [
                {
                    "id": "AwsSolutions-CFR3",
                    "reason": "CloudFront standard logging is incompatible with the Free pricing plan (returns HTTP 400). S3 access logging is active at the origin bucket layer via S3AccessLogsBucket.",
                }
            ],
        )
        # BucketDeployment creates a singleton Custom Resource Lambda at the stack level
        # (not under the deploy construct), so these must be suppressed at the stack level.
        NagSuppressions.add_stack_suppressions(
            self,
            [
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": "CDK BucketDeployment L2 construct attaches AWSLambdaBasicExecutionRole to its internal singleton Lambda service role; not configurable without replacing the construct.",
                },
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "CDK BucketDeployment L2 construct requires wildcard S3 permissions on its internal Lambda role to deploy assets; not configurable without replacing the construct.",
                },
                {
                    "id": "AwsSolutions-L1",
                    "reason": "CDK BucketDeployment L2 construct manages its own internal Lambda runtime version; not configurable without replacing the construct.",
                },
            ],
        )

        CfnOutput(
            self,
            "DistributionDomainName",
            value=distribution.distribution_domain_name,
            description="CloudFront URL",
        )

        CfnOutput(
            self,
            "BucketName",
            value=site_bucket.bucket_name,
            description="S3 Bucket Name",
        )

        CfnOutput(
            self,
            "SiteUrl",
            value=f"https://{domain_name}",
            description="Site URL",
        )

        CfnOutput(
            self,
            "S3AccessLogsBucketName",
            value=s3_access_logs_bucket.bucket_name,
            description="S3 Access Logs Bucket Name",
        )
