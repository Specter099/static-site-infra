import aws_cdk as cdk
from aws_cdk import (
    Stack,
    Duration,
    CfnOutput,
    RemovalPolicy,
    aws_s3 as s3,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_s3_deployment as s3deploy,
    aws_certificatemanager as acm,
    aws_cloudwatch as cloudwatch,
    aws_route53 as route53,
    aws_route53_targets as route53_targets,
)
from constructs import Construct
from cdk_nag import NagSuppressions


class StaticSiteStack(Stack):
    def __init__(
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
        **kwargs,
    ) -> None:
        super().__init__(
            scope,
            construct_id,
            description=f"Static site hosting for {domain_name}",
            **kwargs,
        )

        # CloudWatch dashboard names allow only alphanumerics, dashes, and underscores.
        # Replace dots so domain names work as the default (e.g. "example.com" → "example-com").
        resolved_dashboard_name = (dashboard_name or domain_name).replace(".", "-")

        # S3 access logs bucket
        s3_access_logs_bucket = s3.Bucket(
            self,
            "S3AccessLogsBucket",
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

        # CloudFront access logs bucket
        cloudfront_logs_bucket = s3.Bucket(
            self,
            "CloudFrontLogsBucket",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.KMS_MANAGED,
            enforce_ssl=True,
            removal_policy=RemovalPolicy.RETAIN,
            auto_delete_objects=False,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
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

        # CloudFront distribution
        distribution = cloudfront.Distribution(
            self,
            "SiteDistribution",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin.with_origin_access_control(site_bucket),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                response_headers_policy=cloudfront.ResponseHeadersPolicy.SECURITY_HEADERS,
            ),
            domain_names=[domain_name, f"www.{domain_name}"],
            certificate=certificate,
            default_root_object="index.html",
            error_responses=[
                cloudfront.ErrorResponse(
                    http_status=403,
                    response_http_status=200,
                    response_page_path="/index.html",
                    ttl=Duration.minutes(5),
                ),
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
                                dimensions_map={"DistributionId": distribution.distribution_id},
                                statistic="Average",
                                period=Duration.minutes(5),
                                label="5xx Error Rate",
                            ),
                            cloudwatch.Metric(
                                namespace="AWS/CloudFront",
                                metric_name="4xxErrorRate",
                                dimensions_map={"DistributionId": distribution.distribution_id},
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
                                dimensions_map={"DistributionId": distribution.distribution_id},
                                statistic="Sum",
                                period=Duration.minutes(5),
                                label="Total Requests",
                            ),
                        ],
                    ),
                ],
            ],
        )

        # Route 53 alias records for apex and www
        if hosted_zone:
            cf_target = route53_targets.CloudFrontTarget(distribution)

            route53.ARecord(
                self,
                "ApexAlias",
                zone=hosted_zone,
                target=route53.RecordTarget.from_alias(cf_target),
            )

            route53.AaaaRecord(
                self,
                "ApexAliasIPv6",
                zone=hosted_zone,
                target=route53.RecordTarget.from_alias(cf_target),
            )

            route53.ARecord(
                self,
                "WwwAlias",
                zone=hosted_zone,
                record_name="www",
                target=route53.RecordTarget.from_alias(cf_target),
            )

            route53.AaaaRecord(
                self,
                "WwwAliasIPv6",
                zone=hosted_zone,
                record_name="www",
                target=route53.RecordTarget.from_alias(cf_target),
            )

        # Deploy site assets from dist/
        s3deploy.BucketDeployment(
            self,
            "DeploySite",
            sources=[s3deploy.Source.asset(dist_path)],
            destination_bucket=site_bucket,
            distribution=distribution,
            distribution_paths=["/*"],
        )

        # cdk-nag suppressions for accepted deviations
        NagSuppressions.add_resource_suppressions(
            cloudfront_logs_bucket,
            [{"id": "AwsSolutions-S1", "reason": "CloudFrontLogsBucket is a logging destination; enabling access logs on it would be circular. CloudFront standard logging is disabled due to Free pricing plan incompatibility (HTTP 400)."}],
        )
        NagSuppressions.add_resource_suppressions(
            distribution,
            [{"id": "AwsSolutions-CFR3", "reason": "CloudFront standard logging is incompatible with the Free pricing plan (returns HTTP 400). S3 access logging is active at the bucket layer via S3AccessLogsBucket."}],
        )
        # BucketDeployment creates a singleton Custom Resource Lambda at the stack level
        # (not under the deploy construct), so these must be suppressed at the stack level.
        NagSuppressions.add_stack_suppressions(
            self,
            [
                {"id": "AwsSolutions-IAM4", "reason": "CDK BucketDeployment L2 construct attaches AWSLambdaBasicExecutionRole to its internal singleton Lambda service role; not configurable without replacing the construct."},
                {"id": "AwsSolutions-IAM5", "reason": "CDK BucketDeployment L2 construct requires wildcard S3 permissions on its internal Lambda role to deploy assets; not configurable without replacing the construct."},
                {"id": "AwsSolutions-L1", "reason": "CDK BucketDeployment L2 construct manages its own internal Lambda runtime version; not configurable without replacing the construct."},
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
            "CloudFrontLogsBucketName",
            value=cloudfront_logs_bucket.bucket_name,
            description="CloudFront Logs Bucket Name",
        )

        CfnOutput(
            self,
            "S3AccessLogsBucketName",
            value=s3_access_logs_bucket.bucket_name,
            description="S3 Access Logs Bucket Name",
        )
