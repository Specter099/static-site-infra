#!/usr/bin/env python3
"""Synth-only example app used by CI. Not a user-facing example."""

import os
import tempfile

import aws_cdk as cdk

from specter_static_site import StaticSiteStack

_dist = tempfile.mkdtemp()
with open(os.path.join(_dist, "index.html"), "w") as f:
    f.write("<html>CI synth</html>")

app = cdk.App()
StaticSiteStack(
    app,
    "StaticSiteStack",
    domain_name="example.com",
    dist_path=_dist,
    certificate_arn="arn:aws:acm:us-east-1:123456789012:certificate/00000000-0000-0000-0000-000000000000",
    env=cdk.Environment(account="123456789012", region="us-east-1"),
)
app.synth()
