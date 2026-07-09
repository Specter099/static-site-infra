"""Token exchange and refresh with Cognito OAuth2 endpoints."""

import base64
import json
import urllib.parse

import boto3
import urllib3
from botocore.config import Config

http = urllib3.PoolManager()

_TIMEOUT = urllib3.Timeout(connect=2.0, read=3.0)

# The client secret lives in Secrets Manager in us-east-1 (alongside the
# Lambda@Edge function) and is cached for the container lifetime. Tight
# timeouts keep the cold-start fetch inside the 5-second viewer-request
# budget, which must also fit a JWKS fetch.
_SECRETS_CONFIG = Config(
    region_name="us-east-1",
    connect_timeout=1.0,
    read_timeout=2.0,
    retries={"max_attempts": 2},
)
_cached_secret: str | None = None


def _get_client_secret(client_secret_arn: str) -> str:
    global _cached_secret
    if _cached_secret is None:
        client = boto3.client("secretsmanager", config=_SECRETS_CONFIG)
        resp = client.get_secret_value(SecretId=client_secret_arn)
        _cached_secret = resp["SecretString"]
    return _cached_secret


def _auth_header(client_id: str, client_secret: str) -> str:
    credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    return f"Basic {credentials}"


def exchange_code(
    code: str,
    redirect_uri: str,
    cognito_domain: str,
    client_id: str,
    client_secret_arn: str,
) -> dict:
    """Exchange an authorization code for tokens."""
    body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
        }
    )
    resp = http.request(
        "POST",
        f"https://{cognito_domain}/oauth2/token",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": _auth_header(
                client_id, _get_client_secret(client_secret_arn)
            ),
        },
        body=body,
        timeout=_TIMEOUT,
    )
    if resp.status != 200:
        raise RuntimeError(f"Token exchange failed: HTTP {resp.status}")
    return json.loads(resp.data.decode())


def refresh_tokens(
    refresh_token: str,
    cognito_domain: str,
    client_id: str,
    client_secret_arn: str,
) -> dict:
    """Use a refresh token to obtain new tokens."""
    body = urllib.parse.urlencode(
        {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": client_id,
        }
    )
    resp = http.request(
        "POST",
        f"https://{cognito_domain}/oauth2/token",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": _auth_header(
                client_id, _get_client_secret(client_secret_arn)
            ),
        },
        body=body,
        timeout=_TIMEOUT,
    )
    if resp.status != 200:
        return {}
    return json.loads(resp.data.decode())
