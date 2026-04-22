"""Token exchange and refresh with Cognito OAuth2 endpoints."""

import base64
import json
import urllib.parse

import urllib3

http = urllib3.PoolManager()

_TIMEOUT = urllib3.Timeout(connect=2.0, read=3.0)


def _auth_header(client_id: str, client_secret: str) -> str:
    credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    return f"Basic {credentials}"


def exchange_code(
    code: str,
    redirect_uri: str,
    cognito_domain: str,
    client_id: str,
    client_secret: str,
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
            "Authorization": _auth_header(client_id, client_secret),
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
    client_secret: str,
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
            "Authorization": _auth_header(client_id, client_secret),
        },
        body=body,
        timeout=_TIMEOUT,
    )
    if resp.status != 200:
        return {}
    return json.loads(resp.data.decode())
