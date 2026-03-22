"""Lambda@Edge viewer-request handler for Cognito authentication."""

import hashlib
import json
import os
import urllib.parse
from pathlib import Path

# Config is baked into config.json at CDK bundling time.
_config = json.loads((Path(__file__).parent / "config.json").read_text())

USER_POOL_ID = _config["user_pool_id"]
CLIENT_ID = _config["client_id"]
CLIENT_SECRET = _config["client_secret"]
COGNITO_DOMAIN = _config["cognito_domain"]
REDIRECT_URI = _config["redirect_uri"]
CALLBACK_PATH = _config["callback_path"]
SIGNOUT_PATH = _config["signout_path"]
REGION = _config["region"]


def _parse_cookies(headers: dict) -> dict:
    cookies = {}
    for cookie_header in headers.get("cookie", []):
        for item in cookie_header["value"].split(";"):
            item = item.strip()
            if "=" in item:
                name, _, value = item.partition("=")
                cookies[name.strip()] = value.strip()
    return cookies


def _set_cookie(name: str, value: str, max_age: int) -> str:
    return f"{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}"


def _clear_cookie(name: str) -> str:
    return f"{name}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"


def _redirect(url: str, extra_headers: dict | None = None) -> dict:
    headers = {"location": [{"key": "Location", "value": url}]}
    if extra_headers:
        headers.update(extra_headers)
    return {"status": "302", "statusDescription": "Found", "headers": headers}


def _generate_state() -> str:
    """Generate a cryptographically random state parameter for CSRF protection."""
    return hashlib.sha256(os.urandom(32)).hexdigest()


def _authorize_url(state: str) -> str:
    params = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": state,
        }
    )
    return f"https://{COGNITO_DOMAIN}/oauth2/authorize?{params}"


def _redirect_to_login() -> dict:
    """Redirect to Cognito login with CSRF state cookie."""
    state = _generate_state()
    state_cookie = {
        "set-cookie": [
            {
                "key": "Set-Cookie",
                "value": _set_cookie("auth_state", state, 300),
            }
        ]
    }
    return _redirect(_authorize_url(state), extra_headers=state_cookie)


def _safe_redirect_path(uri: str, qs: str) -> str:
    """Validate and return a safe relative redirect path."""
    # Only allow relative paths starting with /
    if not uri or not uri.startswith("/") or uri.startswith("//"):
        return "/"
    # Strip any scheme or authority that might be smuggled in
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme or parsed.netloc:
        return "/"
    safe_path = parsed.path
    if qs:
        return f"{safe_path}?{qs}"
    return safe_path


def handler(event, context):  # noqa: ARG001
    request = event["Records"][0]["cf"]["request"]
    headers = request.get("headers", {})
    uri = request.get("uri", "/")
    querystring = request.get("querystring", "")
    cookies = _parse_cookies(headers)

    # Handle callback from Cognito.
    if uri == CALLBACK_PATH:
        return _handle_callback(querystring, cookies)

    # Handle sign-out.
    if uri == SIGNOUT_PATH:
        return _handle_signout()

    # Check for valid id_token cookie.
    id_token = cookies.get("id_token")
    if id_token:
        try:
            from jwt_validator import validate_token

            validate_token(id_token, USER_POOL_ID, CLIENT_ID, REGION)
            return request  # Valid token — pass through.
        except Exception:
            # Token invalid or expired — try refresh.
            refresh_token = cookies.get("refresh_token")
            if refresh_token:
                return _try_refresh(refresh_token, uri, querystring)

    # No valid token — redirect to login.
    return _redirect_to_login()


def _handle_callback(querystring: str, cookies: dict) -> dict:
    params = urllib.parse.parse_qs(querystring)
    code = params.get("code", [None])[0]
    state = params.get("state", [None])[0]

    if not code:
        return _redirect("/")

    # Validate state parameter against cookie to prevent CSRF.
    expected_state = cookies.get("auth_state")
    if not state or not expected_state or state != expected_state:
        return _redirect_to_login()

    from cognito_client import exchange_code

    try:
        tokens = exchange_code(
            code, REDIRECT_URI, COGNITO_DOMAIN, CLIENT_ID, CLIENT_SECRET
        )
    except Exception:
        return _redirect_to_login()

    cookie_headers = [
        {
            "key": "Set-Cookie",
            "value": _set_cookie("id_token", tokens["id_token"], 3600),
        },
        {
            "key": "Set-Cookie",
            "value": _clear_cookie("auth_state"),
        },
    ]
    if "refresh_token" in tokens:
        cookie_headers.append(
            {
                "key": "Set-Cookie",
                "value": _set_cookie("refresh_token", tokens["refresh_token"], 2592000),
            }
        )

    return _redirect("/", extra_headers={"set-cookie": cookie_headers})


def _handle_signout() -> dict:
    cookie_headers = [
        {"key": "Set-Cookie", "value": _clear_cookie("id_token")},
        {"key": "Set-Cookie", "value": _clear_cookie("refresh_token")},
        {"key": "Set-Cookie", "value": _clear_cookie("auth_state")},
    ]
    logout_url = f"https://{COGNITO_DOMAIN}/logout?client_id={CLIENT_ID}&logout_uri={urllib.parse.quote(REDIRECT_URI.replace('/_callback', '/'))}"
    return _redirect(logout_url, extra_headers={"set-cookie": cookie_headers})


def _try_refresh(refresh_token: str, uri: str, querystring: str) -> dict:
    from cognito_client import refresh_tokens

    tokens = refresh_tokens(refresh_token, COGNITO_DOMAIN, CLIENT_ID, CLIENT_SECRET)
    if not tokens or "id_token" not in tokens:
        return _redirect_to_login()

    # Refresh succeeded — set new cookie and redirect to validated path.
    target = _safe_redirect_path(uri, querystring)

    cookie_headers = [
        {
            "key": "Set-Cookie",
            "value": _set_cookie("id_token", tokens["id_token"], 3600),
        },
    ]
    return _redirect(target, extra_headers={"set-cookie": cookie_headers})
