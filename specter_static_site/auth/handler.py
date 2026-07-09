"""Lambda@Edge viewer-request handler for Cognito authentication."""

import base64
import hashlib
import json
import logging
import secrets
import urllib.parse
from pathlib import Path

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Config is baked into config.json at CDK bundling time.
_config = json.loads((Path(__file__).parent / "config.json").read_text())

USER_POOL_ID = _config["user_pool_id"]
CLIENT_ID = _config["client_id"]
CLIENT_SECRET_ARN = _config["client_secret_arn"]
COGNITO_DOMAIN = _config["cognito_domain"]
REDIRECT_URI = _config["redirect_uri"]
CALLBACK_PATH = _config["callback_path"]
SIGNOUT_PATH = _config["signout_path"]
REGION = _config["region"]

# __Host- prefix: browsers enforce Secure, no Domain, Path=/ — no subdomain
# can plant or shadow these cookies.
ID_TOKEN_COOKIE = "__Host-id_token"  # noqa: S105 — cookie name, not a secret
REFRESH_TOKEN_COOKIE = "__Host-refresh_token"  # noqa: S105 — cookie name, not a secret
STATE_COOKIE = "__Host-auth_state"
REDIRECT_COOKIE = "__Host-auth_redirect"
NONCE_COOKIE = "__Host-auth_nonce"
PKCE_COOKIE = "__Host-auth_pkce_verifier"
# Pre-v3 cookie names. Cleared alongside the prefixed ones so stale
# credentials (a still-valid refresh token in particular) don't linger in
# browsers after an upgrade.
_LEGACY_COOKIES = ("id_token", "refresh_token", "auth_state")


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
    return secrets.token_urlsafe(32)


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _authorize_url(state: str, code_challenge: str, nonce: str) -> str:
    params = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "nonce": nonce,
        }
    )
    return f"https://{COGNITO_DOMAIN}/oauth2/authorize?{params}"


def _begin_login(target: str | None, *, clear_tokens: bool) -> dict:
    """Redirect to Cognito authorize with fresh state/PKCE/nonce material.

    ``target`` (already validated by ``_safe_redirect_path``) is stored in a
    short-lived cookie so the callback can restore the originally requested
    page after sign-in.
    """
    state = _generate_state()
    nonce = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(64)  # 86 chars, within PKCE's 43-128
    cookie_headers = [
        {"key": "Set-Cookie", "value": _set_cookie(STATE_COOKIE, state, 300)},
        {"key": "Set-Cookie", "value": _set_cookie(NONCE_COOKIE, nonce, 300)},
        {"key": "Set-Cookie", "value": _set_cookie(PKCE_COOKIE, verifier, 300)},
    ]
    if target is not None:
        cookie_headers.append(
            {
                "key": "Set-Cookie",
                "value": _set_cookie(
                    REDIRECT_COOKIE, urllib.parse.quote(target, safe=""), 300
                ),
            }
        )
    if clear_tokens:
        cookie_headers += [
            {"key": "Set-Cookie", "value": _clear_cookie(ID_TOKEN_COOKIE)},
            {"key": "Set-Cookie", "value": _clear_cookie(REFRESH_TOKEN_COOKIE)},
        ]
        cookie_headers += [
            {"key": "Set-Cookie", "value": _clear_cookie(name)}
            for name in _LEGACY_COOKIES
        ]
    return _redirect(
        _authorize_url(state, _pkce_challenge(verifier), nonce),
        extra_headers={"set-cookie": cookie_headers},
    )


def _redirect_to_login(target: str = "/") -> dict:
    """Redirect to Cognito login with CSRF state cookie."""
    return _begin_login(target, clear_tokens=False)


def _redirect_to_login_clearing_cookies() -> dict:
    """Redirect to login and invalidate any existing auth cookies."""
    return _begin_login(None, clear_tokens=True)


def _error_response(message: str) -> dict:
    """Static error page. ``message`` must be a literal — never reflect
    request or IdP-supplied values into the body."""
    return {
        "status": "403",
        "statusDescription": "Forbidden",
        "headers": {
            "content-type": [
                {"key": "Content-Type", "value": "text/html; charset=utf-8"}
            ],
            "cache-control": [{"key": "Cache-Control", "value": "no-store"}],
        },
        "body": (
            "<html><body><h1>Sign-in failed</h1>"
            f"<p>{message}</p>"
            '<p><a href="/">Try again</a></p></body></html>'
        ),
    }


def _safe_redirect_path(uri: str, qs: str) -> str:
    """Validate and return a safe relative redirect path."""
    # Only allow relative paths starting with /
    if not uri or not uri.startswith("/") or uri.startswith("//"):
        return "/"
    # Backslashes (some browsers normalize \ to / in Location, turning
    # /\evil.com into protocol-relative //evil.com) and control characters
    # are never legitimate here.
    if "\\" in uri or any(ord(c) < 0x20 for c in uri):
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

    # Debug level: routine per-request URI logging otherwise accumulates in
    # unmanaged edge-region log groups (see README operational caveats).
    logger.debug("uri=%s cookies=%s", uri, list(cookies.keys()))

    # Handle callback from Cognito.
    if uri == CALLBACK_PATH:
        return _handle_callback(querystring, cookies)

    # Handle sign-out.
    if uri == SIGNOUT_PATH:
        return _handle_signout(cookies)

    # Check for valid id_token cookie.
    id_token = cookies.get(ID_TOKEN_COOKIE)
    if id_token:
        import jwt as _jwt
        from jwt_validator import validate_token

        try:
            validate_token(id_token, USER_POOL_ID, CLIENT_ID, REGION)
            return request  # Valid token — pass through.
        except _jwt.ExpiredSignatureError:
            # Only expired tokens are eligible for a refresh attempt.
            refresh_token = cookies.get(REFRESH_TOKEN_COOKIE)
            if refresh_token:
                return _try_refresh(refresh_token, uri, querystring)
            return _redirect_to_login(_safe_redirect_path(uri, querystring))
        except _jwt.InvalidTokenError as e:
            # Tampered, malformed, or wrong-audience token — fail closed.
            logger.warning("Invalid id_token, clearing cookies: %s", e)
            return _redirect_to_login_clearing_cookies()

    # No token — redirect to login, preserving the requested page.
    return _redirect_to_login(_safe_redirect_path(uri, querystring))


def _handle_callback(querystring: str, cookies: dict) -> dict:
    params = urllib.parse.parse_qs(querystring)

    # The IdP reported an error (e.g. access_denied when the user cancels).
    # Redirecting to "/" would immediately bounce back to the login page —
    # show a static error instead. Log the details; never reflect them.
    if params.get("error"):
        logger.warning(
            "Cognito callback error=%s description=%s",
            params.get("error", [None])[0],
            params.get("error_description", [None])[0],
        )
        return _error_response("The sign-in attempt was cancelled or refused.")

    code = params.get("code", [None])[0]
    state = params.get("state", [None])[0]

    if not code:
        return _redirect("/")

    # Validate state parameter against cookie to prevent CSRF. Use constant-time
    # comparison and do not log the state values themselves.
    expected_state = cookies.get(STATE_COOKIE)
    if (
        not state
        or not expected_state
        or not secrets.compare_digest(state, expected_state)
    ):
        logger.warning("Callback state mismatch")
        return _redirect_to_login()

    from cognito_client import exchange_code

    try:
        tokens = exchange_code(
            code,
            REDIRECT_URI,
            COGNITO_DOMAIN,
            CLIENT_ID,
            CLIENT_SECRET_ARN,
            code_verifier=cookies.get(PKCE_COOKIE),
        )
    except Exception as e:
        logger.error("Token exchange failed: %s", e)
        return _redirect_to_login()

    # Validate the received id_token before trusting it, and require the
    # nonce claim to match the one minted at login (replay/injection guard).
    from jwt_validator import validate_token

    try:
        claims = validate_token(tokens["id_token"], USER_POOL_ID, CLIENT_ID, REGION)
    except Exception as e:
        logger.warning("Post-exchange token validation failed: %s", e)
        return _redirect_to_login_clearing_cookies()
    expected_nonce = cookies.get(NONCE_COOKIE)
    if not expected_nonce or not secrets.compare_digest(
        claims.get("nonce") or "", expected_nonce
    ):
        logger.warning("Callback nonce mismatch")
        return _redirect_to_login_clearing_cookies()

    cookie_headers = [
        {
            "key": "Set-Cookie",
            "value": _set_cookie(ID_TOKEN_COOKIE, tokens["id_token"], 3600),
        },
        {
            "key": "Set-Cookie",
            "value": _clear_cookie(STATE_COOKIE),
        },
        {
            "key": "Set-Cookie",
            "value": _clear_cookie(REDIRECT_COOKIE),
        },
        {
            "key": "Set-Cookie",
            "value": _clear_cookie(NONCE_COOKIE),
        },
        {
            "key": "Set-Cookie",
            "value": _clear_cookie(PKCE_COOKIE),
        },
    ]
    if "refresh_token" in tokens:
        cookie_headers.append(
            {
                "key": "Set-Cookie",
                "value": _set_cookie(
                    REFRESH_TOKEN_COOKIE, tokens["refresh_token"], 2592000
                ),
            }
        )

    # Restore the page requested before login. The cookie is server-set and
    # __Host--protected, but re-validate anyway.
    raw_target = urllib.parse.unquote(cookies.get(REDIRECT_COOKIE, "/"))
    path, _, qs = raw_target.partition("?")
    target = _safe_redirect_path(path, qs)
    return _redirect(target, extra_headers={"set-cookie": cookie_headers})


def _handle_signout(cookies: dict) -> dict:
    # Revoke the refresh token server-side so it can't be replayed after
    # sign-out. Best-effort: clearing cookies must succeed regardless.
    refresh_token = cookies.get(REFRESH_TOKEN_COOKIE)
    if refresh_token:
        from cognito_client import revoke_token

        try:
            if not revoke_token(
                refresh_token, COGNITO_DOMAIN, CLIENT_ID, CLIENT_SECRET_ARN
            ):
                logger.warning("Refresh token revocation returned failure")
        except Exception as e:
            logger.warning("Refresh token revocation failed: %s", e)

    cookie_headers = [
        {"key": "Set-Cookie", "value": _clear_cookie(ID_TOKEN_COOKIE)},
        {"key": "Set-Cookie", "value": _clear_cookie(REFRESH_TOKEN_COOKIE)},
        {"key": "Set-Cookie", "value": _clear_cookie(STATE_COOKIE)},
        {"key": "Set-Cookie", "value": _clear_cookie(REDIRECT_COOKIE)},
        {"key": "Set-Cookie", "value": _clear_cookie(NONCE_COOKIE)},
        {"key": "Set-Cookie", "value": _clear_cookie(PKCE_COOKIE)},
    ]
    cookie_headers += [
        {"key": "Set-Cookie", "value": _clear_cookie(name)} for name in _LEGACY_COOKIES
    ]
    logout_uri = REDIRECT_URI.replace("/_callback", "/")
    params = urllib.parse.urlencode(
        {"client_id": CLIENT_ID, "logout_uri": logout_uri}
    )
    logout_url = f"https://{COGNITO_DOMAIN}/logout?{params}"
    return _redirect(logout_url, extra_headers={"set-cookie": cookie_headers})


def _try_refresh(refresh_token: str, uri: str, querystring: str) -> dict:
    from cognito_client import refresh_tokens

    try:
        tokens = refresh_tokens(
            refresh_token, COGNITO_DOMAIN, CLIENT_ID, CLIENT_SECRET_ARN
        )
    except Exception as e:
        logger.warning("Refresh failed: %s", e)
        return _redirect_to_login_clearing_cookies()
    if not tokens or "id_token" not in tokens:
        return _redirect_to_login_clearing_cookies()

    # Refresh succeeded — set new cookie and redirect to validated path.
    target = _safe_redirect_path(uri, querystring)

    cookie_headers = [
        {
            "key": "Set-Cookie",
            "value": _set_cookie(ID_TOKEN_COOKIE, tokens["id_token"], 3600),
        },
    ]
    # Cognito rotates refresh tokens when the app client has rotation
    # enabled — persist the new one or the session dies at next refresh.
    if tokens.get("refresh_token"):
        cookie_headers.append(
            {
                "key": "Set-Cookie",
                "value": _set_cookie(
                    REFRESH_TOKEN_COOKIE, tokens["refresh_token"], 2592000
                ),
            }
        )
    return _redirect(target, extra_headers={"set-cookie": cookie_headers})
