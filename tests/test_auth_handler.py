"""Unit tests for the Lambda@Edge auth handler (no AWS calls)."""

import importlib
import json
import sys
from pathlib import Path

import jwt
import pytest

AUTH_DIR = Path(__file__).resolve().parent.parent / "specter_static_site" / "auth"


@pytest.fixture
def auth_module(tmp_path, monkeypatch):
    """Import handler.py with a synthetic config.json in place."""
    cfg = {
        "user_pool_id": "us-east-1_Test",
        "client_id": "test-client",
        "client_secret_arn": (
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-AbCdEf"
        ),
        "cognito_domain": "auth.example.com",
        "redirect_uri": "https://site.example.com/_callback",
        "callback_path": "/_callback",
        "signout_path": "/_signout",
        "region": "us-east-1",
    }

    work = tmp_path / "auth_pkg"
    work.mkdir()
    for src in AUTH_DIR.glob("*.py"):
        (work / src.name).write_text(src.read_text())
    (work / "config.json").write_text(json.dumps(cfg))

    monkeypatch.syspath_prepend(str(work))
    # Clear any previously imported copies so config.json is re-read.
    for name in ("handler", "jwt_validator", "cognito_client"):
        sys.modules.pop(name, None)
    mod = importlib.import_module("handler")
    yield mod
    for name in ("handler", "jwt_validator", "cognito_client"):
        sys.modules.pop(name, None)


def _event(uri="/", cookies=None, querystring=""):
    cookie_header = []
    if cookies:
        cookie_header = [
            {"key": "Cookie", "value": "; ".join(f"{k}={v}" for k, v in cookies.items())}
        ]
    return {
        "Records": [
            {
                "cf": {
                    "request": {
                        "uri": uri,
                        "querystring": querystring,
                        "headers": {"cookie": cookie_header} if cookie_header else {},
                    }
                }
            }
        ]
    }


# --- _generate_state -------------------------------------------------------


def test_generate_state_is_random_and_long(auth_module):
    a = auth_module._generate_state()
    b = auth_module._generate_state()
    assert a != b
    assert len(a) > 20


# --- _parse_cookies --------------------------------------------------------


def test_parse_cookies(auth_module):
    headers = {"cookie": [{"key": "Cookie", "value": "a=1; b=two; c=3"}]}
    assert auth_module._parse_cookies(headers) == {"a": "1", "b": "two", "c": "3"}


def test_parse_cookies_handles_missing_cookie_header(auth_module):
    assert auth_module._parse_cookies({}) == {}


# --- _safe_redirect_path ---------------------------------------------------


@pytest.mark.parametrize(
    "uri,qs,expected",
    [
        ("/", "", "/"),
        ("/dashboard", "", "/dashboard"),
        ("/dashboard", "a=1&b=2", "/dashboard?a=1&b=2"),
        ("//evil.com/x", "", "/"),  # protocol-relative
        ("http://evil.com/x", "", "/"),  # absolute URL
        ("", "", "/"),  # empty
        ("javascript:alert(1)", "", "/"),  # scheme smuggle
        ("/\\evil.com", "", "/"),  # browsers may normalize \ to /
        ("/\\\\evil.com", "", "/"),  # double backslash variant
        ("/a\\b", "", "/"),  # embedded backslash
        ("/line\rbreak", "", "/"),  # control chars (header injection)
        ("/line\nbreak", "", "/"),
    ],
)
def test_safe_redirect_path(auth_module, uri, qs, expected):
    assert auth_module._safe_redirect_path(uri, qs) == expected


# --- handler flows ---------------------------------------------------------


def test_handler_no_token_redirects_to_login(auth_module):
    resp = auth_module.handler(_event("/"), None)
    assert resp["status"] == "302"
    loc = resp["headers"]["location"][0]["value"]
    assert loc.startswith("https://auth.example.com/oauth2/authorize?")
    # Sets a __Host- state cookie for CSRF protection.
    set_cookie = resp["headers"]["set-cookie"][0]["value"]
    assert set_cookie.startswith("__Host-auth_state=")
    assert "HttpOnly" in set_cookie
    assert "Secure" in set_cookie
    assert "SameSite=Lax" in set_cookie


def test_handler_preserves_deep_link_through_login(auth_module, monkeypatch):
    """The requested page survives the login round trip via the redirect cookie."""
    resp = auth_module.handler(_event("/reports/q2", querystring="id=7"), None)
    cookies = {c["value"].split("=", 1)[0]: c["value"] for c in resp["headers"]["set-cookie"]}
    assert "__Host-auth_redirect" in cookies
    assert "%2Freports%2Fq2%3Fid%3D7" in cookies["__Host-auth_redirect"]

    # Simulate the callback with that cookie present.
    monkeypatch.setattr(
        "cognito_client.exchange_code",
        lambda *_a, **_k: {"id_token": "id"},
    )
    monkeypatch.setattr(
        "jwt_validator.validate_token", lambda *_a, **_k: {"nonce": "n"}
    )
    event = _event(
        "/_callback",
        cookies={
            "__Host-auth_state": "s",
            "__Host-auth_nonce": "n",
            "__Host-auth_pkce_verifier": "v",
            "__Host-auth_redirect": "%2Freports%2Fq2%3Fid%3D7",
        },
        querystring="code=abc&state=s",
    )
    cb = auth_module.handler(event, None)
    assert cb["status"] == "302"
    assert cb["headers"]["location"][0]["value"] == "/reports/q2?id=7"


def test_login_redirect_includes_pkce_and_nonce(auth_module):
    resp = auth_module.handler(_event("/"), None)
    loc = resp["headers"]["location"][0]["value"]
    assert "code_challenge=" in loc
    assert "code_challenge_method=S256" in loc
    assert "nonce=" in loc
    cookie_names = {
        c["value"].split("=", 1)[0] for c in resp["headers"]["set-cookie"]
    }
    assert "__Host-auth_nonce" in cookie_names
    assert "__Host-auth_pkce_verifier" in cookie_names


def test_callback_passes_pkce_verifier_to_exchange(auth_module, monkeypatch):
    captured = {}

    def fake_exchange(*args, **kwargs):
        captured.update(kwargs)
        return {"id_token": "id"}

    monkeypatch.setattr("cognito_client.exchange_code", fake_exchange)
    monkeypatch.setattr(
        "jwt_validator.validate_token", lambda *_a, **_k: {"nonce": "n"}
    )
    event = _event(
        "/_callback",
        cookies={
            "__Host-auth_state": "s",
            "__Host-auth_nonce": "n",
            "__Host-auth_pkce_verifier": "the-verifier",
        },
        querystring="code=abc&state=s",
    )
    resp = auth_module.handler(event, None)
    assert resp["status"] == "302"
    assert captured["code_verifier"] == "the-verifier"


def test_callback_nonce_mismatch_fails_closed(auth_module, monkeypatch):
    monkeypatch.setattr(
        "cognito_client.exchange_code", lambda *_a, **_k: {"id_token": "id"}
    )
    monkeypatch.setattr(
        "jwt_validator.validate_token", lambda *_a, **_k: {"nonce": "other"}
    )
    event = _event(
        "/_callback",
        cookies={
            "__Host-auth_state": "s",
            "__Host-auth_nonce": "n",
            "__Host-auth_pkce_verifier": "v",
        },
        querystring="code=abc&state=s",
    )
    resp = auth_module.handler(event, None)
    # Back to login, clearing token cookies — the token is never set.
    assert resp["status"] == "302"
    assert "/oauth2/authorize" in resp["headers"]["location"][0]["value"]
    values = [c["value"] for c in resp["headers"]["set-cookie"]]
    assert any(v.startswith("__Host-id_token=;") for v in values)
    assert not any(v.startswith("__Host-id_token=id") for v in values)


def test_callback_invalid_token_from_exchange_fails_closed(auth_module, monkeypatch):
    monkeypatch.setattr(
        "cognito_client.exchange_code", lambda *_a, **_k: {"id_token": "bad"}
    )

    def raise_invalid(*_a, **_k):
        raise jwt.InvalidTokenError("bad signature")

    monkeypatch.setattr("jwt_validator.validate_token", raise_invalid)
    event = _event(
        "/_callback",
        cookies={
            "__Host-auth_state": "s",
            "__Host-auth_nonce": "n",
            "__Host-auth_pkce_verifier": "v",
        },
        querystring="code=abc&state=s",
    )
    resp = auth_module.handler(event, None)
    assert resp["status"] == "302"
    values = [c["value"] for c in resp["headers"]["set-cookie"]]
    assert not any(v.startswith("__Host-id_token=bad") for v in values)


def test_callback_error_param_shows_error_page(auth_module):
    """error= from Cognito must not loop back to login — show a static page."""
    event = _event("/_callback", querystring="error=access_denied&error_description=x")
    resp = auth_module.handler(event, None)
    assert resp["status"] == "403"
    assert "location" not in resp["headers"]
    # Never reflect IdP-supplied values into the body.
    assert "access_denied" not in resp["body"]


def test_handler_valid_token_passes_through(auth_module, monkeypatch):
    monkeypatch.setattr(
        "jwt_validator.validate_token",
        lambda *_a, **_k: {"sub": "user-1"},
    )
    event = _event("/secret", cookies={"__Host-id_token": "valid.token.here"})
    resp = auth_module.handler(event, None)
    # Passthrough returns the original request dict, not a redirect.
    assert "status" not in resp
    assert resp["uri"] == "/secret"


def test_handler_expired_token_without_refresh_redirects_to_login(
    auth_module, monkeypatch
):
    def raise_expired(*_a, **_k):
        raise jwt.ExpiredSignatureError("expired")

    monkeypatch.setattr("jwt_validator.validate_token", raise_expired)
    resp = auth_module.handler(
        _event("/secret", cookies={"__Host-id_token": "expired"}), None
    )
    assert resp["status"] == "302"
    assert "/oauth2/authorize" in resp["headers"]["location"][0]["value"]


def test_handler_expired_token_with_refresh_token_attempts_refresh(
    auth_module, monkeypatch
):
    monkeypatch.setattr(
        "jwt_validator.validate_token",
        lambda *_a, **_k: (_ for _ in ()).throw(jwt.ExpiredSignatureError("x")),
    )
    monkeypatch.setattr(
        "cognito_client.refresh_tokens",
        lambda *_a, **_k: {"id_token": "new-token"},
    )
    resp = auth_module.handler(
        _event(
            "/app",
            cookies={"__Host-id_token": "expired", "__Host-refresh_token": "r"},
            querystring="q=1",
        ),
        None,
    )
    assert resp["status"] == "302"
    # Redirects back to the original path, not to /
    assert resp["headers"]["location"][0]["value"] == "/app?q=1"
    cookies = [c["value"] for c in resp["headers"]["set-cookie"]]
    assert any(c.startswith("__Host-id_token=new-token") for c in cookies)


def test_handler_invalid_token_fails_closed(auth_module, monkeypatch):
    """A tampered / wrong-audience token must NOT trigger a refresh attempt."""

    def raise_invalid(*_a, **_k):
        raise jwt.InvalidAudienceError("wrong aud")

    called = {"refresh": False}

    def refresh(*_a, **_k):
        called["refresh"] = True
        return {"id_token": "x"}

    monkeypatch.setattr("jwt_validator.validate_token", raise_invalid)
    monkeypatch.setattr("cognito_client.refresh_tokens", refresh)

    resp = auth_module.handler(
        _event(
            "/secret",
            cookies={
                "__Host-id_token": "tampered",
                "__Host-refresh_token": "should-not-be-used",
            },
        ),
        None,
    )
    assert called["refresh"] is False
    assert resp["status"] == "302"
    # Clears the token cookies (and the pre-v3 legacy names).
    values = [c["value"] for c in resp["headers"]["set-cookie"]]
    assert any(v.startswith("__Host-id_token=;") for v in values)
    assert any(v.startswith("__Host-refresh_token=;") for v in values)
    assert any(v.startswith("id_token=;") for v in values)
    assert any(v.startswith("refresh_token=;") for v in values)


def test_callback_state_mismatch_redirects_to_login(auth_module):
    event = _event(
        "/_callback",
        cookies={"__Host-auth_state": "expected-state"},
        querystring="code=abc&state=different-state",
    )
    resp = auth_module.handler(event, None)
    assert resp["status"] == "302"
    assert "/oauth2/authorize" in resp["headers"]["location"][0]["value"]


def test_callback_missing_code_redirects_home(auth_module):
    event = _event("/_callback", querystring="")
    resp = auth_module.handler(event, None)
    assert resp["status"] == "302"
    assert resp["headers"]["location"][0]["value"] == "/"


def test_callback_success_sets_tokens_and_clears_state(auth_module, monkeypatch):
    monkeypatch.setattr(
        "cognito_client.exchange_code",
        lambda *_a, **_k: {"id_token": "id", "refresh_token": "rt"},
    )
    monkeypatch.setattr(
        "jwt_validator.validate_token", lambda *_a, **_k: {"nonce": "n"}
    )
    event = _event(
        "/_callback",
        cookies={
            "__Host-auth_state": "s",
            "__Host-auth_nonce": "n",
            "__Host-auth_pkce_verifier": "v",
        },
        querystring="code=abc&state=s",
    )
    resp = auth_module.handler(event, None)
    assert resp["status"] == "302"
    assert resp["headers"]["location"][0]["value"] == "/"
    cookies = [c["value"] for c in resp["headers"]["set-cookie"]]
    assert any(c.startswith("__Host-id_token=id") for c in cookies)
    assert any(c.startswith("__Host-refresh_token=rt") for c in cookies)
    assert any(c.startswith("__Host-auth_state=;") for c in cookies)
    assert any(c.startswith("__Host-auth_nonce=;") for c in cookies)
    assert any(c.startswith("__Host-auth_pkce_verifier=;") for c in cookies)


def test_refresh_rotation_persists_new_refresh_token(auth_module, monkeypatch):
    """When Cognito rotates the refresh token, the new one must be persisted."""
    monkeypatch.setattr(
        "jwt_validator.validate_token",
        lambda *_a, **_k: (_ for _ in ()).throw(jwt.ExpiredSignatureError("x")),
    )
    monkeypatch.setattr(
        "cognito_client.refresh_tokens",
        lambda *_a, **_k: {"id_token": "new-token", "refresh_token": "rotated"},
    )
    resp = auth_module.handler(
        _event(
            "/app",
            cookies={"__Host-id_token": "expired", "__Host-refresh_token": "old"},
        ),
        None,
    )
    cookies = [c["value"] for c in resp["headers"]["set-cookie"]]
    assert any(c.startswith("__Host-refresh_token=rotated") for c in cookies)


def test_signout_revokes_refresh_token(auth_module, monkeypatch):
    called = {}

    def fake_revoke(refresh_token, domain, client_id, secret_arn):
        called["token"] = refresh_token
        return True

    monkeypatch.setattr("cognito_client.revoke_token", fake_revoke)
    resp = auth_module.handler(
        _event("/_signout", cookies={"__Host-refresh_token": "rt"}), None
    )
    assert called["token"] == "rt"
    assert resp["status"] == "302"


def test_signout_without_refresh_token_skips_revocation(auth_module, monkeypatch):
    def fake_revoke(*_a, **_k):
        raise AssertionError("revoke_token must not be called")

    monkeypatch.setattr("cognito_client.revoke_token", fake_revoke)
    resp = auth_module.handler(_event("/_signout"), None)
    assert resp["status"] == "302"


def test_signout_survives_revocation_failure(auth_module, monkeypatch):
    def fake_revoke(*_a, **_k):
        raise RuntimeError("cognito unreachable")

    monkeypatch.setattr("cognito_client.revoke_token", fake_revoke)
    resp = auth_module.handler(
        _event("/_signout", cookies={"__Host-refresh_token": "rt"}), None
    )
    # Cookies still cleared, redirect still happens.
    assert resp["status"] == "302"
    values = [c["value"] for c in resp["headers"]["set-cookie"]]
    assert any(v.startswith("__Host-refresh_token=;") for v in values)


def test_signout_clears_cookies_and_redirects_to_cognito(auth_module):
    resp = auth_module.handler(_event("/_signout"), None)
    assert resp["status"] == "302"
    loc = resp["headers"]["location"][0]["value"]
    assert loc.startswith("https://auth.example.com/logout?")
    assert "client_id=test-client" in loc
    cookie_values = [c["value"] for c in resp["headers"]["set-cookie"]]
    assert any(v.startswith("__Host-id_token=;") for v in cookie_values)
    assert any(v.startswith("__Host-refresh_token=;") for v in cookie_values)
    # Legacy (pre-v3) cookie names are cleared too.
    assert any(v.startswith("id_token=;") for v in cookie_values)
    assert any(v.startswith("refresh_token=;") for v in cookie_values)
