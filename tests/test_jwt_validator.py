"""Unit tests for jwt_validator with a local RSA keypair (no network)."""

import importlib
import json
import sys
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

AUTH_DIR = Path(__file__).resolve().parent.parent / "specter_static_site" / "auth"


@pytest.fixture
def jwt_mod(tmp_path, monkeypatch):
    work = tmp_path / "auth_pkg"
    work.mkdir()
    for src in AUTH_DIR.glob("*.py"):
        (work / src.name).write_text(src.read_text())
    (work / "config.json").write_text("{}")
    monkeypatch.syspath_prepend(str(work))
    for name in ("handler", "jwt_validator", "cognito_client"):
        sys.modules.pop(name, None)
    mod = importlib.import_module("jwt_validator")
    # Ensure a clean cache between tests.
    mod._jwks_cache = {}
    mod._jwks_cache_time = 0.0
    mod._last_forced_refresh = 0.0
    yield mod
    for name in ("handler", "jwt_validator", "cognito_client"):
        sys.modules.pop(name, None)


def _make_rsa_jwk(kid="test-kid"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk["kid"] = kid
    jwk["alg"] = "RS256"
    jwk["use"] = "sig"
    return key, pub_pem, jwk


def _sign(key, claims, kid="test-kid"):
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


def test_validate_token_happy_path(jwt_mod, monkeypatch):
    key, _, jwk = _make_rsa_jwk()
    pool = "us-east-1_Test"
    region = "us-east-1"
    client = "client-1"
    token = _sign(
        key,
        {
            "iss": f"https://cognito-idp.{region}.amazonaws.com/{pool}",
            "aud": client,
            "exp": int(time.time()) + 60,
            "iat": int(time.time()),
        },
    )
    monkeypatch.setattr(jwt_mod, "_fetch_jwks", lambda *_a, **_k: {"keys": [jwk]})
    claims = jwt_mod.validate_token(token, pool, client, region)
    assert claims["aud"] == client


def test_expired_token_raises(jwt_mod, monkeypatch):
    key, _, jwk = _make_rsa_jwk()
    pool, region, client = "us-east-1_Test", "us-east-1", "client-1"
    token = _sign(
        key,
        {
            "iss": f"https://cognito-idp.{region}.amazonaws.com/{pool}",
            "aud": client,
            "exp": int(time.time()) - 10,
        },
    )
    monkeypatch.setattr(jwt_mod, "_fetch_jwks", lambda *_a, **_k: {"keys": [jwk]})
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt_mod.validate_token(token, pool, client, region)


def test_wrong_audience_raises(jwt_mod, monkeypatch):
    key, _, jwk = _make_rsa_jwk()
    pool, region = "us-east-1_Test", "us-east-1"
    token = _sign(
        key,
        {
            "iss": f"https://cognito-idp.{region}.amazonaws.com/{pool}",
            "aud": "other-client",
            "exp": int(time.time()) + 60,
        },
    )
    monkeypatch.setattr(jwt_mod, "_fetch_jwks", lambda *_a, **_k: {"keys": [jwk]})
    with pytest.raises(jwt.InvalidAudienceError):
        jwt_mod.validate_token(token, pool, "expected-client", region)


def test_unknown_kid_forces_jwks_refresh(jwt_mod, monkeypatch):
    """On kid miss, validator should force-refresh JWKS once and retry."""
    key, _, jwk = _make_rsa_jwk(kid="new-kid")
    pool, region, client = "us-east-1_Test", "us-east-1", "client-1"
    token = _sign(
        key,
        {
            "iss": f"https://cognito-idp.{region}.amazonaws.com/{pool}",
            "aud": client,
            "exp": int(time.time()) + 60,
        },
        kid="new-kid",
    )

    stale = {"keys": [{"kid": "old-kid", "kty": "RSA", "n": "x", "e": "AQAB"}]}
    calls = {"n": 0}

    def fake_fetch(*_a, **_k):
        calls["n"] += 1
        return stale if calls["n"] == 1 else {"keys": [jwk]}

    monkeypatch.setattr(jwt_mod, "_fetch_jwks", fake_fetch)
    claims = jwt_mod.validate_token(token, pool, client, region)
    assert claims["aud"] == client
    assert calls["n"] == 2  # initial + one force-refresh


def test_missing_kid_rejected(jwt_mod, monkeypatch):
    key, _, _ = _make_rsa_jwk()
    token = jwt.encode({"a": 1}, key, algorithm="RS256")  # no kid header
    monkeypatch.setattr(jwt_mod, "_fetch_jwks", lambda *_a, **_k: {"keys": []})
    with pytest.raises(jwt.InvalidTokenError, match="kid"):
        jwt_mod.validate_token(token, "pool", "client", "us-east-1")


def test_non_rs256_alg_rejected(jwt_mod, monkeypatch):
    # Forge a token with alg=HS256 (Cognito only issues RS256).
    hs_token = jwt.encode(
        {"a": 1}, "secret", algorithm="HS256", headers={"kid": "any"}
    )
    monkeypatch.setattr(jwt_mod, "_fetch_jwks", lambda *_a, **_k: {"keys": []})
    with pytest.raises(jwt.InvalidTokenError, match="algorithm"):
        jwt_mod.validate_token(hs_token, "pool", "client", "us-east-1")


def test_forced_jwks_refresh_is_rate_limited(jwt_mod, monkeypatch):
    """Unknown-kid tokens must not trigger a JWKS fetch on every request."""
    key, _, jwk = _make_rsa_jwk(kid="known-kid")
    pool, region, client = "us-east-1_Test", "us-east-1", "client-1"
    unknown = _sign(
        key,
        {
            "iss": f"https://cognito-idp.{region}.amazonaws.com/{pool}",
            "aud": client,
            "exp": int(time.time()) + 60,
        },
        kid="attacker-kid",
    )

    calls = {"n": 0}

    def fake_fetch(*_a, **_k):
        calls["n"] += 1
        return {"keys": [jwk]}  # never contains attacker-kid

    monkeypatch.setattr(jwt_mod, "_fetch_jwks", fake_fetch)

    with pytest.raises(jwt.InvalidTokenError, match="not found"):
        jwt_mod.validate_token(unknown, pool, client, region)
    assert calls["n"] == 2  # initial + one forced refresh

    # A second garbage-kid token inside the rate-limit window must be
    # rejected from cache without another fetch.
    with pytest.raises(jwt.InvalidTokenError, match="not found"):
        jwt_mod.validate_token(unknown, pool, client, region)
    assert calls["n"] == 2
