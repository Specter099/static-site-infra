"""Unit tests for cognito_client (no network)."""

import base64
import importlib
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

AUTH_DIR = Path(__file__).resolve().parent.parent / "specter_static_site" / "auth"


@pytest.fixture
def cc(tmp_path, monkeypatch):
    work = tmp_path / "auth_pkg"
    work.mkdir()
    for src in AUTH_DIR.glob("*.py"):
        (work / src.name).write_text(src.read_text())
    (work / "config.json").write_text("{}")
    monkeypatch.syspath_prepend(str(work))
    for name in ("handler", "jwt_validator", "cognito_client"):
        sys.modules.pop(name, None)
    mod = importlib.import_module("cognito_client")
    yield mod
    for name in ("handler", "jwt_validator", "cognito_client"):
        sys.modules.pop(name, None)


def _fake_http(status=200, payload=b'{"id_token":"x"}'):
    http = MagicMock()
    resp = MagicMock()
    resp.status = status
    resp.data = payload
    http.request.return_value = resp
    return http


def test_auth_header_uses_basic_b64(cc):
    header = cc._auth_header("client-id", "secret")
    assert header.startswith("Basic ")
    decoded = base64.b64decode(header.removeprefix("Basic ")).decode()
    assert decoded == "client-id:secret"


def test_exchange_code_urlencodes_body(cc, monkeypatch):
    http = _fake_http()
    monkeypatch.setattr(cc, "http", http)
    tokens = cc.exchange_code(
        "the code+with symbols",
        "https://site/_callback",
        "auth.example.com",
        "client-id",
        "secret",
    )
    assert tokens == {"id_token": "x"}
    body = http.request.call_args.kwargs["body"]
    # Special chars in the code MUST be URL-encoded, not raw.
    assert "the+code%2Bwith+symbols" in body or "the%20code%2Bwith%20symbols" in body
    assert "grant_type=authorization_code" in body


def test_exchange_code_raises_on_non_200(cc, monkeypatch):
    monkeypatch.setattr(cc, "http", _fake_http(status=400, payload=b"bad"))
    with pytest.raises(RuntimeError, match="400"):
        cc.exchange_code("c", "u", "d", "ci", "cs")


def test_refresh_tokens_returns_empty_on_failure(cc, monkeypatch):
    monkeypatch.setattr(cc, "http", _fake_http(status=401, payload=b"no"))
    assert cc.refresh_tokens("rt", "d", "ci", "cs") == {}


def test_refresh_tokens_success(cc, monkeypatch):
    monkeypatch.setattr(
        cc, "http", _fake_http(status=200, payload=b'{"id_token":"new"}')
    )
    assert cc.refresh_tokens("rt", "d", "ci", "cs") == {"id_token": "new"}
