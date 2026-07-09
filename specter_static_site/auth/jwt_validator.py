"""Validate Cognito JWTs using JWKS."""

import json
import time

import jwt
import urllib3

http = urllib3.PoolManager()

# Module-level cache for JWKS keys (persists across warm Lambda invocations).
# TTL is short so Cognito key rotation is picked up quickly. Independently, the
# cache is force-refreshed on a kid miss (new key published mid-TTL) — but at
# most once per _FORCE_REFRESH_MIN_INTERVAL, so attacker-supplied tokens with
# garbage kids can't turn every request into a JWKS fetch.
_jwks_cache: dict = {}
_jwks_cache_time: float = 0.0
_JWKS_CACHE_TTL = 600  # 10 minutes
_last_forced_refresh: float = 0.0
_FORCE_REFRESH_MIN_INTERVAL = 30  # seconds


def _fetch_jwks(user_pool_id: str, region: str) -> dict:
    url = (
        f"https://cognito-idp.{region}.amazonaws.com/"
        f"{user_pool_id}/.well-known/jwks.json"
    )
    resp = http.request("GET", url, timeout=urllib3.Timeout(connect=2.0, read=3.0))
    if resp.status != 200:
        raise RuntimeError(f"Failed to fetch JWKS: {resp.status}")
    return json.loads(resp.data.decode())


def _get_jwks(user_pool_id: str, region: str, *, force: bool = False) -> dict:
    global _jwks_cache, _jwks_cache_time, _last_forced_refresh
    now = time.time()
    if force:
        # Rate-limit forced refreshes; return the (possibly stale) cache in
        # between. Legitimate key rotation tolerates a short delay.
        if _jwks_cache and (now - _last_forced_refresh) < _FORCE_REFRESH_MIN_INTERVAL:
            return _jwks_cache
        _last_forced_refresh = now
    elif _jwks_cache and (now - _jwks_cache_time) < _JWKS_CACHE_TTL:
        return _jwks_cache
    _jwks_cache = _fetch_jwks(user_pool_id, region)
    _jwks_cache_time = now
    return _jwks_cache


def _find_key(jwks: dict, kid: str) -> dict | None:
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return key
    return None


def validate_token(token: str, user_pool_id: str, client_id: str, region: str) -> dict:
    """Validate a Cognito id_token. Returns decoded claims or raises."""
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")
    if not kid:
        raise jwt.InvalidTokenError("Token missing kid header")
    if unverified_header.get("alg") != "RS256":
        raise jwt.InvalidTokenError("Unsupported JWT algorithm")

    jwks = _get_jwks(user_pool_id, region)
    key_data = _find_key(jwks, kid)
    if key_data is None:
        # Could be a newly-rotated key — force a refresh and try once more.
        jwks = _get_jwks(user_pool_id, region, force=True)
        key_data = _find_key(jwks, kid)
    if key_data is None:
        raise jwt.InvalidTokenError(f"Key {kid} not found in JWKS")

    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
    issuer = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"

    return jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        issuer=issuer,
        audience=client_id,
        options={"require": ["exp", "iss", "aud"]},
    )
