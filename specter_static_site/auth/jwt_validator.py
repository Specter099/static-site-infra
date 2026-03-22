"""Validate Cognito JWTs using JWKS."""

import json
import time

import jwt
import urllib3

http = urllib3.PoolManager()

# Module-level cache for JWKS keys (persists across warm Lambda invocations).
_jwks_cache: dict = {}
_jwks_cache_time: float = 0
_JWKS_CACHE_TTL = 3600  # 1 hour


def _get_jwks(user_pool_id: str, region: str) -> dict:
    global _jwks_cache, _jwks_cache_time
    now = time.time()
    if _jwks_cache and (now - _jwks_cache_time) < _JWKS_CACHE_TTL:
        return _jwks_cache

    url = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json"
    resp = http.request("GET", url)
    if resp.status != 200:
        raise RuntimeError(f"Failed to fetch JWKS: {resp.status}")
    _jwks_cache = json.loads(resp.data.decode())
    _jwks_cache_time = now
    return _jwks_cache


def validate_token(token: str, user_pool_id: str, client_id: str, region: str) -> dict:
    """Validate a Cognito id_token. Returns decoded claims or raises."""
    jwks = _get_jwks(user_pool_id, region)

    # Get the key ID from the token header.
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")
    if not kid:
        raise jwt.InvalidTokenError("Token missing kid header")

    # Find the matching public key.
    key_data = None
    for key in jwks.get("keys", []):
        if key["kid"] == kid:
            key_data = key
            break
    if not key_data:
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
