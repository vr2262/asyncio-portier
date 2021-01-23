"""Portier helper functions."""
import asyncio
import json
import re
from typing import cast
import urllib.parse

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
import jwt

from .cache import GenericCache, cache_delete, cache_get, cache_set
from .utils import b64decode, jwk_to_rsa


async def _async_get(url: str) -> str:
    split = urllib.parse.urlsplit(url)
    connect = asyncio.open_connection(split.hostname, 443, ssl=True)
    reader, writer = await connect
    query = f'GET {split.path} HTTP/1.0\r\nHost: {split.hostname}\r\n\r\n'
    writer.write(query.encode('latin-1'))
    line = b''
    while True:
        current_line = await reader.readline()
        if not current_line:
            break
        line = current_line
    writer.close()
    return line.decode('latin1').rstrip()


async def discover_keys(
    broker_url: str, cache: GenericCache
) -> dict[str, RSAPublicKey]:
    """Discover and return Broker's public keys.

    Return a dict mapping from Key ID strings to Public Key instances.
    Portier brokers implement the `OpenID Connect Discovery`_ specification.
    This function follows that specification to discover the broker's current
    cryptographic public keys:
    1. Fetch the Discovery Document from ``/.well-known/openid-configuration``.
    2. Parse it as JSON and read the ``jwks_uri`` property.
    3. Fetch the URL referenced by ``jwks_uri`` to retrieve a `JWK Set`_.
    4. Parse the JWK Set as JSON and extract keys from the ``keys`` property.
    Portier currently only supports keys with the ``RS256`` algorithm type.
    .. _OpenID Connect Discovery:
        https://openid.net/specs/openid-connect-discovery-1_0.html
    .. _JWK Set: https://tools.ietf.org/html/rfc7517#section-5
    """
    # Check for the cache
    cache_key = 'portier:jwks:' + broker_url
    if jwks := await cache_get(cache, cache_key):
        jwks_dict = json.loads(jwks)
    else:
        # Fetch Discovery Document
        url = broker_url.rstrip('/') + '/.well-known/openid-configuration'
        discovery = json.loads(await _async_get(url))
        if 'jwks_uri' not in discovery:
            raise ValueError('No jwks_uri in discovery document')

        # Fetch JWK Set document, then decode and load it
        jwks = await _async_get(discovery['jwks_uri'])
        jwks_dict = json.loads(jwks)
        if 'keys' not in jwks_dict:
            raise ValueError('No keys found in JWK Set')

        await cache_set(cache, cache_key, jwks)

    # Return the discovered keys as a Key ID -> RSA Public Key dictionary
    return {
        key['kid']: jwk_to_rsa(key)
        for key in jwks_dict['keys']
        if key['alg'] == 'RS256'}


async def get_verified_email(
    broker_url: str,
    token: str,
    audience: str,
    issuer: str,
    cache: GenericCache,
) -> tuple[str, str]:
    """Validate an Identity Token (JWT) and return its subject (email address).

    In Portier, the subject field contains the user's verified email address.
    This functions checks the authenticity of the JWT with the following steps:
    1. Verify that the JWT has a valid signature from a trusted broker.
    2. Validate that all claims are present and conform to expectations:
        * ``aud`` (audience) must match this website's origin.
        * ``iss`` (issuer) must match the broker's origin.
        * ``exp`` (expires) must be in the future.
        * ``iat`` (issued at) must be in the past.
        * ``sub`` (subject) must be an email address.
        * ``nonce`` (cryptographic nonce) must not have been seen previously.
    3. If present, verify that the ``nbf`` (not before) claim is in the past.
    Timestamps are allowed a few minutes of leeway to account for clock skew.
    This demo relies on the `PyJWT`_ library to check signatures and validate
    all claims except for ``sub`` and ``nonce``. Those are checked separately.
    .. _PyJWT: https://github.com/jpadilla/pyjwt
    """
    # Retrieve this broker's public keys
    keys = await discover_keys(broker_url, cache)

    # Locate the specific key used to sign this JWT via its ``kid`` header.
    raw_header, _, _ = token.partition('.')
    header = json.loads(b64decode(raw_header).decode('utf-8'))
    try:
        pub_key = keys[header['kid']]
    except KeyError:
        raise ValueError('Cannot find public key with ID %s' % header['kid'])

    # Verify the JWT's signature and validate its claims
    try:
        # jwt.decode's type hints are off, hence the cast
        payload = jwt.decode(token, cast(str, pub_key),
                             algorithms=['RS256'],
                             audience=audience,
                             issuer=issuer,
                             leeway=3 * 60)
    except Exception as exc:
        raise ValueError('Invalid JWT: %s' % exc)

    # Validate that the subject resembles an email address
    if not re.match('.+@.+', payload['sub']):
        raise ValueError('Invalid email address: %s' % payload['sub'])

    # Invalidate the nonce used in this JWT to prevent re-use
    nonce_key = "portier:nonce:%s" % payload['nonce']
    redirect_uri = await cache_get(cache, nonce_key)
    if not redirect_uri:
        raise ValueError('Invalid, expired, or re-used nonce')
    await cache_delete(cache, nonce_key)

    # Done!
    return payload['sub'], redirect_uri
