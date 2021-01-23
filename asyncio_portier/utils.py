"""Utilities for asyncio-portier.

Implementation taken from https://github.com/portier/portier-python/blob/
c1f966f61c9c31572711dc0688b78aa93341f610/portier/utils.py
"""
from base64 import urlsafe_b64decode
import codecs

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

# Public API
__all__ = (
    'b64decode',
    'jwk_to_rsa'
)


def b64decode(text: str) -> bytes:
    """Mostly the same as base64url_decode from PyJWT."""
    binary = text.encode('ascii')

    if rem := len(binary) % 4:
        binary += b'=' * (4 - rem)

    return urlsafe_b64decode(binary)


def jwk_to_rsa(key: dict[str, str]) -> rsa.RSAPublicKey:
    """Convert a deserialized JWK into an RSA Public Key instance."""
    e = int(codecs.encode(b64decode(key['e']), 'hex'), 16)
    n = int(codecs.encode(b64decode(key['n']), 'hex'), 16)
    return rsa.RSAPublicNumbers(e, n).public_key(default_backend())
