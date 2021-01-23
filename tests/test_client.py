import json
from unittest.mock import AsyncMock, Mock, patch

import pytest

from asyncio_portier.client import (
    _async_get,
    discover_keys,
    get_verified_email
)

BROKER_URL = "http://broker-url.tld/"
TOKEN = "eyJraWQiOiAiYWJjIn0.foo.bar"
JWKS_URI = "http://broker-url.tld/jwks_uri"

KEY = {"kid": "abc",
       "e": "KHTPnNouCvwROWeIWQkJiw",
       "n": "ZgKgqvEo_GZMamwy293IvA",
       "alg": "RS256"}

DECODED_JWT = {
    "sub": "foobar@restmail.com",
    "nonce": "a nonce"
}
REDIRECT_URI = "http://redirect_uri"


# Test discover_keys helper
@pytest.mark.asyncio
@patch('asyncio_portier.client._async_get')
@patch('asyncio_portier.client.cache_get')
@patch('asyncio_portier.client.cache_set')
async def test_discover_key_call_the_well_known_url_and_the_jwks_uri(
    mock_cache_set, mock_cache_get, mock_get
):
    mock_cache_get.return_value = None
    mock_get.return_value = json.dumps(dict(jwks_uri=JWKS_URI, keys=[]))

    keys = await discover_keys(BROKER_URL, None)

    assert keys == {}

    first, second = mock_get.call_args_list
    assert first.args == (
        'http://broker-url.tld/.well-known/openid-configuration',
    )
    assert second.args == (JWKS_URI,)

    assert mock_cache_get.call_count == 1
    assert mock_cache_set.call_count == 1


@pytest.mark.asyncio
@patch('asyncio_portier.client._async_get')
@patch('asyncio_portier.client.cache_get')
async def test_discover_key_raises_a_value_error_if_jwks_uri_is_not_found(
    mock_cache_get, mock_get
):
    mock_cache_get.return_value = None
    mock_get.return_value = '{}'

    with pytest.raises(ValueError) as e:
        await discover_keys(BROKER_URL, None)
    assert "No jwks_uri in discovery document" in str(e)


@pytest.mark.asyncio
@patch('asyncio_portier.client._async_get')
@patch('asyncio_portier.client.cache_get')
async def test_discover_key_raises_a_value_error_if_keys_not_found(
    mock_cache_get, mock_get
):
    mock_cache_get.return_value = None
    mock_get.return_value = json.dumps({'jwks_uri': JWKS_URI})

    with pytest.raises(ValueError) as e:
        await discover_keys(BROKER_URL, None)
    assert "No keys found in JWK Set" in str(e)


# Test get_verified_email helper
@pytest.mark.asyncio
@patch('asyncio_portier.client.cache_get')
@patch('asyncio_portier.client.jwt')
async def test_get_verified_email_validate_the_subject_email_address(
    mock_jwt, mock_cache_get
):
    mock_cache_get.side_effect = (json.dumps({"keys": [KEY]}), REDIRECT_URI)
    mock_jwt.decode.return_value = {"sub": "invalid subject"}

    with pytest.raises(ValueError) as e:
        await get_verified_email(
            broker_url=BROKER_URL,
            token=TOKEN,
            audience="audience",
            issuer="issuer",
            cache=None,
        )
    assert "Invalid email address: invalid subject" in str(e)


@pytest.mark.asyncio
@patch('asyncio_portier.client.cache_get')
@patch('asyncio_portier.client.jwt')
async def test_get_verified_email_validate_it_can_find_a_public_key(
    mock_jwt, mock_cache_get
):
    mock_cache_get.side_effect = (json.dumps({"keys": []}), None)
    mock_jwt.decode.return_value = {"sub": "invalid subject"}

    with pytest.raises(ValueError) as e:
        await get_verified_email(
            broker_url=BROKER_URL,
            token=TOKEN,
            audience="audience",
            issuer="issuer",
            cache=None,
        )
    assert "Cannot find public key with ID abc" in str(e)


@pytest.mark.asyncio
@patch('asyncio_portier.client.cache_get')
@patch('asyncio_portier.client.jwt')
async def test_get_verified_email_validate_it_can_decode_the_jwt_payload(
    mock_jwt, mock_cache_get
):
    mock_cache_get.side_effect = (json.dumps({"keys": [KEY]}), REDIRECT_URI)
    mock_jwt.decode.side_effect = Exception("Foobar")

    with pytest.raises(ValueError) as e:
        await get_verified_email(
            broker_url=BROKER_URL,
            token=TOKEN,
            audience="audience",
            issuer="issuer",
            cache=None,
        )
    assert "Invalid JWT: Foobar" in str(e)


@pytest.mark.asyncio
@patch('asyncio_portier.client.cache_get')
@patch('asyncio_portier.client.jwt')
async def test_get_verified_email_validate_the_nonce(mock_jwt, mock_cache_get):
    mock_cache_get.side_effect = (json.dumps({"keys": [KEY]}), None)
    mock_jwt.decode.return_value = DECODED_JWT

    with pytest.raises(ValueError) as e:
        await get_verified_email(
            broker_url=BROKER_URL,
            token=TOKEN,
            audience="audience",
            issuer="issuer",
            cache=None,
        )
    assert "Invalid, expired, or re-used nonce" in str(e)


@pytest.mark.asyncio
@patch('asyncio_portier.client.cache_get')
@patch('asyncio_portier.client.jwt')
@patch('asyncio_portier.client.cache_delete')
async def test_get_verified_return_the_subject_and_redirect_uri(
    mock_cache_delete, mock_jwt, mock_cache_get
):
    mock_cache_get.side_effect = (json.dumps({"keys": [KEY]}), REDIRECT_URI)
    mock_jwt.decode.return_value = DECODED_JWT

    result = await get_verified_email(
        broker_url=BROKER_URL,
        token=TOKEN,
        audience="audience",
        issuer="issuer",
        cache=None,
    )
    assert result == (DECODED_JWT['sub'], REDIRECT_URI)

    [delete_args] = mock_cache_delete.call_args_list
    assert delete_args.args == (None, f"portier:nonce:{DECODED_JWT['nonce']}")


# Extra tests
@pytest.mark.asyncio
@patch('asyncio_portier.client.asyncio.open_connection')
async def test_async_get(mock_open_connection):
    expected_result = '{"a": 1}'
    reader = Mock()
    reader.readline = AsyncMock()
    reader.readline.side_effect = (expected_result.encode('latin-1'), b'')

    writer = Mock()

    mock_open_connection.return_value = (reader, writer)

    result = await _async_get(BROKER_URL)

    assert result == expected_result

    assert reader.readline.call_count == 2

    [write_args] = writer.write.call_args_list
    assert write_args.args == (
        b'GET / HTTP/1.0\r\nHost: broker-url.tld\r\n\r\n',
    )

    assert writer.close.call_count == 1
