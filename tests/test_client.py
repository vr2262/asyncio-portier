import asyncio
import json
from unittest import TestCase as _TestCase
from unittest import mock

from asyncio_portier.client import (
    discover_keys, get_verified_email, _async_get_json)


BROKER_URL = 'http://broker-url.tld/'
TOKEN = 'eyJraWQiOiAiYWJjIn0.foo.bar'
JWKS_URI = 'http://broker-url.tld/jwks_uri'

KEY = {'kid': 'abc',
       'e': 'KHTPnNouCvwROWeIWQkJiw',
       'n': 'ZgKgqvEo_GZMamwy293IvA',
       'alg': 'RS256'}

DECODED_JWT = {
    'sub': 'foobar@restmail.com',
    'nonce': 'a nonce'
}
REDIRECT_URI = 'http://redirect_uri'

empty_cache = mock.MagicMock()
empty_cache.get.return_value = None


def CoroMock():
    """Mock callable lifted from http://stackoverflow.com/a/32505333."""
    coro = mock.Mock(name='CoroutineResult')
    corofunc = mock.Mock(
        name='CoroutineFunction', side_effect=asyncio.coroutine(coro))
    corofunc.coro = coro
    return corofunc


class TestCase(_TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def tearDown(self):
        self.loop.close()


# Tests copied from portier-python


class TestDiscoverKeys(TestCase):
    def test_call_the_well_known_url_and_the_jwks_uri(self):
        empty_cache.reset_mock()
        agj = 'asyncio_portier.client._async_get_json'
        with mock.patch(agj, new_callable=CoroMock) as mocked_async_get_json:
            mocked_async_get_json.coro.return_value = {
                'jwks_uri': JWKS_URI,
                'keys': []}
            keys = self.loop.run_until_complete(discover_keys(
                BROKER_URL, empty_cache, loop=self.loop))

        self.assertIsInstance(keys, dict)

        self.assertEqual(mocked_async_get_json.call_count, 2)
        mocked_async_get_json.assert_any_call(
            'http://broker-url.tld/.well-known/openid-configuration',
            self.loop)
        mocked_async_get_json.assert_any_call(JWKS_URI, self.loop)

        self.assertEqual(empty_cache.get.call_count, 1)
        self.assertEqual(empty_cache.set.call_count, 1)

    def test_raises_a_value_error_if_jwks_uri_is_not_found(self):
        agj = 'asyncio_portier.client._async_get_json'
        with mock.patch(agj, new_callable=CoroMock) as mocked_async_get_json:
            mocked_async_get_json.coro.return_value = {}
            with self.assertRaises(ValueError) as ve:
                self.loop.run_until_complete(discover_keys(
                    BROKER_URL, empty_cache, loop=self.loop))
            self.assertEqual(
                'No jwks_uri in discovery document', str(ve.exception))

    def test_raises_a_value_error_if_keys_not_found(self):
        agj = 'asyncio_portier.client._async_get_json'
        with mock.patch(agj, new_callable=CoroMock) as mocked_async_get_json:
            mocked_async_get_json.coro.return_value = {'jwks_uri': JWKS_URI}
            with self.assertRaises(ValueError) as ve:
                self.loop.run_until_complete(discover_keys(
                    BROKER_URL, empty_cache, loop=self.loop))
            self.assertEqual(
                'No keys found in JWK Set', str(ve.exception))


class TestGetVerifiedEmail(TestCase):
    def test_validate_the_subject_resembles_an_email_address(self):
        cache = mock.MagicMock()
        cache.get.side_effect = ({'keys': [KEY]}, REDIRECT_URI)
        with mock.patch('asyncio_portier.client.jwt') as mocked_jwt:
            mocked_jwt.decode.return_value = {'sub': 'invalid subject'}
            with self.assertRaises(ValueError) as ve:
                self.loop.run_until_complete(get_verified_email(
                    broker_url=BROKER_URL,
                    token=TOKEN,
                    audience='audience',
                    issuer='issuer',
                    cache=cache,
                    loop=self.loop))
            self.assertEqual(
                'Invalid email address: invalid subject', str(ve.exception))

    def test_get_verified_email_validate_it_can_find_a_public_key(self):
        cache = mock.MagicMock()
        cache.get.side_effect = ({'keys': []}, None)
        with mock.patch('asyncio_portier.client.jwt') as mocked_jwt:
            mocked_jwt.decode.return_value = {'sub': 'invalid subject'}
            with self.assertRaises(ValueError) as ve:
                self.loop.run_until_complete(get_verified_email(
                    broker_url=BROKER_URL,
                    token=TOKEN,
                    audience='audience',
                    issuer='issuer',
                    cache=cache,
                    loop=self.loop))
            self.assertEqual(
                'Cannot find public key with ID abc', str(ve.exception))

    def test_it_can_decode_the_jwt_payload(self):
        cache = mock.MagicMock()
        cache.get.side_effect = ({'keys': [KEY]}, REDIRECT_URI)
        with mock.patch('asyncio_portier.client.jwt') as mocked_jwt:
            mocked_jwt.decode.side_effect = Exception('Foobar')
            with self.assertRaises(ValueError) as ve:
                self.loop.run_until_complete(get_verified_email(
                    broker_url=BROKER_URL,
                    token=TOKEN,
                    audience='audience',
                    issuer='issuer',
                    cache=cache,
                    loop=self.loop))
            self.assertEqual('Invalid JWT: Foobar', str(ve.exception))

    def test_validate_the_nonce(self):
        cache = mock.MagicMock()
        cache.get.side_effect = ({'keys': [KEY]}, None)
        with mock.patch('asyncio_portier.client.jwt') as mocked_jwt:
            mocked_jwt.decode.return_value = DECODED_JWT
            with self.assertRaises(ValueError) as ve:
                self.loop.run_until_complete(get_verified_email(
                    broker_url=BROKER_URL,
                    token=TOKEN,
                    audience='audience',
                    issuer='issuer',
                    cache=cache,
                    loop=self.loop))
            self.assertEqual(
                'Invalid, expired, or re-used nonce', str(ve.exception))

    def test_return_the_subject_and_redirect_uri(self):
        cache = mock.MagicMock()
        cache.get.side_effect = ({'keys': [KEY]}, REDIRECT_URI)
        with mock.patch('asyncio_portier.client.jwt') as mocked_jwt:
            mocked_jwt.decode.return_value = DECODED_JWT
            result = self.loop.run_until_complete(get_verified_email(
                broker_url=BROKER_URL,
                token=TOKEN,
                audience='audience',
                issuer='issuer',
                cache=cache,
                loop=self.loop))
            self.assertEqual(result, (DECODED_JWT['sub'], REDIRECT_URI))


# Extra tests


class TestAsyncGetJSON(TestCase):
    def test_success(self):
        reader = mock.MagicMock()
        reader.readline = CoroMock()
        reader.readline.coro.side_effect = ['{"a": 1}'.encode('latin-1'), b'']
        writer = mock.MagicMock()
        open_connection = 'asyncio_portier.client.asyncio.open_connection'
        with mock.patch(open_connection, new_callable=CoroMock) as mocked_oc:
            mocked_oc.coro.return_value = reader, writer
            result = self.loop.run_until_complete(_async_get_json(
                BROKER_URL, self.loop))

        self.assertEqual(result, {'a': 1})

        self.assertEqual(reader.readline.call_count, 2)

        writer.write.assert_any_call(
            b'GET / HTTP/1.0\r\nHost: broker-url.tld\r\n\r\n')

        self.assertEqual(writer.close.call_count, 1)


class TestDiscoverKeysExtra(TestCase):
    def test_get_bytes_from_cache(self):
        """redis returns bytes"""
        cache = mock.MagicMock()
        cache.get.return_value = json.dumps({'keys': []}).encode()
        keys = self.loop.run_until_complete(discover_keys(
            BROKER_URL, cache, loop=self.loop))

        self.assertIsInstance(keys, dict)


class TestGetVerifiedEmailExtra(TestCase):
    def test_no_loop_given(self):
        """In tests, it's best to pass the asyncio event loop explicitly.

        http://stackoverflow.com/a/23642269/1475412
        """
        cache = mock.MagicMock()
        cache.get.side_effect = ({'keys': [KEY]}, REDIRECT_URI)
        with self.assertRaises(RuntimeError) as ve:
            self.loop.run_until_complete(get_verified_email(
                broker_url=BROKER_URL,
                token=TOKEN,
                audience='audience',
                issuer='issuer',
                cache=cache))
        self.assertEqual(
            "There is no current event loop in thread 'MainThread'.",
            str(ve.exception))
