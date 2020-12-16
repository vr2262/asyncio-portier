from asyncio_portier.utils import b64decode


def test_b64decode():
    assert b64decode('abcd') == b'i\xb7\x1d'
