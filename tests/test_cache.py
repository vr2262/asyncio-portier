from datetime import timedelta

import fakeredis
import fakeredis.aioredis
import pytest

from asyncio_portier.cache import cache_delete, cache_get, cache_set


@pytest.fixture
def blocking_cache():
    return fakeredis.FakeStrictRedis()


@pytest.fixture
async def async_cache():
    cache = await fakeredis.aioredis.create_redis_pool()
    yield cache
    cache.close()
    await cache.wait_closed()


@pytest.mark.asyncio
async def test_cache_get_blocking(blocking_cache):
    blocking_cache.set('foo', 'bar')
    result = await cache_get(blocking_cache, 'foo')
    assert result == 'bar'


@pytest.mark.asyncio
async def test_cache_get_async(async_cache):
    await async_cache.set('foo', 'bar')
    result = await cache_get(async_cache, 'foo')
    assert result == 'bar'


@pytest.mark.asyncio
async def test_cache_set_blocking(blocking_cache):
    result = await cache_set(blocking_cache, 'foo', 'bar')
    assert result
    assert blocking_cache.get('foo') == b'bar'


@pytest.mark.asyncio
async def test_cache_set_async(async_cache):
    set_result = await cache_set(async_cache, 'foo', 'bar')
    assert set_result

    get_result = await async_cache.get('foo')
    assert get_result == b'bar'


@pytest.mark.asyncio
@pytest.mark.parametrize('expiration', [None, timedelta(seconds=1)])
async def test_cache_set_async_convert_expiration(async_cache, expiration):
    set_result = await cache_set(async_cache, 'foo', 'bar', expiration)
    assert set_result

    get_result = await async_cache.get('foo')
    assert get_result == b'bar'


@pytest.mark.asyncio
async def test_cache_delete_blocking(blocking_cache):
    blocking_cache.set('foo', 'bar')
    result = await cache_delete(blocking_cache, 'foo')
    assert result == 1
    assert blocking_cache.get('foo') is None


@pytest.mark.asyncio
async def test_cache_delete_async(async_cache):
    await async_cache.set('foo', 'bar')

    delete_result = await cache_delete(async_cache, 'foo')
    assert delete_result == 1

    get_result = await async_cache.get('foo')
    assert get_result is None
