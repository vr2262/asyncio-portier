"""Cache utilities.

This tries to smooth out type-hinting and signature variations among caches.
For the moment, that means redis and aioredis.
"""
from collections.abc import Awaitable
from inspect import isawaitable
from datetime import timedelta
from typing import Optional, Protocol, Union, cast


class BlockingCache(Protocol):  # pragma: no cover
    def get(self, name: Union[str, bytes]) -> Union[None, str, bytes]: ...

    def set(
        self,
        name: Union[str, bytes],
        value: Union[bytes, float, int, str],
        ex: Union[None, int, timedelta] = ...
    ) -> Optional[bool]: ...

    def delete(self, *names: Union[str, bytes]) -> int: ...


class AsyncCache(Protocol):  # pragma: no cover
    def get(
        self, name: Union[str, bytes]
    ) -> Awaitable[Union[None, str, bytes]]: ...

    def set(
        self,
        name: Union[str, bytes],
        value: Union[bytes, float, int, str],
        expire: int = ...  # why does aioredis do this???
    ) -> Awaitable[Optional[bool]]: ...

    async def delete(self, *names: Union[str, bytes]) -> Awaitable[int]: ...


GenericCache = Union[BlockingCache, AsyncCache]


async def cache_get(
    cache: GenericCache, name: Union[str, bytes]
) -> Optional[str]:
    if isawaitable(_result := cache.get(name)):
        result = await cast(Awaitable[Union[None, str, bytes]], _result)
    else:
        result = cast(Union[None, str, bytes], _result)

    return result.decode() if isinstance(result, bytes) else result


async def cache_set(
    cache: GenericCache,
    name: Union[str, bytes],
    value: Union[bytes, float, int, str],
    expiration: Union[None, int, timedelta] = timedelta(minutes=5).seconds,
) -> Optional[bool]:
    try:
        return cast(BlockingCache, cache).set(name, value, expiration)
    except TypeError:
        pass

    if expiration is None:
        expire = 0
    elif isinstance(expiration, timedelta):
        expire = expiration.seconds
    else:
        expire = expiration

    return await cast(AsyncCache, cache).set(name, value, expire=expire)


async def cache_delete(cache: GenericCache, name: Union[str, bytes]) -> int:
    if isawaitable(result := cache.delete(name)):
        return await cast(Awaitable[int], result)
    return cast(int, result)
