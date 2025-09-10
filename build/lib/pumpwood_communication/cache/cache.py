"""Module to implement local cache when using Pumpwood Comunication."""
import os
import hashlib
from diskcache import Cache
from typing import Any
from pumpwood_communication.serializers import pumpJsonDump


class PumpwoodCache:
    """Class to implement local cache for Pumpwood Comunication requests."""

    def __init__(self):
        """__init__."""
        self._size_limit = int(os.getenv(
            'PUMPWOOD_COMUNICATION__CACHE_LIMIT_MB', 250)) * 1e8
        self._expire_time = int(os.getenv(
            'PUMPWOOD_COMUNICATION__CACHE_DEFAULT_EXPIRE', 60))
        cache_path = '/tmp/pumpwood_cache/' # NOQA
        self._cache = Cache(
            directory=cache_path, cache_size=self._size_limit)

    @classmethod
    def _generate_hash(cls, hash_dict: dict) -> str:
        """Generate a hash to be used to storage and retrieve cache.

        It will use pumpJsonDump function from serializers to dump correctly
        any complex data such as date, geometry and numpy.

        Args:
            hash_dict (dict):
                A dictonary with information that will be used on hash.

        Returns:
            Return a hash that will be used as cache.
        """
        str_hash_dict = pumpJsonDump(hash_dict, sort_keys=True)
        return hashlib.sha512(str_hash_dict).hexdigest()

    def get(self, hash_dict: dict) -> Any:
        """Get a value from cache.

        Args:
            hash_dict (dict):
                A dictonary with information that will be used on hash.

        Returns:
            Return the cached value or None if not found.
        """
        hash_str = self._generate_hash(hash_dict=hash_dict)
        return self._cache.get(hash_str)

    def set(self, hash_dict: dict, value: Any, expire: int = None) -> bool:
        """Set cache value.

        Args:
            hash_dict (dict):
                A dictonary with information that will be used on hash.
            value (Any):
                Value that will be set on diskcache.
            expire (int):
                Number of seconds that will be considered as expirity time.

        Returns:
            Return a boolean value
        """
        hash_str = self._generate_hash(hash_dict=hash_dict)
        return self._cache.set(
            hash_str, value=value, expire=self._expire_time)


default_cache = PumpwoodCache()
"""Generate a default cache for Pumpwood."""
