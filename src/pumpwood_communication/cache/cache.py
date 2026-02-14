"""Module to implement local cache when using Pumpwood Comunication."""
import os
import hashlib
from typing import Any
from pathlib import Path
from diskcache import FanoutCache, Timeout
from pumpwood_communication.config import (
    PUMPWOOD_COMUNICATION__CACHE_BASE_PATH)
from pumpwood_communication.serializers import pumpJsonDump
from pumpwood_communication.exceptions import PumpWoodCacheError
from loguru import logger


class PumpwoodCache:
    """Class to implement local cache for Pumpwood Comunication requests."""

    def __init__(self):
        """__init__."""
        self._create_cache_object()

    def _create_cache_object(self):
        self._size_limit = int(os.getenv(
            'PUMPWOOD_COMUNICATION__CACHE_LIMIT_MB', 250)) * 1e8
        self._expire_time = int(os.getenv(
            'PUMPWOOD_COMUNICATION__CACHE_DEFAULT_EXPIRE', 60))
        self._transaction_timeout = float(os.getenv(
            'PUMPWOOD_COMUNICATION__CACHE_TRANSACTION_TIMEOUT', 0.1))
        self._n_shards = int(os.getenv(
            'PUMPWOOD_COMUNICATION__N_SHARDS', 8))
        cache_path = (
            Path('/tmp/pumpwood_cache/') /
            PUMPWOOD_COMUNICATION__CACHE_BASE_PATH)
        self._cache = FanoutCache(
            directory=cache_path, cache_size=self._size_limit,
            tag_index=True, timeout=self._transaction_timeout,
            shards=self._n_shards)

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

    def clear(self) -> bool:
        """Invalidate cache.

        Returns:
            True is ok.
        """
        return self._cache.clear()

    def evict(self, tag_dict: dict) -> bool:
        """Invalidate cache from a tag.

        Returns:
            True is ok.
        """
        from pumpwood_communication.exceptions import PumpWoodCacheError
        if tag_dict is None:
            msg = (
                "At pumpwood_communication cache.evict tag_dict should not be "
                "'None'. To envict all databse use clear function.")
            raise PumpWoodCacheError(msg)
        hash_str = self._generate_hash(hash_dict=tag_dict)
        return self._cache.evict(hash_str)

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

    def set(self, hash_dict: dict, value: Any, expire: int = None,
            tag_dict: dict = None) -> bool:
        """Set cache value.

        Args:
            hash_dict (dict):
                A dictonary with information that will be used on hash.
            value (Any):
                Value that will be set on diskcache.
            expire (int):
                Number of seconds that will be considered as expirity time.
            tag_dict (dict):
                Optional parameter to set a tag to cache. Tagged cache can be
                envicted together using envict function.

        Returns:
            Return a boolean value
        """
        if hash_dict is None:
            msg = (
                "At pumpwood_communication cache.set hash_dict should not be "
                "'None'")
            raise PumpWoodCacheError(msg)
        expire_time = expire or self._expire_time
        hash_str = self._generate_hash(hash_dict=hash_dict)

        tag_str = None
        if tag_dict is not None:
            tag_str = self._generate_hash(hash_dict=tag_dict)

        try:
            return self._cache.set(
                hash_str, value=value, expire=expire_time,
                tag=tag_str)
        except Timeout:
            # in case of deadlock
            warning_msg = (
                "Cache on deadlock, it was not possible " +
                "to set information for key %s" % (hash_str))
            logger.warning(warning_msg)
            return False
        except Exception as e:
            msg = (
                'Error when retrieving cache not associated with Timeout. '
                '{error}')
            raise PumpWoodCacheError(
                message=msg, payload={'error': str(e)})


default_cache = PumpwoodCache()
"""Generate a default cache for Pumpwood."""
