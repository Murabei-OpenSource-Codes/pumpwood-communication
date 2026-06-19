"""Module to implement local cache when using Pumpwood Comunication."""
import hashlib
import sqlite3
import threading
import time
from typing import Any, Callable, Final, Optional
from pathlib import Path
from diskcache import FanoutCache, Timeout
from pumpwood_communication.config import (
    CACHE_BASE_PATH, CACHE_LIMIT_MB, CACHE_DEFAULT_EXPIRE,
    CACHE_TRANSACTION_TIMEOUT, CACHE_N_SHARDS, CACHE_ENABLE,
    CACHE_RETRY_ATTEMPTS, CACHE_RETRY_DELAY)
from pumpwood_communication.serializers import pumpJsonDump
from pumpwood_communication.exceptions import PumpWoodCacheError
from loguru import logger


class PumpwoodCache:
    """Class to implement local cache for Pumpwood Comunication requests."""

    _INIT_LOCK = threading.Lock()
    """Lock to serialize FanoutCache initialization across threads."""

    def __init__(self):
        """Initialize cache settings from configuration."""
        self._cache = None
        self._size_limit = CACHE_LIMIT_MB
        self._expire_time = CACHE_DEFAULT_EXPIRE
        self._transaction_timeout = CACHE_TRANSACTION_TIMEOUT
        self._n_shards = CACHE_N_SHARDS
        self._enable = CACHE_ENABLE
        self._retry_attempts = CACHE_RETRY_ATTEMPTS
        self._retry_delay = CACHE_RETRY_DELAY
        self._cache_path = (
            Path('/tmp/pumpwood_cache/') /
            CACHE_BASE_PATH)

    def _build_fanout_cache(self) -> Optional[FanoutCache]:
        """Build FanoutCache with retries on SQLite lock contention.

        Returns:
            Optional[FanoutCache]:
                Configured cache instance, or None when initialization
                fails after all retry attempts.
        """
        last_error = None
        for attempt in range(1, self._retry_attempts + 1):
            try:
                return FanoutCache(
                    directory=self._cache_path,
                    cache_size=self._size_limit,
                    tag_index=True,
                    timeout=self._transaction_timeout,
                    shards=self._n_shards)
            except (Timeout, sqlite3.OperationalError) as error:
                last_error = error
                if attempt >= self._retry_attempts:
                    break
                delay = self._retry_delay * attempt
                warning_msg = (
                    "Cache init locked, retry {attempt}/{total} "
                    "after {delay}s")
                logger.warning(
                    warning_msg.format(
                        attempt=attempt,
                        total=self._retry_attempts,
                        delay=delay))
                time.sleep(delay)

        warning_msg = (
            "Cache init failed after {total} attempts: {error}")
        logger.warning(
            warning_msg.format(
                total=self._retry_attempts,
                error=last_error))
        return None

    def _create_cache_object(self) -> None:
        """Create FanoutCache once in a thread-safe way."""
        if self._cache is not None:
            return
        with self._INIT_LOCK:
            if self._cache is None:
                self._cache = self._build_fanout_cache()

    def _execute_with_retry(self, operation: Callable[[], Any],
                            default: Any,
                            operation_name: str) -> Any:
        """Execute a cache operation with retries on lock contention.

        Args:
            operation (Callable[[], Any]):
                Callable that performs the cache operation.
            default (Any):
                Value returned when all retries are exhausted or when
                cache initialization fails.
            operation_name (str):
                Operation label used in warning logs.

        Returns:
            Any:
                Result from ``operation``, or ``default`` on failure.
        """
        # Try to execute the operation with retries on lock contention.
        last_error = None
        for attempt in range(1, self._retry_attempts + 1):
            try:
                self._create_cache_object()
                if self._cache is None:
                    return default
                return operation()
            except (Timeout, sqlite3.OperationalError) as error:
                last_error = error
                if attempt >= self._retry_attempts:
                    break
                delay = self._retry_delay * attempt
                warning_msg = (
                    "Cache {operation} locked, retry {attempt}/{total} "
                    "after {delay}s")
                logger.warning(
                    warning_msg.format(
                        operation=operation_name,
                        attempt=attempt,
                        total=self._retry_attempts,
                        delay=delay))
                time.sleep(delay)

        warning_msg = (
            "Cache {operation} failed after {total} attempts: {error}")
        logger.warning(
            warning_msg.format(
                operation=operation_name, total=self._retry_attempts,
                error=last_error))
        return default

    @classmethod
    def generate_hash(cls, hash_dict: dict) -> str:
        """Generate a hash to be used to storage and retrieve cache.

        It will use pumpJsonDump function from serializers to dump correctly
        any complex data such as date, geometry and numpy.

        Expose _generate_hash

        Args:
            hash_dict (dict):
                A dictonary with information that will be used on hash.

        Returns:
            Return a hash that will be used as cache.
        """
        return cls._generate_hash(hash_dict=hash_dict)

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
        return self._execute_with_retry(
            operation=lambda: self._cache.clear(),
            default=False, operation_name="clear")

    def evict(self, tag_dict: dict) -> bool:
        """Invalidate cache from a tag.

        Returns:
            True is ok.
        """
        if tag_dict is None:
            msg = (
                "At pumpwood_communication cache.evict tag_dict should not be "
                "'None'. To envict all databse use clear function.")
            raise PumpWoodCacheError(msg)

        hash_str = self.generate_hash(hash_dict=tag_dict)
        return self._execute_with_retry(
            operation=lambda: self._cache.evict(hash_str),
            default=False, operation_name="evict")

    def get(self, hash_dict: dict) -> Any:
        """Get a value from cache.

        Args:
            hash_dict (dict):
                A dictonary with information that will be used on hash.

        Returns:
            Return the cached value or None if not found.
        """
        if not self._enable:
            logger.info("Get cache not enable")
            return None

        # It cache time is set to 0, than disable cache,
        # this is usefull for testing
        if self._expire_time == 0:
            return None

        hash_str = self.generate_hash(hash_dict=hash_dict)
        return self._execute_with_retry(
            operation=lambda: self._cache.get(hash_str),
            default=None, operation_name="get")

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
        if not self._enable:
            logger.info("Set cache not enable")
            return True

        if hash_dict is None:
            msg = (
                "At pumpwood_communication cache.set hash_dict should not be "
                "'None'")
            raise PumpWoodCacheError(msg)
        expire_time = expire or self._expire_time
        # Do not store cache if expire_time == 0
        if expire_time == 0:
            return True

        hash_str = self.generate_hash(hash_dict=hash_dict)
        tag_str = None
        if tag_dict is not None:
            tag_str = self.generate_hash(hash_dict=tag_dict)

        def _do_set() -> bool:
            return self._cache.set(
                hash_str, value=value, expire=expire_time,
                tag=tag_str)

        try:
            return self._execute_with_retry(
                operation=_do_set, default=False,
                operation_name="set")
        except Exception as error:
            msg = (
                'Error when setting cache not associated with lock '
                'contention. {error}')
            raise PumpWoodCacheError(
                message=msg, payload={'error': str(error)})


default_cache: Final = PumpwoodCache()
"""Generate a default cache for Pumpwood."""
