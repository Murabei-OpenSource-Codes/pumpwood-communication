"""Module to set environment variables configuration.

Reads ``PUMPWOOD_COMMUNICATION__*`` variables. Legacy typo spelling
``PUMPWOOD_COMUNICATION__*`` is supported as fallback.
"""
import os


def _getenv(correct_name, typo_name, default=None):
    """Read env var preferring correct spelling over legacy typo.

    Args:
        correct_name (str):
            Environment variable name with correct spelling.
        typo_name (str):
            Legacy environment variable name with typo.
        default:
            Default when neither variable is set.

    Returns:
        str | None:
            Value from environment or default.
    """
    return os.getenv(
        correct_name, os.getenv(typo_name, default))


# Legacy export name kept for backward compatibility.
PUMPWOOD_COMUNICATION__N_PARALLEL = int(_getenv(
    "PUMPWOOD_COMMUNICATION__N_PARALLEL",
    "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))
"""Number of parallel requests in parallel helper functions."""


# Cache associated config variables
AUTHORIZATION_CACHE_TIMEOUT = int(_getenv(
    "PUMPWOOD_COMMUNICATION__AUTHORIZATION_CACHE_TIMEOUT",
    "PUMPWOOD_COMUNICATION__AUTHORIZATION_CACHE_TIMEOUT", 60))
"""Cache timeout for authorization and row permission cache."""
CACHE_BASE_PATH = _getenv(
    "PUMPWOOD_COMMUNICATION__CACHE_BASE_PATH",
    "PUMPWOOD_COMUNICATION__CACHE_BASE_PATH", '')
"""Base path for cache files."""
CACHE_LIMIT_MB = int(_getenv(
    "PUMPWOOD_COMMUNICATION__CACHE_LIMIT_MB",
    "PUMPWOOD_COMUNICATION__CACHE_LIMIT_MB", 250)) * 1e8
"""Maximum disk cache size in bytes."""
CACHE_DEFAULT_EXPIRE = int(_getenv(
    "PUMPWOOD_COMMUNICATION__CACHE_DEFAULT_EXPIRE",
    "PUMPWOOD_COMUNICATION__CACHE_DEFAULT_EXPIRE", 60))
"""Default cache entry expiration time in seconds."""
CACHE_TRANSACTION_TIMEOUT = float(_getenv(
    "PUMPWOOD_COMMUNICATION__CACHE_TRANSACTION_TIMEOUT",
    "PUMPWOOD_COMUNICATION__CACHE_TRANSACTION_TIMEOUT", 0.1))
"""Default cache transaction timeout in seconds."""
CACHE_N_SHARDS = int(_getenv(
    "PUMPWOOD_COMMUNICATION__CACHE_N_SHARDS",
    "PUMPWOOD_COMUNICATION__CACHE_N_SHARDS", 8))
"""Number of shards used to split the cache."""
CACHE_ENABLE = _getenv(
    "PUMPWOOD_COMMUNICATION__CACHE_ENABLE",
    "PUMPWOOD_COMUNICATION__CACHE_ENABLE", "TRUE") == "TRUE"
"""Whether cache is enabled. Options ``TRUE`` or ``FALSE``."""
CACHE_RETRY_ATTEMPTS = int(_getenv(
    "PUMPWOOD_COMMUNICATION__CACHE_RETRY_ATTEMPTS",
    "PUMPWOOD_COMUNICATION__CACHE_RETRY_ATTEMPTS", 5))
"""Number of retries on SQLite lock contention."""
CACHE_RETRY_DELAY = float(_getenv(
    "PUMPWOOD_COMMUNICATION__CACHE_RETRY_DELAY",
    "PUMPWOOD_COMUNICATION__CACHE_RETRY_DELAY", 0.05))
"""Base delay in seconds between cache lock retries."""


# Parallel operations associated env. variables
N_PARALLEL = n_parallel = PUMPWOOD_COMUNICATION__N_PARALLEL
"""Number of parallel calls performed in parallel helpers."""

PARALLEL_CHUNK_SIZE = int(_getenv(
    "PUMPWOOD_COMMUNICATION__PARALLEL_CHUNK_SIZE",
    "PUMPWOOD_COMUNICATION__PARALLEL_CHUNK_SIZE", 10000))
"""Size of each chunk posted in parallel bulk save."""


# Microservice base associated env. variables
DEFAULT_TIMEOUT = int(_getenv(
    "PUMPWOOD_COMMUNICATION__DEFAULT_TIMEOUT",
    "PUMPWOOD_COMUNICATION__DEFAULT_TIMEOUT", 60))
"""Default HTTP request timeout in seconds."""
DEBUG = _getenv(
    "PUMPWOOD_COMMUNICATION__DEBUG",
    "PUMPWOOD_COMUNICATION__DEBUG", "FALSE") == "TRUE"
"""Whether debug mode is enabled. Options ``TRUE`` or ``FALSE``."""
VERIFY_SSL = _getenv(
    "PUMPWOOD_COMMUNICATION__VERIFY_SSL",
    "PUMPWOOD_COMUNICATION__VERIFY_SSL", "TRUE") == "TRUE"
"""Whether HTTP requests validate the SSL certificate."""


# Encryption associated env. variables
CRYPTO_FERNET_KEY = _getenv(
    "PUMPWOOD_COMMUNICATION__CRYPTO_FERNET_KEY",
    "PUMPWOOD_COMUNICATION__CRYPTO_FERNET_KEY", None)
"""Fernet key used to encrypt and decrypt data."""
