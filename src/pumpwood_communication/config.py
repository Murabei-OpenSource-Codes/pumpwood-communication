"""Module to set enviroment variables configuration."""
import os


PUMPWOOD_COMUNICATION__N_PARALLEL = int(os.getenv(
    "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))
"""Number of parallel requests that will be performed on parallel functions."""


# Cache associated cofig variables
AUTHORIZATION_CACHE_TIMEOUT = int(
    os.getenv('PUMPWOOD_COMUNICATION__AUTHORIZATION_CACHE_TIMEOUT', 60))
"""Config variable to ser cache associated with autorization and row
   permission cache."""
CACHE_BASE_PATH = \
    os.getenv('PUMPWOOD_COMUNICATION__CACHE_BASE_PATH', '')
"""Base path for cache files."""
CACHE_LIMIT_MB = int(os.getenv(
    'PUMPWOOD_COMUNICATION__CACHE_LIMIT_MB', 250)) * 1e8
"""Limit for disckcache size."""
CACHE_DEFAULT_EXPIRE = int(os.getenv(
    'PUMPWOOD_COMUNICATION__CACHE_DEFAULT_EXPIRE', 60))
"""Default expire time for cache."""
CACHE_TRANSACTION_TIMEOUT = float(os.getenv(
    'PUMPWOOD_COMUNICATION__CACHE_TRANSACTION_TIMEOUT', 0.1))
"""Default transaction timeout."""
CACHE_N_SHARDS = int(os.getenv(
    'PUMPWOOD_COMUNICATION__CACHE_N_SHARDS', 8))
"""Number of shards that will be used to split the cache."""
