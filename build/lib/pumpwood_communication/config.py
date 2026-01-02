"""Module to set enviroment variables configuration."""
import os


PUMPWOOD_COMUNICATION__N_PARALLEL = int(os.getenv(
    "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))
"""Number of parallel requests that will be performed on parallel functions."""


PUMPWOOD_COMUNICATION__N_PARALLEL = int(os.getenv(
    "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))
"""Number of parallel requests that will be performed on parallel functions."""

AUTHORIZATION_CACHE_TIMEOUT = int(
    os.getenv('PUMPWOOD_COMUNICATION__AUTHORIZATION_CACHE_TIMEOUT', 60))
"""Config variable to ser cache associated with autorization and row
   permission cache."""
