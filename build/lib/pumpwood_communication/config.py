"""Module to set enviroment variables configuration."""
import os


PUMPWOOD_COMUNICATION__N_PARALLEL = int(os.getenv(
    "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))
"""Number of parallel requests that will be performed on parallel functions."""
