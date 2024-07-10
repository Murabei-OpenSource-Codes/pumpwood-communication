"""Create hash from a dictionary."""
import os
import hashlib
from typing import List
from pumpwood_communication.serializers import pumpJsonDump


def create_hash_from_dict(index_dict: dict, salt: str = "",
                          get_env: bool = True, keys: List[str] = None):
    """Create a hash for the index."""
    # If get_env set as True and salt not set try to get from env variable
    if salt == "" and get_env:
        salt = os.getenv("HASH_SALT", "")

    temp_dict = index_dict
    # Retrict keys to be used in hashing
    if keys is not None:
        temp_dict = dict([(k, index_dict[k]) for k in keys])

    string_dict = pumpJsonDump(temp_dict)
    hash_object = hashlib.sha1(salt.encode() + str(string_dict).encode())
    pbHash = hash_object.hexdigest()
    return pbHash


def create_hash_from_str(index: str, salt: str = "", get_env: bool = True):
    """Create a hash for the index."""
    # If get_env set as True and salt not set try to get from env variable
    if salt == "" and get_env:
        salt = os.getenv("HASH_SALT", "")

    hash_object = hashlib.sha1(salt.encode() + index.encode())
    pbHash = hash_object.hexdigest()
    return pbHash
