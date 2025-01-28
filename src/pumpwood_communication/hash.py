"""Create hash from a dictionary."""
import os
import hashlib
from typing import List
from pumpwood_communication.serializers import pumpJsonDump


def create_hash_from_dict(index_dict: dict, salt: str = "",
                          get_env: bool = True, keys: List[str] = None) -> str:
    """Create a hash from a dictionary limiting keys used at `keys` arguments.

    Create hash from a dictionary, it adds `HASH_SALT` as salt at the
    beginng of the string if `HASH_SALT` enviroment variable is present.

    Args:
        index_dict: Dictionary with the index that will be used to generate
            the hash value.
        salt: Salt text that will be concatenated to string before generating
            the hash.
        get_env: If uses `HASH_SALT` enviroment variable as salt to create
            the hash.
        keys: List of the keys of index_dict that will be used to generate
            hash.

    Returns:
        Return a string with hash create using parameters passed at this
        funcion.
    """
    # If get_env set as True and salt not set try to get from env variable
    if salt == "" and get_env:
        salt = os.getenv("HASH_SALT", "")

    temp_dict = index_dict
    # Retrict keys to be used in hashing
    if keys is not None:
        temp_dict = dict([(k, index_dict[k]) for k in keys])

    string_dict = pumpJsonDump(temp_dict)
    hash_object = hashlib.sha1( # NOQA
        salt.encode() + str(string_dict).encode())
    pbHash = hash_object.hexdigest()
    return pbHash


def create_hash_from_str(index: str, salt: str = "",
                         get_env: bool = True) -> str:
    """Create a hash for the index.

    Args:
        index: String used to create the hash.
        salt: String to be used as salt to generate the hash.
        get_env: If enviroment variable `HASH_SALT` should be used
            to create a salt string,

    Returns:
        Hash string from parameters passed.
    """
    # If get_env set as True and salt not set try to get from env variable
    if salt == "" and get_env:
        salt = os.getenv("HASH_SALT", "")

    hash_object = hashlib.sha1( # NOQA
        salt.encode() + index.encode())
    pbHash = hash_object.hexdigest()
    return pbHash
