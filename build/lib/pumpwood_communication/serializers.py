"""Miscellaneous to help with serializers in communication."""
import base64
import simplejson as json
import orjson
import numpy as np
import pandas as pd
from typing import List, Union, Dict, Any
from simplejson import JSONEncoder
from datetime import datetime
from datetime import date
from datetime import time
from decimal import Decimal
from pandas import Timestamp
from shapely.geometry.base import BaseGeometry
from shapely.geometry import mapping
from sqlalchemy_utils.types.choice import Choice
from pumpwood_communication.exceptions import PumpWoodException
from pumpwood_communication.type import (
    PumpwoodSentinel, PumpwoodDataclassMixin, MISSING)


def default_encoder(obj):
    """Serialize complex objects."""
    # Return None if object is NaN
    if not isinstance(obj, (pd.DataFrame, pd.Series, np.ndarray, list, dict)):
        if pd.isna(obj):
            return None

    if isinstance(obj, (datetime, Timestamp, date, time)):
        return obj.isoformat()
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    if isinstance(obj, pd.DataFrame):
        return obj.to_dict('records')
    if isinstance(obj, pd.Series):
        return obj.tolist()
    if isinstance(obj, np.generic):
        return obj.item()
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, BaseGeometry):
        if obj.is_empty:
            return None
        else:
            return mapping(obj)
    if isinstance(obj, Choice):
        return obj.code
    if isinstance(obj, set):
        return list(obj)

    #########################################################
    # TODO: Adjust convertion of decimal to preseve precision
    # There is lost of precision when converting decimal to float,
    # but Decimal is not currently parsiable using orjson
    if isinstance(obj, Decimal):
        return float(obj)

    ###################################
    # Serialize Pumpwood expecial types
    if isinstance(obj, PumpwoodDataclassMixin):
        return obj.to_dict()
    if isinstance(obj, PumpwoodSentinel):
        return obj.value()
    else:
        raise TypeError(
            "Unserializable object {} of type {}".format(obj, type(obj)))


class PumpWoodJSONEncoder(JSONEncoder):
    """PumpWood default serializer.

    Treat not simple python types to facilitate at serialization of
    pandas, numpy, data, datetime and other data types.
    """

    def default(self, obj):
        """Serialize complex objects."""
        return default_encoder(obj)


def pumpJsonDump(x: any, sort_keys: bool = False,  # NOQA
                 indent: Union[int, bool] = None):
    """Dump a Json to python object.

    Args:
        x (any):
            Object to be serialized using PumpWoodJSONEncoder encoder.
        sort_keys (bool):
            If json serialized data should have its keys sorted. This option
            makes serialization return of data reproductable.
        indent (int):
            Pass indent argument to simplejson dumps.
    """
    # Compatibility with simplejson serialization
    is_indent = indent is not None
    if sort_keys and is_indent:
        return orjson.dumps(x, default=default_encoder, option=(
            orjson.OPT_NAIVE_UTC | orjson.OPT_NON_STR_KEYS |
            orjson.OPT_SORT_KEYS | orjson.OPT_INDENT_2 |
            orjson.OPT_SERIALIZE_NUMPY | orjson.OPT_PASSTHROUGH_DATACLASS))
    elif sort_keys:
        return orjson.dumps(x, default=default_encoder, option=(
            orjson.OPT_NAIVE_UTC | orjson.OPT_NON_STR_KEYS |
            orjson.OPT_SORT_KEYS | orjson.OPT_SERIALIZE_NUMPY |
            orjson.OPT_PASSTHROUGH_DATACLASS))
    elif is_indent:
        return orjson.dumps(x, default=default_encoder, option=(
            orjson.OPT_NAIVE_UTC | orjson.OPT_NON_STR_KEYS |
            orjson.OPT_INDENT_2 | orjson.OPT_SERIALIZE_NUMPY |
            orjson.OPT_PASSTHROUGH_DATACLASS))
    else:
        return orjson.dumps(x, default=default_encoder, option=(
            orjson.OPT_NAIVE_UTC | orjson.OPT_NON_STR_KEYS |
            orjson.OPT_SERIALIZE_NUMPY | orjson.OPT_PASSTHROUGH_DATACLASS))


class CompositePkBase64Converter:
    """Convert composite primary keys in base64 dictionary."""

    @staticmethod
    def get_attribute(obj: Any, att: str) -> Any:
        """Get attribute from object or dictinary.

        Args:
            obj (Any):
                Object or a dictinary.
            att (str):
                Name of the attribute/key that will be used to return
                the value.

        Return:
            Return object/dictionary value associated with attribute.
        """
        if type(obj) is dict:
            return obj.get(att, MISSING)
        else:
            return getattr(obj, att, MISSING)

    @classmethod
    def dump(cls, obj: object | dict,
             primary_keys: Union[str, List[str], Dict[str, str]]
             ) -> Union[str, int]:
        """Convert primary keys and composite to a single value.

        Treat cases when more than one column are used as primary keys,
        at this cases, a base64 used on url serialization of the dictionary
        is returned.

        Args:
            obj:
                SQLAlchemy object or dictionary with data to build the
                forenging key.
            primary_keys (Union[str, List[str], Dict[str, str]):
                As string, a list or a dictionary leading to different
                behaviour.
                - **str:** It will return the value associated with object
                    attribute.
                - **List[str]:** If list has length equal to 1, it will have
                    same behaviour as str. If greater than 1, it will be
                    returned a base64 encoded dictionary with the keys at
                    primary_keys.
                - **Dict[str, str]:** Dictionary to map object fields to
                    other keys. This is usefull when querying related fields
                    by composite forenging keys to match original data fieds.

        Returns:
            If the primary key is unique, return the value of the primary
            key, if is have more than one column as primary key, return
            a dictionary of the primary keys encoded as base64 url safe.
        """
        if obj is None:
            return None

        missing_keys = []
        return_value = None
        if isinstance(primary_keys, str):
            key_value = cls.get_attribute(obj, primary_keys)
            if key_value != MISSING:
                return_value = key_value
            else:
                missing_keys.append(primary_keys)

        elif isinstance(primary_keys, list):
            if len(primary_keys) == 1:
                key_value = cls.get_attribute(obj, primary_keys[0])
                if key_value != MISSING:
                    return key_value
                else:
                    missing_keys.append(primary_keys[0])
            else:
                composite_pk_dict = {}
                for pk_col in primary_keys:
                    key_value = cls.get_attribute(obj, pk_col)
                    if key_value != MISSING:
                        composite_pk_dict[pk_col] = key_value
                    else:
                        missing_keys.append(pk_col)
                return_value = composite_pk_dict

        # Map object values to other, this is used when builds forenging
        # key references and request related field using microservice.
        elif isinstance(primary_keys, dict):
            # Treat the case when the dictinary is only an id->value
            composite_pk_dict = {}
            for key, value in primary_keys.items():
                key_value = cls.get_attribute(obj, key)
                if key_value != MISSING:
                    composite_pk_dict[value] = key_value
                else:
                    missing_keys.append(key)
            return_value = composite_pk_dict

        # Check if some missing keys are there
        if len(missing_keys) != 0:
            msg = (
                "Some keys were not found on object/dict to create "
                "the composite forenging key. "
                "Primary Keys: {primary_keys}; "
                "Missing keys: {missing_keys}")
            raise PumpWoodException(msg, payload={
                "primary_keys": list(primary_keys.keys()),
                "missing_keys": missing_keys})

        if isinstance(return_value, dict):
            if {'id'} == set(return_value.keys()):
                return return_value['id']

            composite_pk_str = pumpJsonDump(return_value)
            base64_composite_pk = base64.urlsafe_b64encode(composite_pk_str)\
                .decode()
            return base64_composite_pk
        else:
            return return_value

    @staticmethod
    def load(value: Union[str, int]) -> Union[int, dict]:
        """Convert encoded primary keys to values.

        If the primary key is a string, try to transform it to dictionary
        decoding json base64 to a dictionary.

        Args:
            value:
                Primary key value as an integer or as a base64
                encoded json dictionary.

        Return:
            Return the primary key as integer if possible, or try to decoded
            it to a dictionary from a base64 encoded json.
        """
        # Try to convert value to integer
        try:
            float_value = float(value)
            if float_value.is_integer():
                return int(float_value)
            else:
                msg = "[{value}] value is a float, but not integer."
                raise PumpWoodException(msg, payload={"value": value})

        # If not possible, try to decode a base64 JSON dictionary
        except Exception as e1:
            try:
                return json.loads(base64.urlsafe_b64decode(value))
            except Exception as e2:
                msg = (
                    "[{value}] value is not an integer and could no be "
                    "decoded as a base64 encoded json dictionary. Value=")
                raise PumpWoodException(
                    message=msg, payload={
                        "value": value,
                        "exception_int": str(e1),
                        "exception_base64": str(e2)})
