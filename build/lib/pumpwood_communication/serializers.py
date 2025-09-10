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
from pandas import Timestamp
from shapely.geometry.base import BaseGeometry
from shapely.geometry import mapping
from sqlalchemy_utils.types.choice import Choice
from pumpwood_communication.exceptions import (
    PumpWoodException, PumpWoodNotImplementedError)


def default_encoder(obj):
    """Serialize complex objects."""
    # Return None if object is NaN
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Timestamp):
        return obj.isoformat()
    if isinstance(obj, date):
        return obj.isoformat()
    if isinstance(obj, time):
        return obj.isoformat()
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    if isinstance(obj, pd.DataFrame):
        return obj.to_dict('records')
    if isinstance(obj, pd.Series):
        obj.dtype == Timestamp
        return obj.tolist()
    if isinstance(obj, np.generic):
        return obj.item()
    if isinstance(obj, BaseGeometry):
        if obj.is_empty:
            return None
        else:
            return mapping(obj)
    if isinstance(obj, BaseGeometry):
        return mapping(obj)
    if isinstance(obj, Choice):
        return obj.code
    if isinstance(obj, set):
        return list(obj)
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
            orjson.OPT_SERIALIZE_NUMPY))
    elif sort_keys:
        return orjson.dumps(x, default=default_encoder, option=(
            orjson.OPT_NAIVE_UTC | orjson.OPT_NON_STR_KEYS |
            orjson.OPT_SORT_KEYS | orjson.OPT_SERIALIZE_NUMPY))
    elif is_indent:
        return orjson.dumps(x, default=default_encoder, option=(
            orjson.OPT_NAIVE_UTC | orjson.OPT_NON_STR_KEYS |
            orjson.OPT_INDENT_2 | orjson.OPT_SERIALIZE_NUMPY))
    else:
        return orjson.dumps(x, default=default_encoder, option=(
            orjson.OPT_NAIVE_UTC | orjson.OPT_NON_STR_KEYS |
            orjson.OPT_SERIALIZE_NUMPY))


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
        temp_pk_value = None
        if type(obj) is dict:
            temp_pk_value = obj[att]
        else:
            temp_pk_value = getattr(obj, att)
        return temp_pk_value

    @classmethod
    def dump(cls, obj, primary_keys: Union[str, List[str], Dict[str, str]]
             ) -> Union[str, int]:
        """Convert primary keys and composite to a single value.

        Treat cases when more than one column are used as primary keys,
        at this cases, a base64 used on url serialization of the dictionary
        is returned.

        Args:
            obj:
                SQLAlchemy object.
            primary_keys (Union[str, List[str], Dict[str, str]):
                As string, a list or a dictionary leading to different
                behaviour.
                - **str:** It will return the value associated with object
                    attribute.
                - **List[str]:** If list has lenght equal to 1, it will have
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
        if type(primary_keys) is str:
            return getattr(obj, primary_keys)

        elif type(primary_keys) is list:
            if len(primary_keys) == 1:
                return getattr(obj, primary_keys[0])
            else:
                # Will return a None value if all composite primary keys are
                # None
                is_all_none = False
                composite_pk_dict = {}
                for pk_col in primary_keys:
                    temp_pk_value = cls.get_attribute(obj, pk_col)
                    is_all_none = is_all_none or (temp_pk_value is None)
                    composite_pk_dict[pk_col] = temp_pk_value
                if is_all_none:
                    return None

                # If not all primary keys are None, them serialize it and
                # convert to a base64 dictionary to be used as PK
                composite_pk_str = pumpJsonDump(composite_pk_dict)
                return base64.urlsafe_b64encode(
                    composite_pk_str.encode()).decode()

        # Map object values to other, this is used when builds forenging
        # key references and request related field using microservice.
        elif type(primary_keys) is dict:
            # Will return a None value if all composite primary keys are
            # None
            is_all_none = False
            composite_pk_dict = {}
            for key, value in primary_keys.items():
                temp_pk_value = cls.get_attribute(obj, key)
                is_all_none = is_all_none or (temp_pk_value is None)
                composite_pk_dict[value] = temp_pk_value
            if is_all_none:
                return None

            # If not all primary keys are None, them serialize it and
            # convert to a base64 dictionary to be used as PK. Using
            # dictionary will map values before converting to base64
            # dictionary
            composite_pk_str = pumpJsonDump(composite_pk_dict)
            base64_composite_pk = base64.urlsafe_b64encode(
                composite_pk_str.encode()).decode()
            return base64_composite_pk

        # This will raise error if primary_keys type is not implemented
        else:
            msg = (
                "CompositePkBase64Converter.dump argument primary_keys "
                "is not a list of strings or a map dictionary. Type "
                "[{arg_type}]").format(arg_type=type(primary_keys))
            raise PumpWoodNotImplementedError(message=msg)

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
                return json.loads(base64.b64decode(value))
            except Exception as e2:
                msg = (
                    "[{value}] value is not an integer and could no be "
                    "decoded as a base64 encoded json dictionary. Value=")
                raise PumpWoodException(
                    message=msg, payload={
                        "value": value,
                        "exception_int": str(e1),
                        "exception_base64": str(e2)})
