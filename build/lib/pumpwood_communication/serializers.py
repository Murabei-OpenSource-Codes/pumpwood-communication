"""
Module serializers.py.

Miscellaneous to help with serializers in communication.
"""
import base64
import numbers
import simplejson as json
import numpy as np
import pandas as pd
from simplejson import JSONEncoder
from datetime import datetime
from datetime import date
from datetime import time
from pandas import Timestamp
from shapely.geometry.base import BaseGeometry
from shapely.geometry import mapping
from sqlalchemy_utils.types.choice import Choice
from pumpwood_communication.exceptions import PumpWoodException


class PumpWoodJSONEncoder(JSONEncoder):
    """PumpWood default serializer."""

    def default(self, obj):
        """Serialize complex objects."""
        # Return None if object is nan
        if isinstance(obj, datetime):
            return obj.isoformat()
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
            return mapping(obj)
        if isinstance(obj, Choice):
            return obj.code
        else:
            raise TypeError(
                "Unserializable object {} of type {}".format(obj, type(obj)))


def pumpJsonDump(x, sort_keys=True):
    """Dump a Json to python object."""
    return json.dumps(
        x, cls=PumpWoodJSONEncoder, ignore_nan=True,
        sort_keys=sort_keys)


class CompositePkBase64Converter:
    """Convert composite primary keys in base64 dictionary."""
    @staticmethod
    def dump(obj, primary_keys: list):
        """
        Convert primary keys and composite to a single value.

        Treat cases when more than one column are used as primary keys,
        at this cases, a base64 used on url serialization of the dictionary
        is returned.

        Args:
            obj: SQLAlchemy object.
            primary_keys [list]: List of primary keys of the object.
        Kwargs:
            No Kwargs.
        Return [int | str]:
            If the primary key is unique, return the value of the primary
                key, if is have more than one column as primary key, return
                a dictionary of the primary keys encoded as base64 url safe.
        """
        if len(primary_keys) == 1:
            return getattr(obj, primary_keys[0])
        else:
            composite_pk_dict = {}
            for pk_col in primary_keys:
                composite_pk_dict[pk_col] = getattr(obj, pk_col)
            composite_pk_str = pumpJsonDump(composite_pk_dict)
            return base64.urlsafe_b64encode(
                composite_pk_str.encode()).decode()

    @staticmethod
    def load(value):
        """
        Convert encoded primary keys to values.

        If the primary key is a string, try to transform it to dictionary
        decoding json base64 to a dictionary.

        Args:
            value [int | str]: Primary key value as an integer or as a base64
                encoded json dictionary.
        Return [int | dict]:
            Return the primary key as integer if possible, or try to decoded
            it to a dictionary from a base64 encoded json.
        """
        try:
            float_value = float(value)
            if float_value.is_integer():
                return int(float_value)
            else:
                msg = "Value is a float, but not integer: {}".format(
                    float_value)
                raise Exception(msg)
        except Exception as e1:
            try:
                return json.loads(base64.b64decode(value))
            except Exception as e2:
                msg = (
                    "Primary is not an integer and could no be "
                    "decoded as a base64 encoded json dictionary")
                raise PumpWoodException(
                    message=msg, payload={
                        "value": value,
                        "exception_int": str(e1),
                        "exception_base64": str(e2)})
