"""
Module serializers.py.

Miscelenius to help with serializers in comunication.
"""
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


class PumpWoodJSONEncoder(JSONEncoder):
    """PumpWood default serializer."""

    def default(self, obj):
        """Serialize complex objects."""
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
            return np.asscalar(obj)
        if isinstance(obj, BaseGeometry):
            return mapping(obj)
        else:
            raise TypeError(
                "Unserializable object {} of type {}".format(obj, type(obj)))


def pumpJsonDump(x, sort_keys=True):
    """Dump a Json to python object."""
    return json.dumps(
        x, cls=PumpWoodJSONEncoder, allow_nan=True,
        sort_keys=sort_keys)
