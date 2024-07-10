# Module pumpwood_communication.serializers

Module serializers.py.

Miscellaneous to help with serializers in communication.

??? example "View Source"
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

                    if obj.is_empty:

                        return None

                    else:

                        return mapping(obj)

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

## Functions

    
### pumpJsonDump

```python3
def pumpJsonDump(
    x,
    sort_keys=True
)
```

Dump a Json to python object.

??? example "View Source"
        def pumpJsonDump(x, sort_keys=True):

            """Dump a Json to python object."""

            return json.dumps(

                x, cls=PumpWoodJSONEncoder, ignore_nan=True,

                sort_keys=sort_keys)

## Classes

### CompositePkBase64Converter

```python3
class CompositePkBase64Converter(
    /,
    *args,
    **kwargs
)
```

Convert composite primary keys in base64 dictionary.

??? example "View Source"
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

------

#### Static methods

    
#### dump

```python3
def dump(
    obj,
    primary_keys: list
)
```

Convert primary keys and composite to a single value.

Treat cases when more than one column are used as primary keys,
at this cases, a base64 used on url serialization of the dictionary
is returned.

**Parameters:**

| Name | Type | Description | Default |
|---|---|---|---|
| obj | None | SQLAlchemy object. | None |
| primary_keys [list] | None | List of primary keys of the object. | None |

??? example "View Source"
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

    
#### load

```python3
def load(
    value
)
```

Convert encoded primary keys to values.

If the primary key is a string, try to transform it to dictionary
decoding json base64 to a dictionary.

**Parameters:**

| Name | Type | Description | Default |
|---|---|---|---|
| value [int | str] | None | Primary key value as an integer or as a base64<br>encoded json dictionary. | None |

??? example "View Source"
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

### PumpWoodJSONEncoder

```python3
class PumpWoodJSONEncoder(
    skipkeys=False,
    ensure_ascii=True,
    check_circular=True,
    allow_nan=True,
    sort_keys=False,
    indent=None,
    separators=None,
    encoding='utf-8',
    default=None,
    use_decimal=True,
    namedtuple_as_object=True,
    tuple_as_array=True,
    bigint_as_string=False,
    item_sort_key=None,
    for_json=False,
    ignore_nan=False,
    int_as_string_bitcount=None,
    iterable_as_array=False
)
```

PumpWood default serializer.

??? example "View Source"
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

                    if obj.is_empty:

                        return None

                    else:

                        return mapping(obj)

                if isinstance(obj, BaseGeometry):

                    return mapping(obj)

                if isinstance(obj, Choice):

                    return obj.code

                else:

                    raise TypeError(

                        "Unserializable object {} of type {}".format(obj, type(obj)))

------

#### Ancestors (in MRO)

* simplejson.encoder.JSONEncoder

#### Class variables

```python3
item_separator
```

```python3
key_separator
```

#### Methods

    
#### default

```python3
def default(
    self,
    obj
)
```

Serialize complex objects.

??? example "View Source"
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

                    if obj.is_empty:

                        return None

                    else:

                        return mapping(obj)

                if isinstance(obj, BaseGeometry):

                    return mapping(obj)

                if isinstance(obj, Choice):

                    return obj.code

                else:

                    raise TypeError(

                        "Unserializable object {} of type {}".format(obj, type(obj)))

    
#### encode

```python3
def encode(
    self,
    o
)
```

Return a JSON string representation of a Python data structure.

>>> from simplejson import JSONEncoder
>>> JSONEncoder().encode({"foo": ["bar", "baz"]})
'{"foo": ["bar", "baz"]}'

??? example "View Source"
            def encode(self, o):

                """Return a JSON string representation of a Python data structure.

                >>> from simplejson import JSONEncoder

                >>> JSONEncoder().encode({"foo": ["bar", "baz"]})

                '{"foo": ["bar", "baz"]}'

                """

                # This is for extremely simple cases and benchmarks.

                if isinstance(o, binary_type):

                    _encoding = self.encoding

                    if (_encoding is not None and not (_encoding == 'utf-8')):

                        o = text_type(o, _encoding)

                if isinstance(o, string_types):

                    if self.ensure_ascii:

                        return encode_basestring_ascii(o)

                    else:

                        return encode_basestring(o)

                # This doesn't pass the iterator directly to ''.join() because the

                # exceptions aren't as detailed.  The list call should be roughly

                # equivalent to the PySequence_Fast that ''.join() would do.

                chunks = self.iterencode(o, _one_shot=True)

                if not isinstance(chunks, (list, tuple)):

                    chunks = list(chunks)

                if self.ensure_ascii:

                    return ''.join(chunks)

                else:

                    return u''.join(chunks)

    
#### iterencode

```python3
def iterencode(
    self,
    o,
    _one_shot=False
)
```

Encode the given object and yield each string

representation as available.

For example::

    for chunk in JSONEncoder().iterencode(bigobject):
        mysocket.write(chunk)

??? example "View Source"
            def iterencode(self, o, _one_shot=False):

                """Encode the given object and yield each string

                representation as available.

                For example::

                    for chunk in JSONEncoder().iterencode(bigobject):

                        mysocket.write(chunk)

                """

                if self.check_circular:

                    markers = {}

                else:

                    markers = None

                if self.ensure_ascii:

                    _encoder = encode_basestring_ascii

                else:

                    _encoder = encode_basestring

                if self.encoding != 'utf-8' and self.encoding is not None:

                    def _encoder(o, _orig_encoder=_encoder, _encoding=self.encoding):

                        if isinstance(o, binary_type):

                            o = text_type(o, _encoding)

                        return _orig_encoder(o)

                def floatstr(o, allow_nan=self.allow_nan, ignore_nan=self.ignore_nan,

                        _repr=FLOAT_REPR, _inf=PosInf, _neginf=-PosInf):

                    # Check for specials. Note that this type of test is processor

                    # and/or platform-specific, so do tests which don't depend on

                    # the internals.

                    if o != o:

                        text = 'NaN'

                    elif o == _inf:

                        text = 'Infinity'

                    elif o == _neginf:

                        text = '-Infinity'

                    else:

                        if type(o) != float:

                            # See #118, do not trust custom str/repr

                            o = float(o)

                        return _repr(o)

                    if ignore_nan:

                        text = 'null'

                    elif not allow_nan:

                        raise ValueError(

                            "Out of range float values are not JSON compliant: " +

                            repr(o))

                    return text

                key_memo = {}

                int_as_string_bitcount = (

                    53 if self.bigint_as_string else self.int_as_string_bitcount)

                if (_one_shot and c_make_encoder is not None

                        and self.indent is None):

                    _iterencode = c_make_encoder(

                        markers, self.default, _encoder, self.indent,

                        self.key_separator, self.item_separator, self.sort_keys,

                        self.skipkeys, self.allow_nan, key_memo, self.use_decimal,

                        self.namedtuple_as_object, self.tuple_as_array,

                        int_as_string_bitcount,

                        self.item_sort_key, self.encoding, self.for_json,

                        self.ignore_nan, decimal.Decimal, self.iterable_as_array)

                else:

                    _iterencode = _make_iterencode(

                        markers, self.default, _encoder, self.indent, floatstr,

                        self.key_separator, self.item_separator, self.sort_keys,

                        self.skipkeys, _one_shot, self.use_decimal,

                        self.namedtuple_as_object, self.tuple_as_array,

                        int_as_string_bitcount,

                        self.item_sort_key, self.encoding, self.for_json,

                        self.iterable_as_array, Decimal=decimal.Decimal)

                try:

                    return _iterencode(o, 0)

                finally:

                    key_memo.clear()