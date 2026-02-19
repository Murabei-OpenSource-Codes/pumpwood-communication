"""Set default dataclasses for pumpwood use."""
import dataclasses
from abc import ABC
from typing import Final, ClassVar


class PumpwoodSentinel(ABC):
    """Pumpwood Sentinel class for missing values."""

    _RETURN_VALUE: str = ""
    """Value that will be returned on dataclass to dict."""

    _HELP_TEXT: str = ""
    """Value that will be returned on dataclass to dict."""

    @classmethod
    def value(cls):
        """Return defult value."""
        return cls._RETURN_VALUE

    @classmethod
    def help_text(cls):
        """Return defult value."""
        return cls._HELP_TEXT


class PumpwoodMissingType(PumpwoodSentinel):
    """Pumpwood Sentinel class for missing values."""

    _RETURN_VALUE: str = "**missing**"
    _HELP_TEXT: str = "Missing value"


class PumpwoodAutoincrementType(PumpwoodSentinel):
    """Pumpwood Sentinel class for missing values."""

    _RETURN_VALUE: str = "**autoincrement**"
    _HELP_TEXT: str = "Auto-increment value, usually an integer"


class PumpwoodAutoNowType(PumpwoodSentinel):
    """Pumpwood Sentinel class for auto now default."""

    _RETURN_VALUE: str = "**now**"
    _HELP_TEXT: str = "Return the now time at the server"


class PumpwoodAutoTodayType(PumpwoodSentinel):
    """Pumpwood Sentinel class for auto now default."""

    _RETURN_VALUE: str = "**today**"
    _HELP_TEXT: str = "Return the todat date at the server"


class PumpwoodPKType(PumpwoodSentinel):
    """Pumpwood Sentinel class for auto now default."""

    _RETURN_VALUE: str = "**pumpwood_pk**"
    _HELP_TEXT: str = (
        "Primary key associated with model. It is an integer if not composite "
        "and a base64 dictionary if it is composite (more than one field)")


MISSING: Final = PumpwoodMissingType()
"""Create a default missing object to not be mixed with None which might be
   a valid value on dataclass."""

AUTOINCREMENT: Final = PumpwoodAutoincrementType()
"""Define the default value for auto increment fields."""

NOW: Final = PumpwoodAutoNowType()
"""Define the default auto now."""

TODAY: Final = PumpwoodAutoTodayType()
"""Define the default value for auto today."""

PUMPWOOD_PK: Final = PumpwoodPKType()
"""Define the default PK type for Pumpwood PK object."""


class PumpwoodDataclassMixin(ABC):
    """Pumpwood Dataclasses with some pre-implemented methods.

    Is implemented so it can be used as an object, but data can also be
    retrived as dictionary using obj['key'] notation.
    """

    _RENAME_FIELDS: ClassVar[dict[str, str]] = {}
    """Rename field on the dataclass and the response, this migth be
       particullary usefull when dealling with fields like 'in', which is
       not avaiable."""

    def to_dict(self):
        """Converts the dataclass instance into a dictionary recursively."""
        clean_data = {}
        # Iterate over the fields of the current dataclass
        for field in dataclasses.fields(self):
            key = field.name
            value = getattr(self, key)

            # Rename the keys
            new_key = self._RENAME_FIELDS.get(key, key)
            clean_data[new_key] = self._process_value(value)
        return clean_data

    def _process_value(self, value):
        """Helper to handle recursion and sentinel replacement."""
        # Handle Sentinels
        if isinstance(value, PumpwoodSentinel):
            return value.value()

        # Handle Nested Pumpwood Dataclasses (Recursion)
        if isinstance(value, PumpwoodDataclassMixin):
            return value.to_dict()

        # Handle Lists (check each element)
        if isinstance(value, list):
            return [
                self._process_value(item)
                for item in value]

        # Handle Dicts (check each value)
        if isinstance(value, dict):
            return {
                k: self._process_value(v)
                for k, v in value.items()}
        return value

    def __iter__(self):
        """This allows: for key, val in my_dataclass."""
        for key, value in self.to_dict().items():
            yield key, value

    def __getitem__(self, key):
        """Allows obj["name"]."""
        return getattr(self, key)

    def keys(self):
        """Allows dict(obj) and spreading **obj."""
        return [f.name for f in dataclasses.fields(self)]
