"""Define sentinel values."""
from typing import Final
from .abc import PumpwoodSentinel


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


class PumpwoodLoggedUserType(PumpwoodSentinel):
    """Pumpwood Sentinel class for logged user default."""

    _RETURN_VALUE: str = "**logged_user**"
    _HELP_TEXT: str = (
        "Use autentication header to fill field with id of the logged "
        "user.")


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

LOGGED_USER: Final = PumpwoodLoggedUserType()
"""Type to be used for ID retrieved from logged user."""
