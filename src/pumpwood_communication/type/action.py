"""Set custom return types for action return."""
from typing import Any
from dataclasses import dataclass
from .abc import PumpwoodDataclassMixin


@dataclass
class ActionReturnFile(PumpwoodDataclassMixin):
    """Type for returning files at Pumpwood Actions."""

    content: bytes
    """Content of the file that will be returned at the action."""
    filename: str
    """Name off the file that will be returned at the action."""
    content_type: str = 'application/octet-stream'
    """Type content the the file that will be returned at the action."""


@dataclass
class ActionInfomation(PumpwoodDataclassMixin):
    """Type to standardize action information exchange."""

    action_name: str
    """Name of the action."""
    is_static_function: bool
    """If action should be considered a static function and should run without
       an associated object (pk should not be passed on function call)."""
    info: str
    """Description of the action."""
    return_: dict
    """Information about the variable that be returned by the action."""
    parameters: dict
    """Description of the parameters used by the action."""
    doc_string: str
    """Doc string avaiable at action definition."""
    required_role: str = 'default'
    """Required role to run the action, if default is set the permission will
       be managed by end-point permission at pumpwood auth."""

    _RENAME_FIELDS = {"return_": "return"}
    """Rename 'return_' to 'return' since it is a retricted expression on
       python."""


@dataclass
class ActionParameterType(PumpwoodDataclassMixin):
    """Type to standardize action parameter type exchange."""

    many: bool
    """Define if the parameter is a list of the type."""
    type_: str
    """Type of the parameter."""
    required: bool
    """Define if the parameter is required or not."""
    default_value: Any
    """Default value associated with the parameter."""
    in_: list[str] | None = None
    """If the parameter if an options, it will return the possible options
       associated with the parameter."""

    _RENAME_FIELDS = {"type_": "type", "in_": "in"}
    """Rename 'return_' to 'return' since it is a retricted expression on
       python."""


@dataclass
class ActionReturnType(PumpwoodDataclassMixin):
    """Type to standardize action return type exchange."""

    many: bool
    """Define if the parameter is a list of the type."""
    type_: str
    """Type of the parameter."""
    in_: list[str] | None = None
    """If the parameter if an options, it will return the possible options
       associated with the parameter."""

    _RENAME_FIELDS = {"type_": "type", "in_": "in"}
    """Rename 'return_' to 'return' since it is a retricted expression on
       python."""
