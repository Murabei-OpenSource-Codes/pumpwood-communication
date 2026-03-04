"""Set custom return types for action return."""
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
