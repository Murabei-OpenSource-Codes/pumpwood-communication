"""Module to define types used at Pumpwood views."""
from functools import cached_property
from dataclasses import dataclass
from .abc import PumpwoodDataclassMixin
from pumpwood_communication.aux import import_function_by_string


@dataclass
class BulkSaveMicroserviceAutoFillField(PumpwoodDataclassMixin):
    """Define a field to be auto filled by microservice at bulk save."""

    field: str
    """Name of the field that will be filled on bulk save."""
    fill_model_class: str
    """String associated with model class to fetch information from."""
    fill_col: str
    """Column of the foreign object that will be used to fill the data."""
    object_fk_column: str | None
    """Column that contains the field with pk for the object used to fill
       the data."""
    use_cache: bool = True
    """If it is allowed to use local cache to fill column value."""


@dataclass
class BulkSaveLocalAutoFillField(PumpwoodDataclassMixin):
    """Define a field to be auto filled by local at bulk save."""

    field: str
    """Name of the field that will be filled on bulk save."""
    fill_model_class: str
    """String or SQLAlchemy class associated with model class to fetch
       information from."""
    fill_col: str
    """Column of the foreign object that will be used to fill the data."""
    object_fk_column: str | None
    """Column that contains the field with pk for the object used to fill
       the data."""
    use_cache: bool = True
    """If it is allowed to use local cache to fill column value."""

    @cached_property
    def cls_fill_model_class(self):
        """Class used to fetch local data information."""
        if isinstance(self.fill_model_class, str):
            return import_function_by_string(self.fill_model_class)
        return self.fill_model_class
