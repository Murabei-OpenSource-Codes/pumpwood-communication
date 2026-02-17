"""Set custom return types for information end-points."""
from typing import Any, ClassVar
from dataclasses import dataclass
from .abc import PumpwoodDataclassMixin, PumpwoodSentinel, MISSING


@dataclass
class ColumnExtraInfo(PumpwoodDataclassMixin):
    """Foreign Key Extra Info for fill column information."""


@dataclass
class EmptyColumnExtraInfo(ColumnExtraInfo):
    """Empty extra info for simple columns."""

    def to_dict(self):
        """Overide the behaviour to always return an empty dictionary."""
        return dict()


@dataclass
class ForeignKeyColumnExtraInfo(ColumnExtraInfo):
    """Foreign Key Extra Info for fill column information."""
    model_class: str
    """Model class associated with the Foreign Key."""
    display_field: str
    """Field that will be used to display the object, it will be serialized
       as `__display_field__`."""
    object_field: str
    """Field that will receive information from the object."""
    source_keys: list[str]
    """Fields that will used to get the data at foreign relation."""
    many: bool = False
    """Foreign keys are always many=False."""


@dataclass
class RelatedColumnExtraInfo(ColumnExtraInfo):
    """Related Key Extra Info for fill column information."""
    model_class: str
    """Model class associated with Foreign Key."""
    pk_field: str
    """Field of the origin model class that will be used to filter
       related models at foreign_key."""
    foreign_key: str
    """Field of the origin model class that will be used to filter
       related models at foreign_key."""
    complementary_foreign_key: dict[str, str]
    """Complementary primary key fields that will be used on query
       to reduce query time."""
    fields: list[str]
    """Set the fileds that will be returned at the foreign key
       object."""
    many: bool = True
    """Related will always return many=True."""


@dataclass
class PrimaryKeyExtraInfo(ColumnExtraInfo):
    """Extra-info associated with primary key information."""
    columns: list[str]
    """Columns that together form the primary key."""
    partition: list[str]
    """Partition logic of the table."""


@dataclass
class FileColumnExtraInfo(ColumnExtraInfo):
    """File field extra info for column information."""

    permited_file_types: list[str]
    """Files allowed to be uploaded."""


@dataclass
class OptionsColumnExtraInfo(ColumnExtraInfo):
    """Options field extra info for column information."""
    _RENAME_FIELDS: ClassVar[dict[str, str]] = {
        'in_': 'in'
    }
    """Rename keys at the result dictionary."""

    in_: list[dict] | PumpwoodSentinel = MISSING
    """Options avaiable for the field."""


@dataclass
class ColumnInfo(PumpwoodDataclassMixin):
    """Type for returning files at Pumpwood Actions."""
    _RENAME_FIELDS: ClassVar[dict[str, str]] = {
        'in_': 'in',
        'type_': 'type'}
    """Rename keys at the result dictionary."""

    primary_key: bool
    """If column should be considered a primary_key."""
    column: str
    """Name of the column."""
    column__verbose: str
    """User friendly name for the column."""
    help_text: str
    """Help text associated with the column."""
    help_text__verbose: str
    """User friendly help text associated with the column."""
    type_: str
    """Type of the column."""
    nullable: bool
    """If column can be nullable."""
    read_only: bool
    """If column column is considered read only."""
    unique: bool
    """Is column is to be considered unique."""
    extra_info: ColumnExtraInfo
    """Extra info associated with custom field types like Foreign Key and
       related."""
    in_: list[dict] | PumpwoodSentinel = MISSING
    """Return a list with options associated with field possible values."""
    default: Any | PumpwoodSentinel = MISSING
    """If column column is considered read only."""

    def to_dict(self):
        """Remove in from dict return when it is missing."""
        data = super().to_dict()

        # Remove the in data if it is missing
        if data.get("in") == "**missing**":
            data.pop("in")
        return data
