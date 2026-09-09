"""Types associated with ETL processes."""
import pandas as pd
from dataclasses import dataclass
from .abc import PumpwoodDataclassMixin


@dataclass
class ETLDimensions(PumpwoodDataclassMixin):
    """Dimensions associated with ETL processes."""

    data: list[dict]
    """Data associated with the dimensions."""
    update_fields: list[str] = None
    """Fields that should be updated in the dimensions if object exists."""
    merge_dict_fields: list[str] = None
    """Dictionary fields that should be merged in the dimensions if object
       exists."""

@dataclass
class ETLDataInputObject(PumpwoodDataclassMixin):
    """Dimensions associated with ETL processes."""

    model_class: str
    """Model class associated with the data input object."""
    description: str | None = None
    """Description of the data input object."""
    notes: str | None = None
    """Notes associated with the data input object."""
    dimensions: list[dict] = None
    """Dimensions associated with the data input object."""
    extra_info: dict | None = None
    """Extra info associated with the data input object."""


@dataclass
class ETLFact(PumpwoodDataclassMixin):
    """Fact associated with ETL processes.

    Fact data is always associated with dimensions codes, the
    column associated with the dimension should always be [column]__code.

    This is need for the process to correctly link the fact data with
    the dimensions ids before saving the data.
    """

    model_class: str
    """Model class associated with the fact data."""
    data: list[dict] | pd.DataFrame
    """Data associated with the fact."""
    datainput: ETLDataInputObject
    """Description of the data input object."""


@dataclass
class ETLAuxResults(PumpwoodDataclassMixin):
    """Auxiliary results associated with ETL processes.

    Auxiliary results are used to store the results of the ETL process.
    """

    result_key: str
    """Key associated with the auxiliary results."""
    data: dict
    """Data associated with the auxiliary results."""
