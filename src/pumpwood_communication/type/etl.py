"""Types associated with ETL processes."""
import pandas as pd
from typing import Any
from dataclasses import dataclass
from .abc import PumpwoodDataclassMixin


# Implemented to be used in the future info standardization of object
# saving and load
@dataclass
class ETLDimensions(PumpwoodDataclassMixin):
    """Dimensions associated with ETL processes."""

    data: list[dict]
    """Data associated with the dimensions."""
    update_fields: list[str] | None = None
    """Fields that should be updated in the dimensions if object exists."""
    merge_dict_fields: list[str] | None = None
    """Dictionary fields that should be merged in the dimensions if object
       exists."""


@dataclass
class ETLDataInputObject(PumpwoodDataclassMixin):
    """Data input metadata for an ETL run."""

    model_class: str
    """Model class associated with the data input object."""
    description: str | None = None
    """Description of the data input object."""
    notes: str | None = None
    """Notes associated with the data input object."""
    dimensions: list[dict] | None = None
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
    """Data input object linked to this fact load."""


# Used to return the results of the ETL process
@dataclass
class ETLAuxResults(PumpwoodDataclassMixin):
    """Auxiliary results associated with ETL processes.

    Auxiliary results are used to store the results of the ETL process.
    """


@dataclass
class ETLResultObjectSave(ETLAuxResults):
    """Auxiliary results associated with ETL processes.

    Auxiliary results are used to store the results of the ETL process.
    """

    object_data: dict
    """Data associated with the object to be saved."""


@dataclass
class ETLResultObjectDelete(ETLAuxResults):
    """Auxiliary results associated with ETL processes.

    Auxiliary results are used to store the results of the ETL process.
    """

    model_class: str
    """Model class associated with the object to be deleted."""
    pk: int | str | dict[str, Any]
    """IDs or dict of IDs of the objects to be deleted."""


@dataclass
class ETLResultActionRun(ETLAuxResults):
    """Auxiliary results associated with ETL processes.

    Auxiliary results are used to store the results of the ETL process.
    """

    model_class: str
    """Model class on which the action was executed."""
    action: str
    """Action that was run at the ETL Job."""
    results: dict
    """Results of the action."""

    pk: int | str | None = None
    """PK of the object at which the action was run."""
    parameters: dict | None = None
    """Parameters that were passed to the action."""


@dataclass
class ETLResultAuxInfo(ETLAuxResults):
    """Auxiliary information associated with ETL processes.

    Auxiliary information are used to store the information of the ETL process.
    """
    info_key: str
    """Key associated with the auxiliary information."""
    info: dict
    """Information associated with the ETL process."""
