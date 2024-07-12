"""Miscelaneus function to help in development."""
import pandas as pd
from typing import List


def unpack_dict_columns(df: pd.DataFrame, columns: List[str]) -> pd.DataFrame:
    """
    Unpack dictinary columns at a dataframe.

    Return a copy of the dataframe with 'columns' unpacked and removed
    from result.

    Args:
        df:
            Dataframe to unpack the columns.
        columns:
            List of columns to unpack in columns.
    Return:
        Return a dataframe with dict columns unpacked.
    """
    list_unpacked_results = []
    for c in columns:
        list_unpacked_results.append(df[c].apply(pd.Series))
    return pd.concat(
        [df.drop(columns=columns)] + list_unpacked_results,
        axis=1)
