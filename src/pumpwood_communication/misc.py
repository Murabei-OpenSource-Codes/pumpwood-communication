"""Miscelaneus function to help in development."""
import pandas as pd


def unpack_dict_columns(df: pd.DataFrame, columns: list) -> pd.DataFrame:
    """
    Unpack dictonary columns at a dataframe.

    Return a copy of the dataframe with 'columns' unpacked and removed
    from result.

    Args:
        df [pd.DataFrame]: Dataframe to unpack the columns.
        columns [list]: List of columns to unpack in columns.
    Return [pd.DataFrame]:
        Return a dataframe with dict columns unpacked.
    """
    list_unpacked_results = []
    for c in columns:
        list_unpacked_results.append(df[c].apply(pd.Series))
    return pd.concat(
        [df.drop(columns=columns)] + list_unpacked_results,
        axis=1)
