"""Miscelaneus function to help in development."""
import pandas as pd
import copy
from typing import List, Literal
from pumpwood_communication.exceptions import PumpWoodException


def unpack_dict_columns(df: pd.DataFrame, columns: List[str]) -> pd.DataFrame:
    """Unpack dictinary columns at a dataframe.

    Return a copy of the dataframe with 'columns' unpacked and removed
    from result.

    Args:
        df (pd.DataFrame):
            Dataframe to unpack the columns.
        columns (List[str]):
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


def extract_dict_subset(data: dict, keys: List[str],
                        raise_not_present: Literal[
                            'raise', 'ignore', 'add_none'] = 'raise'):
    """Extract a subset of data from dictonary.

    Args:
        data (dict):
            Dictionary data from which the subset will be extracted.
        keys (List[str]):
            Keys that will be extracted.
        raise_not_present (str):
            Control if an erros should be raised when key is not present.
            - 'raise': Raise error
            - 'ignore': Does not return the missing key on function result.
            - 'add_none': Return key with None value.

    Returns:
        Return a dictonary with a copy of subset of the keys of original
        dictonary.
    """
    if raise_not_present not in ['raise', 'ignore', 'add_none']:
        msg = (
            'raise_not_present must be in [raise, ignore, add_none].'
            'raise_not_present={raise_not_present}')
        raise PumpWoodException(
            message=msg, payload={
                'raise_not_present': raise_not_present})

    return_dict = {}
    for key in keys:
        temp_data = data.get(key)
        if temp_data is None:
            if raise_not_present == 'raise':
                msg = (
                    'key [{key}] not found on dictonary and raise_not_present '
                    'arg is set as [{raise_not_present}]')
                raise PumpWoodException(
                    message=msg, payload={
                        'key': key, 'raise_not_present': raise_not_present})
            if raise_not_present == 'ignore':
                continue
            if raise_not_present == 'add_none':
                return_dict[key] = None
        else:
            return_dict[key] = copy.deepcopy(temp_data)
    return return_dict
