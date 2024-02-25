"""Auxiliary functions to help run flat_list_by_chunks."""
import pandas as pd
import copy
from pumpwood_communication.exceptions import (
    exceptions_dict, PumpWoodException, PumpWoodUnauthorized,
    PumpWoodObjectSavingException, PumpWoodOtherException,
    PumpWoodQueryException, PumpWoodNotImplementedError)


def build_month_sequence(start_date: str, end_date: str) -> list:
    """
    Build month sequence using start start_date, end_date.

    Args:
        start_date [str]: Start date filter.
        end_date [str]: End date filter.
    Return:
        Return a list of dictionary with start and end date to be used on
        each query chunk.
    """
    if (start_date is not None) and (end_date is not None):
        start_date = pd.to_datetime(start_date)
        end_date = pd.to_datetime(end_date)
        list_month_sequence = pd.date_range(
            start=start_date, end=end_date, freq='MS').tolist()
        month_sequence = pd.Series(
            [start_date] + list_month_sequence + [end_date]
        ).sort_values().tolist()

        month_df = pd.DataFrame({'end': month_sequence})
        month_df['start'] = month_df['end'].shift()
        month_df = month_df.dropna().drop_duplicates()
        month_sequence = month_df.to_dict("records")
        return month_sequence
    elif (start_date is not None) or (end_date is not None):
        msg = (
            "To break query in chunks using start_date and end_date "
            "both must be set.\n"
            "start_date: {start_date}\n"
            "end_date: {end_date}\n").format(
                start_date=start_date, end_date=end_date)
        raise PumpWoodException(
            message=msg, payload={
                "start_date": start_date,
                "end_date": end_date})
    else:
        return None


def split_partition_filters_run_query(partitions: list,
                                      filter_dict: dict) -> list:
    """
    Split in clause partition filters to run in parallel.

    It will use '__in' operations to split query in parallel requests if
    columns is at 1st partition hierachy.

    Args:
        partitions [list]: Partitions of the model_class from which data is
            fetched.
        filter_dict [dict]: Filter dictionary used on query.
    Return [list]:
        Return a list of dictionaries with query filters partitioned for
        parallel request.
    """
    if len(partitions) == 0:
        return [copy.deepcopy(filter_dict)]

    partition_col_1st = partitions[0]
    partition_filter_not_in = {}
    partition_filter_in = []
    count_partition_col_1st_filters = 0
    # filter_dict["attribute_id__gte"] = 3
    # filter_dict["attribute_id__lte"] = 10

    temp_filter_dict = copy.deepcopy(filter_dict)
    for filter_key, filter_data in filter_dict.items():
        splited_query = filter_key.split("__")
        filter_column = splited_query[0]

        # Check if query is using first partition
        if filter_column == partition_col_1st:
            if 2 < len(splited_query):
                raise PumpWoodNotImplementedError(
                    "It is hard to implement paralelization of partition "
                    "using joins. No ideia how do this... sorry.\n"
                    "Partitions: {partitions}\n"
                    "Filter dict: {filter_dict}",
                    payload={
                        "partitions": partitions,
                        "filter_dict": filter_dict})

            operator = splited_query[1] if len(splited_query) == 2 else "equal"
            # If is an in clause split query request each one individualy
            if operator == "in":
                partition_filter_in = [{
                    filter_column: x
                } for x in filter_data]
                del temp_filter_dict[filter_key]

            # Not in clauses will be performed "as is"
            else:
                partition_filter_not_in[filter_key] = filter_data
                del temp_filter_dict[filter_key]
            count_partition_col_1st_filters = \
                count_partition_col_1st_filters + 1

    if 1 < len(partitions) and count_partition_col_1st_filters == 0:
        raise PumpWoodException(
            "Nested partitioned tables must use firts partition "
            "on query.\nPartitions: {partitions}\n"
            "Filter dict: {filter_dict}",
            payload={
                "partitions": partitions,
                "filter_dict": filter_dict})

    if len(partition_filter_in) == 0:
        partition_filter_not_in.update(temp_filter_dict)
        partition_filter_in = [partition_filter_not_in]
    else:
        for x in partition_filter_in:
            x.update(partition_filter_not_in)
            x.update(temp_filter_dict)
    return partition_filter_in


def build_parallel_pool_args(model_class: str,
                             month_sequence: list,
                             splited_filter_dict: list,
                             exclude_dict: dict,
                             fields: list,
                             show_deleted: bool,
                             auth_header: dict,
                             chunk_size: int) -> list:
    """
    Build parallel pool args.

    Use splited filter dictonary crate parallel pool request arguments.

    Args:
        model_class [str]: Model class from which data will be fetched.
        month_sequence [list]: If start_date and end_date were passed to
            flat_list_by_chunks, it will be created a list of dictonary
            with particionated query by month to be requested in parallel.
        splited_filter_dict [list]: List o filter dictionary splited according
            to 1st partition of table (if any).
        exclude_dict [dict]: Exclude clause of the query.
        fields [list[str]]: Fields that should be returned with the query.
        show_deleted [bool]: It deleted data should be returned.
        auth_header [dict]: Authentication header.
        chunk_size [int]: Number of rows that will be returned at each
            request.
    Return [list[dict]]:
        List of dictonary that will be returned at each pagination of pivot
        request.
    """
    list_pool_args = []
    if month_sequence is None:
        for f in splited_filter_dict:
            list_pool_args.append({
                "model_class": model_class,
                "filter_dict": f,
                "exclude_dict": exclude_dict,
                "fields": fields,
                "show_deleted": show_deleted,
                "auth_header": auth_header,
                "chunk_size": chunk_size})
    # if start and end date were passed as arguments split query
    # using month interval
    else:
        for f in splited_filter_dict:
            for i in range(len(month_sequence)):
                # If is not the last interval, query using open
                # right interval so subsequence querys does
                # not overlap
                if i != len(month_sequence) - 1:
                    f["time__gte"] = month_sequence[i]["start"]
                    f["time__lt"] = month_sequence[i]["end"]

                # At the last interaval use closed right interval so
                # last element is also included in the interval
                else:
                    f["time__gte"] = month_sequence[i]["start"]
                    f["time__lte"] = month_sequence[i]["end"]

                list_pool_args.append({
                    "model_class": model_class,
                    "filter_dict": f,
                    "exclude_dict": exclude_dict,
                    "fields": fields,
                    "show_deleted": show_deleted,
                    "auth_header": auth_header,
                    "chunk_size": chunk_size})
    return list_pool_args
