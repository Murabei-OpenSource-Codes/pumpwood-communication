"""Auxiliary functions used on flat_list_by_chunks."""
import pandas as pd
import datetime
import copy
from pumpwood_communication.exceptions import PumpWoodException
from pumpwood_communication.serializers import CompositePkBase64Converter


class AuxFlatListByChunks:
    """Auxiliary codes used on flat list by chucks."""

    @classmethod
    def build_month_partitions(cls, start_date: str | datetime.datetime,
                               end_date: str | datetime.datetime):
        """Create the month partitions to be used on parallel query.

        Args:
            start_date (str | datetime.datetime):
                Date to start the partitions.
            end_date (str | datetime.datetime):
                Date to end the partitions.
        """
        start_date = pd.to_datetime(start_date)
        end_date = pd.to_datetime(end_date)
        list_month_sequence = pd.date_range(
            start=start_date, end=end_date, freq='MS').tolist()
        month_sequence = pd.Series(
            [start_date] + list_month_sequence + [end_date])\
            .drop_duplicates()\
            .sort_values()\
            .tolist()

        # Create the start and end periods for quering the data
        month_df = pd.DataFrame({'end': month_sequence})
        month_df['start'] = month_df['end'].shift()
        month_df = month_df.dropna().drop_duplicates()
        month_sequence = month_df.to_dict("records")
        return month_sequence

    @classmethod
    def build_query_partitions(cls, model_class: str,
                               time_partitions: list[dict] | None,
                               filter_dict: dict, exclude_dict: dict,
                               show_deleted: bool, auth_header: dict,
                               chunk_size: int, fields: list[str],
                               time_column: str | None
                               ) -> list[dict]:
        """Create query partitions to parallel query information on DB.

        It will reapeat the `filter_dict`, `exclude_dict` and `fields` for
        each query and add partitions start and end. If `time_partitions`
        is none a simple dictionary will be returned with `filter_dict`,
        `exclude_dict` and `fields` equal to arguments

        Args:
            model_class (str):
                Object model_class to make the partitions.
            time_partitions (list[dict]):
                Sequence of time to partition the query of the data. Entry
                have `start` and `end` dates to create the partitions.
            filter_dict (dict):
                Filter dictionary that will be used to retrieve information
                from the backend.
            exclude_dict (dict):
                Exclude dictionary that will be used to retrieve information
                from the backend.
            fields (list[str]):
                List of the fields that will be retrieved at the resquest.
            time_column (str | None):
                Name of the column that should be considered as time to
                use on partitioning.
            show_deleted (bool):
                If deleted data should be fetched or ignored.
            auth_header (dict):
                Authentication headers to be used on the requests
            chunk_size (int):
                Size of the chuck that will be used on partition paginating.

        Returns:
            Return a list of dictionaries with the query associated with each
            partition.
        """
        if time_partitions is None:
            return [{
                'model_class': model_class,
                'filter_dict': copy.deepcopy(filter_dict),
                'exclude_dict': copy.deepcopy(exclude_dict),
                'fields': copy.deepcopy(fields),
                'show_deleted': show_deleted,
                'auth_header': auth_header,
                'chunk_size': chunk_size},
            ]

        list_arguments = []
        for i, m in enumerate(time_partitions):
            temp_filter_dict = copy.deepcopy(filter_dict)
            lower_bound = (
                time_column + "__gte"
                if i == 0
                else time_column + "__gt")
            upper_bound = time_column + "__lte"
            temp_filter_dict[lower_bound] = m['start']
            temp_filter_dict[upper_bound] = m['end']
            list_arguments.append({
                'model_class': model_class,
                'filter_dict': temp_filter_dict,
                'exclude_dict': copy.deepcopy(exclude_dict),
                'fields': copy.deepcopy(fields),
                'show_deleted': show_deleted,
                'auth_header': auth_header,
                'chunk_size': chunk_size})
        return list_arguments

    @classmethod
    def add_pk_column(cls, create_composite_pk: bool,
                      primary_key_list: list[str],
                      data: pd.DataFrame) -> pd.DataFrame:
        """Add primary key to dataframe.

        It will build the primary according to `primary_key_list`, if it
        is more than one column, than a base64 will be returned.

        Args:
            create_composite_pk (bool):
                Flag if it is to create the composite key, if false
                the `data` dataframe will be returned.
            primary_key_list (list[str]):
                List of the columns to be considered as primary key.
            data (pd.DataFrame):
                The dataframe to add the primary key data.
        """
        if not create_composite_pk:
            return data

        if len(data) == 0:
            data['pk'] = None
            return data

        missing_pk_cols = set(primary_key_list) - set(data.columns)
        if len(missing_pk_cols):
            msg = (
                "Some primary key columns are not at the dataframe, "
                "it is not possible to create the pk column")
            raise PumpWoodException(msg)

        if len(primary_key_list) == 1:
            pk_column = primary_key_list[0]
            data['pk'] = data.loc[:, pk_column]
        else:
            data["pk"] = data\
                .loc[:, primary_key_list]\
                .apply(
                    CompositePkBase64Converter.dump,
                    primary_keys=primary_key_list, axis=1)
        return data
