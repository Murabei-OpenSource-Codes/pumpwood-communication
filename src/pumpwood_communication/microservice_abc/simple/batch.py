"""Module for Simple Batch end-points of microservice."""
import sys
import copy
import pandas as pd
from abc import ABC
from typing import List, Union, Dict
from multiprocessing import Pool
from pumpwood_communication.config import PUMPWOOD_COMUNICATION__N_PARALLEL
from pumpwood_communication.microservice_abc.base import (
    PumpWoodMicroServiceBase)
from pumpwood_communication.exceptions import PumpWoodException
from pumpwood_communication.serializers import CompositePkBase64Converter


class ABCSimpleBatchMicroservice(ABC, PumpWoodMicroServiceBase):
    """Abstract class for batch end-points."""

    @staticmethod
    def _build_aggregate_url(model_class: str):
        return "rest/%s/aggregate/" % (model_class.lower(),)

    def aggregate(self, model_class: str, group_by: List[str], agg: dict,
                  filter_dict: None | dict = None, exclude_dict: dict = None,
                  order_by: List[str] = None, auth_header: dict = None,
                  limit: int = None) -> pd.DataFrame:
        """Save a list of objects with one request.

        Args:
            model_class (str):
                Model class of the end-point that will be aggregated.
            group_by (List[str]):
                List of the fields that will be used on aggregation as
                group by.
            agg (dict):
                A dictionary with dictionary itens as `field` and `function`
                specifing the field that will be aggregated using a function.
            filter_dict (dict):
                Filter that will be applied before the aggregation.
            exclude_dict (dict):
                Exclude clause that will be applied before the aggregation.
            order_by (list):
                Ordenation acording to grouping elements. It can be used
                fields created as keys of agg dictinary.
            auth_header (dict):
                Authentication header used to impersonation of user.
            limit (int):
                Limit number of returned row at aggregation query.

        Returns:
            Return a DataFrame with aggregation results.
        """
        filter_dict = {} if filter_dict is None else filter_dict
        exclude_dict = {} if exclude_dict is None else exclude_dict
        order_by = [] if order_by is None else order_by

        url_str = self._build_aggregate_url(model_class=model_class)
        data = {
            'agg': agg, 'group_by': group_by, 'filter_dict': filter_dict,
            'exclude_dict': exclude_dict, 'order_by': order_by,
            'limit': limit}
        return self.request_post(
            url=url_str, data=data, auth_header=auth_header)

    @staticmethod
    def _build_pivot_url(model_class):
        return "rest/%s/pivot/" % (model_class.lower(), )

    def pivot(self, model_class: str, columns: None | List[str] = None,
              format: str = 'list', filter_dict: dict = None,
              exclude_dict: dict = None, order_by: List[str] = None,
              variables: List[str] = None, show_deleted: bool = False,
              add_pk_column: bool = False, auth_header: dict = None,
              as_dataframe: bool = False
              ) -> Union[List[dict], Dict[str, list], pd.DataFrame]:
        """Pivot object data acording to columns specified.

        Pivoting per-se is not usually used, beeing the name of the function
        a legacy. Normality data transformation is done at the client level.

        Args:
            model_class (str):
                Model class to check search parameters.
            columns (List[str]):
                List of fields to be used as columns when pivoting the data.
            format (str):
                Format to be used to convert pandas.DataFrame to
                dictionary, must be in ['dict','list','series',
                'split', 'records','index'].
            filter_dict (dict):
                Same as list function.
            exclude_dict (dict):
                Same as list function.
            order_by (List[str]):
                 Same as list function.
            variables (List[str]):
                List of the fields to be returned, if None, the default
                variables will be returned. Same as fields on list functions.
            show_deleted (bool):
                Fields with deleted column will have objects with deleted=True
                omited from results. show_deleted=True will return this
                information.
            add_pk_column (bool):
                If add pk values of the objects at pivot results. Adding
                pk key on pivot end-points won't be possible to pivot since
                pk is unique for each entry.
            auth_header (dict):
                Auth header to substitute the microservice original
                at the request (user impersonation).
            as_dataframe (bool):
                If results should be returned as a dataframe.

        Returns:
            Return a list or a dictinary depending on the format set on
            format parameter.

        Raises:
            PumpWoodException:
                'Columns must be a list of elements.'. Indicates that the list
                argument was not a list.
            PumpWoodException:
                'Column chosen as pivot is not at model variables'. Indicates
                that columns that were set to pivot are not present on model
                variables.
            PumpWoodException:
                "Format must be in ['dict','list','series','split',
                'records','index']". Indicates that format set as paramenter
                is not implemented.
            PumpWoodException:
                "Can not add pk column and pivot information". If
                add_pk_column is True (results will have the pk column), it is
                not possible to pivot the information (pk is an unique value
                for each object, there is no reason to pivot it).
            PumpWoodException:
                "'value' column not at melted data, it is not possible
                to pivot dataframe.". Indicates that data does not have a value
                column, it must have it to populate pivoted table.
        """
        filter_dict = {} if filter_dict is None else filter_dict
        exclude_dict = {} if exclude_dict is None else exclude_dict
        order_by = [] if order_by is None else order_by
        columns = [] if columns is None else columns

        url_str = self._build_pivot_url(model_class)
        post_data = {
            'columns': columns, 'format': format,
            'filter_dict': filter_dict, 'exclude_dict': exclude_dict,
            'order_by': order_by, "variables": variables,
            "show_deleted": show_deleted, "add_pk_column": add_pk_column}
        pivot_results = self.request_post(
            url=url_str, data=post_data, auth_header=auth_header)

        if not add_pk_column:
            if as_dataframe:
                return pd.DataFrame(pivot_results)
            else:
                return pivot_results
        else:
            pd_pivot_results = pd.DataFrame(pivot_results)
            if len(pd_pivot_results) != 0:
                fill_options = self.fill_options(
                    model_class=model_class, auth_header=auth_header)
                primary_keys = fill_options["pk"]["column"]
                pd_pivot_results["pk"] = pd_pivot_results[primary_keys].apply(
                    CompositePkBase64Converter.dump,
                    primary_keys=primary_keys, axis=1)
            if as_dataframe:
                return pd_pivot_results
            else:
                return pd_pivot_results.to_dict(format)

    def _flat_list_by_chunks_helper(self, args):
        try:
            # Unpacking arguments
            model_class = args["model_class"]
            filter_dict = args["filter_dict"]
            exclude_dict = args["exclude_dict"]
            fields = args["fields"]
            show_deleted = args["show_deleted"]
            auth_header = args["auth_header"]
            chunk_size = args["chunk_size"]

            temp_filter_dict = copy.deepcopy(filter_dict)
            url_str = self._build_pivot_url(model_class)
            max_pk = 0

            # Fetch data until an empty result is returned
            list_dataframes = []
            while True:
                sys.stdout.write(".")
                sys.stdout.flush()
                temp_filter_dict["id__gt"] = max_pk
                post_data = {
                    'format': 'list',
                    'filter_dict': temp_filter_dict,
                    'exclude_dict': exclude_dict,
                    'order_by': ["id"], "variables": fields,
                    "show_deleted": show_deleted,
                    "limit": chunk_size,
                    "add_pk_column": True}
                temp_dateframe = pd.DataFrame(self.request_post(
                    url=url_str, data=post_data, auth_header=auth_header))

                # Break if results are less than chunk size, so no more results
                # are avaiable
                if len(temp_dateframe) < chunk_size:
                    list_dataframes.append(temp_dateframe)
                    break

                max_pk = int(temp_dateframe["id"].max())
                list_dataframes.append(temp_dateframe)

            if len(list_dataframes) == 0:
                return pd.DataFrame()
            else:
                return pd.concat(list_dataframes)
        except Exception as e:
            raise Exception("Exception at flat_list_by_chunks:", str(e))

    def flat_list_by_chunks(self, model_class: str, filter_dict: dict = {},
                            exclude_dict: dict = {}, fields: List[str] = None,
                            show_deleted: bool = False,
                            auth_header: dict = None,
                            chunk_size: int = 1000000,
                            n_parallel: int = None,
                            create_composite_pk: bool = False,
                            start_date: str = None,
                            end_date: str = None) -> pd.DataFrame:
        """Incrementally fetch data from pivot end-point.

        Fetch data from pivot end-point paginating by id of chunk_size lenght.

        If table is partitioned it will split the query acording to partition
        to facilitate query at the database.

        If start_date and end_date are set, also breaks the query by month
        retrieving each month data in parallel.

        Args:
            model_class (str):
                Model class to be pivoted.
            filter_dict (dict):
                Dictionary to to be used in objects.filter argument
                (Same as list end-point).
            exclude_dict (dict):
                Dictionary to to be used in objects.exclude argument
                (Same as list end-point).
            fields (List[str] | None):
                List of the variables to be returned,
                if None, the default variables will be returned.
                If fields is set, dataframe will return that columns
                even if data is empty.
            start_date (datetime | str):
                Set a begin date for the query. If begin and end date are
                set, query will be splited with chucks by month that will be
                requested in parallel.
            end_date (datetime | str):
                Set a end date for the query. If begin and end date are
                set, query will be splited with chucks by month that will be
                requested in parallel.
            show_deleted (bool):
                If deleted data should be returned.
            auth_header (dict):
                Auth header to substitute the microservice original
                at the request (user impersonation).
            chunk_size (int):
                Limit of data to fetch per call.
            n_parallel (int):
                Number of parallel process to perform.
            create_composite_pk (bool):
                If true and table has a composite pk, it will create pk
                value based on the hash on the json serialized dictionary
                of the components of the primary key.

        Returns:
            Returns a dataframe with all information fetched.

        Raises:
            No particular raise.
        """
        if n_parallel is None:
            n_parallel = PUMPWOOD_COMUNICATION__N_PARALLEL

        temp_filter_dict = copy.deepcopy(filter_dict)
        fill_options = self.fill_options(
            model_class=model_class, auth_header=auth_header)
        primary_keys = fill_options["pk"]["column"]
        partition = fill_options["pk"].get("partition", [])

        # Create a list of month and include start and end dates if not at
        # the beginning of a month
        month_sequence = None
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

        resp_df = pd.DataFrame()

        ##########################################################
        # If table have more than one partition, run in parallel #
        # the {partition}__in elements along with dates          #
        if 1 < len(partition):
            partition_col_1st = partition[0]
            filter_dict_keys = list(temp_filter_dict.keys())
            partition_filter = None
            count_partition_col_1st_filters = 0
            for col in filter_dict_keys:
                if partition_col_1st + "__in" == col:
                    partition_filter = temp_filter_dict[col]
                    del temp_filter_dict[col]
                    count_partition_col_1st_filters = \
                        count_partition_col_1st_filters + 1
                elif partition_col_1st == col:
                    partition_filter = [temp_filter_dict[col]]
                    del temp_filter_dict[col]
                    count_partition_col_1st_filters = \
                        count_partition_col_1st_filters + 1

            # Validating query for partitioned tables
            if partition_filter is None:
                msg = (
                    "Table is partitioned with sub-partitions, running "
                    "queries without at least first level partition will "
                    "lead to long waiting times or hanging queries. Please "
                    "use first partition level in filter_dict with equal "
                    "or in operators. Table partitions: {}"
                ).format(partition)
                raise PumpWoodException(message=msg)

            if 1 < count_partition_col_1st_filters:
                msg = (
                    "Please give some help for the dev here, use just one "
                    "filter_dict entry for first partition...")
                raise PumpWoodException(message=msg)

            # Parallelizing query using partition columns
            pool_arguments = []
            for filter_key in partition_filter:
                request_filter_dict = copy.deepcopy(temp_filter_dict)
                request_filter_dict[partition_col_1st] = filter_key
                if month_sequence is None:
                    pool_arguments.append({
                        "model_class": model_class,
                        "filter_dict": request_filter_dict,
                        "exclude_dict": exclude_dict,
                        "fields": fields,
                        "show_deleted": show_deleted,
                        "auth_header": auth_header,
                        "chunk_size": chunk_size})
                else:
                    for i in range(len(month_sequence)):
                        request_filter_dict_t = copy.deepcopy(
                            request_filter_dict)
                        # If is not the last interval, query using open
                        # right interval so subsequence queries does
                        # not overlap
                        if i != len(month_sequence) - 1:
                            request_filter_dict_t["time__gte"] = \
                                month_sequence[i]["start"]
                            request_filter_dict_t["time__lt"] = \
                                month_sequence[i]["end"]

                        # At the last interval use closed right interval so
                        # last element is also included in the interval
                        else:
                            request_filter_dict_t["time__gte"] = \
                                month_sequence[i]["start"]
                            request_filter_dict_t["time__lte"] = \
                                month_sequence[i]["end"]

                        pool_arguments.append({
                            "model_class": model_class,
                            "filter_dict": request_filter_dict_t,
                            "exclude_dict": exclude_dict,
                            "fields": fields,
                            "show_deleted": show_deleted,
                            "auth_header": auth_header,
                            "chunk_size": chunk_size})

            # Perform parallel calls to backend each chucked by chunk_size
            print("## Starting parallel flat list: %s" % len(pool_arguments))
            try:
                with Pool(n_parallel) as p:
                    results = p.map(
                        self._flat_list_by_chunks_helper,
                        pool_arguments)
                resp_df = pd.concat(results).reset_index(drop=True)
            except Exception as e:
                PumpWoodException(message=str(e))
            print("\n## Finished parallel flat list: %s" % len(pool_arguments))

        ############################################
        # If table have partition, run in parallel #
        else:
            try:
                results_key_data = self._flat_list_by_chunks_helper({
                    "model_class": model_class,
                    "filter_dict": temp_filter_dict,
                    "exclude_dict": exclude_dict,
                    "fields": fields,
                    "show_deleted": show_deleted,
                    "auth_header": auth_header,
                    "chunk_size": chunk_size})
                resp_df = results_key_data
            except Exception as e:
                PumpWoodException(message=str(e))

        if (1 < len(primary_keys)) and create_composite_pk:
            print("## Creating composite pk")
            if len(resp_df) != 0:
                resp_df["pk"] = resp_df[primary_keys].apply(
                    CompositePkBase64Converter.dump,
                    primary_keys=primary_keys, axis=1)
            else:
                resp_df["pk"] = None

            if fields is not None:
                fields = ['pk'] + fields

        # Adjust columns to return the columns set at fields
        if fields is not None:
            resp_df = pd.DataFrame(resp_df, columns=fields)
        return resp_df
