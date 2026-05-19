"""Module for parallel functions of microservice."""
import pandas as pd
from typing import Union, List, Any
from pumpwood_communication.microservice_abc.parallel.base import (
    ABCParallelBaseMicroservice)


class ABCParallelBatchMicroservice(ABCParallelBaseMicroservice):
    """Abstract class for parallel calls at Pumpwood end-points."""

    def parallel_pivot(self, model_class: str,
                       list_args: list[dict[str, Any]],
                       columns: None | List[str] = None,
                       format: str = 'list',
                       variables: List[str] = None,
                       fields: List[str] = None,
                       show_deleted: bool = False,
                       add_pk_column: bool = False,
                       auth_header: dict = None,
                       as_dataframe: bool = False,
                       n_parallel: int = None,
                       flat_results: bool = True) -> Union[List[dict], pd.DataFrame]: # NOQA
        """Execute parallel calls for pivot end-points.

        This method performs multiple calls to a pivot end-point in
        parallel, allowing to request aggregations with different filters
        or exclusions simultaneously.

        Args:
            model_class (str):
                Model class of the end-point.
            list_args (list[dict[str, Any]]):
                A list of dictionaries containing `filter_dict` and
                `exclude_dict` to be used in the parallel queries.
            columns (list):
                List of columns to group by on the pivot operation.
                Defaults to None.
            format (str):
                Format of the returned data. Defaults to 'list'.
            variables (list):
                Variables to be used in the pivot values. Defaults to None.
            fields (list):
                Fields to be returned by the end-point. Defaults to None.
            show_deleted (bool):
                If deleted objects should be included. Defaults to False.
            add_pk_column (bool):
                If the primary key column should be added to the result.
                Defaults to False.
            auth_header (dict):
                Authorization header to impersonate the request.
                Defaults to None.
            as_dataframe (bool):
                If True, returns the results as a pandas DataFrame.
                Defaults to False.
            n_parallel (int):
                Number of parallel requests. If None, uses default.
                Defaults to None.
            flat_results (bool):
                If True, results will be joined into a single list or
                DataFrame. Defaults to True.

        Returns:
            Union[List[dict], pd.DataFrame]:
                Containing objects resulting from the pivot operation,
                either as a list of dictionaries or a pandas DataFrame.

        Raises:
            No specific raises mapped for this execution.
        """
        n_parallel = self.get_n_parallel(n_parallel=n_parallel)

        # Convert arguments to list
        dict_list = self.expand_list_args(
            list_args=list_args, keys=['filter_dict', 'exclude_dict'])
        list_model_class = self.convert_to_list(
            argument=model_class, length=len(list_args))
        list_auth_header = self.convert_to_list(
            argument=auth_header, length=len(list_args))
        list_fields = self.convert_to_list(
            argument=fields, length=len(list_args),
            force_replicate=True)
        list_format = self.convert_to_list(
            argument=format, length=len(list_args))
        list_columns = self.convert_to_list(
            argument=columns, length=len(list_args),
            force_replicate=True)
        list_variables = self.convert_to_list(
            argument=variables, length=len(list_args),
            force_replicate=True)
        list_show_deleted = self.convert_to_list(
            argument=show_deleted, length=len(list_args),
            force_replicate=True)
        list_add_pk_column = self.convert_to_list(
            argument=add_pk_column, length=len(list_args),
            force_replicate=True)
        list_as_dataframe = self.convert_to_list(
            argument=as_dataframe, length=len(list_args),
            force_replicate=True)

        column_arg = {
            'model_class': list_model_class,
            'auth_header': list_auth_header,
            'fields': list_fields,
            'columns': list_columns,
            'format': list_format,
            'variables': list_variables,
            'show_deleted': list_show_deleted,
            'add_pk_column': list_add_pk_column,
            "as_dataframe": list_as_dataframe}
        column_arg.update(dict_list)

        function_args = self.transpose_args(dict_list=column_arg)
        parallel_results = self.parallel_call(
            function=self.pivot, function_args=function_args,
            n_parallel=n_parallel)
        if flat_results:
            return self.flatten_parallel(
                parallel_results, as_dataframe=as_dataframe)
        else:
            return parallel_results
