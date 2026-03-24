"""Module for parallel functions of microservice."""
from typing import Union, List
from pumpwood_communication.microservice_abc.parallel.base import (
    ABCParallelBaseMicroservice)


class ABCParallelListMicroservice(ABCParallelBaseMicroservice):
    """Abstract class for parallel calls at Pumpwood end-points."""

    def parallel_list(self, model_class: Union[str, List[str]],
                      list_args: List[dict],
                      auth_header: dict = None, fields: list = None,
                      default_fields: bool = False, limit: int = None,
                      foreign_key_fields: bool = False,
                      base_filter_skip: list = None,
                      n_parallel: int = None,
                      flat_results: bool = True) -> List[dict]:
        """List objects with pagination.

        Args:
            model_class:
                Model class of the end-point
            list_args:
                filter_dict:
                    Filter dict to be used at the query. Filter elements from
                    query return that satifies all statements of the dictonary.
                exclude_dict:
                    Exclude dict to be used at the query. Remove elements from
                    query return that satifies all statements of the dictonary.
                order_by: Order results acording to list of strings
                    correspondent to fields. It is possible to use '-' at the
                    begginng of the field name for reverse ordering. Ex.:
                    ['description'] for accendent ordering and ['-description']
                    for descendent ordering.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            fields (list):
                Set the fields to be returned by the list end-point.
            default_fields (bool):
                Boolean, if true and fields arguments None will return the
                default fields set for list by the backend.
            limit (int):
                Set the limit of elements of the returned query. By default,
                backend usually return 50 elements.
            foreign_key_fields (bool):
                Return forenging key objects. It will return the fk
                corresponding object. Ex: `created_by_id` reference to
                a user `model_class` the correspondent to User will be
                returned at `created_by`.
            base_filter_skip (list):
                List of base query filter to be skiped, it is necessary to
                be superuser to skip base query filters.
            n_parallel (int):
                Number of parallel requests, if None will use the default
                one.
            flat_results (bool):
                The results will be joined on a single list.

        Returns:
          Containing objects serialized by list Serializer.

        Raises:
          No especific raises.
        """ # NOQA
        n_parallel = self.get_n_parallel(n_parallel=n_parallel)

        # Convert arguments to list
        dict_list = self.expand_list_args(list_args=list_args)
        list_model_class = self.convert_to_list(
            argument=model_class, length=len(list_args))
        list_auth_header = self.convert_to_list(
            argument=auth_header, length=len(list_args))
        list_fields = self.convert_to_list(
            argument=fields, length=len(list_args),
            force_replicate=True)
        list_default_fields = self.convert_to_list(
            argument=default_fields, length=len(list_args))
        list_limit = self.convert_to_list(
            argument=limit, length=len(list_args))
        list_foreign_key_fields = self.convert_to_list(
            argument=foreign_key_fields, length=len(list_args))
        list_base_filter_skip = self.convert_to_list(
            argument=base_filter_skip, length=len(list_args),
            force_replicate=True)

        column_arg = {
            'model_class': list_model_class,
            'auth_header': list_auth_header,
            'fields': list_fields,
            'default_fields': list_default_fields,
            'limit': list_limit,
            'foreign_key_fields': list_foreign_key_fields,
            'base_filter_skip': list_base_filter_skip}
        column_arg.update(dict_list)

        function_args = self.transpose_args(dict_list=column_arg)
        parallel_results = self.parallel_call(
            function=self.list, function_args=function_args,
            n_parallel=n_parallel)
        if flat_results:
            return self.flatten_parallel(parallel_results)
        else:
            return parallel_results

    def parallel_list_without_pag(self, model_class: Union[str, List[str]],
                                  list_args: List[dict],
                                  auth_header: dict = None,
                                  fields: list = None,
                                  default_fields: bool = False,
                                  foreign_key_fields: bool = False,
                                  base_filter_skip: list = None,
                                  n_parallel: int = None,
                                  flat_results: bool = True) -> List[dict]:
        """List objects with pagination.

        Args:
            model_class:
                Model class of the end-point
            list_args:
                filter_dict:
                    Filter dict to be used at the query. Filter elements from
                    query return that satifies all statements of the dictonary.
                exclude_dict:
                    Exclude dict to be used at the query. Remove elements from
                    query return that satifies all statements of the dictonary.
                order_by: Order results acording to list of strings
                    correspondent to fields. It is possible to use '-' at the
                    begginng of the field name for reverse ordering. Ex.:
                    ['description'] for accendent ordering and ['-description']
                    for descendent ordering.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            fields (list):
                Set the fields to be returned by the list end-point.
            default_fields (bool):
                Boolean, if true and fields arguments None will return the
                default fields set for list by the backend.
            foreign_key_fields (bool):
                Return forenging key objects. It will return the fk
                corresponding object. Ex: `created_by_id` reference to
                a user `model_class` the correspondent to User will be
                returned at `created_by`.
            base_filter_skip (list):
                List of base query filter to be skiped, it is necessary to
                be superuser to skip base query filters.
            n_parallel (int):
                Number of parallel requests, if None will use the default
                one.
            flat_results (bool):
                The results will be joined on a single list.

        Returns:
          Containing objects serialized by list Serializer.

        Raises:
          No especific raises.
        """ # NOQA
        n_parallel = self.get_n_parallel(n_parallel=n_parallel)

        # Convert arguments to list
        dict_list = self.expand_list_args(list_args=list_args)
        list_model_class = self.convert_to_list(
            argument=model_class, length=len(list_args))
        list_auth_header = self.convert_to_list(
            argument=auth_header, length=len(list_args))
        list_fields = self.convert_to_list(
            argument=fields, length=len(list_args),
            force_replicate=True)
        list_default_fields = self.convert_to_list(
            argument=default_fields, length=len(list_args))
        list_foreign_key_fields = self.convert_to_list(
            argument=foreign_key_fields, length=len(list_args))
        list_base_filter_skip = self.convert_to_list(
            argument=base_filter_skip, length=len(list_args),
            force_replicate=True)

        column_arg = {
            'model_class': list_model_class,
            'auth_header': list_auth_header,
            'fields': list_fields,
            'default_fields': list_default_fields,
            'foreign_key_fields': list_foreign_key_fields,
            'base_filter_skip': list_base_filter_skip}
        column_arg.update(dict_list)

        function_args = self.transpose_args(dict_list=column_arg)
        parallel_results = self.parallel_call(
            function=self.list_without_pag, function_args=function_args,
            n_parallel=n_parallel)
        if flat_results:
            return self.flatten_parallel(parallel_results)
        else:
            return parallel_results
