"""Module for parallel functions of microservice."""
from typing import Union, List
from pumpwood_communication.microservice_abc.parallel.base import (
    ABCParallelBaseMicroservice)


class ABCParallelDeleteMicroservice(ABCParallelBaseMicroservice):
    """Abstract class for parallel calls at Pumpwood end-points."""

    def parallel_delete(self, model_class: Union[str, list[str]],
                        list_pk: list[int], n_parallel: int = None,
                        auth_header: dict = None,
                        base_filter_skip: list[str] | list[list[str]] = None,
                        disable_etl_trigger: bool | list[bool] = False):
        """Make many [n_parallel] delete requests.

        Args:
            model_class:
                Model Class to list one.
            list_pk:
                List of the pks to list one.
            n_parallel:
                Number of simultaneous requests. If not set, uses
                ``PUMPWOOD_COMMUNICATION__N_PARALLEL`` env variable
                (legacy spelling supported), default 4.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            base_filter_skip (list):
                List of base query filter to be skiped, it is necessary to
                be superuser to skip base query filters.
            disable_etl_trigger (bool):
                Disable the ETL trigger for the object.

        Returns:
            List of the delete request data.

        Raises:
            PumpWoodException:
                'len(model_class)[{}] != len(list_args)[{}]'. Indicates
                that length of model_class and list_args arguments are not
                equal.
        """
        n_parallel = self.get_n_parallel(n_parallel=n_parallel)

        list_model_class = self.convert_to_list(
            argument=model_class, length=len(list_pk))
        list_auth_header = self.convert_to_list(
            argument=auth_header, length=len(list_pk))
        list_base_filter_skip = self.convert_to_list(
            argument=base_filter_skip, length=len(list_pk),
            force_replicate=True)
        list_disable_etl_trigger = self.convert_to_list(
            argument=disable_etl_trigger, length=len(list_pk))
        column_arg = {
            'model_class': list_model_class,
            'auth_header': list_auth_header,
            'base_filter_skip': list_base_filter_skip,
            'pk': list_pk,
            'disable_etl_trigger': list_disable_etl_trigger,
        }

        function_args = self.transpose_args(dict_list=column_arg)
        return self.parallel_call(
            function=self.delete, function_args=function_args,
            n_parallel=n_parallel)

    def parallel_delete_many(self, model_class: Union[str, List[str]],
                             list_args: List[dict], n_parallel: int = None,
                             auth_header: dict = None,
                             base_filter_skip: list[str] | list[list[str]] = None # NOQA
                             ) -> List[dict]:
        """Make [n_parallel] parallel delete_many request.

        Args:
            model_class (str):
                Model Class to delete many.
            list_args (list):
                A list of list request args (filter_dict, exclude_dict).
            n_parallel:
                Number of simultaneous requests. If not set, uses
                ``PUMPWOOD_COMMUNICATION__N_PARALLEL`` env variable
                (legacy spelling supported), default 4.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            base_filter_skip (list):
                List of base query filter to be skiped, it is necessary to
                be superuser to skip base query filters.

        Returns:
            List of the delete many request reponses.

        Raises:
            PumpWoodException:
                'len(model_class)[{}] != len(list_args)[{}]'. Indicates
                that length of model_class and list_args arguments
                are not equal.

        Example:
            No example yet.
        """
        n_parallel = self.get_n_parallel(n_parallel=n_parallel)

        dict_list = self.expand_list_args(
            list_args=list_args, keys=['filter_dict', 'exclude_dict'])
        list_model_class = self.convert_to_list(
            argument=model_class, length=len(list_args))
        list_auth_header = self.convert_to_list(
            argument=auth_header, length=len(list_args))
        list_base_filter_skip = self.convert_to_list(
            argument=base_filter_skip, length=len(list_args),
            force_replicate=True)
        column_arg = {
            'model_class': list_model_class,
            'auth_header': list_auth_header,
            'base_filter_skip': list_base_filter_skip}
        column_arg.update(dict_list)

        function_args = self.transpose_args(dict_list=column_arg)
        return self.parallel_call(
            function=self.delete_many, function_args=function_args,
            n_parallel=n_parallel)
