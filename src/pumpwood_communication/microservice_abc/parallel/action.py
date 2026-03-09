"""Module for parallel functions of microservice."""
from typing import Union
from pumpwood_communication.microservice_abc.parallel.base import (
    ABCParallelBaseMicroservice)


class ABCParallelActionMicroservice(ABCParallelBaseMicroservice):
    """Abstract class for parallel calls at Pumpwood end-points."""

    def parallel_execute_action(self, model_class: Union[str, list[str]],
                                list_pk: list[int],
                                action: str | list[str],
                                parameters: dict | list[dict] = {},
                                n_parallel: int = None,
                                auth_header: dict = None,
                                base_filter_skip: list[str] | list[list[str]] = None # NOQA
                                ) -> list[dict]:
        """Make [n_parallel] parallel execute_action requests.

        Args:
            model_class:
                Model Class to perform action over,
                or a list of model class o make diferent actions.
            list_pk:
                A list of the pks to perform action or a
                single pk to perform action with different paraemters.
            action:
                A list of actions to perform or a single
                action to perform over all pks and parameters.
            parameters:
                Parameters used to perform actions
                or a single dict to be used in all actions.
            n_parallel:
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            base_filter_skip (list[str] | list[list[str]]):
                List of base query filter to be skiped, it is necessary to
                be superuser to skip base query filters.

        Returns:
            list of the execute_action request data.

        Raises:
            PumpWoodException:
                'parallel_length != len([argument])'. Indicates that function
                arguments does not have all the same length.

        Example:
            No example yet.
        """
        n_parallel = self.get_n_parallel(n_parallel=n_parallel)

        list_model_class = self.convert_to_list(
            argument=model_class, length=len(list_pk))
        list_action = self.convert_to_list(
            argument=action, length=len(list_pk))
        list_parameters = self.convert_to_list(
            argument=parameters, length=len(list_pk))
        list_auth_header = self.convert_to_list(
            argument=auth_header, length=len(list_pk))
        list_base_filter_skip = self.convert_to_list(
            argument=base_filter_skip, length=len(list_pk),
            force_replicate=True)
        column_arg = {
            'model_class': list_model_class,
            'action': list_action,
            'parameters': list_parameters,
            'auth_header': list_auth_header,
            'base_filter_skip': list_base_filter_skip}

        function_args = self.transpose_args(dict_list=column_arg)
        return self.parallel_call(
            function=self.execute_action, function_args=function_args,
            n_parallel=n_parallel)
