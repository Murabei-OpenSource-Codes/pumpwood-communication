"""Module for parallel functions of microservice."""
import sys
import pandas as pd
from abc import ABC
from typing import Union, List, Any
from concurrent.futures import ThreadPoolExecutor
from pumpwood_communication.config import N_PARALLEL
from pumpwood_communication.exceptions import (
    PumpWoodException, PumpWoodNotImplementedError,
    PumpWoodOtherException)


class ABCParallelBaseMicroservice(ABC):
    """Abstract class for parallel calls at Pumpwood end-points."""

    @classmethod
    def convert_to_list(cls, argument: Any | list[Any],
                        length: int, force_replicate: bool = False
                        ) -> list[Any]:
        """Convert argument to list.

        Args:
            argument (Any | list[Any]):
                The argument that will be converted to a list and validated
                according to types_allowed.
            length (int):
                Size of the final arument list, if argument is a list
                already it will validate if it's size matchs.
            force_replicate (bool):
                Force argument replication, this will be usefull
                for list argument that need to be replicated.

        Returns:
            Return the a list with validated parameters.
        """
        temp_argument = None
        if isinstance(argument, list) and not force_replicate:
            temp_argument = argument
        else:
            temp_argument = [argument] * length

        # Check if length compatibility
        if len(temp_argument) != length:
            msg = (
                "Argument length is incompatible: return argument "
                "length[{arg_length}]; length [{length}]")
            raise PumpWoodException(
                message=msg, payload={
                    'arg_length': len(temp_argument),
                    'length': length})
        else:
            return temp_argument

    @classmethod
    def transpose_args(cls, dict_list: dict[str, list]) -> list[dict]:
        """Transpose arguments.

        Receive a dictonary of lists and convert them to a list of dicionaries.
        This will able parallel calls

        Args:
            dict_list (dict[str, list]):
                A dicionary with list as values for keys.

        Returns:
            Return a list of dicionaries using the same keys of the list.
        """
        return pd.DataFrame(dict_list).to_dict('records')

    @classmethod
    def get_n_parallel(cls, n_parallel: int | None) -> int:
        """Get n parallel from default value or from passed argument."""
        return n_parallel or N_PARALLEL

    @staticmethod
    def flatten_parallel(parallel_result: list):
        """Concat all parallel return to one list.

        Args:
            parallel_result:
                A list of lists to be flated (concatenate
                all lists into one).

        Returns:
            A list with all sub list itens.
        """
        return [
            item for sublist in parallel_result
            for item in sublist]

    @classmethod
    def expand_list_args(cls, list_args: list[dict],
                         keys: list[str] = ['filter_dict', 'exclude_dict',
                                            'order_by']
                         ) -> dict[str, list]:
        """Expand list args to columns fields."""
        return_dict = {}
        for key in keys:
            return_dict[key] = [None] * len(list_args)

        for i, x in enumerate(list_args):
            for key in keys:
                return_dict[key][i] = x.get(key)
        return return_dict

    @classmethod
    def parallel_call(cls,
                      function: callable,
                      function_args: list[dict],
                      n_parallel: int = None) -> list[Any]:
        """Concat all parallel return to one list.

        Args:
            function (callable):
                Function callable used on parallel call.
            function_args:
                Args that will be associated with parallel call.
            n_parallel (int):
                Args that will be associated with parallel call.

        Returns:
            A list with all sub list itens.
        """
        n_parallel = cls.get_n_parallel(n_parallel=n_parallel)

        def _thread_wrapper(args):
            """Internal wrapper to handle the progress dots and error."""
            try:
                result = function(**args)
                sys.stdout.write(".")
                sys.stdout.flush()
                return result
            except Exception as e:
                if isinstance(e, PumpWoodException):
                    e.parallel = True
                    raise e
                else:
                    error_template = "Error in parallel call: {error}"
                    raise PumpWoodOtherException(
                        message=error_template, parallel=True,
                        payload={"error": str(e)})

        # Use ThreadPoolExecutor for I/O bound tasks (Network requests)
        with ThreadPoolExecutor(max_workers=n_parallel) as executor:
            # executor.map maintains the order of the input list
            results = list(executor.map(_thread_wrapper, function_args))

        sys.stdout.write("|\n")
        sys.stdout.flush()
        return results

    def parallel_request_get(self, urls_list: list, n_parallel: int = None,
                             parameters: Union[List[dict], dict] = None,
                             auth_header: dict = None) -> List[any]:
        """Make [n_parallel] parallel get requests.

        Args:
            urls_list:
                List of urls to make get requests.
            parameters:
                A list of dictionary or a dictionary that will be replicated
                len(urls_list) and passed to parallel request as url
                parameter. If not set, empty dictionary will be passed to all
                request as default.
            n_parallel:
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            Return a list with all get request reponses. The results are
            on the same order of argument list.

        Raises:
            PumpWoodException:
                'length of urls_list[{}] is different of parameters[{}]'.
                Indicates that the function arguments `urls_list` and
                `parameters` (when passed as a list of dictionaries)
                does not have de same length.
            PumpWoodNotImplementedError:
                'paraemters type[{}] is not implemented'. Indicates that
                `parameters` passed as function argument is not a list of dict
                or a dictinary, so not implemented.
        """
        n_parallel = self.get_n_parallel(n_parallel=n_parallel)

        # Create URL parameters if not set as parameter with
        # empty dicionaries
        n_urls = len(urls_list)
        parameters_list = None
        if parameters is None:
            parameters = [{}] * n_urls
        elif type(parameters) is dict:
            parameters = [{parameters}] * n_urls
        elif type(parameters) is list:
            if len(parameters) == n_urls:
                parameters_list = parameters
            else:
                msg = (
                    'length of urls_list[{}] is different of ' +
                    'parameters[{}]').format(
                        n_urls, len(parameters))
                raise PumpWoodException(msg)
        else:
            msg = 'paraemters type[{}] is not implemented'.format(
                str(type(parameters)))
            raise PumpWoodNotImplementedError(msg)

        # Create Pool arguments to run in parallel
        pool_arguments = []
        for i in range(len(urls_list)):
            pool_arguments.append({
                'url': urls_list[i], 'auth_header': auth_header,
                'parameters': parameters_list[i]})

        return self.parallel_call(
            function=self.request_get, function_args=pool_arguments,
            n_parallel=n_parallel)

    def parallel_request_post(self, urls_list: List[str],
                              data_list: List[dict],
                              parameters: Union[List[dict], dict] = None,
                              n_parallel: int = None,
                              auth_header: dict = None) -> List[any]:
        """Make [n_parallel] parallel post request.

        Args:
            urls_list:
                List of urls to make get requests.
            data_list:
                List of data to be used as post payloads.
            parameters:
                URL paramenters to make the post requests.
            n_parallel:
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            List of the post request reponses.

        Raises:
            No particular raises

        Example:
            No example yet.

        """
        n_parallel = self.get_n_parallel(n_parallel=n_parallel)

        # Create URL parameters if not set as parameter with
        # empty dicionaries
        n_urls = len(urls_list)
        parameters_list = None
        if parameters is None:
            parameters_list = [{}] * n_urls
        elif type(parameters) is dict:
            parameters_list = [{parameters}] * n_urls
        elif type(parameters) is list:
            if len(parameters) == n_urls:
                parameters_list = parameters
            else:
                msg = (
                    'length of urls_list[{}] is different of ' +
                    'parameters[{}]').format(
                        n_urls, len(parameters))
                raise PumpWoodException(msg)
        else:
            msg = 'paraemters type[{}] is not implemented'.format(
                str(type(parameters)))
            raise PumpWoodNotImplementedError(msg)

        # Validate if length of URL is the same of data_list
        if len(urls_list) != len(data_list):
            msg = (
                'len(urls_list)[{}] must be equal ' +
                'to len(data_list)[{}]').format(
                    len(urls_list), len(data_list))
            raise PumpWoodException(msg)

        # Create the arguments for parallel requests
        pool_arguments = []
        for i in range(len(urls_list)):
            pool_arguments.append({
                'url': urls_list[i],
                'data': data_list[i],
                'parameters': parameters_list[i],
                'auth_header': auth_header})

        return self.parallel_call(
            function=self.request_post, function_args=pool_arguments,
            n_parallel=n_parallel)

    def parallel_request_delete(self, urls_list: List[str],
                                parameters: Union[List[dict], dict] = None,
                                n_parallel: int = None,
                                auth_header: dict = None):
        """Make [n_parallel] parallel delete request.

        Args:
            urls_list:
                List of urls to make get requests.
            parameters:
                URL paramenters to make the post requests.
            n_parallel (int): Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            list: List of the get request reponses.

        Raises:
            No particular raises.

        Example:
            No example yet.
        """
        n_parallel = self.get_n_parallel(n_parallel=n_parallel)

        # Create URL parameters if not set as parameter with
        # empty dicionaries
        n_urls = len(urls_list)
        parameters_list = None
        if parameters is None:
            parameters = [{}] * n_urls
        elif type(parameters) is dict:
            parameters = [{parameters}] * n_urls
        elif type(parameters) is list:
            if len(parameters) == n_urls:
                parameters_list = parameters
            else:
                msg = (
                    'length of urls_list[{}] is different of ' +
                    'parameters[{}]').format(
                        n_urls, len(parameters))
                raise PumpWoodException(msg)
        else:
            msg = 'paraemters type[{}] is not implemented'.format(
                str(type(parameters)))
            raise PumpWoodNotImplementedError(msg)

        # Create Pool arguments to run in parallel
        pool_arguments = []
        for i in range(len(urls_list)):
            pool_arguments.append({
                'url': urls_list[i], 'auth_header': auth_header,
                'parameters': parameters_list[i]})

        return self.parallel_call(
            function=self.request_delete, function_args=pool_arguments,
            n_parallel=n_parallel)
