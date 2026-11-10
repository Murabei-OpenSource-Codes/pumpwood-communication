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
from pumpwood_communication.microservice_abc.parallel.error_handler import (
    ParallelErrorSentinel, ParallelErrorHandlerInput,
    ParallelTaskErrorHandler,
    coerce_parallel_task_error_handler, is_parallel_error_sentinel,
    partition_parallel_results)


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
    def flatten_parallel(parallel_result: list,
                         as_dataframe: bool = False) -> list[dict[str, Any]] | pd.DataFrame:  # NOQA
        """Concat all parallel return to one list.

        Args:
            parallel_result:
                A list of lists to be flated (concatenate
                all lists into one).
            as_dataframe (bool):
                If True, return a dataframe instead of a list.

        Returns:
            A list with all sub list itens.
        """
        if not as_dataframe:
            return [
                item for sublist in parallel_result
                for item in sublist]
        else:
            return pd.concat(parallel_result)

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
                      n_parallel: int = None,
                      error_handler: ParallelErrorHandlerInput = None,
                      filter_errors: bool = True) -> list[Any] | dict[
                          str, list[Any]]:
        """Run ``function`` once per dict in ``function_args``.

        Each worker receives ``function(**one_arg_dict)``.

        Args:
            function (callable):
                Callable used on each parallel task.
            function_args (list[dict]):
                Keyword arguments for each parallel call.
            n_parallel (int | None):
                Worker count; uses ``N_PARALLEL`` when ``None``.
            error_handler (ParallelErrorHandlerInput):
                Optional per-task exception callback. Not the HTTP
                ``error_handler`` on ``PumpWoodMicroServiceBase``. Pass a
                ``ParallelTaskErrorHandler`` instance or any callable whose
                parameters include ``index``, ``args``, and ``error`` (bare
                callables are wrapped and validated). When set, a failing
                task calls ``error_handler(index=..., args=..., error=...)``.
                If the callback raises, the batch aborts. If it returns
                ``None``, the task is recorded as ``ParallelErrorSentinel``.
                If it returns an ``Exception``, that error is raised. When
                ``None``, the first worker error aborts the batch.
            filter_errors (bool):
                If ``True`` (default), return a flat list of successes
                only (sentinels removed). If ``False``, return a dict with
                keys ``result`` (success values) and ``errors`` (list of
                ``ParallelErrorSentinel`` objects), both in task order.

        Returns:
            list[Any] | dict[str, list[Any]]:
                Success list, or partitioned dict when
                ``filter_errors`` is ``False``.

        Raises:
            PumpWoodWrongParameters:
                If ``error_handler`` is a callable missing ``index``,
                ``args``, or ``error``.
            PumpWoodException:
                First unhandled worker error when ``error_handler`` is
                ``None``, when the handler re-raises, or when the handler
                returns an ``Exception``.
            PumpWoodNotImplementedError:
                When ``error_handler`` returns a value that is neither
                ``None`` nor an ``Exception``.
        """
        n_parallel = cls.get_n_parallel(n_parallel=n_parallel)
        error_handler = coerce_parallel_task_error_handler(error_handler)

        def _propagate_parallel_error(to_raise: Exception) -> None:
            """Raise ``to_raise`` with parallel error normalization."""
            # Pumpwood errors only need parallel=True before re-raise.
            if isinstance(to_raise, PumpWoodException):
                to_raise.parallel = True
                raise to_raise

            # PumpWoodOtherException does not format {error} from payload;
            # bake the text into message and keep payload for serialization.
            error_template = "Error in parallel call: {error}"\
                .format(error=str(to_raise))
            raise PumpWoodOtherException(
                message=error_template, parallel=True,
                payload={"error": str(to_raise)})

        def _thread_wrapper(indexed_args):
            """Internal wrapper for progress dots and error handling."""
            index, args = indexed_args
            try:
                result = function(**args)
                sys.stdout.write(".")
                sys.stdout.flush()
                return result
            except Exception as e:
                # Normalize every worker error to exc before handler or raise.
                if isinstance(e, PumpWoodException):
                    e.parallel = True
                    exc = e
                else:
                    error_template = "Error in parallel call: {error}"\
                        .format(error=str(e))
                    exc = PumpWoodOtherException(
                        message=error_template, parallel=True,
                        payload={"error": str(e)})

                # Optional per-task callback (not HTTP error_handler).
                # It may log failures and choose raise vs handled failure:
                #   raise from handler -> abort (same as no handler).
                #   return None -> handled failure; sentinel keeps index,
                #       args, and original exc for auditing.
                #   return Exception -> treat as new error to propagate
                #       (handler may swap or return the same exc).
                if error_handler is not None:
                    handler_result = error_handler(
                        index=index, args=args, error=exc)

                    # None: do not raise; slot becomes ParallelErrorSentinel.
                    if handler_result is None:
                        sys.stdout.write("x")
                        sys.stdout.flush()
                        return ParallelErrorSentinel(
                            index=index, args=args, error=exc)
                    elif isinstance(handler_result, Exception):
                        exc = handler_result
                    else:
                        # Programmer error: only None or Exception allowed.
                        handler_type = type(handler_result).__name__
                        msg = (
                            "Error handler returned invalid type [{type}] "
                            "it must return None, to skip exception or an "
                            "error to be raised.")
                        raise PumpWoodNotImplementedError(
                            message=msg, parallel=True,
                            payload={"type": handler_type})

                # No handler, or handler returned an Exception to propagate.
                _propagate_parallel_error(exc)

        # Use ThreadPoolExecutor for I/O bound tasks (Network requests)
        with ThreadPoolExecutor(max_workers=n_parallel) as executor:
            # executor.map maintains the order of the input list
            indexed_args = enumerate(function_args)
            results = list(executor.map(_thread_wrapper, indexed_args))

        # Default: flat list of successes (backward compatible).
        # filter_errors=False -> dict result/errors for DataFrame workflows.
        if filter_errors:
            results = [
                result for result in results
                if not is_parallel_error_sentinel(result)]
        else:
            results = partition_parallel_results(results)

        sys.stdout.write("|\n")
        sys.stdout.flush()
        return results

    @classmethod
    def finalize_parallel_output(cls, parallel_results: list[Any] | dict[
            str, list[Any]], flat_results: bool = False,
            as_dataframe: bool = False) -> list[Any] | dict[str, Any]:
        """Flatten per-task lists when ``flat_results`` is set.

        When ``parallel_results`` is a partitioned dict (``filter_errors``
        was ``False``), only the ``result`` key is flattened; ``errors`` is
        unchanged.

        Args:
            parallel_results (list[Any] | dict[str, list[Any]]):
                Output from ``parallel_call``.
            flat_results (bool):
                Whether to join nested list results.
            as_dataframe (bool):
                Return a DataFrame when flattening.

        Returns:
            list[Any] | dict[str, Any]:
                Same shape as input, optionally flattened.
        """
        if not flat_results:
            return parallel_results
        if isinstance(parallel_results, dict):
            return {
                "result": cls.flatten_parallel(
                    parallel_results["result"],
                    as_dataframe=as_dataframe),
                "errors": parallel_results["errors"],
            }
        return cls.flatten_parallel(
            parallel_results, as_dataframe=as_dataframe)

    def parallel_request_get(self, urls_list: list, n_parallel: int = None,
                             parameters: Union[List[dict], dict] = None,
                             auth_header: dict = None,
                             error_handler: ParallelErrorHandlerInput =
                             None, filter_errors: bool = True) -> List[any]:
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
                Number of simultaneous requests. If not set, uses
                ``PUMPWOOD_COMMUNICATION__N_PARALLEL`` env variable
                (legacy spelling supported), default 4.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            error_handler (ParallelErrorHandlerInput):
                Forwarded to ``parallel_call``.
            filter_errors (bool):
                Forwarded to ``parallel_call``. Default ``True``. When
                ``False``, return shape matches ``parallel_call``.

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
            n_parallel=n_parallel, error_handler=error_handler,
            filter_errors=filter_errors)

    def parallel_request_post(self, urls_list: List[str],
                              data_list: List[dict],
                              parameters: Union[List[dict], dict] = None,
                              n_parallel: int = None,
                              auth_header: dict = None,
                              error_handler: ParallelErrorHandlerInput =
                              None, filter_errors: bool = True) -> List[any]:
        """Make [n_parallel] parallel post request.

        Args:
            urls_list:
                List of urls to make get requests.
            data_list:
                List of data to be used as post payloads.
            parameters:
                URL paramenters to make the post requests.
            n_parallel:
                Number of simultaneous requests. If not set, uses
                ``PUMPWOOD_COMMUNICATION__N_PARALLEL`` env variable
                (legacy spelling supported), default 4.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            error_handler (ParallelErrorHandlerInput):
                Forwarded to ``parallel_call``.
            filter_errors (bool):
                Forwarded to ``parallel_call``. Default ``True``. When
                ``False``, return shape matches ``parallel_call``.

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
            n_parallel=n_parallel, error_handler=error_handler,
            filter_errors=filter_errors)

    def parallel_request_delete(self, urls_list: List[str],
                                parameters: Union[List[dict], dict] = None,
                                n_parallel: int = None,
                                auth_header: dict = None,
                                error_handler: ParallelErrorHandlerInput = None, filter_errors: bool = True):
        """Make [n_parallel] parallel delete request.

        Args:
            urls_list:
                List of urls to make get requests.
            parameters:
                URL paramenters to make the post requests.
            n_parallel (int):
                Number of simultaneous requests. If not set, uses
                ``PUMPWOOD_COMMUNICATION__N_PARALLEL`` env variable
                (legacy spelling supported), default 4.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            error_handler (ParallelErrorHandlerInput):
                Forwarded to ``parallel_call``.
            filter_errors (bool):
                Forwarded to ``parallel_call``. Default ``True``. When
                ``False``, return shape matches ``parallel_call``.

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
            n_parallel=n_parallel, error_handler=error_handler,
            filter_errors=filter_errors)
