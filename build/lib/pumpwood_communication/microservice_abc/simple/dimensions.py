"""Module for dimensions end-point requests."""
from abc import ABC
from pumpwood_communication.microservice_abc.base import (
    PumpWoodMicroServiceBase)


class ABCSimpleDimensionMicroservice(ABC, PumpWoodMicroServiceBase):
    """Abstract class for parallel calls at Pumpwood end-points."""

    @staticmethod
    def _build_list_dimensions(model_class: str):
        return "rest/%s/list-dimensions/" % (model_class.lower(),)

    def list_dimensions(self, model_class: str, filter_dict: dict = {},
                        exclude_dict: dict = {}, auth_header: dict = None,
                        base_filter_skip: list = None) -> list[str]:
        """List dimensions avaiable for model_class.

        It list all keys avaiable at dimension retricting the results with
        query parameters `filter_dict` and `exclude_dict`.

        Args:
            model_class:
                Model class of the end-point
            filter_dict:
                Filter dict to be used at the query. Filter elements from query
                return that satifies all statements of the dictonary.
            exclude_dict:
                Exclude dict to be used at the query. Remove elements from
                query return that satifies all statements of the dictonary.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            base_filter_skip (list):
                List of base query filter to be skiped, it is necessary to
                be superuser to skip base query filters.

        Returns:
            List of keys avaiable in results from the query dict.
        """
        url_str = self._build_list_dimensions(model_class)
        base_filter_skip = (
            [] if base_filter_skip is None else base_filter_skip)
        post_data = {'filter_dict': filter_dict, 'exclude_dict': exclude_dict}
        return self.request_post(
            url=url_str, data=post_data,
            parameters={'base_filter_skip': base_filter_skip},
            auth_header=auth_header)

    @staticmethod
    def _build_list_dimension_values(model_class: str):
        return "rest/%s/list-dimension-values/" % (model_class.lower(), )

    def list_dimension_values(self, model_class: str, key: str,
                              filter_dict: dict = {}, exclude_dict: dict = {},
                              auth_header: dict = None,
                              base_filter_skip: list = None) -> list[any]:
        """List values associated with dimensions key.

        It list all keys avaiable at dimension retricting the results with
        query parameters `filter_dict` and `exclude_dict`.

        Args:
            model_class:
                Model class of the end-point
            filter_dict:
                Filter dict to be used at the query. Filter elements from query
                return that satifies all statements of the dictonary.
            exclude_dict:
                Exclude dict to be used at the query. Remove elements from
                query return that satifies all statements of the dictonary.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            key:
                Key to list the avaiable values using the query filter
                and exclude.
            base_filter_skip (list):
                List of base query filter to be skiped, it is necessary to
                be superuser to skip base query filters.

        Returns:
            List of values associated with dimensions key at the objects that
            are returned with `filter_dict` and `exclude_dict`.
        """
        url_str = self._build_list_dimension_values(model_class)
        base_filter_skip = (
            [] if base_filter_skip is None else base_filter_skip)
        base_filter_skip = None
        post_data = {
            'filter_dict': filter_dict, 'exclude_dict': exclude_dict,
            'key': key}
        return self.request_post(
            url=url_str, data=post_data,
            parameters={'base_filter_skip': base_filter_skip},
            auth_header=auth_header)
