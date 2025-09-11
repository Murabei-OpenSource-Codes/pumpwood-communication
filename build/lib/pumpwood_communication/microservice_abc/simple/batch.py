"""Module for Simple Batch end-points of microservice."""
import pandas as pd
from abc import ABC
from typing import List, Union, Dict
from pumpwood_communication.microservice_abc.base import (
    PumpWoodMicroServiceBase)
from pumpwood_communication.serializers import CompositePkBase64Converter


class ABCSimpleBatchMicroservice(ABC, PumpWoodMicroServiceBase):
    """Abstract class for batch end-points."""

    @staticmethod
    def _build_aggregate_url(model_class: str):
        return "rest/%s/aggregate/" % (model_class.lower(),)

    def aggregate(self, model_class: str, group_by: List[str], agg: dict,
                  filter_dict: dict = {}, exclude_dict: dict = {},
                  order_by: List[str] = [], auth_header: dict = None,
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

    def pivot(self, model_class: str, columns: List[str] = [],
              format: str = 'list', filter_dict: dict = {},
              exclude_dict: dict = {}, order_by: List[str] = [],
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
