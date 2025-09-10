"""Module for Simple Batch end-points of microservice."""
import pandas as pd
from abc import ABC
from typing import List
from pumpwood_communication.microservice_abc.base import (
    PumpWoodMicroServiceBase)


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
