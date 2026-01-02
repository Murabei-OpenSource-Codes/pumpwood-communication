"""Module for list end-point requests."""
import copy
import pandas as pd
import geopandas as geopd
from abc import ABC
from shapely import geometry
from typing import List
from pumpwood_communication.microservice_abc.base import (
    PumpWoodMicroServiceBase)


class ABCSimpleListMicroservice(ABC, PumpWoodMicroServiceBase):
    """Abstract class for parallel calls at Pumpwood end-points."""

    @staticmethod
    def _build_list_url(model_class: str):
        return "rest/%s/list/" % (model_class.lower(),)

    def list(self, model_class: str, filter_dict: dict = {},
             exclude_dict: dict = {}, order_by: list = [],
             auth_header: dict = None, fields: list = None,
             default_fields: bool = False, limit: int = None,
             foreign_key_fields: bool = False,
             base_filter_skip: list = None,
             **kwargs) -> List[dict]:
        """List objects with pagination.

        List end-point (resumed data) of PumpWood like systems,
        results will be paginated. To get next pag, send all recived pk at
        exclude dict (ex.: `exclude_dict={pk__in: [1,2,...,30]}`).

        It is possible to return foreign keys objects associated with
        `model_class`. Use this with carefull since increase the backend
        infrastructure consumption, each object is a retrieve call per
        foreign key (otimization in progress).

        It is possible to use diferent operators using `__` after the name
        of the field, some of the operators avaiable:

        ### General operators
        - **__eq:** Check if the value is the same, same results if no
            operator is passed.
        - **__gt:** Check if value is greter then argument.
        - **__lt:** Check if value is less then argument.
        - **__gte:** Check if value is greter or equal then argument.
        - **__lte:** Check if value is less or equal then argument.
        - **__in:** Check if value is at a list, the argument of this operator
            must be a list.

        ### Text field operators
        - **__contains:** Check if value contains a string. It is case and
            accent sensitive.
        - **__icontains:** Check if a values contains a string, It is case
            insensitive and accent sensitive.
        - **__unaccent_icontains:** Check if a values contains a string, It is
            case insensitive and accent insensitive (consider a, à, á, ã, ...
            the same).
        - **__exact:** Same as __eq or not setting operator.
        - **__iexact:** Same as __eq, but case insensitive and
            accent sensitive.
        - **__unaccent_iexact:** Same as __eq, but case insensitive and
            accent insensitive.
        - **__startswith:** Check if the value stats with a sub-string.
            Case sensitive and accent sensitive.
        - **__istartswith:** Check if the value stats with a sub-string.
            Case insensitive and accent sensitive.
        - **__unaccent_istartswith:** Check if the value stats with a
            sub-string. Case insensitive and accent insensitive.
        - **__endswith:** Check if the value ends with a sub-string. Case
            sensitive and accent sensitive.
        - **__iendswith:** Check if the value ends with a sub-string. Case
            insensitive and accent sensitive.
        - **__unaccent_iendswith:** Check if the value ends with a sub-string.
            Case insensitive and accent insensitive.

        ### Null operators
        - **__isnull:** Check if field is null, it uses as argument a `boolean`
            value false will return all non NULL values and true will return
            NULL values.

        ### Date and datetime operators:
        - **__range:** Receive as argument a list of two elements and return
            objects that field dates are between those values.
        - **__year:** Return object that date field value year is equal to
            argument.
        - **__month:** Return object that date field value month is equal to
            argument.
        - **__day:** Return object that date field value day is equal to
            argument.

        ### Dictionary fields operators:
        - **__json_contained_by:**
            Uses the function [contained_by](https://docs.sqlalchemy.org/en/20/dialects/postgresql.html#sqlalchemy.dialects.postgresql.JSONB.Comparator.contained_by)
            from SQLAlchemy to test if keys are a proper subset of the keys of
            the argument jsonb expression (extracted from SQLAlchemy). The
            argument is a list.
        - **__json_has_any:**
            Uses the function [has_any](https://docs.sqlalchemy.org/en/20/dialects/postgresql.html#sqlalchemy.dialects.postgresql.JSONB.Comparator.has_any)
            from SQLAlchemy to test for presence of a key. Note that the key
            may be a SQLA expression. (extracted from SQLAlchemy). The
            argument is a list.
        - **__json_has_key:**
            Uses the function [has_key](https://docs.sqlalchemy.org/en/20/dialects/postgresql.html#sqlalchemy.dialects.postgresql.JSONB.Comparator.has_key)
            from SQLAlchemy to Test for presence of a key. Note that the key
            may be a SQLA expression. The argument is a str.

        ### Text similarity operators
        To use similariry querys on Postgres it is necessary to `pg_trgm` be
        instaled on server. Check [oficial documentation]
        (https://www.postgresql.org/docs/current/pgtrgm.html).

        - **__similarity:** Check if two strings are similar uses the `%`
            operador.
        - **__word_similar_left:** Check if two strings are similar uses the
            `<%` operador.
        - **__word_similar_right:** Check if two strings are similar uses the
            `%>` operador.
        - **__strict_word__similar_left:** Check if two strings are similar
            uses the `<<%` operador.
        - **__strict_word__similar_right:** Check if two strings are similar
            uses the `%>>` operador.

        Some usage examples:
        ```python
        # Return the first 3 results ordered decreasing acording to `time` and
        # them ordered by `modeling_unit_id`. Results must have time greater
        # or equal to 2017-01-01 and less or equal to 2017-06-01. It also
        # must have attribute_id equal to 6 and not contains modeling_unit_id
        # 3 or 4.
        microservice.list(
            model_class="DatabaseVariable",
            filter_dict={
                "time__gte": "2017-01-01 00:00:00",
                "time__lte": "2017-06-01 00:00:00",
                "attribute_id": 6},
            exclude_dict={
                "modeling_unit_id__in": [3, 4]},
            order_by=["-time", "modeling_unit_id"],
            limit=3,
            fields=["pk", "model_class", "time", "modeling_unit_id", "value"])

        # Return all elements that dimensions field has a key type with
        # value contains `selling` insensitive to case and accent.
        microservice.list(
            model_class="DatabaseAttribute",
            filter_dict={
                "dimensions->type__unaccent_icontains": "selling"})
        ```

        Args:
            model_class:
                Model class of the end-point
            filter_dict:
                Filter dict to be used at the query. Filter elements from query
                return that satifies all statements of the dictonary.
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
            **kwargs:
                Other parameters for compatibility.

        Returns:
          Containing objects serialized by list Serializer.

        Raises:
          No especific raises.
        """ # NOQA
        url_str = self._build_list_url(model_class)
        base_filter_skip = [] if base_filter_skip is None else base_filter_skip
        post_data = {
            'filter_dict': filter_dict, 'exclude_dict': exclude_dict,
            'order_by': order_by, 'default_fields': default_fields,
            'limit': limit, 'foreign_key_fields': foreign_key_fields}
        if fields is not None:
            post_data["fields"] = fields
        return self.request_post(
            url=url_str, data=post_data,
            parameters={'base_filter_skip': base_filter_skip},
            auth_header=auth_header)

    def list_by_chunks(self, model_class: str, filter_dict: dict = {},
                       exclude_dict: dict = {}, auth_header: dict = None,
                       fields: list = None, default_fields: bool = False,
                       chunk_size: int = 50000, base_filter_skip: list = None,
                       **kwargs) -> List[dict]:
        """List object fetching them by chucks using pk to paginate.

        List data by chunck to load by datasets without breaking the backend
        or receive server timeout. It load chunks orderring the results using
        id of the tables, it can be changed but it should be unique otherwise
        unexpected results may occur.

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
            fields:
                Set the fields to be returned by the list end-point.
            default_fields:
                Boolean, if true and fields arguments None will return the
                default fields set for list by the backend.
            chunk_size:
                Number of objects to be fetched each query.
            base_filter_skip (list):
                List of base query filter to be skiped, it is necessary to
                be superuser to skip base query filters.
            **kwargs:
                Other parameters for compatibility.

        Returns:
          Containing objects serialized by list Serializer.

        Raises:
          No especific raises.
        """
        base_filter_skip = [] if base_filter_skip is None else base_filter_skip
        copy_filter_dict = copy.deepcopy(filter_dict)

        list_all_results = []
        max_order_col = 0
        while True:
            print("- fetching chunk [{}]".format(max_order_col))
            copy_filter_dict["pk__gt"] = max_order_col
            temp_results = self.list(
                model_class=model_class, filter_dict=copy_filter_dict,
                exclude_dict=exclude_dict, order_by=["pk"],
                auth_header=auth_header, fields=fields,
                default_fields=default_fields, limit=chunk_size,
                base_filter_skip=base_filter_skip)

            # Break if results is empty
            if len(temp_results) == 0:
                break

            max_order_col = temp_results[-1]["pk"]
            list_all_results.extend(temp_results)

        return list_all_results

    @staticmethod
    def _build_list_without_pag_url(model_class: str):
        return "rest/%s/list-without-pag/" % (model_class.lower(),)

    def list_without_pag(self, model_class: str, filter_dict: dict = {},
                         exclude_dict: dict = {}, order_by: list = [],
                         auth_header: dict = None, return_type: str = 'list',
                         convert_geometry: bool = True, fields: list = None,
                         default_fields: bool = False,
                         foreign_key_fields: bool = False,
                         base_filter_skip: list = None, **kwargs
                         ) -> List[dict]:
        """List object without pagination.

        Function to post at list end-point (resumed data) of PumpWood like
        systems, results won't be paginated.
        **Be carefull with large returns.**

        Args:
            model_class (str):
                Model class of the end-point
            filter_dict (dict):
                Filter dict to be used at the query. Filter elements from query
                return that satifies all statements of the dictonary.
            exclude_dict (dict):
                Exclude dict to be used at the query. Remove elements from
                query return that satifies all statements of the dictonary.
            order_by (bool):
                Order results acording to list of strings
                correspondent to fields. It is possible to use '-' at the
                begginng of the field name for reverse ordering. Ex.:
                ['description'] for accendent ordering and ['-description']
                for descendent ordering.
            auth_header (dict):
                Auth header to substitute the microservice original
                at the request (user impersonation).
            fields (List[str]):
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
            convert_geometry (bool):
                If geometry columns should be convert to shapely geometry.
                Fields with key 'geometry' will be considered geometry.
            return_type (str):
                Set return type to list of dictinary `list` or to a pandas
                dataframe `dataframe`.
            base_filter_skip (list):
                List of base query filter to be skiped, it is necessary to
                be superuser to skip base query filters.
            **kwargs:
                Other unused arguments for compatibility.

        Returns:
          Containing objects serialized by list Serializer.

        Raises:
          No especific raises.
        """
        url_str = self._build_list_without_pag_url(model_class)
        base_filter_skip = (
            [] if base_filter_skip is None else base_filter_skip)
        post_data = {
            'filter_dict': filter_dict, 'exclude_dict': exclude_dict,
            'order_by': order_by, 'default_fields': default_fields,
            'foreign_key_fields': foreign_key_fields}

        if fields is not None:
            post_data["fields"] = fields
        results = self.request_post(
            url=url_str, data=post_data,
            parameters={'base_filter_skip': base_filter_skip},
            auth_header=auth_header)

        ##################################################
        # Converting geometry to Shapely objects in Python
        geometry_in_results = False
        if convert_geometry:
            for obj in results:
                geometry_value = obj.get("geometry")
                if geometry_value is not None:
                    obj["geometry"] = geometry.shape(geometry_value)
                    geometry_in_results = True
        ##################################################

        if return_type == 'list':
            return results
        elif return_type == 'dataframe':
            if (model_class.lower() == "descriptiongeoarea") and \
                    geometry_in_results:
                return geopd.GeoDataFrame(results, geometry='geometry')
            else:
                return pd.DataFrame(results)
        else:
            raise Exception("return_type must be 'list' or 'dataframe'")
