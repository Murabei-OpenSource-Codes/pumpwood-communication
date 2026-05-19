"""Fetch information necessary to run the model."""
import copy
import pandas as pd
from typing import Any
from pumpwood_communication.microservices import PumpWoodMicroService


class FetchDatabase:
    """Class to fetch the database for model associated data."""

    @classmethod
    def run(cls, microservice: PumpWoodMicroService,
            queue_object: dict, model_info: dict,
            row_permissions: list[int]) -> dict:
        """Fetch the database for model associated data."""
        # Fetch filters for the database
        modeling_units = cls.get_modeling_units(
            microservice=microservice,
            row_permissions=row_permissions,
            filter_modeling_unit_set=model_info['filter_modeling_unit_set'])
        geoareas = cls.get_geoareas(
            microservice=microservice,
            row_permissions=row_permissions,
            filter_geoarea_set=model_info['filter_geoarea_set'])

        # Fetch variables that will be used on the model
        geoattributes = cls.get_geoattribute(
            var_geoattribute_set=model_info['var_geoattribute_set'])
        attributes = cls.get_attributes(
            var_attribute_set=model_info['var_attribute_set'])

        # Retrieve information from database
        cls.fetch_database(
            microservice=microservice,
            modeling_units=modeling_units,
            geoareas=geoareas,
            attributes=attributes,
            start_date=queue_object['filter_start_time'],
            end_date=queue_object['filter_end_time'],
            row_permissions=row_permissions
        )


    @classmethod
    def get_modeling_units(cls, microservice: PumpWoodMicroService,
                           row_permissions: list[int],
                           filter_modeling_unit_set: list[dict]
                           ) -> list[dict[str, Any]]:
        """Get modeling unit ids acording to filters at the model."""
        # Create the filter and exclude dict as an union of all filters
        # applied to the data, apply the users access to data
        list_args = []
        for f_mu in filter_modeling_unit_set:
            filter_dict = copy.deepcopy(f_mu['filter']['filter_dict'])
            filter_dict['row_permission_id__in'] = row_permissions
            exclude_dict = copy.deepcopy(f_mu['filter']['exclude_dict'])
            list_args.append({
                "filter_dict": filter_dict,
                "exclude_dict": exclude_dict})

        # Fetch for public data row_permission_id=None
        for f_mu in filter_modeling_unit_set:
            filter_dict = copy.deepcopy(f_mu['filter']['filter_dict'])
            filter_dict['row_permission_id__isnull'] = True
            exclude_dict = copy.deepcopy(f_mu['filter']['exclude_dict'])
            list_args.append({
                "filter_dict": filter_dict,
                "exclude_dict": exclude_dict})

        # Fetch modeling units modeling units
        modeling_units = microservice.parallel_list_by_chunks(
            model_class="DescriptionModelingUnit",
            list_args=list_args,
            fields=['pk'])
        return pd.DataFrame(modeling_units, columns=["pk"])\
            .rename(columns={"pk": "modeling_unit_id"})

    @classmethod
    def get_geoareas(cls, microservice: PumpWoodMicroService,
                     row_permissions: list[int],
                     filter_geoarea_set: list[dict]
                     ) -> list[dict[str, Any]]:
        """Get modeling unit ids acording to filters at the model."""
        # Create the filter and exclude dict as an union of all filters
        # applied to the data, apply the users access to data
        list_args = {
            "output": [],
            "not_output": []}
        for f_geo in filter_geoarea_set:
            is_output = f_geo['filter']['is_output']
            filter_dict = copy.deepcopy(f_geo['filter']['filter_dict'])
            filter_dict['row_permission_id__in'] = row_permissions
            exclude_dict = copy.deepcopy(f_geo['filter']['exclude_dict'])

            filter_dict_public = copy.deepcopy(f_geo['filter']['filter_dict'])
            filter_dict_public['row_permission_id__isnull'] = True
            if is_output:
                list_args["output"].append({
                    "filter_dict": filter_dict,
                    "exclude_dict": exclude_dict})
            else:
                list_args["not_output"].append({
                    "filter_dict": filter_dict_public,
                    "exclude_dict": exclude_dict})

        # Fetch modeling units modeling units
        geoareas_output = microservice.parallel_list_by_chunks(
            model_class="DescriptionGeoarea",
            list_args=list_args['output'],
            fields=['pk', 'dimensions'])
        for x in geoareas_output:
            x['is_output'] = True

        geoareas_not_output = microservice.parallel_list_by_chunks(
            model_class="DescriptionGeoarea",
            list_args=list_args['not_output'],
            fields=['pk', 'dimensions'])
        for x in geoareas_not_output:
            x['is_output'] = False
        return pd.DataFrame(
            geoareas_output + geoareas_not_output,
            columns=['row_permission_id', 'pk', 'dimensions', 'is_output'])\
            .rename(columns={"pk": "geoarea_id"})


    @classmethod
    def get_attributes(cls, var_attribute_set: list[dict[str, Any]]
                       ) -> list[dict[str, Any]]:
        """Return the attributes that will be used on model."""
        list_attributes = []
        for m_att in var_attribute_set:
            list_attributes.append({
                'is_output': m_att['is_output'],
                'attribute_id': m_att['variable']['attribute_id']})
        return pd.DataFrame(
            list_attributes, columns=['attribute_id', 'is_output'])

    @classmethod
    def get_geoattribute(cls, var_geoattribute_set: list[dict[str, Any]]
                         ) -> list[dict[str, Any]]:
        """Return geoattributes used on the model."""
        list_geoattributes = []
        for m_geo in var_geoattribute_set:
            list_geoattributes.append({
                'geoattribute_id': m_geo['variable']['geoattribute_id']})
        return pd.DataFrame(
            list_geoattributes, columns=["geoattribute_id"])

    @classmethod
    def fetch_database(cls, microservice: PumpWoodMicroService,
                       modeling_units: pd.DataFrame,
                       geoareas: pd.DataFrame,
                       attributes: pd.DataFrame,
                       start_date: str | None,
                       end_date: str | None,
                       row_permissions: list[int]) -> pd.DataFrame:
        """."""
        output_geoareas = geoareas\
            .loc[geoareas['is_output'], 'geoarea_id']

        list_args = []
        for _, att in attributes.iterrows():
            filter_dict = {
                "attribute_id": att['attribute_id'],
                "modeling_unit_id__in": modeling_units["modeling_unit_id"],
                "geoarea_id__in": output_geoareas,
                "row_permission_id__in": row_permissions}
            if start_date is not None:
                filter_dict['time__gte'] = start_date
            if end_date is not None:
                filter_dict['time__lte'] = end_date
            list_args.append({"filter_dict": filter_dict})

        return microservice.parallel_pivot(
            model_class="DatabaseVariable",
            list_args=list_args,
            as_dataframe=True)

