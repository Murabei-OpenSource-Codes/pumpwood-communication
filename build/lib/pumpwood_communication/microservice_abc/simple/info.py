"""Module for retrieve functions of microservice."""
from abc import ABC
from pumpwood_communication.microservice_abc.base import (
    PumpWoodMicroServiceBase)


class ABCSimpleInfoMicroservice(ABC, PumpWoodMicroServiceBase):
    """Class for infomation calls."""

    def search_options(self, model_class: str,
                       auth_header: dict = None) -> dict:
        """Return search options.

        DEPRECTED Use `list_options` function instead.

        Return information of the fields including avaiable options for
        options fields and model associated with the foreign key.

        Args:
            model_class:
                Model class to check search parameters
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            Return a dictonary with field names as keys and information of
            them as values. Information at values:
            - **primary_key [bool]:**: Boolean indicating if field is part
                of model_class primary key.
            - **column [str]:**: Name of the column.
            - **column__verbose [str]:** Name of the column translated using
                Pumpwood I8s.
            - **help_text [str]:** Help text associated with column.
            - **help_text__verbose [str]:** Help text associated with column
                translated using Pumpwood I8s.
            - **type [str]:** Python type associated with the column.
            - **nullable [bool]:** If field can be set as null (None).
            - **read_only [bool]:** If field is marked as read-only. Passsing
                information for this field will not be used in save end-point.
            - **default [any]:** Default value of the field if not set using
                save end-poin.
            - **unique [bool]:** If the there is a constrain in database
                setting this field to be unique.
            - **extra_info:** Some extra infomations used to pass associated
                model class for forenging key and related fields.
            - **in [dict]:** At options fields, have their options listed in
                `in` keys. It will return the values as key and de description
                and description__verbose (translated by Pumpwood I8s)
                as values.
            - **partition:** At pk field, this key indicates if the database
                if partitioned. Partitioned will perform better in queries if
                partition is used on filter or exclude clauses. If table has
                more than one level o partition, at least the first one must
                be used when retrieving data.

        Raises:
            No particular raises.
        """
        url_str = "rest/%s/options/" % (model_class.lower(), )
        return self.request_get(url=url_str, auth_header=auth_header)

    def fill_options(self, model_class, parcial_obj_dict: dict = {},
                     field: str = None, auth_header: dict = None):
        """Return options for object fields.

        DEPRECTED Use `fill_validation` function instead.

        This function send partial object data and return options to finish
        object fillment.

        Args:
            model_class:
                Model class to check search parameters
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            parcial_obj_dict:
                Partial object that is sent to backend for validation and
                update fill options acording to values passed for each field.
            field:
                Retrict validation for an especific field if implemented.

        Returns:
            Return a dictonary with field names as keys and information of
            them as values. Information at values:
            - **primary_key [bool]:**: Boolean indicating if field is part
                of model_class primary key.
            - **column [str]:**: Name of the column.
            - **column__verbose [str]:** Name of the column translated using
                Pumpwood I8s.
            - **help_text [str]:** Help text associated with column.
            - **help_text__verbose [str]:** Help text associated with column
                translated using Pumpwood I8s.
            - **type [str]:** Python type associated with the column.
            - **nullable [bool]:** If field can be set as null (None).
            - **read_only [bool]:** If field is marked as read-only. Passsing
                information for this field will not be used in save end-point.
            - **default [any]:** Default value of the field if not set using
                save end-poin.
            - **unique [bool]:** If the there is a constrain in database
                setting this field to be unique.
            - **extra_info:** Some extra infomations used to pass associated
                model class for forenging key and related fields.
            - **in [dict]:** At options fields, have their options listed in
                `in` keys. It will return the values as key and de description
                and description__verbose (translated by Pumpwood I8s)
                as values.
            - **partition:** At pk field, this key indicates if the database
                if partitioned. Partitioned will perform better in queries if
                partition is used on filter or exclude clauses. If table has
                more than one level o partition, at least the first one must
                be used when retrieving data.

        Raises:
            No particular raises.
        """
        url_str = "rest/%s/options/" % (model_class.lower(), )
        if (field is not None):
            url_str = url_str + field
        return self.request_post(
            url=url_str, data=parcial_obj_dict,
            auth_header=auth_header)

    def list_options(self, model_class: str, auth_header: dict) -> dict:
        """Return options to render list views.

        This function send partial object data and return options to finish
        object fillment.

        Args:
            model_class:
                Model class to check search parameters.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            Dictionary with keys:
            - **default_list_fields:** Default list field defined on the
                application backend.
            - **field_descriptions:** Description of the fields associated
                with the model class.

        Raises:
          No particular raise.
        """
        url_str = "rest/{basename}/list-options/".format(
            basename=model_class.lower())
        return self.request_get(
            url=url_str, auth_header=auth_header)

    def retrieve_options(self, model_class: str,
                         auth_header: dict = None) -> dict:
        """Return options to render retrieve views.

        Return information of the field sets that can be used to create
        frontend site. It also return a `verbose_field` which can be used
        to create the tittle of the page substituing the values with
        information of the object.

        Args:
          model_class:
              Model class to check search parameters.
          auth_header:
              Auth header to substitute the microservice original
              at the request (user impersonation).

        Returns:
            Return a dictinary with keys:
            - **verbose_field:** String sugesting how the tittle of the
                retrieve might be created. It will use Python format
                information ex.: `'{pk} | {description}'`.
            - **fieldset:** An dictinary with organization of data,
                setting field sets that could be grouped toguether in
                tabs.

        Raises:
            No particular raises.
        """
        url_str = "rest/{basename}/retrieve-options/".format(
            basename=model_class.lower())
        return self.request_get(
            url=url_str, auth_header=auth_header)

    def fill_validation(self, model_class: str, parcial_obj_dict: dict = {},
                        field: str = None, auth_header: dict = None,
                        user_type: str = 'api') -> dict:
        """Return options for object fields.

        This function send partial object data and return options to finish
        object fillment.

        Args:
            model_class:
                Model class to check search parameters.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            parcial_obj_dict:
                Partial object data to be validated by the backend.
            field:
                Set an especific field to be validated if implemented.
            user_type:
                Set the type of user is requesting fill validation. It is
                possible to set `api` and `gui`. Gui user_type will return
                fields listed in gui_readonly as read-only fields to
                facilitate navegation.

        Returns:
            Return a dictinary with keys:
            - **field_descriptions:** Same of fill_options, but setting as
                read_only=True fields listed on gui_readonly if
                user_type='gui'.
            - **gui_readonly:** Return a list of fields that will be
                considered as read-only if user_type='gui' is requested.

        Raises:
            No particular raises.
        """
        url_str = "rest/{basename}/retrieve-options/".format(
            basename=model_class.lower())
        params = {"user_type": user_type}
        if field is not None:
            params["field"] = field
        return self.request_post(
            url=url_str, auth_header=auth_header, data=parcial_obj_dict,
            parameters=params)
