"""Module microservice.py.

Class and functions to help communication between PumpWood like systems.
"""
import os
import io
import sys
import simplejson as json
import gzip
import pandas as pd
import numpy as np
from typing import Union, List, Any
from multiprocessing import Pool
from pandas import ExcelWriter
from pumpwood_communication.exceptions import (
    PumpWoodException, PumpWoodQueryException, PumpWoodNotImplementedError)
from pumpwood_communication.misc import unpack_dict_columns


# Importing abstract classes for Micro Service
from pumpwood_communication.microservice_abc.simple import (
    ABCSimpleBatchMicroservice, ABCPermissionMicroservice,
    ABCSimpleRetriveMicroservice, ABCSimpleDeleteMicroservice,
    ABCSimpleSaveMicroservice, ABCSimpleListMicroservice,
    ABCSimpleDimensionMicroservice)
from pumpwood_communication.microservice_abc.system import (
    ABCSystemMicroservice)


def break_in_chunks(df_to_break: pd.DataFrame,
                    chunksize: int = 1000) -> List[pd.DataFrame]:
    """Break a dataframe in chunks of chunksize.

    Args:
        df_to_break: Dataframe to be break in chunks of `chunksize` size.
        chunksize: Length of each chuck of the breaks of `df_to_break`.

    Returns:
        Return a list dataframes with lenght chunksize of data from
        `df_to_break`.
    """
    to_return = list()
    for g, df in df_to_break.groupby(np.arange(len(df_to_break)) // chunksize):
        to_return.append(df)
    return to_return


class PumpWoodMicroService(ABCPermissionMicroservice,
                           ABCSimpleBatchMicroservice,
                           ABCSimpleRetriveMicroservice,
                           ABCSimpleDeleteMicroservice,
                           ABCSimpleSaveMicroservice,
                           ABCSystemMicroservice,
                           ABCSimpleListMicroservice,
                           ABCSimpleDimensionMicroservice):
    """Class to define an inter-pumpwood MicroService.

    Create an object ot help communication with Pumpwood based backends. It
    manage login and token refresh if necessary.

    It also implements parallel functions that split requests in parallel
    process to reduce processing time.
    """

    def get_pks_from_unique_field(self, model_class: str, field: str,
                                  values: List[Any]) -> pd.DataFrame:
        """Get pk using unique fields values.

        Use unique field values to retrieve pk of the objects. This end-point
        is usefull for retrieving pks of the objects associated with unique
        fields such as `description` (unique on most model of pumpwood).

        ```python
        # Using description to fetch pks from objects
        data: pd.DataFrame = [data with unique description but without pk]
        data['attribute_id'] = microservice.get_pks_from_unique_field(
            model_class="DescriptionAttribute",
            field="description", values=data['attribute'])['pk']

        # Using a dimension key to fetch pk of the objects, dimension
        # key must be unique
        data['georea_id'] = microservice.get_pks_from_unique_field(
            model_class="DescriptionGeoarea", field="dimension->city",
            values=data['city'])['pk']
        ```

        Args:
            model_class:
                Model class of the objects.
            field:
                Unique field to fetch pk. It is possible to use dimension keys
                as unique field, for that use `dimension->[key]` notation.
            values:
                List of the unique fields used to fetch primary keys.

        Return:
            Return a dataframe in same order as values with columns:
            - **pk**: Correspondent primary key of the unique value.
            - **[field]**: Column with same name of field argument,
                correspondent to pk.

        Raises:
            PumpWoodQueryException:
                Raises if field is not found on the model and it is note
                associated with a dimension tag.
            PumpWoodQueryException:
                Raises if `field` does not have a unique restriction on
                database. Dimension keys does not check for uniqueness on
                database, be carefull not to duplicate the lines.
        """
        is_dimension_tag = 'dimensions->' in field
        if not is_dimension_tag:
            fill_options = self.fill_options(model_class=model_class)
            field_details = fill_options.get(field)
            if field_details is None:
                msg = (
                    "Field is not a dimension tag and not found on model "
                    "fields. Field [{field}]")
                raise PumpWoodQueryException(
                    message=msg, payload={"field": field})

            is_unique_field = field_details.get("unique", False)
            if not is_unique_field:
                msg = "Field [{}] to get pk from is not unique"
                raise PumpWoodQueryException(
                    message=msg, payload={"field": field})

        filter_dict = {field + "__in": list(set(values))}
        pk_map = None
        if not is_dimension_tag:
            list_results = pd.DataFrame(self.list_without_pag(
                model_class=model_class, filter_dict=filter_dict,
                fields=["pk", field]), columns=["pk", field])
            pk_map = list_results.set_index(field)["pk"]

        # If is dimension tag, fetch dimension and unpack it
        else:
            dimension_tag = field.split("->")[1]
            list_results = pd.DataFrame(self.list_without_pag(
                model_class=model_class, filter_dict=filter_dict,
                fields=["pk", "dimensions"]))
            pk_map = {}
            if len(list_results) != 0:
                pk_map = list_results\
                    .pipe(unpack_dict_columns, columns=["dimensions"])\
                    .set_index(dimension_tag)["pk"]

        values_series = pd.Series(values)
        return pd.DataFrame({
            "pk": values_series.map(pk_map).to_numpy(),
            field: values_series
        })

    def list_actions(self, model_class: str,
                     auth_header: dict = None) -> List[dict]:
        """Return a list of all actions avaiable at this model class.

        Args:
          model_class:
              Model class to list possible actions.
          auth_header:
              Auth header to substitute the microservice original
              at the request (user impersonation).

        Returns:
          List of possible actions and its descriptions.

        Raises:
            No particular errors.
        """
        url_str = "rest/%s/actions/" % (model_class.lower())
        return self.request_get(url=url_str, auth_header=auth_header)

    @staticmethod
    def _build_execute_action_url(model_class: str, action: str,
                                  pk: int = None):
        url_str = "rest/%s/actions/%s/" % (model_class.lower(), action)
        if pk is not None:
            url_str = url_str + str(pk) + '/'
        return url_str

    def execute_action(self, model_class: str, action: str, pk: int = None,
                       parameters: dict = {}, files: list = None,
                       auth_header: dict = None) -> dict:
        """Execute action associated with a model class.

        If action is static or classfunction no pk is necessary.

        Args:
            pk (int):
                PK of the object to run action at. If not set action will be
                considered a classmethod and will run over the class.
            model_class:
                Model class to run action the object
            action:
                Action that will be performed.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            parameters:
                Dictionary with the function parameters.
            files:
                A dictionary of files to be added to as a multi-part
                post request. File must be passed as a file object with read
                bytes.

        Returns:
            Return a dictonary with keys:
            - **result:**: Result of the action that was performed.
            - **action:**: Information of the action that was performed.
            - **parameters:** Parameters that were passed to perform the
                action.
            - **object:** If a pk was passed to execute and action (not
                classmethod or staticmethod), the object with the correspondent
                pk is returned.

        Raises:
            PumpWoodException:
                'There is no method {action} in rest actions for {class_name}'.
                This indicates that action requested is not associated with
                the model_class.
            PumpWoodActionArgsException:
                'Function is not static and pk is Null'. This indicate that
                the action solicitated is not static/class method and a pk
                was not passed as argument.
            PumpWoodActionArgsException:
                'Function is static and pk is not Null'. This indicate that
                the action solicitated is static/class method and a pk
                was passed as argument.
            PumpWoodObjectDoesNotExist:
                'Requested object {model_class}[{pk}] not found.'. This
                indicate that pk associated with model class was not found
                on database.
        """
        url_str = self._build_execute_action_url(
            model_class=model_class, action=action, pk=pk)
        return self.request_post(
            url=url_str, data=parameters, files=files,
            auth_header=auth_header)

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


    @staticmethod
    def _build_bulk_save_url(model_class: str):
        return "rest/%s/bulk-save/" % (model_class.lower(),)

    def bulk_save(self, model_class: str, data_to_save: list,
                  auth_header: dict = None) -> dict:
        """Save a list of objects with one request.

        It is used with a unique call save many objects at the same time. It
        is necessary that the end-point is able to receive bulk save requests
        and all objects been of the same model class.

        Args:
            model_class:
                Data model class.
            data_to_save:
                A list of objects to be saved.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            A dictinary with `saved_count` as key indicating the number of
            objects that were saved in database.

        Raises:
            PumpWoodException:
                'Expected columns and data columns do not match: Expected
                columns: {expected} Data columns: {data_cols}'. Indicates
                that the expected fields of the object were not met at the
                objects passed to save.
            PumpWoodException:
                Other sqlalchemy and psycopg2 errors not associated with
                IntegrityError.
            PumpWoodException:
                'Bulk save not avaiable.'. Indicates that Bulk save end-point
                was not configured for this model_class.
            PumpWoodIntegrityError:
                Raise integrity errors from sqlalchemy and psycopg2. Usually
                associated with uniqueness of some column.
        """
        url_str = self._build_bulk_save_url(model_class=model_class)
        return self.request_post(
            url=url_str, data=data_to_save,
            auth_header=auth_header)

    ########################
    # Parallel aux functions
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

    def _request_get_wrapper(self, arguments: dict):
        try:
            results = self.request_get(**arguments)
            sys.stdout.write(".")
            sys.stdout.flush()
            return results
        except Exception as e:
            raise Exception("Error on parallel get: " + str(e))

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
                'lenght of urls_list[{}] is different of parameters[{}]'.
                Indicates that the function arguments `urls_list` and
                `parameters` (when passed as a list of dictionaries)
                does not have de same lenght.
            PumpWoodNotImplementedError:
                'paraemters type[{}] is not implemented'. Indicates that
                `parameters` passed as function argument is not a list of dict
                or a dictinary, so not implemented.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

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
                    'lenght of urls_list[{}] is different of ' +
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

        # Run requests in parallel
        with Pool(n_parallel) as p:
            results = p.map(self._request_get_wrapper, pool_arguments)
        print("|")
        return results

    def _request_post_wrapper(self, arguments: dict):
        try:
            result = self.request_post(**arguments)
            sys.stdout.write(".")
            sys.stdout.flush()
            return result
        except Exception as e:
            raise Exception("Error in parallel post: " + str(e))

    def paralell_request_post(self, urls_list: List[str],
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
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

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
                    'lenght of urls_list[{}] is different of ' +
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

        with Pool(n_parallel) as p:
            results = p.map(self._request_post_wrapper, pool_arguments)
        print("|")
        return results

    def _request_delete_wrapper(self, arguments):
        try:
            result = self.request_delete(**arguments)
            sys.stdout.write(".")
            sys.stdout.flush()
            return result
        except Exception as e:
            raise Exception("Error in parallel delete: " + str(e))

    def paralell_request_delete(self, urls_list: List[str],
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
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

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
                    'lenght of urls_list[{}] is different of ' +
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

        with Pool(n_parallel) as p:
            results = p.map(self._request_delete_wrapper, pool_arguments)
        print("|")
        return results

    ######################
    # Parallel functions #
    def parallel_retrieve(self, model_class: Union[str, List[str]],
                          list_pk: List[int], default_fields: bool = False,
                          foreign_key_fields: bool = False,
                          related_fields: bool = False,
                          fields: list = None, n_parallel: int = None,
                          auth_header: dict = None):
        """Make [n_parallel] parallel retrieve request.

        Args:
            model_class:
                Model Class to retrieve.
            list_pk:
                List of the pks to retrieve.
            fields:
                Set the fields to be returned by the list end-point.
            default_fields:
                Boolean, if true and fields arguments None will return the
                default fields set for list by the backend.
            foreign_key_fields:
                Return forenging key objects. It will return the fk
                corresponding object. Ex: `created_by_id` reference to
                a user `model_class` the correspondent to User will be
                returned at `created_by`.
            related_fields:
                Return related fields objects. Related field objects are
                objects that have a forenging key associated with this
                model_class, results will be returned as a list of
                dictionaries usually in a field with `_set` at end.
                Returning related_fields consume backend resorces, use
                carefully.
            n_parallel (int): Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            List of the retrieve request data.

        Raises:
            PumpWoodException:
                'len(model_class)[{}] != len(list_pk)[{}]'. Indicates that
                the lenght of the arguments model_class and list_pk are
                incompatible.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        if type(model_class) is str:
            model_class = [model_class] * len(list_pk)
        elif type(model_class) is list:
            if len(model_class) != len(list_pk):
                msg = (
                    'len(model_class)[{}] != len(list_pk)[{}]').format(
                        len(model_class), len(list_pk))
                raise PumpWoodException(msg)

        urls_list = [
            self._build_retrieve_url(
                model_class=model_class[i], pk=list_pk[i])
            for i in range(len(model_class))]

        return self.parallel_request_get(
            urls_list=urls_list, n_parallel=n_parallel,
            parameters={
                "fields": fields, "default_fields": default_fields,
                "foreign_key_fields": foreign_key_fields,
                "related_fields": related_fields},
            auth_header=auth_header)

    def _request_retrieve_file_wrapper(self, args):
        sys.stdout.write(".")
        sys.stdout.flush()
        try:
            return self.retrieve_file(**args)
        except Exception as e:
            raise Exception("Error in parallel retrieve_file: " + str(e))

    def parallel_retrieve_file(self, model_class: str,
                               list_pk: List[int], file_field: str = None,
                               save_path: str = "./", save_file: bool = True,
                               list_file_name: List[str] = None,
                               if_exists: str = "fail",
                               n_parallel: int = None,
                               auth_header: dict = None):
        """Make many [n_parallel] retrieve request.

        Args:
            model_class:
                Model Class to retrieve.
            list_pk:
                List of the pks to retrieve.
            file_field:
                Indicates the file field to download from.
            n_parallel:
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            save_path:
                Path to be used to save files.
            save_file:
                True save file locally, False return file content as bites.
            list_file_name:
                Set a file name for each file download.
            if_exists:
                Set how treat when a file will be saved
                and there is another at same path. "fail" will raise an error;
                "overwrite" will overwrite the file with the new one; "skip"
                when list_file_name is set, check before downloaded it file
                already exists, if so skip the download.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            List of the retrieve file request data.

        Raises:
            PumpWoodException:
                'Lenght of list_file_name and list_pk are not equal:
                len(list_file_name)={list_file_name}; len(list_pk)={list_pk}'.
                Indicates that len(list_file_name) and len(list_pk) function
                arguments are not equal.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        if list_file_name is not None:
            if len(list_file_name) != len(list_pk):
                raise PumpWoodException((
                    "Lenght of list_file_name and list_pk are not equal:\n" +
                    "len(list_file_name)={list_file_name}; " +
                    "len(list_pk)={list_pk}").format(
                        list_file_name=len(list_file_name),
                        list_pk=len(list_pk)))

        pool_arguments = []
        for i in range(len(list_pk)):
            pk = list_pk[i]
            file_name = None
            if list_file_name is not None:
                file_name = list_file_name[i]
            pool_arguments.append({
                "model_class": model_class, "pk": pk,
                "file_field": file_field, "auth_header": auth_header,
                "save_file": save_file, "file_name": file_name,
                "save_path": save_path, "if_exists": if_exists})

        try:
            with Pool(n_parallel) as p:
                results = p.map(
                    self._request_retrieve_file_wrapper,
                    pool_arguments)
            print("|")
        except Exception as e:
            raise PumpWoodException(str(e))

        return results

    def parallel_list(self, model_class: Union[str, List[str]],
                      list_args: List[dict], n_parallel: int = None,
                      auth_header: dict = None, fields: list = None,
                      default_fields: bool = False, limit: int = None,
                      foreign_key_fields: bool = False) -> List[dict]:
        """Make [n_parallel] parallel list request.

        Args:
            model_class (str):
                Model Class to retrieve.
            list_args (List[dict]):
                A list of list request args (filter_dict,
                exclude_dict, order_by, fields, default_fields, limit,
                foreign_key_fields).
            n_parallel (int): Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
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

        Returns:
            Flatten List of the list request reponses.

        Raises:
            PumpWoodException:
                'len(model_class)[{}] != len(list_args)[{}]'. Indicates that
                lenght of model_class and list_args arguments are not equal.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        urls_list = None
        if type(model_class) is str:
            urls_list = [self._build_list_url(model_class)] * len(list_args)
        else:
            if len(model_class) != len(list_args):
                msg = 'len(model_class)[{}] != len(list_args)[{}]'.format(
                    len(model_class), len(list_args))
                raise PumpWoodException(msg)
            urls_list = [self._build_list_url(m) for m in model_class]

        print("## Starting parallel_list: %s" % len(urls_list))
        return self.paralell_request_post(
            urls_list=urls_list, data_list=list_args,
            n_parallel=n_parallel, auth_header=auth_header)

    def parallel_list_without_pag(self, model_class: Union[str, List[str]],
                                  list_args: List[dict],
                                  n_parallel: int = None,
                                  auth_header: dict = None):
        """Make [n_parallel] parallel list_without_pag request.

        Args:
            model_class:
                Model Class to retrieve.
            list_args:
                A list of list request args (filter_dict,
                exclude_dict, order_by, fields, default_fields, limit,
                foreign_key_fields).
            n_parallel (int):
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            Flatten List of the list request reponses.

        Raises:
            PumpWoodException:
                'len(model_class)[{}] != len(list_args)[{}]'. Indicates that
                lenght of model_class and list_args arguments are not equal.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        urls_list = None
        if type(model_class) is str:
            url_temp = [self._build_list_without_pag_url(model_class)]
            urls_list = url_temp * len(list_args)
        else:
            if len(model_class) != len(list_args):
                msg = 'len(model_class)[{}] != len(list_args)[{}]'.format(
                    len(model_class), len(list_args))
                raise PumpWoodException(msg)
            urls_list = [
                self._build_list_without_pag_url(m) for m in model_class]

        print("## Starting parallel_list_without_pag: %s" % len(urls_list))
        return self.paralell_request_post(
            urls_list=urls_list, data_list=list_args,
            n_parallel=n_parallel, auth_header=auth_header)

    def parallel_list_one(self, model_class: Union[str, List[str]],
                          list_pk: List[int], n_parallel: int = None,
                          auth_header: dict = None):
        """Make [n_parallel] parallel list_one request.

        DEPRECTED user retrieve call with default_fields=True.

        Args:
            model_class:
                Model Class to list one.
            list_pk:
                List of the pks to list one.
            n_parallel:
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            List of the list_one request data.

        Raises:
            PumpWoodException:
                'len(model_class) != len(list_pk)'. Indicates that lenght
                of model_class and list_pk arguments are not equal.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        if type(model_class) is list:
            model_class = [model_class] * len(list_pk)

        if len(model_class) is len(list_pk):
            raise PumpWoodException('len(model_class) != len(list_pk)')

        urls_list = [
            self._build_list_one_url(model_class=model_class[i],
                                     pk=list_pk[i])
            for i in range(len(model_class))]

        print("## Starting parallel_list_one: %s" % len(urls_list))
        return self.parallel_request_get(
            urls_list=urls_list, n_parallel=n_parallel,
            auth_header=auth_header)

    def parallel_save(self, list_obj_dict: List[dict],
                      n_parallel: int = None,
                      auth_header: dict = None) -> List[dict]:
        """Make [n_parallel] parallel save requests.

        Args:
            list_obj_dict:
                List of dictionaries containing PumpWood objects
                (must have at least 'model_class' key).
            n_parallel:
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            List of the save request data.

        Raises:
            No particular raises
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        urls_list = [
            self._build_save_url(obj['model_class']) for obj in list_obj_dict]
        print("## Starting parallel_save: %s" % len(urls_list))
        return self.paralell_request_post(
            urls_list=urls_list, data_list=list_obj_dict,
            n_parallel=n_parallel, auth_header=auth_header)

    def parallel_delete(self, model_class: Union[str, List[str]],
                        list_pk: List[int], n_parallel: int = None,
                        auth_header: dict = None):
        """Make many [n_parallel] delete requests.

        Args:
            model_class:
                Model Class to list one.
            list_pk:
                List of the pks to list one.
            n_parallel:
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            List of the delete request data.

        Raises:
            PumpWoodException:
                'len(model_class)[{}] != len(list_args)[{}]'. Indicates
                that length of model_class and list_args arguments are not
                equal.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        if type(model_class) is list:
            model_class = [model_class] * len(list_pk)
        if len(model_class) != len(list_pk):
            msg = 'len(model_class)[{}] != len(list_args)[{}]'.format(
                len(model_class), len(list_pk))
            raise PumpWoodException(msg)

        urls_list = [
            self._build_delete_request_url(model_class=model_class[i],
                                           pk=list_pk[i])
            for i in range(len(model_class))]

        print("## Starting parallel_delete: %s" % len(urls_list))
        return self.parallel_request_get(
            urls_list=urls_list, n_parallel=n_parallel,
            auth_header=auth_header)

    def parallel_delete_many(self, model_class: Union[str, List[str]],
                             list_args: List[dict], n_parallel: int = None,
                             auth_header: dict = None) -> List[dict]:
        """Make [n_parallel] parallel delete_many request.

        Args:
            model_class (str):
                Model Class to delete many.
            list_args (list):
                A list of list request args (filter_dict, exclude_dict).
            n_parallel:
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

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
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        urls_list = None
        if type(model_class) is str:
            url_temp = [self._build_delete_many_request_url(model_class)]
            urls_list = url_temp * len(list_args)
        else:
            if len(model_class) != len(list_args):
                msg = 'len(model_class)[{}] != len(list_args)[{}]'.format(
                    len(model_class), len(list_args))
                raise PumpWoodException(msg)
            urls_list = [
                self._build_list_without_pag_url(m) for m in model_class]

        print("## Starting parallel_delete_many: %s" % len(urls_list))
        return self.paralell_request_post(
            urls_list=urls_list, data_list=list_args,
            n_parallel=n_parallel, auth_header=auth_header)

    def parallel_execute_action(self, model_class: Union[str, List[str]],
                                pk: Union[int, List[int]],
                                action: Union[str, List[str]],
                                parameters: Union[dict, List[dict]] = {},
                                n_parallel: int = None,
                                auth_header: dict = None) -> List[dict]:
        """Make [n_parallel] parallel execute_action requests.

        Args:
            model_class:
                Model Class to perform action over,
                or a list of model class o make diferent actions.
            pk:
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

        Returns:
            List of the execute_action request data.

        Raises:
            PumpWoodException:
                'parallel_length != len([argument])'. Indicates that function
                arguments does not have all the same lenght.

        Example:
            No example yet.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        parallel_length = None
        if type(model_class) is list:
            if parallel_length is not None:
                if parallel_length != len(model_class):
                    raise PumpWoodException(
                        'parallel_length != len(model_class)')
            else:
                parallel_length = len(model_class)

        if type(pk) is list:
            if parallel_length is not None:
                if parallel_length != len(pk):
                    raise PumpWoodException(
                        'parallel_length != len(pk)')
            else:
                parallel_length = len(pk)

        if type(action) is list:
            if parallel_length is not None:
                if parallel_length != len(action):
                    raise PumpWoodException(
                        'parallel_length != len(action)')
            else:
                parallel_length = len(action)

        if type(parameters) is list:
            if parallel_length is not None:
                if parallel_length != len(parameters):
                    raise PumpWoodException(
                        'parallel_length != len(parameters)')
            else:
                parallel_length = len(parameters)

        model_class = (
            model_class if type(model_class) is list
            else [model_class] * parallel_length)
        pk = (
            pk if type(pk) is list
            else [pk] * parallel_length)
        action = (
            action if type(action) is list
            else [action] * parallel_length)
        parameters = (
            parameters if type(parameters) is list
            else [parameters] * parallel_length)

        urls_list = [
            self._build_execute_action_url(
                model_class=model_class[i], action=action[i], pk=pk[i])
            for i in range(parallel_length)]

        print("## Starting parallel_execute_action: %s" % len(urls_list))
        return self.paralell_request_post(
            urls_list=urls_list, data_list=parameters,
            n_parallel=n_parallel, auth_header=auth_header)

    def parallel_bulk_save(self, model_class: str,
                           data_to_save: Union[pd.DataFrame, List[dict]],
                           n_parallel: int = None, chunksize: int = 1000,
                           auth_header: dict = None):
        """Break data_to_save in many parallel bulk_save requests.

        Args:
            model_class:
                Model class of the data that will be saved.
            data_to_save:
                Data that will be saved
            chunksize:
                Length of each parallel bulk save chunk.
            n_parallel:
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            List of the responses of bulk_save.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        if type(data_to_save) is list:
            data_to_save = pd.DataFrame(data_to_save)

        chunks = break_in_chunks(df_to_break=data_to_save, chunksize=chunksize)
        url = self._build_bulk_save_url(model_class)
        urls_list = [url] * len(chunks)

        print("## Starting parallel_bulk_save: %s" % len(urls_list))
        self.paralell_request_post(
            urls_list=urls_list, data_list=chunks,
            n_parallel=n_parallel, auth_header=auth_header)

    def parallel_pivot(self, model_class: str, list_args: List[dict],
                       columns: List[str], format: str, n_parallel: int = None,
                       variables: list = None, show_deleted: bool = False,
                       auth_header: dict = None) -> List[dict]:
        """Make [n_parallel] parallel pivot request.

        Args:
            model_class:
                Model Class to retrieve.
            list_args:
                A list of list request args (filter_dict,exclude_dict,
                order_by).
            columns:
                List of columns at the pivoted table.
            format:
                Format of returned table. See pandas.DataFrame
                to_dict args.
            n_parallel:
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            variables:
                Restrict the fields that will be returned at the query.
            show_deleted:
                If results should include data with deleted=True. This will
                be ignored if model class does not have deleted field.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            List of the pivot request reponses.

        Raises:
            No particular raises.

        Example:
            No example yet.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        url_temp = [self._build_pivot_url(model_class)]
        urls_list = url_temp * len(list_args)
        for q in list_args:
            q["variables"] = variables
            q["show_deleted"] = show_deleted
            q["columns"] = columns
            q["format"] = format

        print("## Starting parallel_pivot: %s" % len(urls_list))
        return self.paralell_request_post(
            urls_list=urls_list, data_list=list_args,
            n_parallel=n_parallel, auth_header=auth_header)

    def get_queue_matrix(self, queue_pk: int, auth_header: dict = None,
                         save_as_excel: str = None):
        """Download model queue estimation matrix. In development..."""
        file_content = self.retrieve_file(
            model_class="ModelQueue", pk=queue_pk,
            file_field="model_matrix_file", auth_header=auth_header,
            save_file=False)
        content = gzip.GzipFile(
            fileobj=io.BytesIO(file_content["content"])).read()
        data = json.loads(content.decode('utf-8'))
        columns_info = pd.DataFrame(data["columns_info"])
        model_matrix = pd.DataFrame(data["model_matrix"])

        if save_as_excel is not None:
            writer = ExcelWriter(save_as_excel)
            columns_info.to_excel(writer, 'columns_info', index=False)
            model_matrix.to_excel(writer, 'model_matrix', index=False)
            writer.save()
        else:
            return {
                "columns_info": columns_info,
                "model_matrix": model_matrix}
