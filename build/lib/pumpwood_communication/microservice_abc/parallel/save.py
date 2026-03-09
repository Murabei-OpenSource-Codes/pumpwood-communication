"""Module for parallel save functions of microservice."""
import pandas as pd
from typing import List
from pumpwood_communication.exceptions import PumpWoodException
from pumpwood_communication.microservice_abc.parallel.base import (
    ABCParallelBaseMicroservice)
from pumpwood_communication.misc import break_in_chunks


class ABCParallelSaveMicroservice(ABCParallelBaseMicroservice):
    """Abstract class for parallel calls at Pumpwood end-points."""

    def parallel_save(self, list_obj_dict: list[dict],
                      files: list[dict] = None,
                      auth_header: dict = None,
                      fields: list[str] | list[list[str]] = None,
                      default_fields: bool | list[bool] = False,
                      foreign_key_fields: bool | list[bool] = False,
                      related_fields: bool | list[bool] = False,
                      base_filter_skip: list | list[list[str]] = None,
                      n_parallel: int | None = None
                      ) -> List[dict]:
        """Save or Update a new object.

        Function to save or update a new model_class object. If obj_dict['pk']
        is None or not defined a new object will be created. The obj
        model class is defided at obj_dict['model_class'] and if not defined an
        PumpWoodObjectSavingException will be raised.

        If files argument is set, request will be transfered using a multipart
        request file files mapping file key to file field on backend.

        Args:
            list_obj_dict:
                Model data dictionary. It must have 'model_class'
                key and if 'pk' key is not defined a new object will
                be created, else object with pk will be updated.
            files:
                A dictionary of files to be added to as a multi-part
                post request. File must be passed as a file object with read
                bytes.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
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
            base_filter_skip (list):
                List of base query filter to be skiped, it is necessary to
                be superuser to skip base query filters.
            n_parallel (int):
                Number of parallel requests, if None will use the default
                one.

        Returns:
            Return updated/created object data.

        Raises:
            PumpWoodObjectSavingException:
                'To save an object obj_dict must have model_class defined.'
                This indicates that the obj_dict must have key `model_class`
                indicating model class of the object that will be
                updated/created.
            PumpWoodObjectDoesNotExist:
                'Requested object {model_class}[{pk}] not found.'. This
                indicates that the pk passed on obj_dict was not found on
                backend database.
            PumpWoodIntegrityError:
                Error raised when IntegrityError is raised on database. This
                might ocorrur when saving objects that does not respect
                uniqueness restriction on database or other IntegrityError
                like removal of foreign keys with related data.
            PumpWoodObjectSavingException:
                Return error at object validation on de-serializing the
                object or files with unexpected extensions.
        """
        n_parallel = self.get_n_parallel(n_parallel=n_parallel)

        # Not coping files because it has pointers to files... don't know
        # how would that react
        list_files = None
        if files is None:
            list_files = [None] * len(list_obj_dict)
        else:
            list_files = files

        if len(list_files) != len(list_obj_dict):
            msg = (
                "When parallel save it is necessary that, if provided, "
                "len(files) == len(list_obj_dict)")
            raise PumpWoodException(msg)

        # Convert dataframe to list
        if isinstance(list_obj_dict, pd.DataFrame):
            list_obj_dict = list_obj_dict.to_dict("records")

        list_auth_header = self.convert_to_list(
            argument=auth_header, length=len(list_obj_dict))
        list_fields = self.convert_to_list(
            argument=fields, length=len(list_obj_dict),
            force_replicate=True)
        list_default_fields = self.convert_to_list(
            argument=default_fields, length=len(list_obj_dict))
        list_foreign_key_fields = self.convert_to_list(
            argument=foreign_key_fields, length=len(list_obj_dict))
        list_related_fields = self.convert_to_list(
            argument=related_fields, length=len(list_obj_dict))
        list_base_filter_skip = self.convert_to_list(
            argument=base_filter_skip, length=len(list_obj_dict),
            force_replicate=True)

        column_arg = {
            'obj_dict': list_obj_dict,
            'auth_header': list_auth_header,
            'fields': list_fields,
            'default_fields': list_default_fields,
            'foreign_key_fields': list_foreign_key_fields,
            'related_fields': list_related_fields,
            'base_filter_skip': list_base_filter_skip,
        }
        function_args = self.transpose_args(dict_list=column_arg)
        return self.parallel_call(
            function=self.save, function_args=function_args,
            n_parallel=n_parallel)

    def parallel_bulk_save(self, model_class: str,
                           data_to_save: pd.DataFrame | list[dict],
                           n_parallel: int = None, chunksize: int = 1000,
                           base_filter_skip: list[str] | list[list[str]] = None, # NOQA
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
            base_filter_skip (list):
                List of base query filter to be skiped, it is necessary to
                be superuser to skip base query filters.

        Returns:
            list of the responses of bulk_save.
        """
        n_parallel = self.get_n_parallel(n_parallel=n_parallel)
        if type(data_to_save) is list:
            data_to_save = pd.DataFrame(data_to_save)

        # Break dataframe in chunks to
        chunks = break_in_chunks(
            df_to_break=data_to_save, chunksize=chunksize)
        list_model_class = self.convert_to_list(
            argument=model_class, length=len(chunks))
        list_auth_header = self.convert_to_list(
            argument=auth_header, length=len(chunks))
        list_base_filter_skip = self.convert_to_list(
            argument=base_filter_skip, length=len(chunks),
            force_replicate=True)

        column_arg = {
            'model_class': list_model_class,
            'data_to_save': chunks,
            'auth_header': list_auth_header,
            'base_filter_skip': list_base_filter_skip}
        function_args = self.transpose_args(dict_list=column_arg)
        return self.parallel_call(
            function=self.bulk_save, function_args=function_args,
            n_parallel=n_parallel)
