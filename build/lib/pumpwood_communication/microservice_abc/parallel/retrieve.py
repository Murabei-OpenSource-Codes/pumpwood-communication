"""Module for parallel functions of microservice."""
from pumpwood_communication.microservice_abc.parallel.base import (
    ABCParallelBaseMicroservice)


class ABCParallelRetriveMicroservice(ABCParallelBaseMicroservice):
    """Abstract class for parallel calls at Pumpwood end-points."""

    def parallel_retrieve(self, model_class: str | list[str],
                          list_pk: list[int],
                          default_fields: bool | list[bool] = False,
                          foreign_key_fields: bool | list[bool] = False,
                          related_fields: bool | list[bool] = False,
                          fields: list[str] | list[list[str]] = None,
                          auth_header: dict | list[dict] = None,
                          use_disk_cache: bool | list[bool] = False,
                          disk_cache_expire: int | list[int] = None,
                          base_filter_skip: list[str] | list[list[str]] = None,
                          n_parallel: int | None = None
                          ) -> list[dict]:
        """Retrieve an object from PumpWood.

        Function to get object serialized by retrieve end-point
        (more detailed data).

        Args:
            model_class:
                Model class of the end-point
            list_pk:
                Object pk
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
            use_disk_cache (bool):
                If set true, get request will use local cache to reduce
                the requests to the backend.
            disk_cache_expire (int):
                Time in seconds to expire the cache, it None it will
                use de default set be PumpwoodCache.
            base_filter_skip (list):
                List of base query filter to be skiped, it is necessary to
                be superuser to skip base query filters.
            n_parallel (int | None):
                N parallel request that will be done on backend.

        Returns:
            Return object with the correspondent pk.

        Raises:
            PumpWoodObjectDoesNotExist:
                If pk not found on database.
        """
        n_parallel = self.get_n_parallel(n_parallel=n_parallel)

        list_model_class = self.convert_to_list(
            argument=model_class, length=len(list_pk))
        list_default_fields = self.convert_to_list(
            argument=default_fields, length=len(list_pk))
        list_foreign_key_fields = self.convert_to_list(
            argument=foreign_key_fields, length=len(list_pk))
        list_related_fields = self.convert_to_list(
            argument=related_fields, length=len(list_pk))
        list_fields = self.convert_to_list(
            argument=fields, length=len(list_pk),
            force_replicate=True)
        list_auth_header = self.convert_to_list(
            argument=auth_header, length=len(list_pk))
        list_use_disk_cache = self.convert_to_list(
            argument=use_disk_cache, length=len(list_pk))
        list_disk_cache_expire = self.convert_to_list(
            argument=disk_cache_expire, length=len(list_pk))
        list_base_filter_skip = self.convert_to_list(
            argument=base_filter_skip, length=len(list_pk),
            force_replicate=True)
        column_arg = {
            'model_class': list_model_class,
            'pk': list_pk,
            'default_fields': list_default_fields,
            'foreign_key_fields': list_foreign_key_fields,
            'related_fields': list_related_fields,
            'fields': list_fields,
            'auth_header': list_auth_header,
            'use_disk_cache': list_use_disk_cache,
            'disk_cache_expire': list_disk_cache_expire,
            'base_filter_skip': list_base_filter_skip}

        function_args = self.transpose_args(dict_list=column_arg)
        return self.parallel_call(
            function=self.retrieve, function_args=function_args,
            n_parallel=n_parallel)

    def parallel_list_one(self, model_class: str | list[str],
                          list_pk: list[int],
                          default_fields: bool | list[bool] = True,
                          foreign_key_fields: bool | list[bool] = False,
                          related_fields: bool | list[bool] = False,
                          fields: list[str] | list[list[str]] = None,
                          auth_header: dict | list[dict] = None,
                          use_disk_cache: bool | list[bool] = False,
                          disk_cache_expire: int | list[int] = None,
                          base_filter_skip: list[str] | list[list[str]] = None,
                          n_parallel: int | None = None
                          ) -> list[dict]:
        """Retrieve an object from PumpWood.

        Function to get object serialized by retrieve end-point
        (more detailed data).

        Args:
            model_class:
                Model class of the end-point
            list_pk:
                Object pk
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
            use_disk_cache (bool):
                If set true, get request will use local cache to reduce
                the requests to the backend.
            disk_cache_expire (int):
                Time in seconds to expire the cache, it None it will
                use de default set be PumpwoodCache.
            base_filter_skip (list):
                List of base query filter to be skiped, it is necessary to
                be superuser to skip base query filters.
            n_parallel (int | None):
                N parallel request that will be done on backend.

        Returns:
            Return object with the correspondent pk.

        Raises:
            PumpWoodObjectDoesNotExist:
                If pk not found on database.
        """
        n_parallel = self.get_n_parallel(n_parallel=n_parallel)

        list_model_class = self.convert_to_list(
            argument=model_class, length=len(list_pk))
        list_default_fields = self.convert_to_list(
            argument=default_fields, length=len(list_pk))
        list_foreign_key_fields = self.convert_to_list(
            argument=foreign_key_fields, length=len(list_pk))
        list_related_fields = self.convert_to_list(
            argument=related_fields, length=len(list_pk))
        list_fields = self.convert_to_list(
            argument=fields, length=len(list_pk),
            force_replicate=True)
        list_auth_header = self.convert_to_list(
            argument=auth_header, length=len(list_pk))
        list_use_disk_cache = self.convert_to_list(
            argument=use_disk_cache, length=len(list_pk))
        list_disk_cache_expire = self.convert_to_list(
            argument=disk_cache_expire, length=len(list_pk))
        list_base_filter_skip = self.convert_to_list(
            argument=base_filter_skip, length=len(list_pk),
            force_replicate=True)
        column_arg = {
            'model_class': list_model_class,
            'pk': list_pk,
            'default_fields': list_default_fields,
            'foreign_key_fields': list_foreign_key_fields,
            'related_fields': list_related_fields,
            'fields': list_fields,
            'auth_header': list_auth_header,
            'use_disk_cache': list_use_disk_cache,
            'disk_cache_expire': list_disk_cache_expire,
            'base_filter_skip': list_base_filter_skip}

        function_args = self.transpose_args(dict_list=column_arg)
        return self.parallel_call(
            function=self.list_one, function_args=function_args,
            n_parallel=n_parallel)

    def parallel_retrieve_file(self, model_class: str | list[str],
                               list_pk: list[int],
                               file_field: str | list[str],
                               auth_header: dict | list[dict] = None,
                               save_file: bool | list[bool] = True,
                               save_path: str | list[str] = "./",
                               file_name: str | list[str] = None,
                               if_exists: str | list[str] = "fail",
                               base_filter_skip: list[str] | list[list[str]] = None,  #NOQA
                               n_parallel: int | None = None
                               ) -> list[str] | list[dict]:
        """Retrieve a file from PumpWood.

        This function will retrieve file as a single request, depending on the
        size of the files it would be preferred to use streaming end-point.

        Args:
            model_class:
                Class of the model to retrieve file.
            list_pk:
                Pk of the object associeted file.
            file_field:
                Field of the file to be downloaded.
            auth_header:
                Dictionary containing the auth header.
            save_file:
                If data is to be saved as file or return get
                response.
            save_path:
                Path of the directory to save file.
            file_name:
                Name of the file, if None it will have same name as
                saved in PumpWood.
            if_exists:
                Values must be in {'fail', 'change_name', 'overwrite', 'skip'}.
                Set what to do if there is a file with same name. Skip
                will not download file if there is already with same
                os.path.join(save_path, file_name), file_name must be set
                for skip argument.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            base_filter_skip (list):
                List of base query filter to be skiped, it is necessary to
                be superuser to skip base query filters.
            n_parallel (int):
                Number of parallel requests, if None will use the default
                one.

        Returns:
            May return the file name if save_file=True; If false will return
            a dictonary with keys `filename` with original file name and
            `content` with binary data of file content.

        Raises:
            PumpWoodForbidden:
                'storage_object attribute not set for view, file operations
                are disable'. This indicates that storage for this backend
                was not configured, so it is not possible to make storage
                operations,
            PumpWoodForbidden:
                'file_field must be set on self.file_fields dictionary'. This
                indicates that the `file_field` parameter is not listed as
                a file field on the backend.
            PumpWoodObjectDoesNotExist:
                'field [{}] not found or null at object'. This indicates that
                the file field requested is not present on object fields.
            PumpWoodObjectDoesNotExist:
                'Object not found in storage [{}]'. This indicates that the
                file associated with file_field is not avaiable at the
                storage. This should not ocorrur, it might have a manual
                update at the model_class table or manual removal/rename of
                files on storage.
        """
        n_parallel = self.get_n_parallel(n_parallel=n_parallel)

        # Convert arguments to list
        list_model_class = self.convert_to_list(
            argument=model_class, length=len(list_pk))
        list_file_field = self.convert_to_list(
            argument=file_field, length=len(list_pk))
        list_auth_header = self.convert_to_list(
            argument=auth_header, length=len(list_pk))
        list_save_file = self.convert_to_list(
            argument=save_file, length=len(list_pk))
        list_save_path = self.convert_to_list(
            argument=save_path, length=len(list_pk))
        list_file_name = self.convert_to_list(
            argument=file_name, length=len(list_pk))
        list_if_exists = self.convert_to_list(
            argument=if_exists, length=len(list_pk))
        list_base_filter_skip = self.convert_to_list(
            argument=base_filter_skip, length=len(list_pk),
            force_replicate=True)
        list_n_parallel = self.convert_to_list(
            argument=n_parallel, length=len(list_pk))

        column_arg = {
            'model_class': list_model_class,
            'pk': list_pk,
            'file_field': list_file_field,
            'auth_header': list_auth_header,
            'save_file': list_save_file,
            'save_path': list_save_path,
            'file_name': list_file_name,
            'if_exists': list_if_exists,
            'base_filter_skip': list_base_filter_skip,
            'n_parallel': list_n_parallel}
        function_args = self.transpose_args(dict_list=column_arg)
        return self.parallel_call(
            function=self.retrieve_file, function_args=function_args,
            n_parallel=n_parallel)

    def parallel_retrieve_streaming_file(self, model_class: str,
                                         list_pk: int | list[int],
                                         file_field: str | list[str],
                                         file_name: str | list[str],
                                         auth_header: dict | list[dict] = None,
                                         save_path: str | list[str] = "./",
                                         if_exists: str | list[str] = "fail",
                                         base_filter_skip: list | list[list] = None, # NOQA
                                         n_parallel: int | None = None
                                         ) -> str:
        """Retrieve a file from PumpWood using streaming to retrieve content.

        This funcion uses file streaming to retrieve file content, it should be
        prefered when dealing with large (bigger than 10Mb) files transfer.
        Using this end-point the file is not loaded on backend memory content
        is transfered by chucks that are read at the storage and transfered
        to user.

        It will necessarily save the content as a file, there is not the
        possibility of retrieving the content directly from request.

        Args:
            model_class:
                Class of the model to retrieve file.
            list_pk:
                Pk of the object associeted file.
            file_field:
                Field of the file to be downloaded.
            auth_header:
                Dictionary containing the auth header.
            save_path:
                Path of the directory to save file.
            file_name:
                Name of the file, if None it will have same name as
                saved in PumpWood.
            if_exists:
                Values must be in {'fail', 'change_name', 'overwrite'}.
                Set what to do if there is a file with same name.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            base_filter_skip (list):
                List of base query filter to be skiped, it is necessary to
                be superuser to skip base query filters.
            n_parallel (int):
                Number of parallel requests, if None will use the default
                one.

        Returns:
            Returns the file path that recived the file content.

        Raises:
            PumpWoodForbidden:
                'storage_object attribute not set for view, file operations
                are disable'. This indicates that storage for this backend
                was not configured, so it is not possible to make storage
                operations,
            PumpWoodForbidden:
                'file_field must be set on self.file_fields dictionary'. This
                indicates that the `file_field` parameter is not listed as
                a file field on the backend.
            PumpWoodObjectDoesNotExist:
                'field [{}] not found or null at object'. This indicates that
                the file field requested is not present on object fields.
            PumpWoodObjectDoesNotExist:
                'Object not found in storage [{}]'. This indicates that the
                file associated with file_field is not avaiable at the
                storage. This should not ocorrur, it might have a manual
                update at the model_class table or manual removal/rename of
                files on storage.
        """
        n_parallel = self.get_n_parallel(n_parallel=n_parallel)

        # Convert arguments to list
        list_model_class = self.convert_to_list(
            argument=model_class, length=len(list_pk))
        list_file_field = self.convert_to_list(
            argument=file_field, length=len(list_pk))
        list_file_name = self.convert_to_list(
            argument=file_name, length=len(list_pk))
        list_auth_header = self.convert_to_list(
            argument=auth_header, length=len(list_pk))
        list_save_path = self.convert_to_list(
            argument=save_path, length=len(list_pk))
        list_if_exists = self.convert_to_list(
            argument=if_exists, length=len(list_pk))
        list_base_filter_skip = self.convert_to_list(
            argument=base_filter_skip, length=len(list_pk),
            force_replicate=True)

        column_arg = {
            'model_class': list_model_class,
            'pk': list_pk,
            'file_field': list_file_field,
            'file_name': list_file_name,
            'auth_header': list_auth_header,
            'save_path': list_save_path,
            'if_exists': list_if_exists,
            'base_filter_skip': list_base_filter_skip,
        }
        function_args = self.transpose_args(dict_list=column_arg)
        return self.parallel_call(
            function=self.retrieve_streaming_file, function_args=function_args,
            n_parallel=n_parallel)
