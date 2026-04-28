"""Module for retrieve functions of microservice."""
import os
import requests
import numbers
import numpy as np
from decimal import Decimal
from abc import ABC
from werkzeug.utils import secure_filename
from pumpwood_communication.exceptions import PumpWoodException
from pumpwood_communication.microservice_abc.base import (
    PumpWoodMicroServiceBase)
from pumpwood_communication.serializers import CompositePkBase64Converter


class ABCSimpleRetriveMicroservice(ABC, PumpWoodMicroServiceBase):
    """Abstract class for parallel calls at Pumpwood end-points."""

    @staticmethod
    def _build_list_one_url(model_class, pk):
        return "rest/%s/retrieve/%s/" % (model_class.lower(), pk)

    def list_one(self, model_class: str, pk: int, fields: list = None,
                 default_fields: bool = True, foreign_key_fields: bool = False,
                 related_fields: bool = False, auth_header: dict = None,
                 use_disk_cache: bool = False,
                 disk_cache_expire: int = None,
                 base_filter_skip: list = None) -> dict:
        """Retrieve an object using list serializer (simple).

        **# DEPRECTED #** It is the same as retrieve using
        `default_fields: bool = True`, if possible migrate to retrieve
        function.

        Args:
            model_class:
                Model class of the end-point
            pk:
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
            base_filter_skip (list[str]):
                List of base query filter to be skiped, it is necessary to
                be superuser to skip base query filters.

        Returns:
            Return object with the correspondent pk.

        Raises:
            PumpWoodObjectDoesNotExist:
                If pk not found on database.
        """
        base_filter_skip = (
            [] if base_filter_skip is None else base_filter_skip)
        url_str = self._build_list_one_url(model_class, pk)
        return self.request_get(
            url=url_str, parameters={
                "fields": fields, "default_fields": default_fields,
                "foreign_key_fields": foreign_key_fields,
                "related_fields": related_fields,
                "base_filter_skip": base_filter_skip},
            auth_header=auth_header, use_disk_cache=use_disk_cache,
            disk_cache_expire=disk_cache_expire)

    @staticmethod
    def _build_retrieve_url(model_class: str, pk: int):
        return "rest/%s/retrieve/%s/" % (model_class.lower(), pk)

    def retrieve(self, model_class: str, pk: int | str | dict,
                 default_fields: bool = False,
                 foreign_key_fields: bool = False,
                 related_fields: bool = False,
                 fields: list = None,
                 auth_header: dict = None,
                 use_disk_cache: bool = False,
                 disk_cache_expire: int = None,
                 base_filter_skip: list = None) -> dict:
        """Retrieve an object from PumpWood.

        Function to get an object serialized by the retrieve endpoint (more
        detailed data). It will fetch information for a single object
        based on the primary key, which may be a simple ID, a composite key
        passed as a dictionary, or a base64 URL-safe string.

        It is also possible to retrieve single objects using unique fields,
        such as codes or multiple column uniqueness constraints. This can
        be done by passing the argument as a base64 string or a dictionary
        containing the filtering clauses.

        Example:
            ```python
            microservice.retrieve(
                model_class="ModelClassWithUniqueCode",
                pk={'code': 'unique code for object'})

            microservice.retrieve(
                model_class="ModelClassWithCompositeUniqueConstraint",
                pk={'time': '2026-01-01', 'attribute_id': 1})
            ```

        Args:
            model_class (str):
                Model class of the endpoint.
            pk (Union[int, str, dict]):
                The primary key or unique identifier for the object.
            auth_header (dict, optional):
                Authentication header to substitute the microservice's original
                credentials (used for user impersonation). Defaults to None.
            fields (list, optional):
                Set of fields to be returned by the endpoint.
            default_fields (bool):
                If True and 'fields' is None, will return the default fields
                defined by the backend. Defaults to False.
            foreign_key_fields (bool):
                If True, returns full objects for foreign keys instead of just
                their IDs. For example, 'created_by_id' will also return the
                user object at 'created_by'. Defaults to False.
            related_fields (bool):
                If True, returns related objects (those that have a foreign key
                pointing to this model). Results are typically returned as a
                list of dictionaries in a field with a '_set' suffix.
                Warning: Using this may consume significant backend resources.
                Defaults to False.
            use_disk_cache (bool):
                If True, the GET request will use a local disk cache to reduce
                backend load. Defaults to False.
            disk_cache_expire (int, optional):
                TTL in seconds for the cache. If None, uses the default
                PumpwoodCache settings. Defaults to None.
            base_filter_skip (list, optional):
                List of base query filters to skip. Requires superuser
                privileges. Defaults to None.

        Returns:
            dict: The object matching the provided primary key/identifier.

        Raises:
            PumpWoodObjectDoesNotExist:
                If the PK is not found in the database.
            PumpWoodException:
                For other errors during retrieval or communication.
        """
        # Type checking and complex default values
        is_allowed_types = isinstance(
            pk, (numbers.Number, np.number, Decimal, str, dict))
        if not is_allowed_types:
            msg = (
                "Retrieve pk must be a number, string or dict,"
                " got type [{type}]")
            raise PumpWoodException(
                msg, payload={"type": type(pk).__name__})
        base_filter_skip = (
            [] if base_filter_skip is None else base_filter_skip)

        # Convert to base64 dict unique queries
        serialized_pk = None
        if isinstance(pk, dict):
            # Use the correct keyword argument 'primary_key_dict'
            serialized_pk = CompositePkBase64Converter.dump_dict(
                primary_key_dict=pk)
        else:
            serialized_pk = pk

        # Fetch information from Pumpwood
        url_str = self._build_retrieve_url(
            model_class=model_class, pk=serialized_pk)
        return self.request_get(
            url=url_str, parameters={
                "fields": fields, "default_fields": default_fields,
                "foreign_key_fields": foreign_key_fields,
                "related_fields": related_fields,
                "base_filter_skip": base_filter_skip},
            auth_header=auth_header, use_disk_cache=use_disk_cache,
            disk_cache_expire=disk_cache_expire)

    @staticmethod
    def _build_retrieve_file_url(model_class: str, pk: int):
        return "rest/%s/retrieve-file/%s/" % (model_class.lower(), pk)

    def retrieve_file(self, model_class: str, pk: int, file_field: str,
                      auth_header: dict = None, save_file: bool = True,
                      save_path: str = "./", file_name: str = None,
                      if_exists: str = "fail",
                      base_filter_skip: list = None) -> any:
        """Retrieve a file from PumpWood.

        This function will retrieve file as a single request, depending on the
        size of the files it would be preferred to use streaming end-point.

        Args:
            model_class:
                Class of the model to retrieve file.
            pk:
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
        base_filter_skip = (
            [] if base_filter_skip is None else base_filter_skip)

        if if_exists not in ["fail", "change_name", "overwrite", "skip"]:
            raise PumpWoodException(
                "if_exists must be in ['fail', 'change_name', 'overwrite', "
                "'skip']")

        if file_name is not None and if_exists == 'skip':
            file_path = os.path.join(save_path, file_name)
            is_file_already = os.path.isfile(file_path)
            if is_file_already:
                print("skiping file already exists: ", file_path)
                return file_path

        url_str = self._build_retrieve_file_url(model_class=model_class, pk=pk)
        file_response = self.request_get(
            url=url_str, parameters={
                "file-field": file_field,
                "base_filter_skip": base_filter_skip},
            auth_header=auth_header)
        if not save_file:
            return file_response

        if not os.path.exists(save_path):
            raise PumpWoodException(
                "Path to save retrieved file [{}] does not exist".format(
                    save_path))

        file_name = secure_filename(file_name or file_response["filename"])
        file_path = os.path.join(save_path, file_name)
        is_file_already = os.path.isfile(file_path)
        if is_file_already:
            if if_exists == "change_name":
                filename, file_extension = os.path.splitext(file_path)
                too_many_tries = True
                for i in range(10):
                    new_path = "{filename}__{count}{extension}".format(
                        filename=filename, count=i,
                        extension=file_extension)
                    if not os.path.isfile(new_path):
                        file_path = new_path
                        too_many_tries = False
                        break
                if too_many_tries:
                    raise PumpWoodException(
                        ("Too many tries to find a not used file name." +
                         " file_path[{}]".format(file_path)))

            elif if_exists == "fail":
                raise PumpWoodException(
                    ("if_exists set as 'fail' and there is a file with same" +
                     "name. file_path [{}]").format(file_path))

        with open(file_path, "wb") as file:
            file.write(file_response["content"])
        return file_path

    @staticmethod
    def _build_retrieve_file_straming_url(model_class: str, pk: int):
        return "rest/%s/retrieve-file-streaming/%s/" % (
            model_class.lower(), pk)

    def retrieve_streaming_file(self, model_class: str, pk: int,
                                file_field: str, file_name: str,
                                auth_header: dict = None,
                                save_path: str = "./",
                                if_exists: str = "fail",
                                base_filter_skip: list = None) -> str:
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
            pk:
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
        base_filter_skip = (
            [] if base_filter_skip is None else base_filter_skip)

        request_header = self._check_auth_header(auth_header)

        # begin Args check
        if if_exists not in ["fail", "change_name", "overwrite"]:
            raise PumpWoodException(
                "if_exists must be in ['fail', 'change_name', 'overwrite']")

        if not os.path.exists(save_path):
            raise PumpWoodException(
                "Path to save retrieved file [{}] does not exist".format(
                    save_path))
        # end Args check

        file_path = os.path.join(save_path, file_name)
        if os.path.isfile(file_path) and if_exists == "change_name":
            filename, file_extension = os.path.splitext(file_path)
            too_many_tries = False
            for i in range(10):
                new_path = "{filename}__{count}{extension}".format(
                    filename=filename, count=i,
                    extension=file_extension)
                if not os.path.isfile(new_path):
                    file_path = new_path
                    too_many_tries = True
                    break
            if not too_many_tries:
                raise PumpWoodException(
                    ("Too many tries to find a not used file name." +
                     " file_path[{}]".format(file_path)))

        if os.path.isfile(file_path) and if_exists == "fail":
            raise PumpWoodException(
                ("if_exists set as 'fail' and there is a file with same" +
                 "name. file_path [{}]").format(file_path))

        url_str = self._build_retrieve_file_straming_url(
            model_class=model_class, pk=pk)

        get_url = self.server_url + url_str
        with requests.get(
                get_url, verify=self._verify_ssl, headers=request_header,
                params={
                    "file-field": file_field,
                    "base_filter_skip": base_filter_skip},
                timeout=self._default_timeout) as response:
            self.error_handler(response)
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
        return file_path
