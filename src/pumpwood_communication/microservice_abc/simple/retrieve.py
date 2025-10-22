"""Module for retrieve functions of microservice."""
import os
import requests
from abc import ABC
from werkzeug.utils import secure_filename
from pumpwood_communication.exceptions import PumpWoodException
from pumpwood_communication.microservice_abc.base import (
    PumpWoodMicroServiceBase)


class ABCSimpleRetriveMicroservice(ABC, PumpWoodMicroServiceBase):
    """Abstract class for parallel calls at Pumpwood end-points."""

    @staticmethod
    def _build_list_one_url(model_class, pk):
        return "rest/%s/retrieve/%s/" % (model_class.lower(), pk)

    def list_one(self, model_class: str, pk: int, fields: list = None,
                 default_fields: bool = True, foreign_key_fields: bool = False,
                 related_fields: bool = False, auth_header: dict = None,
                 use_disk_cache: bool = False,
                 disk_cache_expire: int = None) -> dict:
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

        Returns:
            Return object with the correspondent pk.

        Raises:
            PumpWoodObjectDoesNotExist:
                If pk not found on database.
        """
        url_str = self._build_list_one_url(model_class, pk)
        return self.request_get(
            url=url_str, parameters={
                "fields": fields, "default_fields": default_fields,
                "foreign_key_fields": foreign_key_fields,
                "related_fields": related_fields},
            auth_header=auth_header, use_disk_cache=use_disk_cache,
            disk_cache_expire=disk_cache_expire)

    @staticmethod
    def _build_retrieve_url(model_class: str, pk: int):
        return "rest/%s/retrieve/%s/" % (model_class.lower(), pk)

    def retrieve(self, model_class: str, pk: int,
                 default_fields: bool = False,
                 foreign_key_fields: bool = False,
                 related_fields: bool = False,
                 fields: list = None,
                 auth_header: dict = None,
                 use_disk_cache: bool = False,
                 disk_cache_expire: int = None) -> dict:
        """Retrieve an object from PumpWood.

        Function to get object serialized by retrieve end-point
        (more detailed data).

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

        Returns:
            Return object with the correspondent pk.

        Raises:
            PumpWoodObjectDoesNotExist:
                If pk not found on database.
        """
        url_str = self._build_retrieve_url(model_class=model_class, pk=pk)
        return self.request_get(
            url=url_str, parameters={
                "fields": fields, "default_fields": default_fields,
                "foreign_key_fields": foreign_key_fields,
                "related_fields": related_fields},
            auth_header=auth_header, use_disk_cache=use_disk_cache,
            disk_cache_expire=disk_cache_expire)

    @staticmethod
    def _build_retrieve_file_url(model_class: str, pk: int):
        return "rest/%s/retrieve-file/%s/" % (model_class.lower(), pk)

    def retrieve_file(self, model_class: str, pk: int, file_field: str,
                      auth_header: dict = None, save_file: bool = True,
                      save_path: str = "./", file_name: str = None,
                      if_exists: str = "fail") -> any:
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
            url=url_str, parameters={"file-field": file_field},
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
                                if_exists: str = "fail"):
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
                params={"file-field": file_field},
                timeout=self._default_timeout) as response:
            self.error_handler(response)
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
        return file_path
