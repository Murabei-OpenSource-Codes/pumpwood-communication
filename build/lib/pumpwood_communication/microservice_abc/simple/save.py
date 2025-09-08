"""Module for save functions of microservice."""
import io
import requests
from abc import ABC
from pumpwood_communication.exceptions import (
    PumpWoodException, PumpWoodObjectSavingException)


class ABCSimpleSaveMicroservice(ABC):
    """Abstract class for parallel calls at Pumpwood end-points."""

    @staticmethod
    def _build_save_url(model_class):
        return "rest/%s/save/" % (model_class.lower())

    def save(self, obj_dict, files: dict = None, auth_header: dict = None,
             fields: list = None, default_fields: bool = False,
             foreign_key_fields: bool = False,
             related_fields: bool = False) -> dict:
        """Save or Update a new object.

        Function to save or update a new model_class object. If obj_dict['pk']
        is None or not defined a new object will be created. The obj
        model class is defided at obj_dict['model_class'] and if not defined an
        PumpWoodObjectSavingException will be raised.

        If files argument is set, request will be transfered using a multipart
        request file files mapping file key to file field on backend.

        Args:
            obj_dict:
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
        model_class = obj_dict.get('model_class')
        if model_class is None:
            raise PumpWoodObjectSavingException(
                'To save an object obj_dict must have model_class defined.')

        url_str = self._build_save_url(model_class)
        parameters = {
            "fields": fields, "default_fields": default_fields,
            "foreign_key_fields": foreign_key_fields,
            "related_fields": related_fields}
        return self.request_post(
            url=url_str, data=obj_dict, parameters=parameters, files=files,
            auth_header=auth_header)

    @staticmethod
    def _build_save_streaming_file_url(model_class, pk):
        return "rest/{model_class}/save-file-streaming/{pk}/".format(
            model_class=model_class.lower(), pk=pk)

    def save_streaming_file(self, model_class: str, pk: int, file_field: str,
                            file: io.BufferedReader, file_name: str = None,
                            auth_header: dict = None,
                            fields: list = None, default_fields: bool = False,
                            foreign_key_fields: bool = False,
                            related_fields: bool = False) -> str:
        """Stream file to PumpWood.

        Use streaming to transfer a file content to Pumpwood storage, this
        end-point is prefered when transmiting files bigger than 10Mb. It
        is necessary to have the object created before the file transfer.

        Args:
            model_class:
                Model class of the object.
            pk:
                pk of the object.
            file_field:
                File field that will receive file stream.
            file:
                File to upload as a file object with read bytes option.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            file_name:
                Name of the file, if not set it will be saved as
                {pk}__{file_field}.{extension at permited extension}
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

        Returns:
            Return the file name associated with data at the storage.

        Raises:
            PumpWoodForbidden:
                'file_field must be set on self.file_fields dictionary'. This
                indicates that the `file_field` passed is not associated
                with a file field on the backend.
            PumpWoodException:
                'Saved bytes in streaming [{}] differ from file bytes [{}].'.
                This indicates that there was an error when transfering data
                to storage, the file bytes and transfered bytes does not
                match.
        """
        request_header = self._check__auth_header(auth_header=auth_header)
        request_header["Content-Type"] = "application/octet-stream"
        post_url = self.server_url + self._build_save_streaming_file_url(
            model_class=model_class, pk=pk)

        parameters = {
            "fields": fields, "default_fields": default_fields,
            "foreign_key_fields": foreign_key_fields,
            "related_fields": related_fields, "file_field": file_field}
        if file_name is not None:
            parameters["file_name"] = file_name

        response = requests.post(
            url=post_url, data=file, params=parameters,
            verify=self.verify_ssl, headers=request_header, stream=True,
            timeout=self.default_timeout)

        file_last_bite = file.tell()
        self.error_handler(response)
        json_response = self.angular_json(response)

        if file_last_bite != json_response["bytes_uploaded"]:
            template = (
                "Saved bytes in streaming [{}] differ from file " +
                "bites [{}].")
            raise PumpWoodException(
                    template.format(
                        json_response["bytes_uploaded"], file_last_bite))
        return json_response["file_path"]
