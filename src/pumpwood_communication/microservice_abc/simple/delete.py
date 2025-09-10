"""Module for retrieve functions of microservice."""
from abc import ABC
from pumpwood_communication.microservice_abc.base import (
    PumpWoodMicroServiceBase)


class ABCSimpleDeleteMicroservice(ABC, PumpWoodMicroServiceBase):
    """Abstract class for calls at Pumpwood delete end-points."""

    @staticmethod
    def _build_delete_request_url(model_class, pk):
        return "rest/%s/delete/%s/" % (model_class.lower(), pk)

    def delete(self, model_class: str, pk: int,
               auth_header: dict = None) -> dict:
        """Send delete request to a PumpWood object.

        Delete (or whatever the PumpWood system have been implemented) the
        object with the specified pk.

        Args:
            model_class:
                Model class to delete the object
            pk:
                Object pk to be deleted (or whatever the PumpWood system
                have been implemented). Some model_class with 'deleted' field
                does not remove the entry, it will flag deleted=True at this
                cases. Model class with delete=True will be not retrieved
                by default on `list` and `list_without_pag` end-points.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            Returns delete object.

        Raises:
            PumpWoodObjectDoesNotExist:
                'Requested object {model_class}[{pk}] not found.' This
                indicates that the pk was not found in database.
        """
        url_str = self._build_delete_request_url(model_class, pk)
        return self.request_delete(url=url_str, auth_header=auth_header)

    @staticmethod
    def _build_remove_file_field(model_class, pk):
        return "rest/%s/remove-file-field/%s/" % (model_class.lower(), pk)

    def delete_file(self, model_class: str, pk: int, file_field: str,
                    auth_header: dict = None) -> bool:
        """Send delete request to a PumpWood object.

        Delete (or whatever the PumpWood system have been implemented) the
        object with the specified pk.

        At previous versions this function was `remove_file_field`. An alias
        is created for backward compatibility.

        Args:
            model_class:
                Model class to delete the object
            pk:
                Object pk to be deleted (or whatever the PumpWood system
                have been implemented).
            file_field:
                File field to be removed from storage.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            Return True is file was successful removed

        Raises:
            PumpWoodForbidden:
                'storage_object attribute not set for view, file operations
                are disable'. This indicates that storage_object is not
                associated with view, not allowing it to make storage
                operations.
            PumpWoodForbidden:
                'file_field must be set on self.file_fields dictionary.'.
                This indicates that the `file_field` was not set as a file
                field on the backend.
            PumpWoodObjectDoesNotExist:
                'File does not exist. File field [{}] is set as None'.
                This indicates that the object does not exists on storage,
                it should not occur. It might have been some manual update
                of the database or at the storage level.
        """
        url_str = self._build_remove_file_field(model_class, pk)
        return self.request_delete(
            url=url_str, auth_header=auth_header,
            parameters={"file-field": file_field})

    # Create an alias for backward compatibility.
    remove_file_field = delete_file

    @staticmethod
    def _build_delete_many_request_url(model_class):
        return "rest/%s/delete/" % (model_class.lower(), )

    def delete_many(self, model_class: str, filter_dict: dict = {},
                    exclude_dict: dict = {}, auth_header: dict = None) -> bool:
        """Remove many objects using query to retrict removal.

        CAUTION It is not possible to undo this operation, model_class
        this deleted field will be removed from database when using this
        end-point, different from using delete end-point.

        Args:
            model_class:
                Model class to delete the object
            filter_dict:
                Dictionary to make filter query.
            exclude_dict:
                Dictionary to make exclude query.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            True if delete is ok.

        Raises:
            PumpWoodObjectDeleteException:
                Raises error if there is any error when commiting object
                deletion on database.
        """
        url_str = self._build_delete_many_request_url(model_class)
        return self.request_post(
            url=url_str,
            data={'filter_dict': filter_dict, 'exclude_dict': exclude_dict},
            auth_header=auth_header)
