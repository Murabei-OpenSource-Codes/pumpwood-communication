"""Module for action calls."""
from abc import ABC
from pumpwood_communication.microservice_abc.base import (
    PumpWoodMicroServiceBase)


class ABCSimpleActionMicroservice(ABC, PumpWoodMicroServiceBase):
    """Abstract class for parallel calls at Pumpwood end-points."""

    def list_actions(self, model_class: str,
                     auth_header: dict = None) -> list[dict]:
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
                       auth_header: dict = None,
                       base_filter_skip: list[str] | list[list[str]] = None
                       ) -> dict:
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
            base_filter_skip (list):
                List of base query filter to be skiped, it is necessary to
                be superuser to skip base query filters.

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
        base_filter_skip = (
            [] if base_filter_skip is None else base_filter_skip)
        url_str = self._build_execute_action_url(
            model_class=model_class, action=action, pk=pk)
        return self.request_post(
            url=url_str, data=parameters, files=files, auth_header=auth_header,
            parameters={"base_filter_skip": base_filter_skip})
