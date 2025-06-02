"""Module for permission related functions of microservice."""
from abc import ABC
from pumpwood_communication.exceptions import PumpWoodUnauthorized


class ABCPermissionMicroservice(ABC):
    """Abstract class for permission checking at pumpwood."""

    def check_if_logged(self, auth_header: dict = None) -> bool:
        """Check if user is logged.

        Args:
            auth_header (dict): = None
                AuthHeader to substitute the microservice original at
                request. If not passed, microservice object auth_header
                will be used.

        Returns:
            Return True if auth_header is looged and False if not
        """
        try:
            check = self.request_get(
                url="rest/registration/check/",
                auth_header=auth_header)
        except PumpWoodUnauthorized:
            return False
        return check

    def get_user_info(self, auth_header: dict = None) -> dict:
        """Get user info.

        Args:
            auth_header (dict): = None
                AuthHeader to substitute the microservice original at
                request. If not passed, microservice object auth_header
                will be used.

        Returns:
            A serialized user object with information of the logged user.
        """
        user_info = self.request_get(
            url="rest/registration/retrieveauthenticateduser/",
            auth_header=auth_header, timeout=self.default_timeout)
        return user_info

    def check_permission(self, model_class: str, end_point: str,
                         extra_arg: str = None, allow_service_user: str = None,
                         allow_external: str = None, auth_header: dict = None,
                         ) -> dict:
        """Get user info.

        Args:
            model_class (str):
                Model class associated to be checked for access.
            end_point (str):
                Name of the end-point that will be checked for permission. Ex.:
                retrieve, save, list, list-without-pag, ...
            extra_arg (str):
                Used on some end-points. On action end-point it is reponsible
                for setting the action associated with the call.
            allow_service_user: str = None:

            allow_external: str = None:

            auth_header (dict):
                AuthHeader to substitute the microservice original at
                request. If not passed, microservice object auth_header
                will be used.

        Returns:
            A serialized user object with information of the logged user.
        """
        # user_info = self.request_post(
        #     url="rest/registration/check/",
        #     payload={
        #         'end_point': end_point,
        #         'first_arg': first_arg,
        #         'second_arg': second_arg,
        #         'api_config_allow': api_config_allow,
        #         'api_config_deny': api_config_deny},
        #     auth_header=auth_header, timeout=self.default_timeout)
        # return user_info
        return True
