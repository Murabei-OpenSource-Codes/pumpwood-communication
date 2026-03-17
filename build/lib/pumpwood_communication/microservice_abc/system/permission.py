"""Module for permission related functions of microservice."""
from abc import ABC
from loguru import logger
from pumpwood_communication.cache import default_cache
from pumpwood_communication.exceptions import PumpWoodUnauthorized
from pumpwood_communication.microservice_abc.base import (
    PumpWoodMicroServiceBase)
from pumpwood_communication.config import AUTHORIZATION_CACHE_TIMEOUT


class ABCPermissionMicroservice(ABC, PumpWoodMicroServiceBase):
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

    def get_user_info(self, auth_header: dict = None,
                      use_disk_cache: bool = False,
                      disk_cache_expire: int = None) -> dict:
        """Get user info.

        Args:
            auth_header (dict): = None
                AuthHeader to substitute the microservice original at
                request. If not passed, microservice object auth_header
                will be used.
            use_disk_cache (bool):
                It possible use disk cache.
            disk_cache_expire (int):
                Set a time to expire the cache. If not passed env variable
                `PUMPWOOD_COMUNICATION__AUTHORIZATION_CACHE_TIMEOUT` will
                be used with 60 seconds as default.

        Returns:
            A serialized user object with information of the logged user.
        """
        url = "rest/registration/retrieveauthenticateduser/"
        temp_disk_cache_expire = (
            disk_cache_expire
            if disk_cache_expire is not None else
            AUTHORIZATION_CACHE_TIMEOUT)

        user_info = self.request_get(
            url=url, auth_header=auth_header, use_disk_cache=use_disk_cache,
            disk_cache_expire=temp_disk_cache_expire)
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

    def get_user_row_permission(self, auth_header: dict = None,
                                use_disk_cache: bool = False,
                                disk_cache_expire: int = None,
                                return_ids: bool = False
                                ) -> list[dict] | list[int]:
        """Get all user associated row pemission.

        It will include row permissions associated directly to user or by
        row permission associated with user groups that they are into.

        Args:
            auth_header (dict): = None
                AuthHeader to substitute the microservice original at
                request. If not passed, microservice object auth_header
                will be used.
            use_disk_cache (bool):
                It possible use disk cache.
            disk_cache_expire (int):
                Set a time to expire the cache. If not passed env variable
                `PUMPWOOD_COMUNICATION__AUTHORIZATION_CACHE_TIMEOUT` will
                be used with 60 seconds as default.
            return_ids (bool):
                Return only the ids of the row permissions.

        Returns:
            Return a list Row permissions associatef with user directly or
            by a user group.
        """
        url = '/rest/userprofile/actions/self_row_permissions/'
        temp_disk_cache_expire = (
            disk_cache_expire
            if disk_cache_expire is not None else
            AUTHORIZATION_CACHE_TIMEOUT)

        # Try to retrieve disk cache using authorization header to create
        # the cache hash
        request_header = self._check_auth_header(auth_header)
        hash_dict = None
        results = None
        is_on_cache = False
        if use_disk_cache:
            hash_dict = {
                'context': 'pumpwood_communication-get_user_row_permission',
                'authorization': request_header['Authorization']}
            results = default_cache.get(hash_dict=hash_dict)
            if results is not None:
                msg = "row_permission from cache url[{url}]".format(url=url)
                logger.info(msg)
                is_on_cache = True

        if results is None:
            results = self.request_post(
                url=url, auth_header=auth_header, data={})['result']

        if use_disk_cache and not is_on_cache:
            default_cache.set(
                hash_dict=hash_dict, value=results,
                expire=temp_disk_cache_expire)

        if return_ids:
            return [x['pk'] for x in results]
        else:
            return results
