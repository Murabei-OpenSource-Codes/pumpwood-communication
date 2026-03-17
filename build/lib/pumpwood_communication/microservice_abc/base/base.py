"""Module for Pumpwood Base Class.

This module contain base implementation with Pumpwood Backend information.
"""
import os
import re
import copy
import orjson
import datetime
import requests
import time
import pandas as pd
from loguru import logger
from requests import Response
from typing import Any
from urllib.parse import urljoin
from pumpwood_communication.exceptions import (
    exceptions_dict, PumpWoodJSONLoadError, PumpWoodUnauthorized,
    PumpWoodForbidden, PumpWoodOtherException)
from pumpwood_communication.serializers import pumpJsonDump
from pumpwood_communication.cache import default_cache


class PumpWoodMicroServiceBase:
    """Base class for Pumpwood MicroService.

    Enviroment variables can be used to set MicroService parameters:
    - **PUMPWOOD_COMUNICATION__DEFAULT_TIMEOUT:** Default requests timeout in
        seconds.
    - **PUMPWOOD_COMUNICATION__DEBUG:** If object will be initiated using
        debug parameter. It will have more verbosity and login at each
        request. Options 'TRUE', 'FALSE'.
    - **PUMPWOOD_COMUNICATION__VERIFY_SSL:** If requests will validate SSL
        certificate.
    """

    __base_header = {'Content-Type': 'application/json'}
    """Base header for the requests."""

    @staticmethod
    def _adjust_server_url(server_url):
        """Remove tralling / if present on server URL."""
        if server_url is None:
            return None
        if server_url[-1] != '/':
            return server_url + '/'
        else:
            return server_url

    def __init__(self, name: str = None, server_url: str = None,
                 username: str = None, password: str = None,
                 verify_ssl: bool = True, debug: bool = None,
                 default_timeout: int = None, **kwargs):
        """Create new PumpWoodMicroService object.

        Creates a new microservice object. If just name is passed, object must
        be initiate after with init() method.

        Args:
            name:
                Name of the microservice, helps when exceptions
                are raised.
            server_url:
                URL of the server that will be connected.
            username:
                Username that will be logged on.
            password:
                Variable to be converted to JSON and posted along
                with the request.
            verify_ssl:
                Set if microservice will verify SSL certificate.
            debug:
                If microservice will be used as debug mode. This will obrigate
                auth token refresh for each call.
            default_timeout:
                Default timeout for Pumpwood calls.
            **kwargs:
                Other parameters used for compatibility between versions.

        Returns:
            PumpWoodMicroService: New PumpWoodMicroService object

        Raises:
            No particular Raises.
        """
        # Create attributes to be set at init function
        self.name = None
        """Name of the microservice instance."""
        self.server_url = None
        """Pumpwood server URL."""
        self._default_timeout: int = None
        """Default timeout for Pumpwood requests."""
        self._debug: bool = None
        """Name of the microservice instance."""
        self._verify_ssl: bool = None
        """If microservice should check the certificate."""
        self._is_mfa_login: bool = None
        """Set if is MFA login."""
        self.__headers: dict = None
        """Headers to be used on the requests."""
        self.__user: dict = None
        """Information of the logged user."""
        self.__auth_header: dict = None
        """Authenticated auth header."""
        self.__token_expiry: pd.Timedelta = None
        """Expirity datetime of the authetication token."""
        self.__username: str = None
        """Username associated with microservice."""
        self.__password: str = None
        """Password associated with microservice."""
        self.init(
            name=name, server_url=server_url,
            username=username, password=password,
            verify_ssl=verify_ssl, debug=debug,
            default_timeout=default_timeout)

    def init(self, name: str = None, server_url: str = None,
             username: str = None, password: str = None,
             verify_ssl: bool = True, debug: bool = None,
             default_timeout: int = None, **kwargs):
        """Lazzy initialization of the MicroService of object.

        This function might be usefull to use the object as a singleton at
        the backends. Using this function it is possible to instanciate an
        empty object and them set the attributes latter at the systems.

        Args:
            name:
                Name of the microservice, helps when exceptions
                are raised.
            server_url:
                URL of the server that will be connected.
            username:
                Username that will be logged on.
            password:
                Variable to be converted to JSON and posted along
                with the request.
            verify_ssl:
                Set if microservice will verify SSL certificate.
            debug:
                If microservice will be used as debug mode. This will obrigate
                auth token refresh for each call.
            default_timeout:
                Default timeout for Pumpwood calls.
            **kwargs:
                Other parameters used for compatibility between versions.

        Returns:
            No return

        Raises:
            No particular Raises
        """
        self.name = name
        """Name of the microservice instance."""
        self.server_url = self._adjust_server_url(server_url)
        """Pumpwood server URL."""

        # Set parameter using arguments or enviroment variables
        if default_timeout is None:
            self._default_timeout = int(os.getenv(
                'PUMPWOOD_COMUNICATION__DEFAULT_TIMEOUT', 60))
        else:
            self._default_timeout = default_timeout

        if debug is None:
            self._debug = os.getenv(
                'PUMPWOOD_COMUNICATION__DEBUG', 'FALSE') == 'TRUE'
        else:
            self._debug = debug

        if verify_ssl is None:
            self._verify_ssl = os.getenv(
                'PUMPWOOD_COMUNICATION__VERIFY_SSL', 'TRUE') == 'TRUE'
        else:
            self._verify_ssl = verify_ssl

        self._is_mfa_login = False
        self.__headers = None
        self.__user = None
        self.__auth_header = None
        self.__token_expiry = None
        self.__username = username
        self.__password = password

    @staticmethod
    def angular_json(request_result) -> Any:
        r"""Convert text to Json removing any XSSI at the beging of JSON.

        Some backends add `)]}',\n` at the beginning of the JSON data to
        prevent injection of functions. This function remove this characters
        if present.

        Args:
            request_result:
                JSON request to be converted.

        Returns:
            No return

        Raises:
            PumpWoodJSONLoadError:
                If it is not possible to load JSON from request data.
        """
        if request_result.text == '':
            return None

        string_start = ")]}',\n"
        try:
            if request_result.text[:6] == string_start:
                return (orjson.loads(request_result.text[6:]))
            else:
                return (orjson.loads(request_result.text))
        except Exception:
            msg = "Can not decode to Json"
            raise PumpWoodJSONLoadError(
                message=msg, payload={"request_data": request_result.text})

    def time_to_expiry(self) -> pd.Timedelta:
        """Return time to token expiry.

        Args:
            No Args.

        Returns:
            Return time until token expiration.
        """
        if self.__token_expiry is None:
            return None

        now_datetime = pd.to_datetime(
            datetime.datetime.now(datetime.UTC), utc=True)
        time_to_expiry = self.__token_expiry - now_datetime
        return time_to_expiry

    def is_credential_set(self) -> bool:
        """Check if username and password are set on object.

        Args:
            No Args.

        Returns:
            True if usename and password were set during object creation or
            later with init function.
        """
        is_username_not_none = self.__username is not None
        is_password_not_none = self.__password is not None
        return is_username_not_none and is_password_not_none

    @classmethod
    def is_invalid_token_response(cls, response: Response) -> bool:
        """Check if reponse has invalid token error.

        Args:
            response:
                Request reponse to check for invalid token.

        Returns:
            Return True if response has an invalid token status.
        """
        if response.status_code == 401:
            return True
        return False

    def _login_resquest(self) -> Response:
        """Request login with object credentials.

        Args:
            No Args

        Returns (Response):
            Request object.
        """
        login_url = urljoin(
            self.server_url, 'rest/registration/login/')

        # Make a retry loop for authentication
        login_result = None
        for i in range(5):
            login_result = requests.post(
                login_url, json={
                    'username': self.__username,
                    'password': self.__password},
                verify=self._verify_ssl, timeout=self._default_timeout)
            if login_result.ok:
                try:
                    login_data = self.angular_json(login_result)
                    return login_data
                except Exception: # NOQA
                    pass

            # Handle Unauthorized responses
            elif self.is_invalid_token_response(login_result):
                error_data = self.angular_json(login_result)
                raise PumpWoodUnauthorized(
                    message="Login is not possible",
                    payload=error_data)

            # Handle Forbidden responses
            elif login_result.status_code == 403:
                error_data = self.angular_json(login_result)
                raise PumpWoodForbidden(
                    message="Login resquest is forbidden",
                    payload=error_data)
            time.sleep(0.2)

        # If response is not returned then something is not ok
        error_data = self.angular_json(login_result)
        raise PumpWoodOtherException(
            message="Login not possible, server is not responding correctly",
            payload=error_data)

    def confirm_mfa_code(self, mfa_login_data: dict) -> dict:
        """Ask user to confirm MFA code to login.

        Open an input interface at terminal for user to validate MFA token.

        Args:
            mfa_login_data:
                Result from login request with 'mfa_token'
                as key.

        Returns:
            Return login returned with MFA confimation.

        Raise:
            Raise error if reponse is not valid using error_handler.
        """
        code = input("## Please enter MFA code: ")
        url = urljoin(
            self.server_url, 'rest/registration/mfa-validate-code/')
        mfa_response = requests.post(url, headers={
            "X-PUMPWOOD-MFA-Autorization": mfa_login_data['mfa_token']},
            json={"mfa_code": code}, timeout=self._default_timeout)
        self.error_handler(mfa_response)

        # Set _is_mfa_login true to indicate that login required MFA
        self._is_mfa_login = True
        return self.angular_json(mfa_response)

    def login(self, force_refresh: bool = False) -> None:
        """Log microservice in using username and password provided.

        Args:
            force_refresh (bool):
                Force token refresh despise still valid
                according to self.__token_expiry.

        Returns:
            No return

        Raises:
            Exception:
                If login response has status diferent from 200.
        """
        if not self.is_credential_set():
            raise PumpWoodUnauthorized(
                message="Microservice username or/and password not set")

        # Check if expiry time is 1h from now
        refresh_expiry = False
        if self.__token_expiry is None:
            refresh_expiry = True
        else:
            time_to_expiry = self.time_to_expiry()
            if time_to_expiry < datetime.timedelta(hours=1):
                refresh_expiry = True

        # When if debug always refresh token
        if refresh_expiry or force_refresh or self._debug:
            login_data = self._login_resquest()
            if 'mfa_token' in login_data.keys():
                login_data = self.confirm_mfa_code(
                    mfa_login_data=login_data)

            self.set_auth_header(
                auth_token='Token ' + login_data['token'],
                token_expiry=pd.to_datetime(login_data['expiry']),
                user=login_data["user"])
        else:
            # Token is not expired or envicted, them keep same token
            return None

    def logout(self, auth_header: dict = None) -> bool:
        """Logout token.

        Args:
            auth_header:
                Authentication header.

        Returns:
            True if logout was ok.
        """
        resp = self.request_post(
            url='rest/registration/logout/',
            data={}, auth_header=auth_header)
        # Set expiry to None to envict the token
        self.__token_expiry = None
        return resp is None

    def logout_all(self, auth_header: dict = None) -> bool:
        """Logout all tokens from user.

        Args:
            auth_header (dict):
                Authentication header.

        Returns:
            True if logout all was ok.
        """
        resp = self.request_post(
            url='rest/registration/logoutall/',
            data={}, auth_header=auth_header)
        # Set expiry to None to envict the token
        self.__token_expiry = None
        return resp is None

    def get_auth_header(self) -> dict:
        """Retrieve auth_header and token_expiry from object.

        Args:
            No Args.

        Returns:
            Return authorization header and token_expiry datetime from object.
        """
        # Copy the dictonary to avoid updating the original one
        return copy.deepcopy({
            "auth_header": self.__auth_header,
            "token_expiry": self.__token_expiry})

    def set_auth_header(self, auth_token: str,
                        token_expiry: pd.Timestamp,
                        user: dict = None) -> dict:
        """Retrieve auth_header and token_expiry from object.

        Args:
            auth_token (str):
                Auth token that will be set for authentication.
            token_expiry (pd.Timestamp):
                Token expiry time.
            user (dict):
                User information to be set on authetication.

        Returns:
            Return authorization header and token_expiry datetime from object.
        """
        # Copy the dictonary to avoid updating the original one
        self.__auth_header = {
            'Authorization': auth_token}
        self.__token_expiry = token_expiry
        self.__user = user
        return True

    def _check_auth_header(self, auth_header: dict,
                           multipart: bool = False) -> dict:
        """Check if auth_header is set or auth_header if provided.

        Args:
            auth_header (dict):
                AuthHeader to substitute the microservice original
                at the request (user impersonation).
            multipart (dict):
                Set if call should be made as a multipart instead of JSON.

        Returns (dict):
            Return a header dict to be used in requests.

        Raises:
            PumpWoodUnauthorized:
                If microservice is not logged and a auth_header method
                argument is not provided.
            PumpWoodUnauthorized:
                If microservice is logged and a auth_header method argument
                is provided.
        """
        if auth_header is None:
            # Login will refresh token if it is 1h to expire, it will also
            # check if credentials are set.
            self.login()
            auth_header_data = self.get_auth_header()
            auth_header = auth_header_data['auth_header']
            if multipart:
                return auth_header
            else:
                return self.__base_header | auth_header
        else:
            if self.is_credential_set():
                msg = (
                    'Microservice [{object_name}] with credentials and '
                    'auth_header was provided')
                raise PumpWoodUnauthorized(
                    message=msg, payload={'object_name': self.name})

            # Set base header as JSON since unserialization is done using
            # Pumpwood Communication serialization function
            temp__auth_header = auth_header.copy()
            if multipart:
                return temp__auth_header
            else:
                return self.__base_header | temp__auth_header

    @classmethod
    def error_handler(cls, response):
        """Handle request error.

        Check if is a Json and propagate the error with
        same type if possible. If not Json raises the content.

        Args:
            response:
                response to be handled, it is a PumpWoodException
                return it will raise the same exception at microservice
                object.

        Returns:
            No return.

        Raises:
            PumpWoodOtherException:
                If content-type is not application/json.
            PumpWoodOtherException:
                If content-type is application/json, but type not
                present or not recognisable at `exceptions.exceptions_dict`.
            Other PumpWoodException sub-types:
                If content-type is application/json if type is present and
                recognisable.

        Example:
            No example
        """
        if not response.ok:
            utcnow = datetime.datetime.now(datetime.UTC)
            response_content_type = response.headers['content-type']

            # Request information
            url = response.url
            method = response.request.method
            if 'application/json' not in response_content_type.lower():
                # Raise the exception as first in exception deep.
                exception_dict = [{
                    "exception_url": url,
                    "exception_method": method,
                    "exception_utcnow": utcnow.isoformat(),
                    "exception_deep": 1}]
                raise PumpWoodOtherException(
                    message=response.text, payload={
                        "!exception_stack!": exception_dict})

            # Build error stack
            response_dict = cls.angular_json(response)

            # Removing previous error stack
            payload = copy.deepcopy(
                response_dict.get("payload", {}))
            exception_stack = copy.deepcopy(
                payload.pop("!exception_stack!", []))

            exception_deep = len(exception_stack)
            exception_dict = {
                "exception_url": url,
                "exception_method": method,
                "exception_utcnow": utcnow.isoformat(),
                "exception_deep": exception_deep + 1
            }
            exception_stack.insert(0, exception_dict)
            payload["!exception_stack!"] = exception_stack

            ###################
            # Propagate error #
            # get exception using 'type' key at response data and get the
            # exception from exceptions_dict at exceptions
            exception_message = response_dict.get("message", "")
            exception_type = response_dict.get("type", None)
            TempPumpwoodException = exceptions_dict.get(exception_type)
            if TempPumpwoodException is not None:
                raise TempPumpwoodException(
                    message=exception_message,
                    status_code=response.status_code,
                    payload=payload)
            else:
                # If token is invalid is at response, return a
                # PumpWoodUnauthorized error
                is_invalid_token = cls.is_invalid_token_response(response)
                response_dict["!exception_stack!"] = exception_stack
                if is_invalid_token:
                    raise PumpWoodUnauthorized(
                        message="Invalid token", payload=payload)
                else:
                    # If the error is not mapped return a
                    # PumpWoodOtherException limiting the message size to 1k
                    # characters
                    raise PumpWoodOtherException(
                        message="Not mapped exception JSON",
                        payload=response_dict)

    def _request_post_json(self, post_url: str, data: any,
                           auth_header: dict = None,
                           parameters: None | dict = None) -> any:
        """Make a POST a request to url with data as JSON payload.

        Args:
            post_url:
                URL to make the request, already with server url.
            data:
                Data to be used as Json payload.
            parameters:
                URL parameters.
            auth_header:
                AuthHeader to substitute the microservice original
                at the request (user impersonation).

        Returns:
            Return the post response data.

        Raises:
            PumpWoodException sub-types:
                Response is passed to error_handler.
        """
        parameters = {} if parameters is None else parameters

        response = None
        request_header = self._check_auth_header(auth_header=auth_header)
        dumped_data = pumpJsonDump(data)
        response = requests.post(
            url=post_url, data=dumped_data,
            params=parameters, verify=self._verify_ssl,
            headers=request_header, timeout=self._default_timeout)

        # Retry request if token is not valid forcing token renew
        retry_with_login = (
            self.is_invalid_token_response(response) and
            auth_header is None)
        if not retry_with_login:
            return response
        else:
            # Force token refresh if Unauthorized
            time.sleep(0.5)
            self.login(force_refresh=True)
            request_header = self._check_auth_header(auth_header=auth_header)
            return requests.post(
                url=post_url, data=dumped_data,
                params=parameters, verify=self._verify_ssl,
                headers=request_header, timeout=self._default_timeout)

    def _request_post_multi(self, post_url: str, data: any, files: list = None,
                            auth_header: dict = None,
                            parameters: None | dict = None) -> any:
        """Make a POST a request to url with data as multipart payload.

        Args:
            post_url:
                URL to make the request, already with server url.
            data:
                Data to be used as Json payload.
            files:
                A dictonary with file data, files will be set on field
                corresponding.to dictonary key.
                `{'file1': open('file1', 'rb'), {'file2': open('file2', 'rb')}`
            parameters:
                URL parameters.
            auth_header:
                AuthHeader to substitute the microservice original
                at the request (user impersonation).

        Returns:
            Return the post response data.

        Raises:
            PumpWoodException sub-types:
                Response is passed to error_handler.
        """
        parameters = {} if parameters is None else parameters

        # Request with files are done using multipart serializing all fields
        # as JSON
        request_header = self._check_auth_header(
            auth_header=auth_header, multipart=True)
        temp_data = {'__json__': pumpJsonDump(data)}

        response = requests.post(
            url=post_url, data=temp_data, files=files, params=parameters,
            verify=self._verify_ssl, headers=request_header,
            timeout=self._default_timeout)
        retry_with_login = (
            self.is_invalid_token_response(response) and
            auth_header is None)
        if not retry_with_login:
            return response
        else:
            # Force token refresh if Unauthorized
            time.sleep(0.5)
            self.login(force_refresh=True)
            request_header = self._check_auth_header(
                auth_header=auth_header, multipart=True)
            return requests.post(
                url=post_url, data=temp_data, files=files,
                params=parameters, verify=self._verify_ssl,
                headers=request_header, timeout=self._default_timeout)

    @classmethod
    def _treat_response_for_file(cls, response: Response) -> dict:
        """Return if response contain a file.

        Args:
            response (Response):
                Response to be checked for a file content.

        Returns (bool):
            Returns if reponse has a file.
        """
        headers = response.headers
        content_disposition = headers.get('content-disposition')
        if content_disposition is None:
            return cls.angular_json(response)
        else:
            fname = re.findall("filename=(.+)", content_disposition)[0]
            return {
                "__file__": True,
                "content": response.content,
                "content-type": response.headers['content-type'],
                "filename": fname}

    @classmethod
    def _dump_query_parameters(cls, parameters: dict) -> dict:
        """Dump query parameters to javascript compatibility.

        Args:
            parameters (dict):
                Parameters to be parsed to JSON.

        Returns:
            pass
        """
        # If parameters are not none convert them to json before
        # sending information on query string, 'True' is 'true' on javascript
        # for example
        if parameters is not None:
            temp_parameters = copy.deepcopy(parameters)
            for key in temp_parameters.keys():
                # Do not convert str to json, it put extra "" araound string
                if type(temp_parameters[key]) is not str:
                    temp_parameters[key] = pumpJsonDump(parameters[key])
            return temp_parameters
        else:
            return None

    def request_post(self, url: str, data: any, files: list = None,
                     auth_header: dict = None,
                     parameters: None | dict = {}) -> any:
        """Make a POST a request to url with data as multipart/json payload.

        Args:
            url:
                URL to make the request, already with server url.
            data:
                Data to be used as Json payload.
            files:
                A dictonary with file data, files will be set on field
                corresponding.to dictonary key.
                `{'file1': open('file1', 'rb'), {'file2': open('file2', 'rb')}`
            parameters:
                URL parameters.
            auth_header:
                AuthHeader to substitute the microservice original
                at the request (user impersonation).

        Returns:
            Return the post response data.

        Raises:
            PumpWoodException sub-types:
                Response is passed to error_handler.
        """
        parameters = {} if parameters is None else parameters

        post_url = urljoin(self.server_url, url)
        dumped_parameters = self._dump_query_parameters(parameters=parameters)
        response = None
        if files is None:
            response = self._request_post_json(
                post_url=post_url, data=data, auth_header=auth_header,
                parameters=dumped_parameters)
        else:
            response = self._request_post_multi(
                post_url=post_url, data=data, files=files,
                auth_header=auth_header, parameters=dumped_parameters)

        # Handle errors and re-raise if Pumpwood Exceptions
        self.error_handler(response)
        return self._treat_response_for_file(response=response)

    def request_get(self, url: str, parameters: None | dict = None,
                    auth_header: dict = None,
                    use_disk_cache: bool = False,
                    disk_cache_expire: int = None,
                    disk_cache_tag_dict: dict = None) -> Any:
        """Make a GET a request to url with data as JSON payload.

        Add the auth_header acording to login information and refresh token
        if auth_header=None and object token is expired.

        Args:
            url (str):
                URL to make the request.
            parameters (dict):
                URL parameters to make the request.
            auth_header (dict):
                Auth header to substitute the microservice original
                at the request (user impersonation).
            use_disk_cache (bool):
                If set true, get request will use local cache to reduce
                the requests to the backend.
            disk_cache_expire (int):
                Time in seconds to expire the cache, it None it will
                use de default set be PumpwoodCache.
            disk_cache_tag_dict (dict):
                Dictionary to be used as a tag on get request.

        Returns:
            Return the post reponse data.

        Raises:
            PumpWoodException sub-types:
                Raise exception if reponse is not 2XX and if 'type' key on
                JSON payload if found at exceptions_dict. Use the same
                exception, message and payload.
            PumpWoodOtherException:
                If exception type is not found or return is not a json.
        """
        parameters = {} if parameters is None else parameters

        request_header = self._check_auth_header(auth_header)
        # If is set to use diskcache, it will create a hash cash using
        # the query paramerers, url and user access token. The
        # hash will be used as index, not exposing the token at cache
        # database
        hash_dict = None
        if use_disk_cache:
            hash_dict = {
                'context': 'pumpwood_communication-request_get',
                'authorization': request_header['Authorization'],
                'parameters': parameters,
                'url': url}
            cache_results = default_cache.get(hash_dict=hash_dict)
            if cache_results is not None:
                msg = "get from cache url[{url}]".format(url=url)
                logger.info(msg)
                return cache_results

        dumped_parameters = self._dump_query_parameters(parameters=parameters)
        get_url = urljoin(self.server_url, url)
        response = requests.get(
            get_url, verify=self._verify_ssl, headers=request_header,
            params=dumped_parameters, timeout=self._default_timeout)

        # If token is expired, refresh it
        retry_with_login = (
            self.is_invalid_token_response(response) and
            auth_header is None)
        if retry_with_login:
            time.sleep(0.5)
            self.login(force_refresh=True)
            request_header = self._check_auth_header(auth_header=auth_header)
            response = requests.get(
                get_url, verify=self._verify_ssl, headers=request_header,
                params=dumped_parameters, timeout=self._default_timeout)

        # Re-raise Pumpwood exceptions
        self.error_handler(response=response)
        results = self._treat_response_for_file(response=response)

        # If is set to use cache for this calls, set the local cache
        if use_disk_cache and not results.get('__file__', False):
            default_cache.set(
                hash_dict=hash_dict, value=results,
                expire=disk_cache_expire,
                tag_dict=disk_cache_tag_dict)
        return results

    def request_delete(self, url, parameters: dict = None,
                       auth_header: dict = None):
        """Make a DELETE a request to url with data as Json payload.

        Args:
            url:
                Url to make the request.
            parameters:
                Dictionary with Urls parameters.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            Return the delete reponse payload.

        Raises:
            PumpWoodException sub-types:
                Raise exception if reponse is not 2XX and if 'type' key on
                JSON payload if found at exceptions_dict. Use the same
                exception, message and payload.
            PumpWoodOtherException:
                If exception type is not found or return is not a json.
        """
        request_header = self._check_auth_header(auth_header)
        dumped_parameters = self._dump_query_parameters(parameters=parameters)

        post_url = self.server_url + url
        response = requests.delete(
            post_url, verify=self._verify_ssl, headers=request_header,
            params=dumped_parameters, timeout=self._default_timeout)

        # Retry request if token is not valid forcing token renew
        retry_with_login = (
            self.is_invalid_token_response(response) and
            auth_header is None)
        if retry_with_login:
            time.sleep(0.5)
            self.login(force_refresh=True)
            request_header = self._check_auth_header(auth_header=auth_header)
            response = requests.delete(
                post_url, verify=self._verify_ssl, headers=request_header,
                params=dumped_parameters, timeout=self._default_timeout)

        # Re-raise Pumpwood Exceptions
        self.error_handler(response)
        return self.angular_json(response)
