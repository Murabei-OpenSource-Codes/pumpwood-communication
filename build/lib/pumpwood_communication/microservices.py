"""Module microservice.py.

Class and functions to help communication between PumpWood like systems.
"""
import re
import os
import io
import sys
import logging
import simplejson as json
import gzip
import requests
import pandas as pd
import geopandas as geopd
import numpy as np
import datetime
import copy
from urllib.parse import urljoin
from shapely import geometry
from typing import Union, List, Any, Dict
from multiprocessing import Pool
from pandas import ExcelWriter
from copy import deepcopy
from pumpwood_communication.exceptions import (
    exceptions_dict, PumpWoodException, PumpWoodUnauthorized,
    PumpWoodOtherException, PumpWoodQueryException,
    PumpWoodNotImplementedError)
from pumpwood_communication.serializers import (
    pumpJsonDump, CompositePkBase64Converter)
from pumpwood_communication.misc import unpack_dict_columns


# Importing abstract classes for Micro Service
from pumpwood_communication.microservice_abc.simple import (
    ABCSimpleBatchMicroservice, ABCPermissionMicroservice,
    ABCSimpleRetriveMicroservice, ABCSimpleDeleteMicroservice,
    ABCSimpleSaveMicroservice)


# Creating logger for Micro Service calls
_Log_Format = "%(levelname)s %(asctime)s - %(message)s"
logging.basicConfig()
logging.basicConfig(stream=sys.stdout, format=_Log_Format)
_microservice_logger = logging.getLogger('pumpwood_comunication')
_microservice_logger.setLevel(logging.INFO)


def break_in_chunks(df_to_break: pd.DataFrame,
                    chunksize: int = 1000) -> List[pd.DataFrame]:
    """Break a dataframe in chunks of chunksize.

    Args:
        df_to_break: Dataframe to be break in chunks of `chunksize` size.
        chunksize: Length of each chuck of the breaks of `df_to_break`.

    Returns:
        Return a list dataframes with lenght chunksize of data from
        `df_to_break`.
    """
    to_return = list()
    for g, df in df_to_break.groupby(np.arange(len(df_to_break)) // chunksize):
        to_return.append(df)
    return to_return


class PumpWoodMicroService(ABCPermissionMicroservice,
                           ABCSimpleBatchMicroservice,
                           ABCSimpleRetriveMicroservice,
                           ABCSimpleDeleteMicroservice,
                           ABCSimpleSaveMicroservice):
    """Class to define an inter-pumpwood MicroService.

    Create an object ot help communication with Pumpwood based backends. It
    manage login and token refresh if necessary.

    It also implements parallel functions that split requests in parallel
    process to reduce processing time.
    """

    name: str
    """Name of the MicroService object, can be used for debug proposes."""
    server_url: str
    """URL of the Pumpwood server."""
    verify_ssl: bool
    """If SSL certificates will be checked on HTTPs requests."""
    debug: bool
    """
    If microservice service is set as debug, if debug=TRUE all request will
    refresh authorization token.
    """

    @staticmethod
    def _ajust_server_url(server_url):
        if server_url is None:
            return None
        if server_url[-1] != '/':
            return server_url + '/'
        else:
            return server_url

    def __init__(self, name: str = None, server_url: str = None,
                 username: str = None, password: str = None,
                 verify_ssl: bool = True, debug: bool = None,
                 default_timeout: int = 60, **kwargs,):
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
        self.name = name
        self.__headers = None
        self.__user = None
        self.__username = username
        self.__password = password
        self.server_url = self._ajust_server_url(server_url)
        self.verify_ssl = verify_ssl
        self.__base_header = {'Content-Type': 'application/json'}
        self.__auth_header = None
        self.__token_expiry = None
        self.debug = debug
        self._is_mfa_login = False
        self.default_timeout = default_timeout

    def init(self, name: str = None, server_url: str = None,
             username: str = None, password: str = None,
             verify_ssl: bool = True, debug: bool = None,
             default_timeout: int = 300, **kwargs,):
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
        self.__headers = None
        self.__username = username
        self.__password = password
        self.server_url = self._ajust_server_url(server_url)
        self.verify_ssl = verify_ssl
        self.default_timeout = default_timeout
        self.debug = debug

    @staticmethod
    def angular_json(request_result):
        r"""Convert text to Json removing any XSSI at the beging of JSON.

        Some backends add `)]}',\n` at the beginning of the JSON data to
        prevent injection of functions. This function remove this characters
        if present.

        Args:
            request_result:
                JSON Request to be converted

        Returns:
            No return

        Raises:
            No particular Raises
        """
        if request_result.text == '':
            return None

        string_start = ")]}',\n"
        try:
            if request_result.text[:6] == string_start:
                return (json.loads(request_result.text[6:]))
            else:
                return (json.loads(request_result.text))
        except Exception:
            return {"error": "Can not decode to Json",
                    'msg': request_result.text}

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
        return not (self.__username is None or self.__password is None)

    def login(self, force_refresh: bool = False) -> None:
        """Log microservice in using username and password provided.

        Args:
            force_refresh (bool):
                Force token refresh despise still valid
                according to self.__token_expiry.

        Returns:
            No return

        Raises:
            Exception: If login response has status diferent from 200.
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
        is_debug = None
        if self.debug is None:
            is_debug = os.getenv(
                "PUMPWOOD_COMUNICATION__DEBUG", "FALSE") == "TRUE"
        else:
            is_debug = self.debug

        if refresh_expiry or force_refresh or is_debug:
            login_url = urljoin(
                self.server_url, 'rest/registration/login/')
            login_result = requests.post(
                login_url, json={
                    'username': self.__username,
                    'password': self.__password},
                verify=self.verify_ssl, timeout=self.default_timeout)

            login_data = {}
            try:
                login_data = PumpWoodMicroService.angular_json(login_result)
                login_result.raise_for_status()
            except Exception as e:
                raise PumpWoodUnauthorized(
                    message="Login not possible.\nError: " + str(e),
                    payload=login_data)

            if 'mfa_token' in login_data.keys():
                login_data = self.confirm_mfa_code(mfa_login_data=login_data)

            self.__auth_header = {
                'Authorization': 'Token ' + login_data['token']}
            self.__user = login_data["user"]
            self.__token_expiry = pd.to_datetime(login_data['expiry'])

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
            json={"mfa_code": code}, timeout=self.default_timeout)
        self.error_handler(mfa_response)

        # Set _is_mfa_login true to indicate that login required MFA
        self._is_mfa_login = True
        return PumpWoodMicroService.angular_json(mfa_response)

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
        return resp is None

    def set_auth_header(self, auth_header: dict,
                        token_expiry: pd.Timestamp) -> None:
        """Set auth_header and token_expiry date.

        Args:
            auth_header:
                Authentication header to be set.
            token_expiry:
                Token expiry datetime to be set.

        Returns:
            No return.
        """
        self.__auth_header = auth_header
        self.__token_expiry = pd.to_datetime(token_expiry, utc=True)

    def get_auth_header(self) -> dict:
        """Retrieve auth_header and token_expiry from object.

        Args:
            No Args.

        Returns:
            Return authorization header and token_expiry datetime from object.
        """
        return {
            "auth_header": self.__auth_header,
            "token_expiry": self.__token_expiry}

    def _check__auth_header(self, auth_header, multipart: bool = False):
        """Check if auth_header is set or auth_header if provided.

        Args:
            auth_header:
                AuthHeader to substitute the microservice original
                at the request (user impersonation).
            multipart:
                Set if call should be made as a multipart instead of JSON.

        Returns:
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
            temp__auth_header = self.__auth_header.copy()
            if multipart:
                return temp__auth_header
            else:
                temp__auth_header.update(self.__base_header)
                return temp__auth_header
        else:
            if self.is_credential_set():
                msg_tmp = (
                    'MicroService {name} already looged and '
                    'auth_header was provided')
                raise PumpWoodUnauthorized(
                    msg_tmp.format(name=self.name))

            # Set base header as JSON since unserialization is done using
            # Pumpwood Communication serialization funciton
            temp__auth_header = auth_header.copy()
            if multipart:
                return temp__auth_header
            else:
                temp__auth_header.update(self.__base_header)
                return temp__auth_header

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
            response_dict = PumpWoodMicroService.angular_json(response)

            # Removing previous error stack
            payload = deepcopy(response_dict.get("payload", {}))
            exception_stack = deepcopy(payload.pop("!exception_stack!", []))

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
            TempPumpwoodException = exceptions_dict.get(exception_type) # NOQA
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
                        message="Invalid token.",
                        payload=response.json())
                else:
                    # If the error is not mapped return a
                    # PumpWoodOtherException limiting the message size to 1k
                    # characters
                    raise PumpWoodOtherException(
                        message="Not mapped exception JSON",
                        payload=response_dict)

    @classmethod
    def is_invalid_token_response(cls,
                                  response: requests.models.Response) -> bool:
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

    def request_post(self, url: str, data: any, files: list = None,
                     auth_header: dict = None, parameters: dict = {}) -> any:
        """Make a POST a request to url with data as JSON payload.

        Args:
            url:
                URL to make the request.
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
        # If parameters are not none convert them to JSON before
        # sending information on query string, 'True' is 'true' on Javascript
        # for exemple
        if parameters is not None:
            parameters = copy.deepcopy(parameters)
            for key in parameters.keys():
                # Do not convert str to json, it put extra "" araound string
                if type(parameters[key]) is not str:
                    parameters[key] = pumpJsonDump(parameters[key])

        response = None
        if files is None:
            request_header = self._check__auth_header(auth_header=auth_header)
            post_url = urljoin(self.server_url, url)
            response = requests.post(
                url=post_url, data=pumpJsonDump(data),
                params=parameters, verify=self.verify_ssl,
                headers=request_header, timeout=self.default_timeout)

            # Retry request if token is not valid forcing token renew
            retry_with_login = (
                self.is_invalid_token_response(response) and
                auth_header is None)
            if retry_with_login:
                self.login(force_refresh=True)
                request_header = self._check__auth_header(
                    auth_header=auth_header)
                response = requests.post(
                    url=post_url, data=pumpJsonDump(data),
                    params=parameters, verify=self.verify_ssl,
                    headers=request_header, timeout=self.default_timeout)

        # Request with files are done using multipart serializing all fields
        # as JSON
        else:
            request_header = self._check__auth_header(
                auth_header=auth_header, multipart=True)
            post_url = urljoin(self.server_url, url)
            temp_data = {'__json__': pumpJsonDump(data)}
            response = requests.post(
                url=post_url, data=temp_data, files=files, params=parameters,
                verify=self.verify_ssl, headers=request_header,
                timeout=self.default_timeout)

            retry_with_login = (
                self.is_invalid_token_response(response) and
                auth_header is None)
            if retry_with_login:
                self.login(force_refresh=True)
                request_header = self._check__auth_header(
                    auth_header=auth_header)
                response = requests.post(
                    url=post_url, data=temp_data, files=files,
                    params=parameters, verify=self.verify_ssl,
                    headers=request_header, timeout=self.default_timeout)

        # Handle errors and re-raise if Pumpwood Exceptions
        self.error_handler(response)

        # Check if response is a file
        headers = response.headers
        content_disposition = headers.get('content-disposition')
        if content_disposition is not None:
            file_name = re.findall('filename=(.+)', content_disposition)
            if len(file_name) == 1:
                return {
                    "__file_name__": file_name[0],
                    "__content__": response.content}
            else:
                return {
                    "__file_name__": None,
                    "__content__": response.content}
        else:
            return PumpWoodMicroService.angular_json(response)

    def request_get(self, url, parameters: dict = {},
                    auth_header: dict = None):
        """Make a GET a request to url with data as JSON payload.

        Add the auth_header acording to login information and refresh token
        if auth_header=None and object token is expired.

        Args:
            url:
                URL to make the request.
            parameters:
                URL parameters to make the request.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

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
        request_header = self._check__auth_header(auth_header)

        # If parameters are not none convert them to json before
        # sending information on query string, 'True' is 'true' on javascript
        # for example
        if parameters is not None:
            parameters = copy.deepcopy(parameters)
            for key in parameters.keys():
                # Do not convert str to json, it put extra "" araound string
                if type(parameters[key]) is not str:
                    parameters[key] = pumpJsonDump(parameters[key])

        get_url = urljoin(self.server_url, url)
        response = requests.get(
            get_url, verify=self.verify_ssl, headers=request_header,
            params=parameters, timeout=self.default_timeout)

        retry_with_login = (
            self.is_invalid_token_response(response) and
            auth_header is None)
        if retry_with_login:
            self.login(force_refresh=True)
            request_header = self._check__auth_header(auth_header=auth_header)
            response = requests.get(
                get_url, verify=self.verify_ssl, headers=request_header,
                params=parameters, timeout=self.default_timeout)

        # Re-raise Pumpwood exceptions
        self.error_handler(response=response)

        json_types = ["application/json", "application/json; charset=utf-8"]
        if response.headers['content-type'] in json_types:
            return PumpWoodMicroService.angular_json(response)
        else:
            d = response.headers['content-disposition']
            fname = re.findall("filename=(.+)", d)[0]

            return {
                "content": response.content,
                "content-type": response.headers['content-type'],
                "filename": fname}

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
        request_header = self._check__auth_header(auth_header)

        post_url = self.server_url + url
        response = requests.delete(
            post_url, verify=self.verify_ssl, headers=request_header,
            params=parameters, timeout=self.default_timeout)

        # Retry request if token is not valid forcing token renew
        retry_with_login = (
            self.is_invalid_token_response(response) and
            auth_header is None)
        if retry_with_login:
            self.login(force_refresh=True)
            request_header = self._check__auth_header(auth_header=auth_header)
            response = requests.delete(
                post_url, verify=self.verify_ssl, headers=request_header,
                params=parameters, timeout=self.default_timeout)

        # Re-raise Pumpwood Exceptions
        self.error_handler(response)
        return PumpWoodMicroService.angular_json(response)

    def list_registered_routes(self, auth_header: dict = None):
        """List routes that have been registed at Kong."""
        list_url = 'rest/pumpwood/routes/'
        routes = self.request_get(
            url=list_url, auth_header=auth_header)
        for key, item in routes.items():
            item.sort()
        return routes

    def is_microservice_registered(self, microservice: str,
                                   auth_header: dict = None) -> bool:
        """Check if a microservice (kong service) is registered at Kong.

        Args:
            microservice (str):
                Service associated with microservice registered on
                Pumpwood Kong.
            auth_header (dict):
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            Return true if microservice is registered.
        """
        routes = self.list_registered_routes(auth_header=auth_header)
        return microservice in routes.keys()

    def list_registered_endpoints(self, auth_header: dict = None,
                                  availability: str = 'front_avaiable'
                                  ) -> list:
        """List all routes and services that have been registed at Kong.

        It is possible to restrict the return to end-points that should be
        avaiable at the frontend. Using this feature it is possibel to 'hide'
        services from GUI keeping them avaiable for programatic calls.

        Args:
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            availability:
                Set the availability that is associated with the service.
                So far it is implemented 'front_avaiable' and 'all'.

        Returns:
            Return a list of serialized services objects containing the
            routes associated with at `route_set`.

            Service and routes have `notes__verbose` and `description__verbose`
            that are  the repective strings associated with note and
            description but translated using Pumpwood's I8s,

        Raises:
            PumpWoodWrongParameters:
                Raise PumpWoodWrongParameters if availability passed as
                paraemter is not implemented.
        """
        list_url = 'rest/pumpwood/endpoints/'
        routes = self.request_get(
            url=list_url, parameters={'availability': availability},
            auth_header=auth_header)
        return routes

    def dummy_call(self, payload: dict = None,
                   auth_header: dict = None) -> dict:
        """Return a dummy call to ensure headers and payload reaching app.

        The request just bounce on the server and return the headers and
        payload that reached the application. It is usefull for probing
        proxy servers, API gateways and other security and load balance
        tools.

        Args:
            payload:
                Payload to be returned by the dummy call end-point.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            Return a dictonary with:
            - **full_path**: Full path of the request.
            - **method**: Method used at the call
            - **headers**: Headers at the request.
            - **data**: Post payload sent at the request.
        """
        list_url = 'rest/pumpwood/dummy-call/'
        if payload is None:
            return self.request_get(
                url=list_url, auth_header=auth_header)
        else:
            return self.request_post(
                url=list_url, data=payload,
                auth_header=auth_header)

    def dummy_raise(self, exception_class: str, exception_deep: int,
                    payload: dict = {}, auth_header: dict = None) -> None:
        """Raise an Pumpwood error with the payload.

        This and point raises an Arbitrary PumpWoodException error, it can be
        used for debuging error treatment.

        Args:
            exception_class:
                Class of the exception to be raised.
            exception_deep:
                Deep of the exception in microservice calls. This arg will
                make error recusive, calling the end-point it self for
                `exception_deep` time before raising the error.
            payload:
                Payload that will be returned with error.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            Should not return any results, all possible call should result
            in raising the correspondent error.

        Raises:
            Should raise the correspondent error passed on exception_class
            arg, with payload.
        """
        url = 'rest/pumpwood/dummy-raise/'
        payload["exception_class"] = exception_class
        payload["exception_deep"] = exception_deep
        self.request_post(url=url, data=payload, auth_header=auth_header)

    def get_pks_from_unique_field(self, model_class: str, field: str,
                                  values: List[Any]) -> pd.DataFrame:
        """Get pk using unique fields values.

        Use unique field values to retrieve pk of the objects. This end-point
        is usefull for retrieving pks of the objects associated with unique
        fields such as `description` (unique on most model of pumpwood).

        ```python
        # Using description to fetch pks from objects
        data: pd.DataFrame = [data with unique description but without pk]
        data['attribute_id'] = microservice.get_pks_from_unique_field(
            model_class="DescriptionAttribute",
            field="description", values=data['attribute'])['pk']

        # Using a dimension key to fetch pk of the objects, dimension
        # key must be unique
        data['georea_id'] = microservice.get_pks_from_unique_field(
            model_class="DescriptionGeoarea", field="dimension->city",
            values=data['city'])['pk']
        ```

        Args:
            model_class:
                Model class of the objects.
            field:
                Unique field to fetch pk. It is possible to use dimension keys
                as unique field, for that use `dimension->[key]` notation.
            values:
                List of the unique fields used to fetch primary keys.

        Return:
            Return a dataframe in same order as values with columns:
            - **pk**: Correspondent primary key of the unique value.
            - **[field]**: Column with same name of field argument,
                correspondent to pk.

        Raises:
            PumpWoodQueryException:
                Raises if field is not found on the model and it is note
                associated with a dimension tag.
            PumpWoodQueryException:
                Raises if `field` does not have a unique restriction on
                database. Dimension keys does not check for uniqueness on
                database, be carefull not to duplicate the lines.
        """
        is_dimension_tag = 'dimensions->' in field
        if not is_dimension_tag:
            fill_options = self.fill_options(model_class=model_class)
            field_details = fill_options.get(field)
            if field_details is None:
                msg = (
                    "Field is not a dimension tag and not found on model "
                    "fields. Field [{field}]")
                raise PumpWoodQueryException(
                    message=msg, payload={"field": field})

            is_unique_field = field_details.get("unique", False)
            if not is_unique_field:
                msg = "Field [{}] to get pk from is not unique"
                raise PumpWoodQueryException(
                    message=msg, payload={"field": field})

        filter_dict = {field + "__in": list(set(values))}
        pk_map = None
        if not is_dimension_tag:
            list_results = pd.DataFrame(self.list_without_pag(
                model_class=model_class, filter_dict=filter_dict,
                fields=["pk", field]), columns=["pk", field])
            pk_map = list_results.set_index(field)["pk"]

        # If is dimension tag, fetch dimension and unpack it
        else:
            dimension_tag = field.split("->")[1]
            list_results = pd.DataFrame(self.list_without_pag(
                model_class=model_class, filter_dict=filter_dict,
                fields=["pk", "dimensions"]))
            pk_map = {}
            if len(list_results) != 0:
                pk_map = list_results\
                    .pipe(unpack_dict_columns, columns=["dimensions"])\
                    .set_index(dimension_tag)["pk"]

        values_series = pd.Series(values)
        return pd.DataFrame({
            "pk": values_series.map(pk_map).to_numpy(),
            field: values_series
        })

    @staticmethod
    def _build_list_url(model_class: str):
        return "rest/%s/list/" % (model_class.lower(),)

    def list(self, model_class: str, filter_dict: dict = {},
             exclude_dict: dict = {}, order_by: list = [],
             auth_header: dict = None, fields: list = None,
             default_fields: bool = False, limit: int = None,
             foreign_key_fields: bool = False,
             **kwargs) -> List[dict]:
        """List objects with pagination.

        List end-point (resumed data) of PumpWood like systems,
        results will be paginated. To get next pag, send all recived pk at
        exclude dict (ex.: `exclude_dict={pk__in: [1,2,...,30]}`).

        It is possible to return foreign keys objects associated with
        `model_class`. Use this with carefull since increase the backend
        infrastructure consumption, each object is a retrieve call per
        foreign key (otimization in progress).

        It is possible to use diferent operators using `__` after the name
        of the field, some of the operators avaiable:

        ### General operators
        - **__eq:** Check if the value is the same, same results if no
            operator is passed.
        - **__gt:** Check if value is greter then argument.
        - **__lt:** Check if value is less then argument.
        - **__gte:** Check if value is greter or equal then argument.
        - **__lte:** Check if value is less or equal then argument.
        - **__in:** Check if value is at a list, the argument of this operator
            must be a list.

        ### Text field operators
        - **__contains:** Check if value contains a string. It is case and
            accent sensitive.
        - **__icontains:** Check if a values contains a string, It is case
            insensitive and accent sensitive.
        - **__unaccent_icontains:** Check if a values contains a string, It is
            case insensitive and accent insensitive (consider a, à, á, ã, ...
            the same).
        - **__exact:** Same as __eq or not setting operator.
        - **__iexact:** Same as __eq, but case insensitive and
            accent sensitive.
        - **__unaccent_iexact:** Same as __eq, but case insensitive and
            accent insensitive.
        - **__startswith:** Check if the value stats with a sub-string.
            Case sensitive and accent sensitive.
        - **__istartswith:** Check if the value stats with a sub-string.
            Case insensitive and accent sensitive.
        - **__unaccent_istartswith:** Check if the value stats with a
            sub-string. Case insensitive and accent insensitive.
        - **__endswith:** Check if the value ends with a sub-string. Case
            sensitive and accent sensitive.
        - **__iendswith:** Check if the value ends with a sub-string. Case
            insensitive and accent sensitive.
        - **__unaccent_iendswith:** Check if the value ends with a sub-string.
            Case insensitive and accent insensitive.

        ### Null operators
        - **__isnull:** Check if field is null, it uses as argument a `boolean`
            value false will return all non NULL values and true will return
            NULL values.

        ### Date and datetime operators:
        - **__range:** Receive as argument a list of two elements and return
            objects that field dates are between those values.
        - **__year:** Return object that date field value year is equal to
            argument.
        - **__month:** Return object that date field value month is equal to
            argument.
        - **__day:** Return object that date field value day is equal to
            argument.

        ### Dictionary fields operators:
        - **__json_contained_by:**
            Uses the function [contained_by](https://docs.sqlalchemy.org/en/20/dialects/postgresql.html#sqlalchemy.dialects.postgresql.JSONB.Comparator.contained_by)
            from SQLAlchemy to test if keys are a proper subset of the keys of
            the argument jsonb expression (extracted from SQLAlchemy). The
            argument is a list.
        - **__json_has_any:**
            Uses the function [has_any](https://docs.sqlalchemy.org/en/20/dialects/postgresql.html#sqlalchemy.dialects.postgresql.JSONB.Comparator.has_any)
            from SQLAlchemy to test for presence of a key. Note that the key
            may be a SQLA expression. (extracted from SQLAlchemy). The
            argument is a list.
        - **__json_has_key:**
            Uses the function [has_key](https://docs.sqlalchemy.org/en/20/dialects/postgresql.html#sqlalchemy.dialects.postgresql.JSONB.Comparator.has_key)
            from SQLAlchemy to Test for presence of a key. Note that the key
            may be a SQLA expression. The argument is a str.

        ### Text similarity operators
        To use similariry querys on Postgres it is necessary to `pg_trgm` be
        instaled on server. Check [oficial documentation]
        (https://www.postgresql.org/docs/current/pgtrgm.html).

        - **__similarity:** Check if two strings are similar uses the `%`
            operador.
        - **__word_similar_left:** Check if two strings are similar uses the
            `<%` operador.
        - **__word_similar_right:** Check if two strings are similar uses the
            `%>` operador.
        - **__strict_word__similar_left:** Check if two strings are similar
            uses the `<<%` operador.
        - **__strict_word__similar_right:** Check if two strings are similar
            uses the `%>>` operador.

        Some usage examples:
        ```python
        # Return the first 3 results ordered decreasing acording to `time` and
        # them ordered by `modeling_unit_id`. Results must have time greater
        # or equal to 2017-01-01 and less or equal to 2017-06-01. It also
        # must have attribute_id equal to 6 and not contains modeling_unit_id
        # 3 or 4.
        microservice.list(
            model_class="DatabaseVariable",
            filter_dict={
                "time__gte": "2017-01-01 00:00:00",
                "time__lte": "2017-06-01 00:00:00",
                "attribute_id": 6},
            exclude_dict={
                "modeling_unit_id__in": [3, 4]},
            order_by=["-time", "modeling_unit_id"],
            limit=3,
            fields=["pk", "model_class", "time", "modeling_unit_id", "value"])

        # Return all elements that dimensions field has a key type with
        # value contains `selling` insensitive to case and accent.
        microservice.list(
            model_class="DatabaseAttribute",
            filter_dict={
                "dimensions->type__unaccent_icontains": "selling"})
        ```

        Args:
            model_class:
                Model class of the end-point
            filter_dict:
                Filter dict to be used at the query. Filter elements from query
                return that satifies all statements of the dictonary.
            exclude_dict:
                Exclude dict to be used at the query. Remove elements from
                query return that satifies all statements of the dictonary.
            order_by: Order results acording to list of strings
                correspondent to fields. It is possible to use '-' at the
                begginng of the field name for reverse ordering. Ex.:
                ['description'] for accendent ordering and ['-description']
                for descendent ordering.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            fields (list):
                Set the fields to be returned by the list end-point.
            default_fields (bool):
                Boolean, if true and fields arguments None will return the
                default fields set for list by the backend.
            limit (int):
                Set the limit of elements of the returned query. By default,
                backend usually return 50 elements.
            foreign_key_fields (bool):
                Return forenging key objects. It will return the fk
                corresponding object. Ex: `created_by_id` reference to
                a user `model_class` the correspondent to User will be
                returned at `created_by`.
            **kwargs:
                Other parameters for compatibility.

        Returns:
          Containing objects serialized by list Serializer.

        Raises:
          No especific raises.
        """ # NOQA
        url_str = self._build_list_url(model_class)
        post_data = {
            'filter_dict': filter_dict, 'exclude_dict': exclude_dict,
            'order_by': order_by, 'default_fields': default_fields,
            'limit': limit, 'foreign_key_fields': foreign_key_fields}
        if fields is not None:
            post_data["fields"] = fields
        return self.request_post(
            url=url_str, data=post_data, auth_header=auth_header)

    def list_by_chunks(self, model_class: str, filter_dict: dict = {},
                       exclude_dict: dict = {}, auth_header: dict = None,
                       fields: list = None, default_fields: bool = False,
                       chunk_size: int = 50000, **kwargs) -> List[dict]:
        """List object fetching them by chucks using pk to paginate.

        List data by chunck to load by datasets without breaking the backend
        or receive server timeout. It load chunks orderring the results using
        id of the tables, it can be changed but it should be unique otherwise
        unexpected results may occur.

        Args:
            model_class:
                Model class of the end-point
            filter_dict:
                Filter dict to be used at the query. Filter elements from query
                return that satifies all statements of the dictonary.
            exclude_dict:
                Exclude dict to be used at the query. Remove elements from
                query return that satifies all statements of the dictonary.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            fields:
                Set the fields to be returned by the list end-point.
            default_fields:
                Boolean, if true and fields arguments None will return the
                default fields set for list by the backend.
            chunk_size:
                Number of objects to be fetched each query.
            **kwargs:
                Other parameters for compatibility.

        Returns:
          Containing objects serialized by list Serializer.

        Raises:
          No especific raises.
        """
        copy_filter_dict = copy.deepcopy(filter_dict)

        list_all_results = []
        max_order_col = 0
        while True:
            print("- fetching chunk [{}]".format(max_order_col))
            copy_filter_dict["pk__gt"] = max_order_col
            temp_results = self.list(
                model_class=model_class, filter_dict=copy_filter_dict,
                exclude_dict=exclude_dict, order_by=["pk"],
                auth_header=auth_header, fields=fields,
                default_fields=default_fields, limit=chunk_size)

            # Break if results is empty
            if len(temp_results) == 0:
                break

            max_order_col = temp_results[-1]["pk"]
            list_all_results.extend(temp_results)

        return list_all_results

    @staticmethod
    def _build_list_without_pag_url(model_class: str):
        return "rest/%s/list-without-pag/" % (model_class.lower(),)

    def list_without_pag(self, model_class: str, filter_dict: dict = {},
                         exclude_dict: dict = {}, order_by: list = [],
                         auth_header: dict = None, return_type: str = 'list',
                         convert_geometry: bool = True, fields: list = None,
                         default_fields: bool = False,
                         foreign_key_fields: bool = False, **kwargs):
        """List object without pagination.

        Function to post at list end-point (resumed data) of PumpWood like
        systems, results won't be paginated.
        **Be carefull with large returns.**

        Args:
            model_class (str):
                Model class of the end-point
            filter_dict (dict):
                Filter dict to be used at the query. Filter elements from query
                return that satifies all statements of the dictonary.
            exclude_dict (dict):
                Exclude dict to be used at the query. Remove elements from
                query return that satifies all statements of the dictonary.
            order_by (bool):
                Order results acording to list of strings
                correspondent to fields. It is possible to use '-' at the
                begginng of the field name for reverse ordering. Ex.:
                ['description'] for accendent ordering and ['-description']
                for descendent ordering.
            auth_header (dict):
                Auth header to substitute the microservice original
                at the request (user impersonation).
            fields (List[str]):
                Set the fields to be returned by the list end-point.
            default_fields (bool):
                Boolean, if true and fields arguments None will return the
                default fields set for list by the backend.
            limit (int):
                Set the limit of elements of the returned query. By default,
                backend usually return 50 elements.
            foreign_key_fields (bool):
                Return forenging key objects. It will return the fk
                corresponding object. Ex: `created_by_id` reference to
                a user `model_class` the correspondent to User will be
                returned at `created_by`.
            convert_geometry (bool):
                If geometry columns should be convert to shapely geometry.
                Fields with key 'geometry' will be considered geometry.
            return_type (str):
                Set return type to list of dictinary `list` or to a pandas
                dataframe `dataframe`.
            **kwargs:
                Other unused arguments for compatibility.

        Returns:
          Containing objects serialized by list Serializer.

        Raises:
          No especific raises.
        """
        url_str = self._build_list_without_pag_url(model_class)
        post_data = {
            'filter_dict': filter_dict, 'exclude_dict': exclude_dict,
            'order_by': order_by, 'default_fields': default_fields,
            'foreign_key_fields': foreign_key_fields}

        if fields is not None:
            post_data["fields"] = fields
        results = self.request_post(
            url=url_str, data=post_data, auth_header=auth_header)

        ##################################################
        # Converting geometry to Shapely objects in Python
        geometry_in_results = False
        if convert_geometry:
            for obj in results:
                geometry_value = obj.get("geometry")
                if geometry_value is not None:
                    obj["geometry"] = geometry.shape(geometry_value)
                    geometry_in_results = True
        ##################################################

        if return_type == 'list':
            return results
        elif return_type == 'dataframe':
            if (model_class.lower() == "descriptiongeoarea") and \
                    geometry_in_results:
                return geopd.GeoDataFrame(results, geometry='geometry')
            else:
                return pd.DataFrame(results)
        else:
            raise Exception("return_type must be 'list' or 'dataframe'")

    @staticmethod
    def _build_list_dimensions(model_class: str):
        return "rest/%s/list-dimensions/" % (model_class.lower(),)

    def list_dimensions(self, model_class: str, filter_dict: dict = {},
                        exclude_dict: dict = {}, auth_header: dict = None
                        ) -> List[str]:
        """List dimensions avaiable for model_class.

        It list all keys avaiable at dimension retricting the results with
        query parameters `filter_dict` and `exclude_dict`.

        Args:
            model_class:
                Model class of the end-point
            filter_dict:
                Filter dict to be used at the query. Filter elements from query
                return that satifies all statements of the dictonary.
            exclude_dict:
                Exclude dict to be used at the query. Remove elements from
                query return that satifies all statements of the dictonary.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            List of keys avaiable in results from the query dict.
        """
        url_str = self._build_list_dimensions(model_class)
        post_data = {'filter_dict': filter_dict, 'exclude_dict': exclude_dict}
        return self.request_post(
            url=url_str, data=post_data, auth_header=auth_header)

    @staticmethod
    def _build_list_dimension_values(model_class: str):
        return "rest/%s/list-dimension-values/" % (model_class.lower(), )

    def list_dimension_values(self, model_class: str, key: str,
                              filter_dict: dict = {}, exclude_dict: dict = {},
                              auth_header: dict = None) -> List[any]:
        """List values associated with dimensions key.

        It list all keys avaiable at dimension retricting the results with
        query parameters `filter_dict` and `exclude_dict`.

        Args:
            model_class:
                Model class of the end-point
            filter_dict:
                Filter dict to be used at the query. Filter elements from query
                return that satifies all statements of the dictonary.
            exclude_dict:
                Exclude dict to be used at the query. Remove elements from
                query return that satifies all statements of the dictonary.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            key:
                Key to list the avaiable values using the query filter
                and exclude.

        Returns:
            List of values associated with dimensions key at the objects that
            are returned with `filter_dict` and `exclude_dict`.
        """
        url_str = self._build_list_dimension_values(model_class)
        post_data = {'filter_dict': filter_dict, 'exclude_dict': exclude_dict,
                     'key': key}
        return self.request_post(
            url=url_str, data=post_data, auth_header=auth_header)

    def list_actions(self, model_class: str,
                     auth_header: dict = None) -> List[dict]:
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
                       auth_header: dict = None) -> dict:
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
        url_str = self._build_execute_action_url(
            model_class=model_class, action=action, pk=pk)
        return self.request_post(
            url=url_str, data=parameters, files=files,
            auth_header=auth_header)

    def search_options(self, model_class: str,
                       auth_header: dict = None) -> dict:
        """Return search options.

        DEPRECTED Use `list_options` function instead.

        Return information of the fields including avaiable options for
        options fields and model associated with the foreign key.

        Args:
            model_class:
                Model class to check search parameters
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            Return a dictonary with field names as keys and information of
            them as values. Information at values:
            - **primary_key [bool]:**: Boolean indicating if field is part
                of model_class primary key.
            - **column [str]:**: Name of the column.
            - **column__verbose [str]:** Name of the column translated using
                Pumpwood I8s.
            - **help_text [str]:** Help text associated with column.
            - **help_text__verbose [str]:** Help text associated with column
                translated using Pumpwood I8s.
            - **type [str]:** Python type associated with the column.
            - **nullable [bool]:** If field can be set as null (None).
            - **read_only [bool]:** If field is marked as read-only. Passsing
                information for this field will not be used in save end-point.
            - **default [any]:** Default value of the field if not set using
                save end-poin.
            - **unique [bool]:** If the there is a constrain in database
                setting this field to be unique.
            - **extra_info:** Some extra infomations used to pass associated
                model class for forenging key and related fields.
            - **in [dict]:** At options fields, have their options listed in
                `in` keys. It will return the values as key and de description
                and description__verbose (translated by Pumpwood I8s)
                as values.
            - **partition:** At pk field, this key indicates if the database
                if partitioned. Partitioned will perform better in queries if
                partition is used on filter or exclude clauses. If table has
                more than one level o partition, at least the first one must
                be used when retrieving data.

        Raises:
            No particular raises.
        """
        url_str = "rest/%s/options/" % (model_class.lower(), )
        return self.request_get(url=url_str, auth_header=auth_header)

    def fill_options(self, model_class, parcial_obj_dict: dict = {},
                     field: str = None, auth_header: dict = None):
        """Return options for object fields.

        DEPRECTED Use `fill_validation` function instead.

        This function send partial object data and return options to finish
        object fillment.

        Args:
            model_class:
                Model class to check search parameters
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            parcial_obj_dict:
                Partial object that is sent to backend for validation and
                update fill options acording to values passed for each field.
            field:
                Retrict validation for an especific field if implemented.

        Returns:
            Return a dictonary with field names as keys and information of
            them as values. Information at values:
            - **primary_key [bool]:**: Boolean indicating if field is part
                of model_class primary key.
            - **column [str]:**: Name of the column.
            - **column__verbose [str]:** Name of the column translated using
                Pumpwood I8s.
            - **help_text [str]:** Help text associated with column.
            - **help_text__verbose [str]:** Help text associated with column
                translated using Pumpwood I8s.
            - **type [str]:** Python type associated with the column.
            - **nullable [bool]:** If field can be set as null (None).
            - **read_only [bool]:** If field is marked as read-only. Passsing
                information for this field will not be used in save end-point.
            - **default [any]:** Default value of the field if not set using
                save end-poin.
            - **unique [bool]:** If the there is a constrain in database
                setting this field to be unique.
            - **extra_info:** Some extra infomations used to pass associated
                model class for forenging key and related fields.
            - **in [dict]:** At options fields, have their options listed in
                `in` keys. It will return the values as key and de description
                and description__verbose (translated by Pumpwood I8s)
                as values.
            - **partition:** At pk field, this key indicates if the database
                if partitioned. Partitioned will perform better in queries if
                partition is used on filter or exclude clauses. If table has
                more than one level o partition, at least the first one must
                be used when retrieving data.

        Raises:
            No particular raises.
        """
        url_str = "rest/%s/options/" % (model_class.lower(), )
        if (field is not None):
            url_str = url_str + field
        return self.request_post(
            url=url_str, data=parcial_obj_dict,
            auth_header=auth_header)

    def list_options(self, model_class: str, auth_header: dict) -> dict:
        """Return options to render list views.

        This function send partial object data and return options to finish
        object fillment.

        Args:
            model_class:
                Model class to check search parameters.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            Dictionary with keys:
            - **default_list_fields:** Default list field defined on the
                application backend.
            - **field_descriptions:** Description of the fields associated
                with the model class.

        Raises:
          No particular raise.
        """
        url_str = "rest/{basename}/list-options/".format(
            basename=model_class.lower())
        return self.request_get(
            url=url_str, auth_header=auth_header)

    def retrieve_options(self, model_class: str,
                         auth_header: dict = None) -> dict:
        """Return options to render retrieve views.

        Return information of the field sets that can be used to create
        frontend site. It also return a `verbose_field` which can be used
        to create the tittle of the page substituing the values with
        information of the object.

        Args:
          model_class:
              Model class to check search parameters.
          auth_header:
              Auth header to substitute the microservice original
              at the request (user impersonation).

        Returns:
            Return a dictinary with keys:
            - **verbose_field:** String sugesting how the tittle of the
                retrieve might be created. It will use Python format
                information ex.: `'{pk} | {description}'`.
            - **fieldset:** An dictinary with organization of data,
                setting field sets that could be grouped toguether in
                tabs.

        Raises:
            No particular raises.
        """
        url_str = "rest/{basename}/retrieve-options/".format(
            basename=model_class.lower())
        return self.request_get(
            url=url_str, auth_header=auth_header)

    def fill_validation(self, model_class: str, parcial_obj_dict: dict = {},
                        field: str = None, auth_header: dict = None,
                        user_type: str = 'api') -> dict:
        """Return options for object fields.

        This function send partial object data and return options to finish
        object fillment.

        Args:
            model_class:
                Model class to check search parameters.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).
            parcial_obj_dict:
                Partial object data to be validated by the backend.
            field:
                Set an especific field to be validated if implemented.
            user_type:
                Set the type of user is requesting fill validation. It is
                possible to set `api` and `gui`. Gui user_type will return
                fields listed in gui_readonly as read-only fields to
                facilitate navegation.

        Returns:
            Return a dictinary with keys:
            - **field_descriptions:** Same of fill_options, but setting as
                read_only=True fields listed on gui_readonly if
                user_type='gui'.
            - **gui_readonly:** Return a list of fields that will be
                considered as read-only if user_type='gui' is requested.

        Raises:
            No particular raises.
        """
        url_str = "rest/{basename}/retrieve-options/".format(
            basename=model_class.lower())
        params = {"user_type": user_type}
        if field is not None:
            params["field"] = field
        return self.request_post(
            url=url_str, auth_header=auth_header, data=parcial_obj_dict,
            parameters=params)

    @staticmethod
    def _build_pivot_url(model_class):
        return "rest/%s/pivot/" % (model_class.lower(), )

    def pivot(self, model_class: str, columns: List[str] = [],
              format: str = 'list', filter_dict: dict = {},
              exclude_dict: dict = {}, order_by: List[str] = [],
              variables: List[str] = None, show_deleted: bool = False,
              add_pk_column: bool = False, auth_header: dict = None,
              as_dataframe: bool = False
              ) -> Union[List[dict], Dict[str, list], pd.DataFrame]:
        """Pivot object data acording to columns specified.

        Pivoting per-se is not usually used, beeing the name of the function
        a legacy. Normality data transformation is done at the client level.

        Args:
            model_class (str):
                Model class to check search parameters.
            columns (List[str]):
                List of fields to be used as columns when pivoting the data.
            format (str):
                Format to be used to convert pandas.DataFrame to
                dictionary, must be in ['dict','list','series',
                'split', 'records','index'].
            filter_dict (dict):
                Same as list function.
            exclude_dict (dict):
                Same as list function.
            order_by (List[str]):
                 Same as list function.
            variables (List[str]):
                List of the fields to be returned, if None, the default
                variables will be returned. Same as fields on list functions.
            show_deleted (bool):
                Fields with deleted column will have objects with deleted=True
                omited from results. show_deleted=True will return this
                information.
            add_pk_column (bool):
                If add pk values of the objects at pivot results. Adding
                pk key on pivot end-points won't be possible to pivot since
                pk is unique for each entry.
            auth_header (dict):
                Auth header to substitute the microservice original
                at the request (user impersonation).
            as_dataframe (bool):
                If results should be returned as a dataframe.

        Returns:
            Return a list or a dictinary depending on the format set on
            format parameter.

        Raises:
            PumpWoodException:
                'Columns must be a list of elements.'. Indicates that the list
                argument was not a list.
            PumpWoodException:
                'Column chosen as pivot is not at model variables'. Indicates
                that columns that were set to pivot are not present on model
                variables.
            PumpWoodException:
                "Format must be in ['dict','list','series','split',
                'records','index']". Indicates that format set as paramenter
                is not implemented.
            PumpWoodException:
                "Can not add pk column and pivot information". If
                add_pk_column is True (results will have the pk column), it is
                not possible to pivot the information (pk is an unique value
                for each object, there is no reason to pivot it).
            PumpWoodException:
                "'value' column not at melted data, it is not possible
                to pivot dataframe.". Indicates that data does not have a value
                column, it must have it to populate pivoted table.
        """
        url_str = self._build_pivot_url(model_class)
        post_data = {
            'columns': columns, 'format': format,
            'filter_dict': filter_dict, 'exclude_dict': exclude_dict,
            'order_by': order_by, "variables": variables,
            "show_deleted": show_deleted, "add_pk_column": add_pk_column}
        pivot_results = self.request_post(
            url=url_str, data=post_data, auth_header=auth_header)

        if not add_pk_column:
            if as_dataframe:
                return pd.DataFrame(pivot_results)
            else:
                return pivot_results
        else:
            pd_pivot_results = pd.DataFrame(pivot_results)
            if len(pd_pivot_results) != 0:
                fill_options = self.fill_options(
                    model_class=model_class, auth_header=auth_header)
                primary_keys = fill_options["pk"]["column"]
                pd_pivot_results["pk"] = pd_pivot_results[primary_keys].apply(
                    CompositePkBase64Converter.dump,
                    primary_keys=primary_keys, axis=1)
            if as_dataframe:
                return pd_pivot_results
            else:
                return pd_pivot_results.to_dict(format)

    def _flat_list_by_chunks_helper(self, args):
        try:
            # Unpacking arguments
            model_class = args["model_class"]
            filter_dict = args["filter_dict"]
            exclude_dict = args["exclude_dict"]
            fields = args["fields"]
            show_deleted = args["show_deleted"]
            auth_header = args["auth_header"]
            chunk_size = args["chunk_size"]

            temp_filter_dict = copy.deepcopy(filter_dict)
            url_str = self._build_pivot_url(model_class)
            max_pk = 0

            # Fetch data until an empty result is returned
            list_dataframes = []
            while True:
                sys.stdout.write(".")
                sys.stdout.flush()
                temp_filter_dict["id__gt"] = max_pk
                post_data = {
                    'format': 'list',
                    'filter_dict': temp_filter_dict,
                    'exclude_dict': exclude_dict,
                    'order_by': ["id"], "variables": fields,
                    "show_deleted": show_deleted,
                    "limit": chunk_size,
                    "add_pk_column": True}
                temp_dateframe = pd.DataFrame(self.request_post(
                    url=url_str, data=post_data, auth_header=auth_header))

                # Break if results are less than chunk size, so no more results
                # are avaiable
                if len(temp_dateframe) < chunk_size:
                    list_dataframes.append(temp_dateframe)
                    break

                max_pk = int(temp_dateframe["id"].max())
                list_dataframes.append(temp_dateframe)

            if len(list_dataframes) == 0:
                return pd.DataFrame()
            else:
                return pd.concat(list_dataframes)
        except Exception as e:
            raise Exception("Exception at flat_list_by_chunks:", str(e))

    def flat_list_by_chunks(self, model_class: str, filter_dict: dict = {},
                            exclude_dict: dict = {}, fields: List[str] = None,
                            show_deleted: bool = False,
                            auth_header: dict = None,
                            chunk_size: int = 1000000,
                            n_parallel: int = None,
                            create_composite_pk: bool = False,
                            start_date: str = None,
                            end_date: str = None) -> pd.DataFrame:
        """Incrementally fetch data from pivot end-point.

        Fetch data from pivot end-point paginating by id of chunk_size lenght.

        If table is partitioned it will split the query acording to partition
        to facilitate query at the database.

        If start_date and end_date are set, also breaks the query by month
        retrieving each month data in parallel.

        Args:
            model_class (str):
                Model class to be pivoted.
            filter_dict (dict):
                Dictionary to to be used in objects.filter argument
                (Same as list end-point).
            exclude_dict (dict):
                Dictionary to to be used in objects.exclude argument
                (Same as list end-point).
            fields (List[str] | None):
                List of the variables to be returned,
                if None, the default variables will be returned.
                If fields is set, dataframe will return that columns
                even if data is empty.
            start_date (datetime | str):
                Set a begin date for the query. If begin and end date are
                set, query will be splited with chucks by month that will be
                requested in parallel.
            end_date (datetime | str):
                Set a end date for the query. If begin and end date are
                set, query will be splited with chucks by month that will be
                requested in parallel.
            show_deleted (bool):
                If deleted data should be returned.
            auth_header (dict):
                Auth header to substitute the microservice original
                at the request (user impersonation).
            chunk_size (int):
                Limit of data to fetch per call.
            n_parallel (int):
                Number of parallel process to perform.
            create_composite_pk (bool):
                If true and table has a composite pk, it will create pk
                value based on the hash on the json serialized dictionary
                of the components of the primary key.

        Returns:
            Returns a dataframe with all information fetched.

        Raises:
            No particular raise.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        temp_filter_dict = copy.deepcopy(filter_dict)
        fill_options = self.fill_options(
            model_class=model_class, auth_header=auth_header)
        primary_keys = fill_options["pk"]["column"]
        partition = fill_options["pk"].get("partition", [])

        # Create a list of month and include start and end dates if not at
        # the beginning of a month
        month_sequence = None
        if (start_date is not None) and (end_date is not None):
            start_date = pd.to_datetime(start_date)
            end_date = pd.to_datetime(end_date)
            list_month_sequence = pd.date_range(
                start=start_date, end=end_date, freq='MS').tolist()
            month_sequence = pd.Series(
                [start_date] + list_month_sequence + [end_date]
            ).sort_values().tolist()

            month_df = pd.DataFrame({'end': month_sequence})
            month_df['start'] = month_df['end'].shift()
            month_df = month_df.dropna().drop_duplicates()
            month_sequence = month_df.to_dict("records")
        elif (start_date is not None) or (end_date is not None):
            msg = (
                "To break query in chunks using start_date and end_date "
                "both must be set.\n"
                "start_date: {start_date}\n"
                "end_date: {end_date}\n").format(
                    start_date=start_date, end_date=end_date)
            raise PumpWoodException(
                message=msg, payload={
                    "start_date": start_date,
                    "end_date": end_date})

        resp_df = pd.DataFrame()

        ##########################################################
        # If table have more than one partition, run in parallel #
        # the {partition}__in elements along with dates          #
        if 1 < len(partition):
            partition_col_1st = partition[0]
            filter_dict_keys = list(temp_filter_dict.keys())
            partition_filter = None
            count_partition_col_1st_filters = 0
            for col in filter_dict_keys:
                if partition_col_1st + "__in" == col:
                    partition_filter = temp_filter_dict[col]
                    del temp_filter_dict[col]
                    count_partition_col_1st_filters = \
                        count_partition_col_1st_filters + 1
                elif partition_col_1st == col:
                    partition_filter = [temp_filter_dict[col]]
                    del temp_filter_dict[col]
                    count_partition_col_1st_filters = \
                        count_partition_col_1st_filters + 1

            # Validating query for partitioned tables
            if partition_filter is None:
                msg = (
                    "Table is partitioned with sub-partitions, running "
                    "queries without at least first level partition will "
                    "lead to long waiting times or hanging queries. Please "
                    "use first partition level in filter_dict with equal "
                    "or in operators. Table partitions: {}"
                ).format(partition)
                raise PumpWoodException(message=msg)

            if 1 < count_partition_col_1st_filters:
                msg = (
                    "Please give some help for the dev here, use just one "
                    "filter_dict entry for first partition...")
                raise PumpWoodException(message=msg)

            # Parallelizing query using partition columns
            pool_arguments = []
            for filter_key in partition_filter:
                request_filter_dict = copy.deepcopy(temp_filter_dict)
                request_filter_dict[partition_col_1st] = filter_key
                if month_sequence is None:
                    pool_arguments.append({
                        "model_class": model_class,
                        "filter_dict": request_filter_dict,
                        "exclude_dict": exclude_dict,
                        "fields": fields,
                        "show_deleted": show_deleted,
                        "auth_header": auth_header,
                        "chunk_size": chunk_size})
                else:
                    for i in range(len(month_sequence)):
                        request_filter_dict_t = copy.deepcopy(
                            request_filter_dict)
                        # If is not the last interval, query using open
                        # right interval so subsequence queries does
                        # not overlap
                        if i != len(month_sequence) - 1:
                            request_filter_dict_t["time__gte"] = \
                                month_sequence[i]["start"]
                            request_filter_dict_t["time__lt"] = \
                                month_sequence[i]["end"]

                        # At the last interval use closed right interval so
                        # last element is also included in the interval
                        else:
                            request_filter_dict_t["time__gte"] = \
                                month_sequence[i]["start"]
                            request_filter_dict_t["time__lte"] = \
                                month_sequence[i]["end"]

                        pool_arguments.append({
                            "model_class": model_class,
                            "filter_dict": request_filter_dict_t,
                            "exclude_dict": exclude_dict,
                            "fields": fields,
                            "show_deleted": show_deleted,
                            "auth_header": auth_header,
                            "chunk_size": chunk_size})

            # Perform parallel calls to backend each chucked by chunk_size
            print("## Starting parallel flat list: %s" % len(pool_arguments))
            try:
                with Pool(n_parallel) as p:
                    results = p.map(
                        self._flat_list_by_chunks_helper,
                        pool_arguments)
                resp_df = pd.concat(results)
            except Exception as e:
                PumpWoodException(message=str(e))
            print("\n## Finished parallel flat list: %s" % len(pool_arguments))

        ############################################
        # If table have partition, run in parallel #
        else:
            try:
                results_key_data = self._flat_list_by_chunks_helper({
                    "model_class": model_class,
                    "filter_dict": temp_filter_dict,
                    "exclude_dict": exclude_dict,
                    "fields": fields,
                    "show_deleted": show_deleted,
                    "auth_header": auth_header,
                    "chunk_size": chunk_size})
                resp_df = results_key_data
            except Exception as e:
                PumpWoodException(message=str(e))

        if (1 < len(partition)) and create_composite_pk:
            print("## Creating composite pk")
            resp_df["pk"] = resp_df[primary_keys].apply(
                CompositePkBase64Converter.dump,
                primary_keys=primary_keys, axis=1)
            if fields is not None:
                fields = ['pk'] + fields

        # Adjust columns to return the columns set at fields
        if fields is not None:
            resp_df = pd.DataFrame(resp_df, columns=fields)
        return resp_df

    @staticmethod
    def _build_bulk_save_url(model_class: str):
        return "rest/%s/bulk-save/" % (model_class.lower(),)

    def bulk_save(self, model_class: str, data_to_save: list,
                  auth_header: dict = None) -> dict:
        """Save a list of objects with one request.

        It is used with a unique call save many objects at the same time. It
        is necessary that the end-point is able to receive bulk save requests
        and all objects been of the same model class.

        Args:
            model_class:
                Data model class.
            data_to_save:
                A list of objects to be saved.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            A dictinary with `saved_count` as key indicating the number of
            objects that were saved in database.

        Raises:
            PumpWoodException:
                'Expected columns and data columns do not match: Expected
                columns: {expected} Data columns: {data_cols}'. Indicates
                that the expected fields of the object were not met at the
                objects passed to save.
            PumpWoodException:
                Other sqlalchemy and psycopg2 errors not associated with
                IntegrityError.
            PumpWoodException:
                'Bulk save not avaiable.'. Indicates that Bulk save end-point
                was not configured for this model_class.
            PumpWoodIntegrityError:
                Raise integrity errors from sqlalchemy and psycopg2. Usually
                associated with uniqueness of some column.
        """
        url_str = self._build_bulk_save_url(model_class=model_class)
        return self.request_post(
            url=url_str, data=data_to_save,
            auth_header=auth_header)

    ########################
    # Parallel aux functions
    @staticmethod
    def flatten_parallel(parallel_result: list):
        """Concat all parallel return to one list.

        Args:
            parallel_result:
                A list of lists to be flated (concatenate
                all lists into one).

        Returns:
            A list with all sub list itens.
        """
        return [
            item for sublist in parallel_result
            for item in sublist]

    def _request_get_wrapper(self, arguments: dict):
        try:
            results = self.request_get(**arguments)
            sys.stdout.write(".")
            sys.stdout.flush()
            return results
        except Exception as e:
            raise Exception("Error on parallel get: " + str(e))

    def parallel_request_get(self, urls_list: list, n_parallel: int = None,
                             parameters: Union[List[dict], dict] = None,
                             auth_header: dict = None) -> List[any]:
        """Make [n_parallel] parallel get requests.

        Args:
            urls_list:
                List of urls to make get requests.
            parameters:
                A list of dictionary or a dictionary that will be replicated
                len(urls_list) and passed to parallel request as url
                parameter. If not set, empty dictionary will be passed to all
                request as default.
            n_parallel:
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            Return a list with all get request reponses. The results are
            on the same order of argument list.

        Raises:
            PumpWoodException:
                'lenght of urls_list[{}] is different of parameters[{}]'.
                Indicates that the function arguments `urls_list` and
                `parameters` (when passed as a list of dictionaries)
                does not have de same lenght.
            PumpWoodNotImplementedError:
                'paraemters type[{}] is not implemented'. Indicates that
                `parameters` passed as function argument is not a list of dict
                or a dictinary, so not implemented.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        # Create URL parameters if not set as parameter with
        # empty dicionaries
        n_urls = len(urls_list)
        parameters_list = None
        if parameters is None:
            parameters = [{}] * n_urls
        elif type(parameters) is dict:
            parameters = [{parameters}] * n_urls
        elif type(parameters) is list:
            if len(parameters) == n_urls:
                parameters_list = parameters
            else:
                msg = (
                    'lenght of urls_list[{}] is different of ' +
                    'parameters[{}]').format(
                        n_urls, len(parameters))
                raise PumpWoodException(msg)
        else:
            msg = 'paraemters type[{}] is not implemented'.format(
                str(type(parameters)))
            raise PumpWoodNotImplementedError(msg)

        # Create Pool arguments to run in parallel
        pool_arguments = []
        for i in range(len(urls_list)):
            pool_arguments.append({
                'url': urls_list[i], 'auth_header': auth_header,
                'parameters': parameters_list[i]})

        # Run requests in parallel
        with Pool(n_parallel) as p:
            results = p.map(self._request_get_wrapper, pool_arguments)
        print("|")
        return results

    def _request_post_wrapper(self, arguments: dict):
        try:
            result = self.request_post(**arguments)
            sys.stdout.write(".")
            sys.stdout.flush()
            return result
        except Exception as e:
            raise Exception("Error in parallel post: " + str(e))

    def paralell_request_post(self, urls_list: List[str],
                              data_list: List[dict],
                              parameters: Union[List[dict], dict] = None,
                              n_parallel: int = None,
                              auth_header: dict = None) -> List[any]:
        """Make [n_parallel] parallel post request.

        Args:
            urls_list:
                List of urls to make get requests.
            data_list:
                List of data to be used as post payloads.
            parameters:
                URL paramenters to make the post requests.
            n_parallel:
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            List of the post request reponses.

        Raises:
            No particular raises

        Example:
            No example yet.

        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        # Create URL parameters if not set as parameter with
        # empty dicionaries
        n_urls = len(urls_list)
        parameters_list = None
        if parameters is None:
            parameters_list = [{}] * n_urls
        elif type(parameters) is dict:
            parameters_list = [{parameters}] * n_urls
        elif type(parameters) is list:
            if len(parameters) == n_urls:
                parameters_list = parameters
            else:
                msg = (
                    'lenght of urls_list[{}] is different of ' +
                    'parameters[{}]').format(
                        n_urls, len(parameters))
                raise PumpWoodException(msg)
        else:
            msg = 'paraemters type[{}] is not implemented'.format(
                str(type(parameters)))
            raise PumpWoodNotImplementedError(msg)

        # Validate if length of URL is the same of data_list
        if len(urls_list) != len(data_list):
            msg = (
                'len(urls_list)[{}] must be equal ' +
                'to len(data_list)[{}]').format(
                    len(urls_list), len(data_list))
            raise PumpWoodException(msg)

        # Create the arguments for parallel requests
        pool_arguments = []
        for i in range(len(urls_list)):
            pool_arguments.append({
                'url': urls_list[i],
                'data': data_list[i],
                'parameters': parameters_list[i],
                'auth_header': auth_header})

        with Pool(n_parallel) as p:
            results = p.map(self._request_post_wrapper, pool_arguments)
        print("|")
        return results

    def _request_delete_wrapper(self, arguments):
        try:
            result = self.request_delete(**arguments)
            sys.stdout.write(".")
            sys.stdout.flush()
            return result
        except Exception as e:
            raise Exception("Error in parallel delete: " + str(e))

    def paralell_request_delete(self, urls_list: List[str],
                                parameters: Union[List[dict], dict] = None,
                                n_parallel: int = None,
                                auth_header: dict = None):
        """Make [n_parallel] parallel delete request.

        Args:
            urls_list:
                List of urls to make get requests.
            parameters:
                URL paramenters to make the post requests.
            n_parallel (int): Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            list: List of the get request reponses.

        Raises:
            No particular raises.

        Example:
            No example yet.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        # Create URL parameters if not set as parameter with
        # empty dicionaries
        n_urls = len(urls_list)
        parameters_list = None
        if parameters is None:
            parameters = [{}] * n_urls
        elif type(parameters) is dict:
            parameters = [{parameters}] * n_urls
        elif type(parameters) is list:
            if len(parameters) == n_urls:
                parameters_list = parameters
            else:
                msg = (
                    'lenght of urls_list[{}] is different of ' +
                    'parameters[{}]').format(
                        n_urls, len(parameters))
                raise PumpWoodException(msg)
        else:
            msg = 'paraemters type[{}] is not implemented'.format(
                str(type(parameters)))
            raise PumpWoodNotImplementedError(msg)

        # Create Pool arguments to run in parallel
        pool_arguments = []
        for i in range(len(urls_list)):
            pool_arguments.append({
                'url': urls_list[i], 'auth_header': auth_header,
                'parameters': parameters_list[i]})

        with Pool(n_parallel) as p:
            results = p.map(self._request_delete_wrapper, pool_arguments)
        print("|")
        return results

    ######################
    # Parallel functions #
    def parallel_retrieve(self, model_class: Union[str, List[str]],
                          list_pk: List[int], default_fields: bool = False,
                          foreign_key_fields: bool = False,
                          related_fields: bool = False,
                          fields: list = None, n_parallel: int = None,
                          auth_header: dict = None):
        """Make [n_parallel] parallel retrieve request.

        Args:
            model_class:
                Model Class to retrieve.
            list_pk:
                List of the pks to retrieve.
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
            n_parallel (int): Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            List of the retrieve request data.

        Raises:
            PumpWoodException:
                'len(model_class)[{}] != len(list_pk)[{}]'. Indicates that
                the lenght of the arguments model_class and list_pk are
                incompatible.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        if type(model_class) is str:
            model_class = [model_class] * len(list_pk)
        elif type(model_class) is list:
            if len(model_class) != len(list_pk):
                msg = (
                    'len(model_class)[{}] != len(list_pk)[{}]').format(
                        len(model_class), len(list_pk))
                raise PumpWoodException(msg)

        urls_list = [
            self._build_retrieve_url(
                model_class=model_class[i], pk=list_pk[i])
            for i in range(len(model_class))]

        return self.parallel_request_get(
            urls_list=urls_list, n_parallel=n_parallel,
            parameters={
                "fields": fields, "default_fields": default_fields,
                "foreign_key_fields": foreign_key_fields,
                "related_fields": related_fields},
            auth_header=auth_header)

    def _request_retrieve_file_wrapper(self, args):
        sys.stdout.write(".")
        sys.stdout.flush()
        try:
            return self.retrieve_file(**args)
        except Exception as e:
            raise Exception("Error in parallel retrieve_file: " + str(e))

    def parallel_retrieve_file(self, model_class: str,
                               list_pk: List[int], file_field: str = None,
                               save_path: str = "./", save_file: bool = True,
                               list_file_name: List[str] = None,
                               if_exists: str = "fail",
                               n_parallel: int = None,
                               auth_header: dict = None):
        """Make many [n_parallel] retrieve request.

        Args:
            model_class:
                Model Class to retrieve.
            list_pk:
                List of the pks to retrieve.
            file_field:
                Indicates the file field to download from.
            n_parallel:
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            save_path:
                Path to be used to save files.
            save_file:
                True save file locally, False return file content as bites.
            list_file_name:
                Set a file name for each file download.
            if_exists:
                Set how treat when a file will be saved
                and there is another at same path. "fail" will raise an error;
                "overwrite" will overwrite the file with the new one; "skip"
                when list_file_name is set, check before downloaded it file
                already exists, if so skip the download.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            List of the retrieve file request data.

        Raises:
            PumpWoodException:
                'Lenght of list_file_name and list_pk are not equal:
                len(list_file_name)={list_file_name}; len(list_pk)={list_pk}'.
                Indicates that len(list_file_name) and len(list_pk) function
                arguments are not equal.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        if list_file_name is not None:
            if len(list_file_name) != len(list_pk):
                raise PumpWoodException((
                    "Lenght of list_file_name and list_pk are not equal:\n" +
                    "len(list_file_name)={list_file_name}; " +
                    "len(list_pk)={list_pk}").format(
                        list_file_name=len(list_file_name),
                        list_pk=len(list_pk)))

        pool_arguments = []
        for i in range(len(list_pk)):
            pk = list_pk[i]
            file_name = None
            if list_file_name is not None:
                file_name = list_file_name[i]
            pool_arguments.append({
                "model_class": model_class, "pk": pk,
                "file_field": file_field, "auth_header": auth_header,
                "save_file": save_file, "file_name": file_name,
                "save_path": save_path, "if_exists": if_exists})

        try:
            with Pool(n_parallel) as p:
                results = p.map(
                    self._request_retrieve_file_wrapper,
                    pool_arguments)
            print("|")
        except Exception as e:
            raise PumpWoodException(str(e))

        return results

    def parallel_list(self, model_class: Union[str, List[str]],
                      list_args: List[dict], n_parallel: int = None,
                      auth_header: dict = None, fields: list = None,
                      default_fields: bool = False, limit: int = None,
                      foreign_key_fields: bool = False) -> List[dict]:
        """Make [n_parallel] parallel list request.

        Args:
            model_class (str):
                Model Class to retrieve.
            list_args (List[dict]):
                A list of list request args (filter_dict,
                exclude_dict, order_by, fields, default_fields, limit,
                foreign_key_fields).
            n_parallel (int): Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header (dict):
                Auth header to substitute the microservice original
                at the request (user impersonation).
            fields (List[str]):
                Set the fields to be returned by the list end-point.
            default_fields (bool):
                Boolean, if true and fields arguments None will return the
                default fields set for list by the backend.
            limit (int):
                Set the limit of elements of the returned query. By default,
                backend usually return 50 elements.
            foreign_key_fields (bool):
                Return forenging key objects. It will return the fk
                corresponding object. Ex: `created_by_id` reference to
                a user `model_class` the correspondent to User will be
                returned at `created_by`.

        Returns:
            Flatten List of the list request reponses.

        Raises:
            PumpWoodException:
                'len(model_class)[{}] != len(list_args)[{}]'. Indicates that
                lenght of model_class and list_args arguments are not equal.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        urls_list = None
        if type(model_class) is str:
            urls_list = [self._build_list_url(model_class)] * len(list_args)
        else:
            if len(model_class) != len(list_args):
                msg = 'len(model_class)[{}] != len(list_args)[{}]'.format(
                    len(model_class), len(list_args))
                raise PumpWoodException(msg)
            urls_list = [self._build_list_url(m) for m in model_class]

        print("## Starting parallel_list: %s" % len(urls_list))
        return self.paralell_request_post(
            urls_list=urls_list, data_list=list_args,
            n_parallel=n_parallel, auth_header=auth_header)

    def parallel_list_without_pag(self, model_class: Union[str, List[str]],
                                  list_args: List[dict],
                                  n_parallel: int = None,
                                  auth_header: dict = None):
        """Make [n_parallel] parallel list_without_pag request.

        Args:
            model_class:
                Model Class to retrieve.
            list_args:
                A list of list request args (filter_dict,
                exclude_dict, order_by, fields, default_fields, limit,
                foreign_key_fields).
            n_parallel (int):
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            Flatten List of the list request reponses.

        Raises:
            PumpWoodException:
                'len(model_class)[{}] != len(list_args)[{}]'. Indicates that
                lenght of model_class and list_args arguments are not equal.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        urls_list = None
        if type(model_class) is str:
            url_temp = [self._build_list_without_pag_url(model_class)]
            urls_list = url_temp * len(list_args)
        else:
            if len(model_class) != len(list_args):
                msg = 'len(model_class)[{}] != len(list_args)[{}]'.format(
                    len(model_class), len(list_args))
                raise PumpWoodException(msg)
            urls_list = [
                self._build_list_without_pag_url(m) for m in model_class]

        print("## Starting parallel_list_without_pag: %s" % len(urls_list))
        return self.paralell_request_post(
            urls_list=urls_list, data_list=list_args,
            n_parallel=n_parallel, auth_header=auth_header)

    def parallel_list_one(self, model_class: Union[str, List[str]],
                          list_pk: List[int], n_parallel: int = None,
                          auth_header: dict = None):
        """Make [n_parallel] parallel list_one request.

        DEPRECTED user retrieve call with default_fields=True.

        Args:
            model_class:
                Model Class to list one.
            list_pk:
                List of the pks to list one.
            n_parallel:
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            List of the list_one request data.

        Raises:
            PumpWoodException:
                'len(model_class) != len(list_pk)'. Indicates that lenght
                of model_class and list_pk arguments are not equal.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        if type(model_class) is list:
            model_class = [model_class] * len(list_pk)

        if len(model_class) is len(list_pk):
            raise PumpWoodException('len(model_class) != len(list_pk)')

        urls_list = [
            self._build_list_one_url(model_class=model_class[i],
                                     pk=list_pk[i])
            for i in range(len(model_class))]

        print("## Starting parallel_list_one: %s" % len(urls_list))
        return self.parallel_request_get(
            urls_list=urls_list, n_parallel=n_parallel,
            auth_header=auth_header)

    def parallel_save(self, list_obj_dict: List[dict],
                      n_parallel: int = None,
                      auth_header: dict = None) -> List[dict]:
        """Make [n_parallel] parallel save requests.

        Args:
            list_obj_dict:
                List of dictionaries containing PumpWood objects
                (must have at least 'model_class' key).
            n_parallel:
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            List of the save request data.

        Raises:
            No particular raises
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        urls_list = [
            self._build_save_url(obj['model_class']) for obj in list_obj_dict]
        print("## Starting parallel_save: %s" % len(urls_list))
        return self.paralell_request_post(
            urls_list=urls_list, data_list=list_obj_dict,
            n_parallel=n_parallel, auth_header=auth_header)

    def parallel_delete(self, model_class: Union[str, List[str]],
                        list_pk: List[int], n_parallel: int = None,
                        auth_header: dict = None):
        """Make many [n_parallel] delete requests.

        Args:
            model_class:
                Model Class to list one.
            list_pk:
                List of the pks to list one.
            n_parallel:
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            List of the delete request data.

        Raises:
            PumpWoodException:
                'len(model_class)[{}] != len(list_args)[{}]'. Indicates
                that length of model_class and list_args arguments are not
                equal.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        if type(model_class) is list:
            model_class = [model_class] * len(list_pk)
        if len(model_class) != len(list_pk):
            msg = 'len(model_class)[{}] != len(list_args)[{}]'.format(
                len(model_class), len(list_pk))
            raise PumpWoodException(msg)

        urls_list = [
            self._build_delete_request_url(model_class=model_class[i],
                                           pk=list_pk[i])
            for i in range(len(model_class))]

        print("## Starting parallel_delete: %s" % len(urls_list))
        return self.parallel_request_get(
            urls_list=urls_list, n_parallel=n_parallel,
            auth_header=auth_header)

    def parallel_delete_many(self, model_class: Union[str, List[str]],
                             list_args: List[dict], n_parallel: int = None,
                             auth_header: dict = None) -> List[dict]:
        """Make [n_parallel] parallel delete_many request.

        Args:
            model_class (str):
                Model Class to delete many.
            list_args (list):
                A list of list request args (filter_dict, exclude_dict).
            n_parallel:
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            List of the delete many request reponses.

        Raises:
            PumpWoodException:
                'len(model_class)[{}] != len(list_args)[{}]'. Indicates
                that length of model_class and list_args arguments
                are not equal.

        Example:
            No example yet.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        urls_list = None
        if type(model_class) is str:
            url_temp = [self._build_delete_many_request_url(model_class)]
            urls_list = url_temp * len(list_args)
        else:
            if len(model_class) != len(list_args):
                msg = 'len(model_class)[{}] != len(list_args)[{}]'.format(
                    len(model_class), len(list_args))
                raise PumpWoodException(msg)
            urls_list = [
                self._build_list_without_pag_url(m) for m in model_class]

        print("## Starting parallel_delete_many: %s" % len(urls_list))
        return self.paralell_request_post(
            urls_list=urls_list, data_list=list_args,
            n_parallel=n_parallel, auth_header=auth_header)

    def parallel_execute_action(self, model_class: Union[str, List[str]],
                                pk: Union[int, List[int]],
                                action: Union[str, List[str]],
                                parameters: Union[dict, List[dict]] = {},
                                n_parallel: int = None,
                                auth_header: dict = None) -> List[dict]:
        """Make [n_parallel] parallel execute_action requests.

        Args:
            model_class:
                Model Class to perform action over,
                or a list of model class o make diferent actions.
            pk:
                A list of the pks to perform action or a
                single pk to perform action with different paraemters.
            action:
                A list of actions to perform or a single
                action to perform over all pks and parameters.
            parameters:
                Parameters used to perform actions
                or a single dict to be used in all actions.
            n_parallel:
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            List of the execute_action request data.

        Raises:
            PumpWoodException:
                'parallel_length != len([argument])'. Indicates that function
                arguments does not have all the same lenght.

        Example:
            No example yet.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        parallel_length = None
        if type(model_class) is list:
            if parallel_length is not None:
                if parallel_length != len(model_class):
                    raise PumpWoodException(
                        'parallel_length != len(model_class)')
            else:
                parallel_length = len(model_class)

        if type(pk) is list:
            if parallel_length is not None:
                if parallel_length != len(pk):
                    raise PumpWoodException(
                        'parallel_length != len(pk)')
            else:
                parallel_length = len(pk)

        if type(action) is list:
            if parallel_length is not None:
                if parallel_length != len(action):
                    raise PumpWoodException(
                        'parallel_length != len(action)')
            else:
                parallel_length = len(action)

        if type(parameters) is list:
            if parallel_length is not None:
                if parallel_length != len(parameters):
                    raise PumpWoodException(
                        'parallel_length != len(parameters)')
            else:
                parallel_length = len(parameters)

        model_class = (
            model_class if type(model_class) is list
            else [model_class] * parallel_length)
        pk = (
            pk if type(pk) is list
            else [pk] * parallel_length)
        action = (
            action if type(action) is list
            else [action] * parallel_length)
        parameters = (
            parameters if type(parameters) is list
            else [parameters] * parallel_length)

        urls_list = [
            self._build_execute_action_url(
                model_class=model_class[i], action=action[i], pk=pk[i])
            for i in range(parallel_length)]

        print("## Starting parallel_execute_action: %s" % len(urls_list))
        return self.paralell_request_post(
            urls_list=urls_list, data_list=parameters,
            n_parallel=n_parallel, auth_header=auth_header)

    def parallel_bulk_save(self, model_class: str,
                           data_to_save: Union[pd.DataFrame, List[dict]],
                           n_parallel: int = None, chunksize: int = 1000,
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

        Returns:
            List of the responses of bulk_save.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        if type(data_to_save) is list:
            data_to_save = pd.DataFrame(data_to_save)

        chunks = break_in_chunks(df_to_break=data_to_save, chunksize=chunksize)
        url = self._build_bulk_save_url(model_class)
        urls_list = [url] * len(chunks)

        print("## Starting parallel_bulk_save: %s" % len(urls_list))
        self.paralell_request_post(
            urls_list=urls_list, data_list=chunks,
            n_parallel=n_parallel, auth_header=auth_header)

    def parallel_pivot(self, model_class: str, list_args: List[dict],
                       columns: List[str], format: str, n_parallel: int = None,
                       variables: list = None, show_deleted: bool = False,
                       auth_header: dict = None) -> List[dict]:
        """Make [n_parallel] parallel pivot request.

        Args:
            model_class:
                Model Class to retrieve.
            list_args:
                A list of list request args (filter_dict,exclude_dict,
                order_by).
            columns:
                List of columns at the pivoted table.
            format:
                Format of returned table. See pandas.DataFrame
                to_dict args.
            n_parallel:
                Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            variables:
                Restrict the fields that will be returned at the query.
            show_deleted:
                If results should include data with deleted=True. This will
                be ignored if model class does not have deleted field.
            auth_header:
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            List of the pivot request reponses.

        Raises:
            No particular raises.

        Example:
            No example yet.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        url_temp = [self._build_pivot_url(model_class)]
        urls_list = url_temp * len(list_args)
        for q in list_args:
            q["variables"] = variables
            q["show_deleted"] = show_deleted
            q["columns"] = columns
            q["format"] = format

        print("## Starting parallel_pivot: %s" % len(urls_list))
        return self.paralell_request_post(
            urls_list=urls_list, data_list=list_args,
            n_parallel=n_parallel, auth_header=auth_header)

    def get_queue_matrix(self, queue_pk: int, auth_header: dict = None,
                         save_as_excel: str = None):
        """Download model queue estimation matrix. In development..."""
        file_content = self.retrieve_file(
            model_class="ModelQueue", pk=queue_pk,
            file_field="model_matrix_file", auth_header=auth_header,
            save_file=False)
        content = gzip.GzipFile(
            fileobj=io.BytesIO(file_content["content"])).read()
        data = json.loads(content.decode('utf-8'))
        columns_info = pd.DataFrame(data["columns_info"])
        model_matrix = pd.DataFrame(data["model_matrix"])

        if save_as_excel is not None:
            writer = ExcelWriter(save_as_excel)
            columns_info.to_excel(writer, 'columns_info', index=False)
            model_matrix.to_excel(writer, 'model_matrix', index=False)
            writer.save()
        else:
            return {
                "columns_info": columns_info,
                "model_matrix": model_matrix}
