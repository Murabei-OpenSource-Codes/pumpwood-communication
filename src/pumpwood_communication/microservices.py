"""
Module microservice.py.

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
from typing import Union, List, Any
from multiprocessing import Pool
from pandas import ExcelWriter
from copy import deepcopy
from werkzeug.utils import secure_filename
from pumpwood_communication.exceptions import (
    exceptions_dict, PumpWoodException, PumpWoodUnauthorized,
    PumpWoodObjectSavingException, PumpWoodOtherException,
    PumpWoodQueryException)
from pumpwood_communication.serializers import (
    pumpJsonDump, CompositePkBase64Converter)
from pumpwood_communication.misc import unpack_dict_columns

# Creating logger for MicroService calls
Log_Format = "%(levelname)s %(asctime)s - %(message)s"
logging.basicConfig()
logging.basicConfig(stream=sys.stdout, format=Log_Format)
microservice_logger = logging.getLogger('pumpwood_comunication')
microservice_logger.setLevel(logging.INFO)


def break_in_chunks(df_to_break: pd.DataFrame, chunksize: int = 1000):
    """Break a dataframe in chunks of chunksize."""
    to_return = list()
    for g, df in df_to_break.groupby(np.arange(len(df_to_break)) // chunksize):
        to_return.append(df)
    return to_return


class PumpWoodMicroService():
    """Class to define an inter-pumpwood MicroService."""

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
                 verify_ssl: bool = True, auth_suffix: str = None,
                 debug: bool = None):
        """
        Create new PumpWoodMicroService object.

        Creates a new microservice object. If just name is passed, object must
        be initiate after with init() method.

        Args:
            name (str): Name of the microservice, helps when exceptions
                        are raised.
        Kwargs:
            server_url (str): url of the server that will be connected.
            username (str): Username that will be logged on.
            password (str): Variable to be converted to JSON and posted along
            with the request
            verify_ssl (bool): Set if microservice will verify ssl certificate
        Returns:
            PumpWoodMicroService: New PumpWoodMicroService object
        Raises:
            No particular Raises
        Example:
            No example
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
        self.auth_suffix = auth_suffix
        self.debug = debug
        self.is_mfa_login = False

    def init(self, name: str, server_url: str, username: str,
             password: str, verify_ssl: bool = True, auth_suffix: str = None,
             debug: bool = None):
        """
        Start a microservice after creation.

        Usefull in flask app config.

        Args:
            name (str): Name of the microservice, helps when exceptions
                        are raised.
            server_url (str): url of the server that will be connected.
            user_name (str): Username that will be logged on.
            password (str): Variable to be converted to JSON and posted along
            with the request
            verify_ssl (bool): Set if microservice will verify ssl certificate
        Kwargs:
            auth_suffix (str): Add a suffix to auth end-point in case of
                authentication end-point have any suffix.
        Returns:
            No return
        Raises:
            No particular Raises
        Example:
            No example
        """
        self.name = name
        self.__headers = None
        self.__username = username
        self.__password = password
        self.server_url = self._ajust_server_url(server_url)
        self.verify_ssl = verify_ssl
        self.auth_suffix = auth_suffix
        self.debug = debug

    @staticmethod
    def angular_json(request_result):
        """
        Convert text to Json removing any XSSI at the beging of JSON.

        Args:
            request_result (Request): JSON Request to be converted
        Kwargs:
            No Kwargs
        Returns:
            No return
        Raises:
            No particular Raises
        Example:
            No example
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
        """
        Return time to token expiry.

        Args:
            No Args.
        Kwargs:
            No Kwargs.
        Return:
            Return time until token expiration.
        """
        if self.__token_expiry is None:
            return None

        now_datetime = pd.to_datetime(datetime.datetime.utcnow(), utc=True)
        time_to_expiry = self.__token_expiry - now_datetime
        return time_to_expiry

    def is_credential_set(self) -> bool:
        """
        Check if username and password are set on object.

        Args:
            No Args.
        Kwargs:
            No Kwargs.
        Return:
            True if usename and password were set during object creation or
            later with init function.
        """
        return not (self.__username is None or self.__password is None)

    def login(self, force_refresh: bool = False) -> None:
        """
        Log microservice in using username and password provided.

        Args:
            No Args.
        Kwargs:
            force_refresh [bool]: Force token refresh despise still valid
                according to self.__token_expiry.
        Returns:
            No return
        Raises:
            Exception: If login response has status diferent from 200.
        Example:
            No example

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
            is_debug = os.getenv("DEBUG", "FALSE") == "TRUE"
        else:
            is_debug = self.debug

        if refresh_expiry or force_refresh or is_debug:
            login_url = None
            if self.auth_suffix is None:
                login_url = urljoin(
                    self.server_url, 'rest/registration/login/')
            else:
                temp_url = 'rest/{suffix}registration/login/'.format(
                    suffix=self.auth_suffix.lower())
                login_url = urljoin(self.server_url, temp_url)

            login_result = requests.post(
                login_url, json={
                    'username': self.__username,
                    'password': self.__password},
                verify=self.verify_ssl)

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
        """
        Ask user to confirm MFA code to login.

        Args:
            mfa_login_data [dict]: Result from login request with 'mfa_token'
                as key.
        Return [dict]:
            Return login returned with MFA confimation.
        Raise:
            Raise error if reponse is not valid.
        """
        code = input("## Please enter MFA code: ")
        url = urljoin(
            self.server_url, 'rest/registration/mfa-validate-code/')
        mfa_response = requests.post(url, headers={
            "X-PUMPWOOD-MFA-Autorization": mfa_login_data['mfa_token']},
            json={"mfa_code": code})
        self.error_handler(mfa_response)

        # Set is_mfa_login true to indicate that login required MFA
        self.is_mfa_login = True
        return PumpWoodMicroService.angular_json(mfa_response)

    def logout(self, auth_header: dict = None) -> bool:
        """
        Logout token.

        Args:
            No args.
        Kwards:
            auth_header [dict] Authentication header.
        Return [bool]:
            True if logout was ok.
        """
        resp = self.request_post(
            url='rest/registration/logout/',
            data={}, auth_header=auth_header)
        return resp is None

    def logout_all(self, auth_header: dict = None) -> bool:
        """
        Logout all tokens from user.

        Args:
            No args.
        Kwards:
            auth_header [dict] Authentication header.
        Return [bool]:
            True if logout all was ok.
        """
        resp = self.request_post(
            url='rest/registration/logoutall/',
            data={}, auth_header=auth_header)
        return resp is None

    def set_auth_header(self, auth_header: dict,
                        token_expiry: pd.Timestamp) -> None:
        """
        Set auth_header and token_expiry date.

        Args:
            auth_header [dict]: Authentication header to be set.
            token_expiry [pd.Timestamp]: Token expiry datetime to be set.
        Return [None]:
            No return.
        """
        self.__auth_header = auth_header
        self.__token_expiry = pd.to_datetime(token_expiry, utc=True)

    def get_auth_header(self) -> dict:
        """
        Retrieve auth_header and token_expiry from object.

        Args:
            No Args.
        Kwargs:
            No Kwargs.
        Return:
            Return authorization header and token_expiry datetime from object.
        """
        return {
            "auth_header": self.__auth_header,
            "token_expiry": self.__token_expiry}

    def check_if_logged(self, auth_header: dict) -> bool:
        """
        Check if user is logged.

        Args:
            auth_header (dict): AuthHeader to substitute the
                microservice original
        Return [bool]:
            Return True if auth_header is looged and False if not
        """
        try:
            check = self.request_get(
                url="rest/registration/check/", auth_header=auth_header)
        except PumpWoodUnauthorized:
            return False
        return check

    def get_user_info(self, auth_header: dict = None) -> dict:
        """
        Get user info.

        Args:
            No Args:

        Return [dict]:
            A serialized user object with information of the logged user.
        """
        user_info = self.request_get(
            url="rest/registration/retrieveauthenticateduser/",
            auth_header=auth_header)
        return user_info

    def _check__auth_header(self, auth_header, multipart: bool = False):
        """
        Check if auth_header is set or auth_header if provided.

        Args:
            auth_header (dict): AuthHeader to substitute the
                                microservice original
        Kwargs:
            No Kwargs
        Returns:
            dict: Return a header dict to be used in requests.
        Raises:
            PumpWoodUnauthorized: If microservice is not logged and a
                                  auth_header method argument is not provided.
            PumpWoodUnauthorized: If microservice is logged and a auth_header
                                  method argument is provided.
        Example:
            No example

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

    def error_handler(cls, response):
        """
        Handle request error.

        Check if is a Json and propagate the error with
        same type if possible. If not Json raises the content.

        Arg:
            response (Response): response to be handled.
        Kwargs:
            No kwargs.
        Returns:
            No return.
        Raises:
            Exception: If content-type is not application/json.
            Exception: If content-type is application/json, but type not
                       present or not recognisable.
            Other Exception: If content-type is application/json if type is
                             present and recognisable.
        Example:
            No example

        """
        if not response.ok:
            utcnow = datetime.datetime.utcnow()
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

            # Removing previus error stack
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

            # Propagate error
            exception_message = response_dict.get("message", "")
            exception_type = response_dict.get("type", None)
            if exception_type is not None:
                raise exceptions_dict[exception_type](
                    message=exception_message,
                    status_code=response.status_code,
                    payload=payload)
            else:
                is_invalid_token = cls.is_invalid_token_response(response)
                response_dict["!exception_stack!"] = exception_stack
                if is_invalid_token:
                    raise PumpWoodUnauthorized(
                        message="Invalid token.",
                        payload=response.json())
                else:
                    raise PumpWoodOtherException(
                        message="Not mapped exception JSON",
                        payload=response_dict)

    @classmethod
    def is_invalid_token_response(cls,
                                  response: requests.models.Response) -> bool:
        """
        Check if reponse has invalid token error.

        Args:
            response [requests.models.Response]: Request reponse to check for
                invalid token.
        Return [bool]:
            Return True if response has an invalid token status.
        """
        if response.status_code == 401:
            return True
        return False

    def request_post(self, url: str, data: any, files: list = None,
                     auth_header: dict = None, parameters: dict = {}):
        """
        Make a POST a request to url with data as Json payload.

        Args:
            url (str): Url to make the request.
            data (any); Data to be used as Json payload.
        Kwargs:
            files(list of tuples): A list of tuples with
                                   (file name, [file1, file2, ...]).
            params [dict]: Url parameters.
            auth_header(dict): Auth data to overhide microservice's.
        Returns:
            any: Return the post result
        Raises:
            Response is passed to error_handler function.
        Example:
            No example

        """
        # If parameters are not none convert them to json before
        # sending information on query string, 'True' is 'true' on javascript
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
                headers=request_header)

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
                    headers=request_header)

        # Request with files are done using multipart serializing all fields
        # as json
        else:
            request_header = self._check__auth_header(
                auth_header=auth_header, multipart=True)
            post_url = urljoin(self.server_url, url)
            temp_data = {'__json__': pumpJsonDump(data)}
            response = requests.post(
                url=post_url, data=temp_data, files=files, params=parameters,
                verify=self.verify_ssl, headers=request_header)

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
                    headers=request_header)

        # Handle errors and re-raise if Pumpwood Exceptions
        self.error_handler(response)

        # Check if reponse is a file
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
        """
        Make a GET a request to url with data as Json payload.

        Args:
            url (str): Url to make the request.
        Kwargs:
            parameters (dict): Url parameters to make the request.
            auth_header (dict): Authentication dictionary.
        Returns:
            any: Return the post result
        Raises:
            Response is passed to error_handler function.
        Example:
            No example
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
            params=parameters)

        retry_with_login = (
            self.is_invalid_token_response(response) and
            auth_header is None)
        if retry_with_login:
            self.login(force_refresh=True)
            request_header = self._check__auth_header(auth_header=auth_header)
            response = requests.get(
                get_url, verify=self.verify_ssl, headers=request_header,
                params=parameters)

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
        """
        Make a DELETE a request to url with data as Json payload.

        Args:
            url (str): Url to make the request.
        Kwargs:
            parameters (dict): Dictionary with Urls parameters.
            auth_header (dict): Auth header if microservice not logged.
        Returns:
            any: Return the post result
        Raises:
            Response is passed to error_handler function.
        Example:
            No example
        """
        request_header = self._check__auth_header(auth_header)

        post_url = self.server_url + url
        response = requests.delete(
            post_url, verify=self.verify_ssl, headers=request_header,
            params=parameters)

        # Retry request if token is not valid forcing token renew
        retry_with_login = (
            self.is_invalid_token_response(response) and
            auth_header is None)
        if retry_with_login:
            self.login(force_refresh=True)
            request_header = self._check__auth_header(auth_header=auth_header)
            response = requests.delete(
                post_url, verify=self.verify_ssl, headers=request_header,
                params=parameters)

        # Re-raise Pumpwood Exceptions
        self.error_handler(response)
        return PumpWoodMicroService.angular_json(response)

    def list_registered_routes(self, auth_header: dict = None):
        """List routes that have been registed at Kong."""
        list_url = None
        if self.auth_suffix is None:
            list_url = 'rest/pumpwood/routes/'
        else:
            list_url = 'rest/{suffix}pumpwood/routes/'.format(
                suffix=self.auth_suffix.lower())
        routes = self.request_get(
            url=list_url, auth_header=auth_header)
        for key, item in routes.items():
            item.sort()
        return routes

    def is_microservice_registered(self, microservice: str,
                                   auth_header: dict = None) -> bool:
        """
        List routes that have been registed at Kong.

        Args:
            microservice [str]: Service associated with microservice
                registered on Pumpwood Kong.
        Kwargs:
            No Kwargs.
        Return:
            Return true if microservice is registered.
        """
        routes = self.list_registered_routes(auth_header=auth_header)
        return microservice in routes.keys()

    def list_registered_endpoints(self, auth_header: dict = None):
        """List routes that have been registed at Kong."""
        list_url = None
        if self.auth_suffix is None:
            list_url = 'rest/pumpwood/endpoints/'
        else:
            list_url = 'rest/{suffix}pumpwood/endpoints/'.format(
                suffix=self.auth_suffix.lower())
        routes = self.request_get(
            url=list_url, auth_header=auth_header)
        return routes

    def dummy_call(self, payload: dict = None,
                   auth_header: dict = None) -> dict:
        """
        Return a dummy call to ensure headers and payload reaching app.

        Args:
            No args.
        Kwards:
            payload (dict]): Payload to be returned by the dummy call
                end-point.
            auth_header (dict): Auth header if microservice not logged.

        Return:
            Return a dictonary with:
            - full_path (dict): Full path of the request.
            - method (dict): Method used at the call
            - headers (dict): Headers at the request.
            - data (dict): Post payload sent at the request.
        """
        list_url = None
        if self.auth_suffix is None:
            list_url = 'rest/pumpwood/dummy-call/'
        else:
            list_url = 'rest/{suffix}pumpwood/dummy-call/'.format(
                suffix=self.auth_suffix.lower())

        if payload is None:
            return self.request_get(
                url=list_url, auth_header=auth_header)
        else:
            return self.request_post(
                url=list_url, data=payload,
                auth_header=auth_header)

    def dummy_raise(self, exception_class: str, exception_deep: int,
                    payload: dict = {}, auth_header: dict = None) -> None:
        """
        Raise an Pumpwood error with the payload.

        Can be used for debug purposes.

        Args:
            exception_class (str): Class of the exception to be raised.
            exception_deep (int): Deep of the exception in microservice
                calls.
        Kwards:
            payload (dict]): Payload to be returned by the dummy call
                end-point.
            auth_header (dict): Auth header if microservice not logged.
        Return:
            Should not return any results, all possible call should result
            in raising the correspondent error.
        Exceptions:
            Should raise the correspondent error passed on exception_class
            arg, with payload.
        """
        url = 'rest/pumpwood/dummy-raise/'
        payload["exception_class"] = exception_class
        payload["exception_deep"] = exception_deep
        self.request_post(url=url, data=payload, auth_header=auth_header)

    def get_pks_from_unique_field(self, model_class: str, field: str,
                                  values: List[Any]) -> pd.DataFrame:
        """
        Get pk using unique fields values.

        Use unique field values to retrieve pk of the objects.

        Args:
            model_class [str]: Model class of the objects.
            field [str]: Unique field to fetch pk.
            values [List[Any]]: List of the unique fields used to fetch
                primary keys.
        Return [pd.DataFrame]:
            Return a dataframe in same order as values with columns:
                - pk: correspondent primary key of the unique value.
                - [field]: Column with same name of field argument,
                    correspondent to pk.
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
            "pk": values_series.map(pk_map).values,
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
             **kwargs) -> list:
        """
        List objects with pagination.

        Function to post at list end-point (resumed data) of PumpWood like
        systems, results will be paginated. To get next pag, send recived pk at
        exclude dict (ex.: exclude_dict={id__in: [1,2,...,30]}).

        Args:
          model_class (str): Model class of the end-point

        Kwargs:
          filter_dict (dict): Filter dict to be used at the query
            (objects.filter arguments).
          exclude_dict (dict):  Exclude dict to be used at the query
            (objects.exclude arguments).
          order_by (list): Ordering list to be used at the query
            (objects.order_by arguments).
          auth_header(dict): Dictionary containing the auth header.
          fields(list[str]): Select the fields to be returned by the list
            end-point.
          default_fields [bool]: Return the fields specified at
              self.list_fields.
          limit [int]: Set the limit of elements of the returned query.
          foreign_key_fields [bool]: Return forenging key objects.

        Returns:
          list: Contaiing objects serialized by list Serializer.

        Raises:
          No especific raises.

        Example:
          No example yet.

        """
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
                       chunk_size: int = 50000, **kwargs) -> list:
        """
        List object fetching them by chucks using pk to paginate.

        List data by chunck to load by datasets without breaking the backend
        or receive server timeout. It load chunks orderring the results using
        id of the tables, it can be changed but it should be unique otherwise
        unexpected results may occur.

        Args:
          model_class (str): Model class of the end-point

        Kwargs:
          filter_dict (dict) = {}: Filter dict to be used at the query
            (objects.filter arguments).
          exclude_dict (dict) = {}:  Exclude dict to be used at the query
            (objects.exclude arguments).
          auth_header (dict) = None: Dictionary containing the auth header.
          fields (list[str]) = None: Select the fields to be returned by the
            list end-point.
          default_fields (bool) = False: Return the fields specified at
              self.list_fields.
          chuck_size [int]: Number of objects to be fetched each query.

        Returns:
          list: Contaiing objects serialized by list Serializer.

        Raises:
          No especific raises.

        Example:
          No example yet.

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
        """
        List object without pagination.

        Function to post at list end-point (resumed data) of PumpWood like
        systems, results won't be paginated.
        **Be carefull with large returns.**

        Args:
          model_class (str): Model class of the end-point

        Kwargs:
          filter_dict (dict): Filter dict to be used at the query
            (objects.filter arguments)
          exclude_dict (dict):  Exclude dict to be used at the query
            (objects.exclude arguments)
          order_by (list): Ordering list to be used at the query
            (objects.order_by arguments)
          auth_header(dict): Dictionary containing the auth header.
          return_type(str): Set the return type, can be [list, dataframe].
          convert_geometry(bool) = True: Covert geometry to shapely.
          fields(list[str]): Select the fields to be returned by the list
            end-point.
          default_fields [bool]: Return the fields specified at
              self.list_fields.
          foreign_key_fields [bool]: Return forenging key objects.
        Returns:
          list: Contaiing objects serialized by list Serializer.

        Raises:
          No especific raises.

        Example:
          No example yet.

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
                        exclude_dict: dict = {}, auth_header: dict = None):
        """List dimensions avaiable for model_class with the filters.

        Parameters
        ----------
        Args:
          model_class: str
            model_class (str): Model class of the end-point

        Kwargs:
          filter_dict: dict = {}
            Filter dict to be used at the query (objects.filter arguments).
          exclude_dict: dict = {}
            Exclude dict to be used at the query (objects.exclude arguments).
          auth_header: dict= {}
            Dictionary containing the auth header.

        Returns
        -------
        list
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
                              auth_header: dict = None):
        """List dimensions avaiable for model_class with the filters.

        Parameters
        ----------
        Args:
          model_class: str
            Model class of the end-point.
          key: str
            Key to list the avaiable values using the query filter and exclude.
        Kwargs:
          filter_dict: dict = {}
            Filter dict to be used at the query (objects.filter arguments).
          exclude_dict: dict = {}
            Exclude dict to be used at the query (objects.exclude arguments).
          auth_header: dict= {}
            Dictionary containing the auth header.

        Returns
        -------
        list
            List of keys avaiable in results from the query dict.
        """
        url_str = self._build_list_dimension_values(model_class)
        post_data = {'filter_dict': filter_dict, 'exclude_dict': exclude_dict,
                     'key': key}
        return self.request_post(
            url=url_str, data=post_data, auth_header=auth_header)

    @staticmethod
    def _build_list_one_url(model_class, pk):
        return "rest/%s/retrieve/%s/" % (model_class.lower(), pk)

    def list_one(self, model_class: str, pk: int, fields: list = None,
                 default_fields: bool = True, foreign_key_fields: bool = False,
                 related_fields: bool = False, auth_header: dict = None):
        """
        Retrieve an object using list serializer (simple).

        Function to get object serialized by retrieve end-point with list
        serializer.

        Args:
          model_class (str): Model class of the end-point
          pk (int): Object pk
        Kwargs:
          auth_header(dict): Dictionary containing the auth header.
        Returns:
          list: Contaiing objects serialized by retrieve Serializer.
        Raises:
          No especific raises.
        Example:
          No example yet.
        """
        url_str = self._build_list_one_url(model_class, pk)
        return self.request_get(
            url=url_str, parameters={
                "fields": fields, "default_fields": default_fields,
                "foreign_key_fields": foreign_key_fields,
                "related_fields": related_fields,
            }, auth_header=auth_header)

    @staticmethod
    def _build_retrieve_url(model_class: str, pk: int):
        return "rest/%s/retrieve/%s/" % (model_class.lower(), pk)

    def retrieve(self, model_class: str, pk: int,
                 foreign_key_fields: bool = False,
                 related_fields: bool = False, fields: list = None,
                 auth_header: dict = None):
        """
        Retrieve an object from PumpWood.

        Function to get object serialized by retrieve end-point
        (more detailed data).

        Args:
          model_class (str): Model class of the end-point
          pk (int): Object pk
        Kwargs:
          foreign_key_fields [bool]: Return forenging key objects.
          related_fields [bool]: Return related fields information.
          fields [list]:
          auth_header(dict): Dictionary containing the auth header.
        Returns:
          list: Contaiing objects serialized by retrieve Serializer.
        Raises:
          No especific raises.
        Example:
          No example yet.

        """
        url_str = self._build_retrieve_url(model_class=model_class, pk=pk)
        return self.request_get(
            url=url_str,
            parameters={
                "fields": fields,
                "foreign_key_fields": foreign_key_fields,
                "related_fields": related_fields,
            }, auth_header=auth_header)

    @staticmethod
    def _build_retrieve_file_url(model_class: str, pk: int):
        return "rest/%s/retrieve-file/%s/" % (model_class.lower(), pk)

    def retrieve_file(self, model_class: str, pk: int, file_field: str,
                      auth_header: dict = None, save_file: bool = True,
                      save_path: str = "./", file_name: str = None,
                      if_exists: str = "fail"):
        """
        Retrieve a file from PumpWood.

        Args:
          model_class (str): Class of the model to retrieve file.
          pk (int): Pk of the object associeted file.
          file_field (str): Field of the file to be downloaded.
        Kwargs:
          auth_header(dict): Dictionary containing the auth header.
          save_file (bool): If data is to be saved as file or return get
            response.
          save_path (str): Path of the directory to save file.
          file_name (str): Name of the file, if None it will have same name as
                saved in PumpWood.
          if_exists {'fail', 'change_name', 'overwrite', 'skip'}: Set what to
            do if there is a file with same name. Skip will not download file
            if there is already with same os.path.join(save_path, file_name),
            file_name must be set for skip argument.
        Returns:
          requset.response or str
        Raises:
          No especific raises.
        Example:
          No example yet.

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
        """
        Retrieve a file from PumpWood.

        Args:
          model_class (str): Class of the model to retrieve file.
          pk (int): Pk of the object associeted file.
          file_field (str): Field of the file to be downloaded.
          file_name (str): Name of the file, if None it will have same name as
                saved in PumpWood.

        Kwargs:
          auth_header(dict): Dictionary containing the auth header.
          save_path (str): Path of the directory to save file.
          if_exists {'fail', 'change_name', 'overwrite'}: Set what to do if
            there is a file with same name.

        Returns:
          requset.response or str

        Raises:
          No especific raises.

        Example:
          No example yet.
        """
        request_header = self._check__auth_header(auth_header)

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
                get_url, verify=self.verify_ssl, headers=request_header,
                params={"file-field": file_field}) as response:
            self.error_handler(response)
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
        return file_path

    @staticmethod
    def _build_save_url(model_class):
        return "rest/%s/save/" % (model_class.lower())

    def save(self, obj_dict, files: dict = None, auth_header: dict = None):
        """
        Save or Update a new object.

        Function to save or update a new model_class object. If obj_dict{'pk'}
        is None or not defined a new object will be created. The obj
        model class is defided at obj_dict['model_class'] and if not defined an
        PumpWoodObjectSavingException will be raised.

        Args:
          obj_dict (dict): Model data dictionary. It must have 'model_class'
                           key and if 'pk' key is not defined a new object will
                           be created, else object with pk will be updated.
        Kwargs:
          files (dict): A dictionary of files to be added to as a multi-part
                        post request.
          auth_header(dict): Dictionary containing the auth header.
        Returns:
          dict: Updated/Created object data.
        Raises:
          PumpWoodObjectSavingException(
              'To save an object obj_dict must have model_class defined.'):
            Will be raised if model_class key is not present on
            obj_dict dictionary
        Example:
          No example yet.

        """
        model_class = obj_dict.get('model_class')
        if model_class is None:
            raise PumpWoodObjectSavingException(
                'To save an object obj_dict must have model_class defined.')

        url_str = self._build_save_url(model_class)
        return self.request_post(
            url=url_str, data=obj_dict, files=files,
            auth_header=auth_header)

    @staticmethod
    def _build_save_streaming_file_url(model_class, pk):
        return "rest/{model_class}/save-file-streaming/{pk}/".format(
            model_class=model_class.lower(), pk=pk)

    def save_streaming_file(self, model_class: str, pk: int, file_field: str,
                            file: io.BufferedReader, file_name: str = None,
                            auth_header: dict = None):
        """
        Stream file to PumpWood.

        Args:
            model_class (str): Model class of the object.
            pk (int): pk of the object.
            file_field (str): File field that will receive file stream.
            file (io.BufferedReader): File to upload.

        Kwargs:
            file_name (str): Name of the file, is not set it will be saved as
                {pk}__{file_field}.{extension at permited extension}
            auth_header (dict): Authentication dictionary.
        """
        request_header = self._check__auth_header(auth_header=auth_header)
        request_header["Content-Type"] = "application/octet-stream"
        post_url = self.server_url + self._build_save_streaming_file_url(
            model_class=model_class, pk=pk)

        parameters = {}
        parameters["file_field"] = file_field
        if file_name is not None:
            parameters["file_name"] = file_name

        response = requests.post(
            url=post_url, data=file, params=parameters,
            verify=self.verify_ssl, headers=request_header, stream=True)

        file_last_bite = file.tell()
        self.error_handler(response)
        json_response = PumpWoodMicroService.angular_json(response)

        if file_last_bite != json_response["bytes_uploaded"]:
            template = "Saved bytes in streaming [{}] differ from file " + \
                "bites [{}]."
            raise PumpWoodException(
                    template.format(
                        json_response["bytes_uploaded"], file_last_bite))
        return json_response["file_path"]

    @staticmethod
    def _build_delete_request_url(model_class, pk):
        return "rest/%s/delete/%s/" % (model_class.lower(), pk)

    def delete(self, model_class: str, pk: int, auth_header: dict = None):
        """
        Send delete request to a PumpWood object.

        Delete (or whatever the PumpWood system have been implemented) the
        object with the specified pk.

        Args:
            model_class (str): Model class to delete the object
            pk (int): Object pk to be deleted (or whatever the PumpWood system
            have been implemented)
        Kwargs:
            auth_header(dict): Dictionary containing the auth header.s
        Returns:
            Dependends on backend implementation
        Raises:
            Dependends on backend implementation
        Example:
            No example yet.

        """
        url_str = self._build_delete_request_url(model_class, pk)
        return self.request_delete(url=url_str, auth_header=auth_header)

    @staticmethod
    def _build_remove_file_field(model_class, pk):
        return "rest/%s/remove-file-field/%s/" % (model_class.lower(), pk)

    def remove_file_field(self, model_class: str, pk: int, file_field: str,
                          auth_header: dict = None):
        """
        Send delete request to a PumpWood object.

        Delete (or whatever the PumpWood system have been implemented) the
        object with the specified pk.

        Args:
            model_class (str): Model class to delete the object
            pk (int): Object pk to be deleted (or whatever the PumpWood system
                have been implemented)
            file_field (str): File field to be removed.
        Kwargs:
            auth_header(dict): Dictionary containing the auth header.s
        Returns:
            Dependends on backend implementation
        Raises:
            Dependends on backend implementation
        Example:
            No example yet.

        """
        url_str = self._build_remove_file_field(model_class, pk)
        return self.request_delete(
            url=url_str, auth_header=auth_header,
            parameters={"file_field": file_field})

    @staticmethod
    def _build_delete_many_request_url(model_class):
        return "rest/%s/delete/" % (model_class.lower(), )

    def delete_many(self, model_class: str, filter_dict: dict = {},
                    exclude_dict: dict = {}, auth_header: dict = None):
        """
        Send a post request to a delete objects in a query.

        Delete objects in the results of a query.

        Args:
            model_class (str): Model class to delete the object
            filter_dict (dict): Dictionary to make filter query.
            exclude_dict (dict): Dictionary to make exclude query.
        Kwargs:
            auth_header (dict): Dictionary containing the auth header
        Returns:
            bool: True if delete is ok.
        Raises:
            Dependends on backend implementation
        Example:
            No example yet.

        """
        url_str = self._build_delete_many_request_url(model_class)
        return self.request_post(
            url=url_str,
            data={'filter_dict': filter_dict, 'exclude_dict': exclude_dict},
            auth_header=auth_header)

    def list_actions(self, model_class: str, auth_header: dict = None):
        """
        Return a list of all actions avaiable at this model class.

        Args:
          model_class (str): Model class to list possible actions.

        Kwargs:
          auth_header(dict): Dictionary containing the auth header.

        Returns:
          list: List of possible actions and its descriptions

        Raises:
          Dependends on backend implementation

        Example:
          No example yet.

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
                       auth_header: dict = None):
        """
        Execute action.

        If action is static or classfunction no pk
        is necessary.

        Args:
          model_class (str): Model class to run action the object
          action (str): Action that will be performed.

        Kwargs:
          auth_header(dict): Dictionary containing the auth header.
          parameters(dict): Dictionary with the function parameters.
          files(list of tuples): A list of tuples with
                                 (file name, [file1, file2, ...]).

        Returns:
          pk (int): Pk of the object that action will be performed over.
          parameters (dict): Parameter dictionary to use in the action.

        Raises:
          dict: Return a dict with four keys:
            - result: Result of the action.
            - action: Action description.
            - parameters: Parameters used to perform action.
            - obj: Object over which were performed the action.

        Example:
          No example yet.

        """
        url_str = self._build_execute_action_url(
            model_class=model_class, action=action, pk=pk)
        return self.request_post(
            url=url_str, data=parameters, files=files,
            auth_header=auth_header)

    def search_options(self, model_class: str, auth_header: dict = None):
        """
        Return search options.

        Returns options to search, like forenging keys and choice fields.
        Args:
            model_class (str): Model class to check search parameters
        Kwargs:
            auth_header(dict): Dictionary containing the auth header.
        Returns:
            dict: Dictionary with search parameters
        Raises:
            Dependends on backend implementation
        Example:
            No example yet.

        """
        url_str = "rest/%s/options/" % (model_class.lower(), )
        return self.request_get(url=url_str, auth_header=auth_header)

    def fill_options(self, model_class, parcial_obj_dict: dict = {},
                     field: str = None, auth_header: dict = None):
        """
        Return options for object fields.

        This function send partial object data and return options to finish
        object fillment.

        Args:
          model_class (str): Model class to check filment options.
        Kwargs:
          parcial_obj_dict (dict): Partial object data
          field (str): Get an specific field information
          auth_header(dict): Dictionary containing the auth header.
        Returns:
          dict: Dictionary with possible data.
        Raises:
          Dependends on backend implementation
        Example:
          No example yet.
        """
        url_str = "rest/%s/options/" % (model_class.lower(), )
        if (field is not None):
            url_str = url_str + field
        return self.request_post(
            url=url_str, data=parcial_obj_dict,
            auth_header=auth_header)

    def list_options(self, model_class: str, auth_header: dict):
        """
        Return options to render list views.

        This function send partial object data and return options to finish
        object fillment.

        Args:
          model_class (str): Model class to check filment options.
        Kwargs:
          auth_header(dict): Dictionary containing the auth header.
        Returns:
          dict: Dictionary with possible data.
        Raises:
          Dependends on backend implementation.
        Example:
          No example yet.
        """
        url_str = "rest/{basename}/list-options/".format(
            basename=model_class.lower())
        return self.request_get(
            url=url_str, auth_header=auth_header)

    def retrieve_options(self, model_class: str, auth_header: dict = None):
        """
        Return options to render retrieve views.

        Args:
          model_class (str): Model class to check filment options.
        Kwargs:
          auth_header(dict): Dictionary containing the auth header.
        Returns:
          dict: Dictionary with possible data.
        Raises:
          Dependends on backend implementation.
        Example:
          No example yet.
        """
        url_str = "rest/{basename}/retrieve-options/".format(
            basename=model_class.lower())
        return self.request_get(
            url=url_str, auth_header=auth_header)

    def fill_validation(self, model_class: str, parcial_obj_dict: dict = {},
                        field: str = None, auth_header: dict = None,
                        user_type: str = 'api'):
        """
        Return options for object fields.

        This function send partial object data and return options to finish
        object fillment.

        Args:
          model_class (str): Model class to check filment options.
        Kwargs:
          parcial_obj_dict (dict): Partial object data
          field (str): Get an specific field information
          auth_header(dict): Dictionary containing the auth header.
        Returns:
          dict: Dictionary with possible data.
        Raises:
          Dependends on backend implementation
        Example:
          No example yet.
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

    def pivot(self, model_class: str, columns: list = [], format: str = 'list',
              filter_dict: dict = {}, exclude_dict: dict = {},
              order_by: list = [], variables: list = None,
              show_deleted=False, auth_header: dict = None):
        """
        Pivot object data acording to columns specified.

        Args:
            model_class (str): Model class to be pivoted.
        Kwargs:
            columns (str): Fields to be used as columns.
            format (str): Format to be used to convert pandas.DataFrame to
                          dictionary, must be in ['dict','list','series',
                          'split', 'records','index'].
            filter_dict (dict): Dictionary to to be used in objects.filter
                                argument (Same as list end-point).
            exclude_dict (dict): Dictionary to to be used in objects.exclude
                                 argument (Same as list end-point).
            order_by (list): Dictionary to to be used in objects.order_by
                             argument (Same as list end-point).
            variables (list[str]) = None: List of the variables to be returned,
                if None, the default variables will be returned.
            show_deleted (bool): If deleted data should be returned.
            auth_header(dict): Dictionary containing the auth header.
        Returns:
            dict or list: Depends on format type used to convert
                          pandas.DataFrame
        Raises:
            Dependends on backend implementation
        Example:
            No example yet.
        """
        url_str = self._build_pivot_url(model_class)
        post_data = {
            'columns': columns, 'format': format,
            'filter_dict': filter_dict, 'exclude_dict': exclude_dict,
            'order_by': order_by, "variables": variables,
            "show_deleted": show_deleted}
        return self.request_post(
            url=url_str, data=post_data, auth_header=auth_header)

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
                            exclude_dict: dict = {}, fields: list = None,
                            show_deleted: bool = False,
                            auth_header: dict = None,
                            chunk_size: int = 1000000,
                            n_parallel: int = None,
                            create_composite_pk: bool = False,
                            start_date: str = None,
                            end_date: str = None):
        """
        Use the same end-point as pivot which does not unserialize results.

        Args:
            model_class (str): Model class to be pivoted.

        Kwargs:
            filter_dict (dict): Dictionary to to be used in objects.filter
                                argument (Same as list end-point).
            exclude_dict (dict): Dictionary to to be used in objects.exclude
                                 argument (Same as list end-point).
            fields (list[str]) = None: List of the variables to be returned,
                if None, the default variables will be returned.
            show_deleted (bool): If deleted data should be returned.
            auth_header(dict): Dictionary containing the auth header.
            chunk_size (int): Limit of data to fetch per call.
            n_parallel (int): Number of parallel process to perform.

        Returns:
            dict or list: Depends on format type used to convert
                          pandas.DataFrame

        Raises:
            Dependends on backend implementation

        Example:
            No example yet.
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
                        # right interval so subsequence querys does
                        # not overlap
                        if i != len(month_sequence) - 1:
                            request_filter_dict_t["time__gte"] = \
                                month_sequence[i]["start"]
                            request_filter_dict_t["time__lt"] = \
                                month_sequence[i]["end"]

                        # At the last interaval use closed right interval so
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
        return resp_df

    @staticmethod
    def _build_bulk_save_url(model_class: str):
        return "rest/%s/bulk-save/" % (model_class.lower(),)

    def bulk_save(self, model_class: str, data_to_save: list,
                  auth_header: dict = None):
        """
        Save a list of objects.

        Args:
            model_class(str): Data model class.
            data_to_save(list): A list of objects to be saved.
        Kwargs:
            auth_header(dict): A dictionary with authorization headers.
        Return:
            dict['saved_count']: Number of saved objects.
        """
        url_str = self._build_bulk_save_url(model_class=model_class)
        return self.request_post(url=url_str, data=data_to_save,
                                 auth_header=auth_header)

    ########################
    # Paralell aux functions
    def _request_get_wrapper(self, arguments: dict):
        try:
            results = self.request_get(**arguments)
            sys.stdout.write(".")
            sys.stdout.flush()
            return results
        except Exception as e:
            raise Exception("Error on parallel get: " + str(e))

    @staticmethod
    def flatten_parallel(parallel_result: list):
        """
        Concat all parallel return to one list.

        Args:
            parallel_result (list): A list of lists to be flated (concatenate
                all lists into one).
        Return:
            A list with all sub list itens.
        """
        return [
            item for sublist in parallel_result
            for item in sublist]

    def parallel_request_get(self, urls_list: list, n_parallel: int = None,
                             auth_header: dict = None):
        """
        Make many [n_parallel] get request.

        Args:
            urls_list (list): List of urls to make get requests.
        Kwargs:
            n_parallel (int): Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header(dict): Dictionary containing the auth header.
        Returns:
            list: List of the get request reponses.
        Raises:
            No particular raises
        Example:
            No example yet.

        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        pool_arguments = [
            {'url': u, 'auth_header': auth_header} for u in urls_list]

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

    def paralell_request_post(self, urls_list: list, data_list: list,
                              n_parallel: int = None,
                              auth_header: dict = None):
        """
        Make many [n_parallel] post request.

        Args:
            urls_list (list<str>): List of urls to make get requests.
            data_list (list<any>): List of data to be used as post payloads.
        Kwargs:
            n_parallel (int): Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header(dict): Dictionary containing the auth header.
        Returns:
            list: List of the post request reponses.
        Raises:
            No particular raises
        Example:
            No example yet.

        """
        if len(urls_list) != len(data_list):
            raise Exception(
                'len(urls_list) must be equal to len(data_list)')

        pool_arguments = []
        for i in range(len(urls_list)):
            pool_arguments.append(
                {'url': urls_list[i], 'data': data_list[i],
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

    def paralell_request_delete(self, urls_list: list, n_parallel: int = None,
                                auth_header: dict = None):
        """
        Make many [n_parallel] delete request.

        Args:
            urls_list (list): List of urls to make get requests.
        Kwargs:
            n_parallel (int): Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header(dict): Dictionary containing the auth header.
        Returns:
            list: List of the get request reponses.
        Raises:
            No particular raises
        Example:
            No example yet.

        """
        pool_arguments = [
            {'url': u, 'auth_header': auth_header} for u in urls_list]

        with Pool(n_parallel) as p:
            results = p.map(self._request_delete_wrapper, pool_arguments)
        print("|")
        return results

    ####################
    # Paralell functions
    def parallel_retrieve(self, model_class: Union[str, List[str]],
                          list_pk: List[int], n_parallel: int = None,
                          auth_header: dict = None):
        """
        Make many [n_parallel] retrieve request.

        Args:
            model_class (str, List[str]): Model Class to retrieve.
            list_pk (List[int]): List of the pks to retrieve.
        Kwargs:
            n_parallel (int): Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header(dict): Dictionary containing the auth header.
        Returns:
            list: List of the retrieve request reponses.
        Raises:
            No particular raises
        Example:
            No example yet.

        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        if type(model_class) != list:
            model_class = [model_class]*len(list_pk)

        if len(model_class) != len(list_pk):
            raise Exception('len(model_class) != len(list_pk)')

        urls_list = [
            self._build_retrieve_url(model_class=model_class[i],
                                     pk=list_pk[i])
            for i in range(len(model_class))]
        return self.parallel_request_get(
            urls_list=urls_list, n_parallel=n_parallel,
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
        """
        Make many [n_parallel] retrieve request.

        Args:
            model_class (str, List[str]): Model Class to retrieve.
            list_pk (List[int]): List of the pks to retrieve.
            file_field (str): Indicates the file field to download from.
        Kwargs:
            n_parallel (int): Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            save_path (str) = "./"
            save_file (bool) = True: True save file locally, False return
                file content as bites.
            list_file_name (List[str]) = None: Set a file name for each file
                download.
            if_exists (str) = "fail": Set how treat when a file will be saved
                and there is another at same path. "fail" will raise an error;
                "overwrite" will overwrite the file with the new one; "skip"
                when list_file_name is set, check before downloaded it file
                already exists, if so skip the download.
            auth_header(dict): Dictionary containing the auth header.

        Returns:
            list: List of the retrieve request reponses.
        Raises:
            No particular raises
        Example:
            No example yet.

        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        if list_file_name is not None:
            if len(list_file_name) != len(list_pk):
                raise PumpWoodException((
                    "Lenght of list_file_name and list_pk are not equal:\n"
                    "len(list_file_name)={list_file_name}; "
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
                      auth_header: dict = None):
        """
        Make many [n_parallel] list request.

        Args:
            model_class (str): Model Class to retrieve.
            list_args_list (list): A list of list request args (filter_dict,
                                   exclude_dict, order_by).
        Kwargs:
            n_parallel (int): Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header(dict): Dictionary containing the auth header.
        Returns:
            list: List of the retrieve request reponses.
        Raises:
            No particular raises
        Example:
            No example yet.

        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        urls_list = None
        if type(model_class) == str:
            urls_list = [self._build_list_url(model_class)]*len(list_args)
        else:
            if len(model_class) != len(list_args):
                raise Exception('len(model_class) != len(list_args)')
            urls_list = [self._build_list_url(m) for m in model_class]

        print("## Starting parallel_list: %s" % len(urls_list))
        return self.paralell_request_post(
            urls_list=urls_list, data_list=list_args,
            n_parallel=n_parallel, auth_header=auth_header)

    def parallel_list_without_pag(self, model_class: Union[str, List[str]],
                                  list_args: List[dict],
                                  n_parallel: int = None,
                                  auth_header: dict = None):
        """
        Make many [n_parallel] list_without_pag request.

        Args:
            model_class (str): Model Class to retrieve.
            list_args (list): A list of list request args
                                               (filter_dict,exclude_dict,
                                               order_by).
        Kwargs:
            n_parallel (int): Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header(dict): Dictionary containing the auth header.
        Returns:
            list: List of the retrieve request reponses.
        Raises:
            No particular raises
        Example:
            No example yet.

        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        urls_list = None
        if type(model_class) == str:
            url_temp = [self._build_list_without_pag_url(model_class)]
            urls_list = url_temp*len(list_args)
        else:
            if len(model_class) != len(list_args):
                raise Exception(
                    'len(model_class) != len(list_args)')
            urls_list = [
                self._build_list_without_pag_url(m) for m in model_class]

        print("## Starting parallel_list_without_pag: %s" % len(urls_list))
        return self.paralell_request_post(
            urls_list=urls_list, data_list=list_args,
            n_parallel=n_parallel, auth_header=auth_header)

    def parallel_list_one(self, model_class: Union[str, List[str]],
                          list_pk: List[int], n_parallel: int = None,
                          auth_header: dict = None):
        """
        Make many [n_parallel] list_one request.

        Args:
            model_class (str or list<str>): Model Class to retrieve.
            list_pk (list): List of the pks to retrieve.
        Kwargs:
            n_parallel (int): Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header(dict): Dictionary containing the auth header.
        Returns:
            list: List of the retrieve request reponses.
        Raises:
            No particular raises
        Example:
            No example yet.

        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        if type(model_class) != list:
            model_class = [model_class]*len(list_pk)

        if len(model_class) != len(list_pk):
            raise Exception('len(model_class) != len(list_pk)')

        urls_list = [
            self._build_list_one_url(model_class=model_class[i],
                                     pk=list_pk[i])
            for i in range(len(model_class))]

        print("## Starting parallel_list_one: %s" % len(urls_list))
        return self.parallel_request_get(
            urls_list=urls_list, n_parallel=n_parallel,
            auth_header=auth_header)

    def parallel_save(self, list_obj_dict: List[dict],
                      n_parallel: int = None, auth_header: dict = None):
        """
        Make many [n_parallel] save requests.

        Args:
            list_obj_dict (list<dict>): List of dictionaries containing
                PumpWood objects (must have at least 'model_class' key)
        Kwargs:
            n_parallel (int): Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header(dict): Dictionary containing the auth header.
        Returns:
            list: List of the retrieve request reponses.
        Raises:
            No particular raises
        Example:
            No example yet.

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
        """
        Make many [n_parallel] delete requests.

        Args:
            model_class (str): Model Class to retrieve.
            list_obj_dict (list<dict>): List of dictionaries containing
                PumpWood objects (must have at least 'model_class' key)
        Kwargs:
            n_parallel (int): Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header(dict): Dictionary containing the auth header.
        Returns:
            list: List of the retrieve request reponses.
        Raises:
            No particular raises
        Example:
            No example yet.

        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        if type(model_class) != list:
            model_class = [model_class]*len(list_pk)

        if len(model_class) != len(list_pk):
            raise Exception('len(model_class) != len(list_pk)')

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
                             auth_header: dict = None):
        """
        Make many [n_parallel] list_without_pag request.

        Args:
            model_class (str): Model Class to retrieve.
            list_args (list): A list of list request args
                                               (filter_dict,exclude_dict,
                                               order_by).
        Kwargs:
            n_parallel (int): Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header(dict): Dictionary containing the auth header.
        Returns:
            list: List of the retrieve request reponses.
        Raises:
            No particular raises
        Example:
            No example yet.

        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        urls_list = None
        if type(model_class) == str:
            url_temp = [self._build_delete_many_request_url(model_class)]
            urls_list = url_temp*len(list_args)
        else:
            if len(model_class) != len(list_args):
                raise Exception(
                    'len(model_class) != len(list_args)')
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
                                auth_header: dict = None):
        """
        Make many [n_parallel] execute_action requests.

        Args:
            model_class (str, list(str)): Model Class to perform action over,
                or a list of model class o make diferent actions.
            pk (int, list[int]): A list of the pks to perform action or a
                single pk to perform action with different paraemters.
            action (str, list[str]): A list of actions to perform or a single
                action to perform over all pks and parameters.
        Kwargs:
            parameters (dict, list[dict]): Parameters used to perform actions
                or a single dict to be used in all actions.
            n_parallel (int): Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header(dict): Dictionary containing the auth header.
        Returns:
            list: List of the retrieve request reponses.
        Raises:
            No particular raises
        Example:
            No example yet.

        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        parallel_length = None
        if type(model_class) == list:
            if parallel_length is not None:
                if parallel_length != len(model_class):
                    raise Exception('parallel_length != len(model_class)')
            else:
                parallel_length = len(model_class)
        if type(pk) == list:
            if parallel_length is not None:
                if parallel_length != len(pk):
                    raise Exception('parallel_length != len(pk)')
            else:
                parallel_length = len(pk)
        if type(action) == list:
            if parallel_length is not None:
                if parallel_length != len(action):
                    raise Exception('parallel_length != len(action)')
            else:
                parallel_length = len(action)
        if type(parameters) == list:
            if parallel_length is not None:
                if parallel_length != len(parameters):
                    raise Exception('parallel_length != len(parameters)')
            else:
                parallel_length = len(parameters)

        model_class = model_class if type(model_class) == list \
            else [model_class]*parallel_length
        pk = pk if type(pk) == list \
            else [pk]*parallel_length
        action = action if type(action) == list \
            else [action]*parallel_length
        parameters = parameters if type(parameters) == list \
            else [parameters]*parallel_length

        urls_list = [
            self._build_execute_action_url(
                model_class=model_class[i], action=action[i], pk=pk[i])
            for i in range(parallel_length)]

        print("## Starting parallel_execute_action: %s" % len(urls_list))
        return self.paralell_request_post(
            urls_list=urls_list, data_list=parameters,
            n_parallel=n_parallel, auth_header=auth_header)

    def parallel_bulk_save(self, model_class, data_to_save,
                           n_parallel: int = None, chunksize: int = 1000,
                           auth_header: dict = None):
        """
        Break data_to_save in many parallel requests.

        Args:
            model_class: Model class of the data that will be saved.
            data_to_save(list or pandas.DataFrame): Data that will be saved
        Kwards:
            n_parallel(int)=10: Number of parallel jobs to be used.
            chunksize(int)=1000: Length of each parallel post chunk.
            auth_header(dict)=None: Dictionary containing the auth header.
        Return:
            list: List of the responses of bulk_save.
        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        if type(data_to_save) == list:
            data_to_save = pd.DataFrame(data_to_save)

        chunks = break_in_chunks(df_to_break=data_to_save,
                                 chunksize=chunksize)
        url = self._build_bulk_save_url(model_class)
        urls_list = [url]*len(chunks)

        print("## Starting parallel_bulk_save: %s" % len(urls_list))
        self.paralell_request_post(
            urls_list=urls_list, data_list=chunks,
            n_parallel=n_parallel, auth_header=auth_header)

    def parallel_pivot(self, model_class: str, list_args: List[dict],
                       columns: List[str], format: str, n_parallel: int = None,
                       variables: list = None, show_deleted=False,
                       auth_header: dict = None):
        """
        Make many [n_parallel] pivot request.

        Args:
            model_class (str): Model Class to retrieve.
            list_args (list): A list of list request args
                                               (filter_dict,exclude_dict,
                                               order_by).
            columns (List[str]): List of columns at the pivoted table.
            format (str): Format of returned table. See pandas.DataFrame
                to_dict args.
        Kwargs:
            n_parallel (int): Number of simultaneus get requests, if not set
                get from PUMPWOOD_COMUNICATION__N_PARALLEL env variable, if
                not set then 4 will be considered.
            auth_header(dict): Dictionary containing the auth header.
        Returns:
            list: List of the pivot request reponses.
        Raises:
            No particular raises
        Example:
            No example yet.

        """
        if n_parallel is None:
            n_parallel = int(os.getenv(
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 4))

        url_temp = [self._build_pivot_url(model_class)]
        urls_list = url_temp*len(list_args)
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
        """Download model queue estimation matrix."""
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
