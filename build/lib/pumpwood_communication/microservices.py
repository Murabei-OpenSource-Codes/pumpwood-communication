"""
Module microservice.py.

Class and functions to help comunication between PumpWood like systems.
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
from shapely import geometry
from typing import Union, List
from multiprocessing import Pool
from pandas import ExcelWriter
from copy import deepcopy
from pumpwood_communication.exceptions import (
    exceptions_dict, PumpWoodException, PumpWoodUnauthorized,
    PumpWoodObjectSavingException, PumpWoodOtherException)
from pumpwood_communication.serializers import pumpJsonDump


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
                 verify_ssl: bool = True, auth_suffix: str = None):
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
        self.auth_suffix = auth_suffix

    def init(self, name: str, server_url: str, username: str,
             password: str, verify_ssl: bool = True, auth_suffix: str = None):
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
        string_start = ")]}',\n"
        try:
            if request_result.text[:6] == string_start:
                return (json.loads(request_result.text[6:]))
            else:
                return (json.loads(request_result.text))
        except Exception:
            return {"error": "Can not decode to Json",
                    'msg': request_result.text}

    def login(self, refresh: bool = False):
        """
        Log microservice in using username and password provided.

        Args:
            No Args
        Kwargs:
            No Kwargs
        Returns:
            No return
        Raises:
            Exception: If login response has status diferent from 200.
        Example:
            No example

        """
        if self.__auth_header is None or refresh:
            login_url = None
            if self.auth_suffix is None:
                login_url = self.server_url + 'rest/registration/login/'
            else:
                temp_url = 'rest/{suffix}registration/login/'.format(
                    suffix=self.auth_suffix.lower())
                login_url = self.server_url + temp_url

            login_result = requests.post(
                login_url,
                data=json.dumps({
                    'username': self.__username,
                    'password': self.__password}),
                headers=self.__base_header,
                verify=self.verify_ssl)

            login_data = PumpWoodMicroService.angular_json(login_result)
            if login_result.status_code != 200:
                raise Exception(json.dumps(login_data))

            self.__auth_header = {
                'Authorization': 'Token ' + login_data['token']}
            self.__user = login_data["user"]

    def get_user_info(self) -> dict:
        """
        Get user info retrieved at login.

        Args:
            No Args:

        Return [dict]:
            A serialized user object with information of the logged user.
        """
        return deepcopy(self.__user)

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
        if self.__auth_header is None:
            if auth_header is None:
                msg_tmp = 'MicroService {name} not looged and auth_header ' + \
                    'not provided'
                raise PumpWoodUnauthorized(msg_tmp.format(name=self.name))
            else:
                temp__auth_header = auth_header.copy()
                if multipart:
                    return temp__auth_header
                else:
                    temp__auth_header.update(self.__base_header)
                    return temp__auth_header
        else:
            if auth_header is not None:
                msg_tmp = 'MicroService {name} already looged and ' + \
                          'auth_header was provided'
                raise PumpWoodUnauthorized(
                    msg_tmp.format(name=self.name))
            else:
                temp__auth_header = self.__auth_header.copy()
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
                response_dict["!exception_stack!"] = exception_stack
                raise PumpWoodOtherException(
                    message="Not mapped exception JSON",
                    payload=response_dict)

    def request_post(self, url: str, data: any, files: list = None,
                     auth_header: dict = None):
        """
        Make a POST a request to url with data as Json payload.

        Args:
            url (str): Url to make the request.
            data (any); Data to be used as Json payload.
        Kwargs:
            files(list of tuples): A list of tuples with
                                   (file name, [file1, file2, ...]).
            auth_header(dict): Auth data to overhide microservice's.
        Returns:
            any: Return the post result
        Raises:
            Response is passed to error_handler function.
        Example:
            No example

        """
        if files is None:
            request_header = self._check__auth_header(auth_header=auth_header)
            post_url = self.server_url + url
            response = requests.post(
                url=post_url, data=pumpJsonDump(data),
                verify=self.verify_ssl, headers=request_header)

            self.error_handler(response)
            return PumpWoodMicroService.angular_json(response)
        else:
            request_header = self._check__auth_header(
                auth_header=auth_header, multipart=True)
            post_url = self.server_url + url
            temp_data = {}
            for key, item in data.items():
                temp_data[key] = pumpJsonDump(data[key])
            response = requests.post(
                url=post_url, data=temp_data, files=files,
                verify=self.verify_ssl, headers=request_header)
            self.error_handler(response)
            return PumpWoodMicroService.angular_json(response)

    def request_get(self, url, parameters: dict = None,
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

        get_url = self.server_url + url
        response = requests.get(
            get_url, verify=self.verify_ssl, headers=request_header,
            params=parameters)
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

    @staticmethod
    def _build_list_url(model_class: str):
        return "rest/%s/list/" % (model_class.lower(),)

    def list(self, model_class: str, filter_dict: dict = {},
             exclude_dict: dict = {}, order_by: list = [],
             auth_header: dict = None, fields: list = None,
             default_fields: bool = False, limit: int = None,
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
            'limit': limit}
        if fields is not None:
            post_data["fields"] = fields
        return self.request_post(
            url=url_str, data=post_data, auth_header=auth_header)

    def list_by_chunck(self, model_class: str, filter_dict: dict = {},
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
                         default_fields: bool = False, **kwargs):
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
            'order_by': order_by, 'default_fields': default_fields}

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
        return "rest/%s/list-one/%d/" % (model_class.lower(), pk)

    def list_one(self, model_class: str, pk: int, auth_header: dict = None):
        """
        Retrive an object using list serializer (simple).

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
        return self.request_get(url=url_str, auth_header=auth_header)

    @staticmethod
    def _build_retrieve_url(model_class: str, pk: int):
        return "rest/%s/retrieve/%d/" % (model_class.lower(), pk)

    def retrieve(self, model_class: str, pk: int, auth_header: dict = None):
        """
        Retrieve an object from PumpWood.

        Function to get object serialized by retrieve end-point
        (more detailed data).

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
        url_str = self._build_retrieve_url(model_class=model_class, pk=pk)
        return self.request_get(url=url_str, auth_header=auth_header)

    @staticmethod
    def _build_retrieve_file_url(model_class: str, pk: int):
        return "rest/%s/retrieve-file/%d/" % (model_class.lower(), pk)

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
          if_exists {'fail', 'change_name', 'overwrite'}: Set what to do if
            there is a file with same name.
        Returns:
          requset.response or str
        Raises:
          No especific raises.
        Example:
          No example yet.

        """
        if if_exists not in ["fail", "change_name", "overwrite"]:
            raise PumpWoodException(
                "if_exists must be in ['fail', 'change_name', 'overwrite']")

        url_str = self._build_retrieve_file_url(model_class=model_class, pk=pk)
        file_response = self.request_get(
            url=url_str, parameters={"file-field": file_field},
            auth_header=auth_header)

        if save_file:
            if not os.path.exists(save_path):
                raise PumpWoodException(
                    "Path to save retrieved file [{}] does not exist".format(
                        save_path))
            file_name = file_name or file_response["filename"]
            file_path = os.path.join(save_path, file_name)

            if os.path.isfile(file_path) and if_exists == "change_name":
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

            if os.path.isfile(file_path) and if_exists == "fail":
                raise PumpWoodException(
                    ("if_exists set as 'fail' and there is a file with same" +
                     "name. file_path [{}]").format(file_path))

            with open(file_path, "wb") as file:
                file.write(file_response["content"])
            return file_path
        else:
            return file_response

    @staticmethod
    def _build_retrieve_file_straming_url(model_class: str, pk: int):
        return "rest/%s/retrieve-file-streaming/%d/" % (
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
        return self.request_post(url=url_str, data=obj_dict, files=files,
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
        return "rest/%s/delete/%d/" % (model_class.lower(), pk)

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
        return "rest/%s/remove-file-field/%d/" % (model_class.lower(), pk)

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
                       parameters={}, files: list = None,
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
        return self.request_post(url=url_str, data=parameters, files=files,
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
        return self.request_post(url=url_str, data=parcial_obj_dict,
                                 auth_header=auth_header)

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
        Kwargs:
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

    def flat_list_by_chucks(self, model_class: str, filter_dict: dict = {},
                            exclude_dict: dict = {}, fields: list = None,
                            show_deleted=False, auth_header: dict = None,
                            chunk_size: int = 100000):
        """
        Use the same end-point as pivot which does not unserialize results.

        Args:
            model_class (str): Model class to be pivoted.
            filter_dict (dict): Dictionary to to be used in objects.filter
                                argument (Same as list end-point).
            exclude_dict (dict): Dictionary to to be used in objects.exclude
                                 argument (Same as list end-point).
        Kwargs:
            fields (list[str]) = None: List of the variables to be returned,
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
        temp_filter_dict = copy.deepcopy(filter_dict)
        url_str = self._build_pivot_url(model_class)
        max_pk = 0

        # Fetch data until an empty result is returned
        list_dataframes = []
        while True:
            print("- fetching chunk [{}]".format(max_pk))
            temp_filter_dict["pk__gt"] = max_pk
            post_data = {
                'format': 'list',
                'filter_dict': temp_filter_dict, 'exclude_dict': exclude_dict,
                'order_by': ["pk"], "variables": fields,
                "show_deleted": show_deleted, "limit": chunk_size,
                "add_pk_column": True}
            temp_dateframe = pd.DataFrame(self.request_post(
                url=url_str, data=post_data, auth_header=auth_header))
            # Break if results are empty
            if len(temp_dateframe) == 0:
                break
            max_pk = temp_dateframe["id"].max()
            list_dataframes.append(temp_dateframe)
        return pd.concat(list_dataframes)

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
            print("- process finished")
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
                not set then 10 will be considered.
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
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 10))

        pool_arguments = [
            {'url': u, 'auth_header': auth_header} for u in urls_list]

        with Pool(n_parallel) as p:
            print('Waiting for tasks to complete')
            logging.basicConfig(level=logging.DEBUG)
            results = p.map(self._request_get_wrapper, pool_arguments)
        return results

    def _request_post_wrapper(self, arguments: dict):
        try:
            result = self.request_post(**arguments)
            print("- process finished")
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
                not set then 10 will be considered.
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

        return results

    def _request_delete_wrapper(self, arguments):
        try:
            result = self.request_delete(**arguments)
            print("- process finished")
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
                not set then 10 will be considered.
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
            return p.map(self._request_delete_wrapper, pool_arguments)

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
                not set then 10 will be considered.
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
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 10))

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
                not set then 10 will be considered.
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
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 10))

        urls_list = None
        if type(model_class) == str:
            urls_list = [self._build_list_url(model_class)]*len(list_args)
        else:
            if len(model_class) != len(list_args):
                raise Exception('len(model_class) != len(list_args)')
            urls_list = [self._build_list_url(m) for m in model_class]

        print(
            "## Starting parallel_list: %s" % len(urls_list))
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
                not set then 10 will be considered.
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
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 10))

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

        print(
            "## Starting parallel_list_without_pag: %s" % len(urls_list))
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
                not set then 10 will be considered.
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
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 10))

        if type(model_class) != list:
            model_class = [model_class]*len(list_pk)

        if len(model_class) != len(list_pk):
            raise Exception('len(model_class) != len(list_pk)')

        urls_list = [
            self._build_list_one_url(model_class=model_class[i],
                                     pk=list_pk[i])
            for i in range(len(model_class))]

        print(
            "## Starting parallel_list_one: %s" % len(urls_list))
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
                not set then 10 will be considered.
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
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 10))

        urls_list = [
            self._build_save_url(obj['model_class']) for obj in list_obj_dict]
        print(
            "## Starting parallel_save: %s" % len(urls_list))
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
                not set then 10 will be considered.
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
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 10))

        if type(model_class) != list:
            model_class = [model_class]*len(list_pk)

        if len(model_class) != len(list_pk):
            raise Exception('len(model_class) != len(list_pk)')

        urls_list = [
            self._build_delete_request_url(model_class=model_class[i],
                                           pk=list_pk[i])
            for i in range(len(model_class))]

        print(
            "## Starting parallel_delete: %s" % len(urls_list))
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
                not set then 10 will be considered.
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
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 10))

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

        print(
            "## Starting parallel_delete_many: %s" % len(urls_list))
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
                not set then 10 will be considered.
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
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 10))

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

        print(
            "## Starting parallel_execute_action: %s" % len(urls_list))
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
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 10))

        if type(data_to_save) == list:
            data_to_save = pd.DataFrame(data_to_save)

        chunks = break_in_chunks(df_to_break=data_to_save,
                                 chunksize=chunksize)
        url = self._build_bulk_save_url(model_class)
        urls_list = [url]*len(chunks)

        print(
            "## Starting parallel_bulk_save: %s" % len(urls_list))
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
                not set then 10 will be considered.
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
                "PUMPWOOD_COMUNICATION__N_PARALLEL", 10))

        url_temp = [self._build_pivot_url(model_class)]
        urls_list = url_temp*len(list_args)
        for q in list_args:
            q["variables"] = variables
            q["show_deleted"] = show_deleted
            q["columns"] = columns
            q["format"] = format

        print(
            "## Starting parallel_pivot: %s" % len(urls_list))
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
