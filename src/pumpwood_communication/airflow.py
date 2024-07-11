"""MicroService class to comunicate with Airflow."""
import math
import string
import random
import datetime
import pandas as pd
import copy
from typing import List
from airflow_client import client
from airflow_client.client.api import dag_api
from airflow_client.client.api import dag_run_api
from airflow_client.client.model.dag_run import DAGRun
from airflow_client.client.api import monitoring_api
from pumpwood_communication.exceptions import AirflowMicroServiceException


class AirflowMicroService():
    """Class to facilitate interaction with Airflow API."""

    _airflow_config = None
    _api_client = None

    def __init__(self, server_url: str = None, username: str = None,
                 password: str = None) -> None:
        """
        Create new AirflowMicroService object.

        Args:
            server_url:
                URL of the server that will be connected.
            username:
                Username that will be logged on.
            password:
                Variable to be converted to JSON and posted along.

        Returns:
            AirflowMicroService: New AirflowMicroService object
        """
        if (server_url is not None) and (username is not None) and (
                password is not None):
            self._airflow_config = client.Configuration(
                host=server_url, username=username,
                password=password)
            self._api_client = client.ApiClient(self._airflow_config)
            self.initiated = True
            try:
                self.health_check()
            except Exception:
                msg = (
                    "!! AirflowMicroService initiated, but health "
                    "check failed !!")
                print(msg)
        else:
            self.initiated = False

    def init(self, server_url: str, username: str, password: str) -> None:
        """
        Init AirflowMicroService object.

        Args:
            server_url:
                url of the server that will be connected.
            username:
                Username that will be logged on.
            password:
                Variable to be converted to JSON and posted along
        Returns:
            No return
        Raises:
            AirflowMicroServiceException: If some of the argument is None.
        """
        if (server_url is not None) and (username is not None) and (
                password is not None):
            self._airflow_config = client.Configuration(
                host=server_url,
                username=username,
                password=password)
            self._api_client = client.ApiClient(self._airflow_config)
            self.initiated = True
            try:
                self.health_check()
            except Exception:
                msg = (
                    "!! AirflowMicroService initiated, but health "
                    "check failed !!")
                print(msg)
        else:
            msg = (
                "AirflowMicroService object init must have server_url, "
                "username and password not None.")
            raise AirflowMicroServiceException(message=msg)

    def health_check(self) -> None:
        """
        Test connection to Airflow API.

        Args:
            No args.
        Raises:
            AirflowMicroServiceException: If it is not possible to list one
                dag using the API and return its error.
        """
        if not self.initiated:
            msg = "AirflowMicroservice not initiated"
            raise AirflowMicroServiceException(message=msg)

        api_instance = monitoring_api.MonitoringApi(self._api_client)
        try:
            # Get instance status
            api_response = api_instance.get_health()
            return api_response
        except Exception as e:
            raise AirflowMicroServiceException(message=str(e))

    def get_dag(self, dag_id: str) -> dict:
        """
        Get Dag information using its dag_id.

        Args:
            dag_id:
                ID of the DAG to get information.

        Returns [dict]:
            Return a dictionary with dag information.
        """
        self.health_check()

        dag_api_instance = dag_api.DAGApi(self._api_client)
        try:
            dag_info = dag_api_instance.get_dag(dag_id)
        except Exception as e:
            msg = "Dag id not found on Airflow, full error:\n{}".format(str(e))
            raise AirflowMicroServiceException(msg, payload={"dag_id": dag_id})
        return dag_info

    def list_dags(self, only_active: bool = True, tags: List[str] = [],
                  max_results: int = math.inf):
        """
        List all dags on Airflow.

        Args:
            only_active:
                List only active DAGs.
            tags:
                Filter DASs using tags.
            max_results:
                Limit query results.
        """
        self.health_check()

        dag_api_instance = dag_api.DAGApi(self._api_client)

        offset = 0
        list_all_dags = []
        while True:
            dags = dag_api_instance.get_dags(
                limit=100, offset=offset, tags=tags,
                only_active=only_active,
                order_by="-next_dagrun")["dags"]

            # Check if all results were fetched
            if len(dags) == 0:
                break

            list_all_dags.extend(dags)
            offset = len(list_all_dags)

            # Check if fetched have passed max_results
            if max_results <= len(list_all_dags):
                break
        return [x.to_dict() for x in list_all_dags]

    def run_dag(self, dag_id: str, arguments: dict = {},
                paused_raise_error: bool = True,
                dag_run_id: str = None,
                dag_run_id_sufix: str = None) -> dict:
        """
        Run an Airflow DAG passing arguments as arguments.

        Args:
            dag_id:
                Dag id that will called.
            arguments:
                Dictionary with arguments to be passed to dag run on Airflow
                as conf.
            paused_raise_error:
                Raise error if DAG is paused or inactive at the moment it is
                asked to run.

        Return [dict]:
            Return dictionary with dag run information.

        Raise:
            AirflowMicroServiceException: If DAG not found.
            AirflowMicroServiceException: If DAG is inactive.
            AirflowMicroServiceException: If DAG paused and
                paused_raise_error=True.
            AirflowMicroServiceException: If other exception when asking DAG
                to run on Airflow.
        """
        self.health_check()

        # Checking on DAG object
        dag_info = self.get_dag(dag_id)
        if not dag_info["is_active"]:
            msg = "DAG [{}] is not active".format(dag_id)
            raise AirflowMicroServiceException(
                message=msg, payload={"dag_id": dag_id})
        if dag_info["is_paused"] and paused_raise_error:
            msg = "DAG [{}] is paused and paused_raise_error=True".format(
                dag_id)
            raise AirflowMicroServiceException(
                message=msg, payload={"dag_id": dag_id})

        # Running DAG
        if dag_run_id is None:
            now_str = datetime.datetime.now().isoformat()
            random_letters = "".join(
                random.choices(string.ascii_uppercase, k=12))
            dag_run_id = (
                "{time}__{random_letters}").format(
                    time=now_str, random_letters=random_letters)

        if dag_run_id_sufix is None:
            dag_run_id = dag_run_id + "__dag_id[{}]".format(dag_id)
        else:
            if dag_run_id_sufix != "":
                dag_run_id = dag_run_id + "__" + dag_run_id_sufix

        # Create dag run object and sent it to Airflow queue
        dag_run_id = DAGRun(dag_run_id=dag_run_id, conf=arguments)
        dagrun_api_instance = dag_run_api.DAGRunApi(self._api_client)
        dagrun_result = dagrun_api_instance.post_dag_run(dag_id, dag_run_id)
        return dagrun_result.to_dict()

    def list_dag_runs(self, dag_id: str,
                      limit: int = 100,
                      execution_date_gte: str = None,
                      execution_date_lte: str = None,
                      start_date_gte: str = None,
                      start_date_lte: str = None,
                      end_date_gte: str = None,
                      end_date_lte: str = None,
                      state: list = None,
                      order_by: str = "-execution_date") -> list:
        """
        List dag runs ordered inverted to creation time.

        Args:
            dag_id:
                Id of the dag to list dag runs.
            limit:
                Limit the number of dag runs to be returned.
            execution_date_gte:
                Query parameters.
            execution_date_lte:
                Query parameters.
            start_date_gte:
                Query parameters.
            start_date_lte:
                Query parameters.
            end_date_gte:
                Query parameters.
            end_date_lte:
                Query parameters.
            state:
                Query parameters.
            order_by:
                Query parameters.
        Return [list]:
            Return DAG run associated with ETLJob DAG.
        """
        self.health_check()

        api_instance = dag_run_api.DAGRunApi(self._api_client)
        get_dag_runs_args = {
            "limit": 100,
            "dag_id": dag_id,
            "order_by": order_by
        }

        if execution_date_gte is not None:
            if type(execution_date_gte) is str:
                execution_date_gte = pd.to_datetime(
                    execution_date_gte).to_pydatetime()
            get_dag_runs_args["execution_date_gte"] = execution_date_gte

        if execution_date_lte is not None:
            if type(execution_date_lte) is str:
                execution_date_lte = pd.to_datetime(
                    execution_date_lte).to_pydatetime()
            get_dag_runs_args["execution_date_lte"] = execution_date_lte

        if start_date_gte is not None:
            if type(start_date_gte) is str:
                start_date_gte = pd.to_datetime(
                    start_date_gte).to_pydatetime()
            get_dag_runs_args["start_date_gte"] = start_date_gte

        if start_date_lte is not None:
            if type(start_date_lte) is str:
                start_date_lte = pd.to_datetime(
                    start_date_lte).to_pydatetime()
            get_dag_runs_args["start_date_lte"] = start_date_lte

        if end_date_gte is not None:
            if type(end_date_gte) is str:
                end_date_gte = pd.to_datetime(
                    end_date_gte).to_pydatetime()
            get_dag_runs_args["end_date_gte"] = end_date_gte

        if end_date_lte is not None:
            if type(end_date_lte) is str:
                end_date_lte = pd.to_datetime(
                    end_date_lte).to_pydatetime()
            get_dag_runs_args["end_date_lte"] = end_date_lte

        if state is not None:
            get_dag_runs_args["state"] = state

        offset = 0
        all_results = []
        while True:
            temp_get_dag_runs_args = copy.deepcopy(get_dag_runs_args)
            temp_get_dag_runs_args["offset"] = offset
            results = api_instance.get_dag_runs(
                **temp_get_dag_runs_args)['dag_runs']

            if len(results) == 0:
                break

            all_results.extend(results)
            offset = len(all_results)

            if limit <= len(all_results):
                break
        return [x.to_dict() for x in all_results]

    def get_dag_run(self, dag_id: str, dag_run_id: str) -> dict:
        """
        Get DAG run information.

        Args:
            dag_id:
                Identification of the DAG.
            dag_run_id:
                Identification of the DAG run.
        Kwargs:
            No Kwargs.
        Return [dict]:
            Serialized DAG run information.
        """
        self.health_check()

        api_instance = dag_run_api.DAGRunApi(self._api_client)
        try:
            return api_instance.get_dag_run(dag_id, dag_run_id).to_dict()
        except client.ApiException as e:
            msg = (
                "If was not possible to find dag run with dag_id[{dag_id}]"
                "and dag_run_id[{dag_run_id}]. Error:\n{error}").format(
                    dag_id=dag_id, dag_run_id=dag_run_id, error=str(e))
            raise AirflowMicroServiceException(
                message=msg, payload={
                    "dag_id": dag_id, "dag_run_id": dag_run_id})
            print("Exception when calling DAGRunApi->get_dag_run: %s\n" % e)
