"""Pumpwood internal and auxiliary associated requests."""
import requests
from abc import ABC
from urllib.parse import urljoin
from pumpwood_communication.microservice_abc.base import (
    PumpWoodMicroServiceBase)
from pumpwood_communication.exceptions import (
    PumpWoodMicroserviceUnavailableError)


class ABCSystemMicroservice(ABC, PumpWoodMicroServiceBase):
    """ABC class to define system associated requests.

    System associated request involve list of routes, services that were
    registed on Pumpwood, but also some test usefull features such as
    cache invalidation and health check calls.
    """

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

    def clear_service_cache(self, service: str,
                            auth_header: dict = None) -> bool:
        """Clear disk cache associated with service container.

        This request will ask service to clear disk cache. If there are
        replicas at same service it is possible that the cache might be
        invalidated on just one of the replicas leading to inconsistent
        cache behavior.

        Args:
            service (str):
                Pumpwood service to have its cache invalidated, it is expected
                that the service implement the invalidation end-point
                `/rest/[service-name]/clear-diskcache`.
            auth_header (dict):
                Auth header to substitute the microservice original
                at the request (user impersonation).

        Returns:
            True if cache was invalidated.
        """
        # Service url begging are related to service general functions
        url = 'service/{service}/clear-diskcache/'\
            .format(service=service)
        response = self.request_post(
            url=url, data={}, auth_header=auth_header)
        return response

    def health_check_service(self, service: str,
                             raise_error: bool = False) -> bool:
        """Hits the health_check, it is not necessary authentication.

        Helth check end-points are simple and does not involve connection
        with database or storage. It will just check if container is up
        and receiving requests. It is usefull for tests and for inter-service
        calls.

        If `raise_error` is set as True, function will raise
        PumpWoodMicroserviceUnavailableError.

        Args:
            service (str):
                Pumpwood service to have its cache invalidated, it is expected
                that the service implement the invalidation end-point
                `/rest/[service-name]/clear-diskcache`.
            raise_error (bool):
                If request does not return 200 status, it will raise a
                PumpWoodMicroserviceUnavailableError.

        Returns:
            True if service is healthy.

        Raises:
            PumpWoodMicroserviceUnavailableError if request does not
            return 200 code.
        """
        # Service url begging are related to service general functions
        url = 'service/{service}/health-check/'.format(service=service)
        get_url = urljoin(self.server_url, url)
        response = requests.get(get_url, timeout=5)

        # Raise a Pumpwood error if raise_if_not_healthy informing that the
        # service health-check did not return a OK status
        if not response.ok and raise_error:
            msg = (
                "Call on service [{service}] health-check end-point did not "
                "return a OK status.")
            raise PumpWoodMicroserviceUnavailableError(
                msg, payload={'service': service})

        return response.ok
