"""Define PumpWood exceptions to be treated as API errors.

Define especific errors for PumpWood plataform. These errors will be treated
and will not result in default 500 errors
"""
from typing import Any
from loguru import logger


class PumpWoodException(Exception): # NOQA
    """Special exception used in Pumpowod Systems.

    It permits treatment of raises on applications serializing response
    using to_dict function and return status code as `status_code`
    attribute value.
    """

    status_code: int = 400
    """PumpWoodException will return status 400 on Pumpwood backend."""

    message: str
    """Message associated with raise."""

    payload: dict
    """Dictionary payload that will be returned by to_dict funcion and format
       message string."""

    translate: bool
    """If message will be translated or not."""

    parallel: bool
    """If error was raised on a parallel request."""

    def __repr__(self):
        """@private."""
        message_fmt = self.format_message()
        template = "{class_name}[status_code={status_code}]: " + \
            "{message_fmt}\nerror payload={payload}"
        return template.format(
            class_name=self.__class__.__name__,
            status_code=self.status_code,
            message_fmt=message_fmt,
            payload=self.payload)

    def __str__(self):
        """@private."""
        message_fmt = self.format_message()
        template = "{class_name}[status_code={status_code}]: " + \
            "{message_fmt}\nerror payload={payload}"
        return template.format(
            class_name=self.__class__.__name__,
            status_code=self.status_code,
            message_fmt=message_fmt,
            payload=self.payload)

    def __init__(self, message: str, payload: dict = None,
                 status_code: int = None, translate: bool = False,
                 parallel: bool = False):
        """Initialize the PumpWood exception.

        Args:
            message (str):
                Message that will be formated using payload
                information using `{key}` to replace information.
            payload (dict):
                Payload data passed as a dictionary, it will be returned
                in payload at `to_dict` funcion and used to format message.
                Defaults to None.
            status_code (int):
                Change the default status code of the exception.
                Defaults to None.
            translate (bool):
                Set if message should be translated or not.
                Defaults to False.
            parallel (bool):
                Error on a parallel request. Defaults to False.
        """
        Exception.__init__(self)

        # Initialize payload to avoid mutable default issues
        if payload is None:
            payload = {}

        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload
        self.translate = translate
        self.parallel = parallel

    def format_message(self) -> str:
        """Format exception message using payload data.

        Substitute placeholders at exception message with payload.

        Returns:
            Return a string of message with placeholders substituted with
            payload data.
        """
        if self.translate:
            try:
                return self.message.format(**self.payload)
            except Exception:
                return self.message + "\n** format error **"
        else:
            try:
                return self.message.format(**self.payload)
            except Exception:
                return self.message + "\n** format error **"

    def to_dict(self) -> dict[str, Any]:
        """Serialize Exception object to return as reponse.

        Returns:
            Return a dictionary with keys:
            - **payload [dict]:** Payload associated with raise.
            - **type [str]:** Return name of the class of the Exception.
            - **message_not_fmt [str]:** Return msg without replacemnt of the
                msg with payload information.
            - **message [str]:** Return msg formated with payload information.
        """
        message_fmt = self.format_message()
        rv = {
            "__error__": 'PumpWoodException',
            "type": self.__class__.__name__,
            "payload": self.payload,
            "message_not_fmt": self.message,
            "message": message_fmt,
            "parallel": self.parallel}
        return rv


class PumpWoodDataLoadingException(PumpWoodException):
    """Problem when loading data at dataloaders and to_load models."""

    pass


class PumpWoodDatabaseError(PumpWoodException):
    """Errors raised by Postgres and not treated by other handlers."""

    pass


class PumpWoodUniqueDatabaseError(PumpWoodException):
    """Unique errors raised by Postgres."""

    pass


class PumpWoodDataTransformationException(PumpWoodException):
    """Problem when transforming model data."""

    pass


class PumpWoodWrongParameters(PumpWoodException):
    """Raise for errors in object deserialization."""

    pass


class PumpWoodObjectSavingException(PumpWoodException):
    """Raise for errors in object deserialization."""

    pass


class PumpWoodObjectDeleteException(PumpWoodException):
    """Raise for errors in object deserialization."""

    pass


class PumpWoodActionArgsException(PumpWoodException):
    """Missing arguments to perform action."""

    pass


class PumpWoodUnauthorized(PumpWoodException):
    """User Unauthorized to perform action."""

    status_code = 401


class PumpWoodForbidden(PumpWoodException):
    """Action not permited."""

    status_code = 403


class PumpWoodObjectDoesNotExist(PumpWoodException):
    """Object not found in database."""

    status_code = 404


class PumpWoodQueryException(PumpWoodException):
    """Problem when querying data, like wrong fields or operators."""

    pass


class PumpWoodIntegrityError(PumpWoodException):
    """Problem when saving data due to IntegrityError."""

    pass


class PumpWoodNotImplementedError(PumpWoodException):
    """Problem when saving data due to NotImplementedError."""

    pass


class PumpWoodMicroserviceUnavailableError(PumpWoodException):
    """Problem when trying to use a microservice that was not deployied."""

    pass


class PumpWoodMFAError(PumpWoodException):
    """Problem when using MFA."""

    pass


class PumpWoodJSONLoadError(PumpWoodException):
    """Problem loading json data from request."""

    pass


class PumpWoodCacheError(PumpWoodException):
    """Problem using pumpwood cache."""

    pass


class PumpWoodOtherException(PumpWoodException):
    """Other untreated error on server."""

    status_code = 500

    def __init__(self, message: str, payload: dict = None,
                 status_code: int = None, parallel: bool = False):
        """Initialize the PumpWoodOtherException.

        Args:
            message (str):
                Message that will be formated using payload
                information using `{key}` to replace information.
            payload (dict):
                Payload data passed as a dictionary, it will be returned
                in payload at `to_dict` funcion and used to format message.
                Defaults to None.
            status_code (int):
                Change the default status code of the exception.
                Defaults to None.
            parallel (bool):
                Error on a parallel request. Defaults to False.
        """
        Exception.__init__(self)

        # Initialize payload to avoid mutable default issues
        if payload is None:
            payload = {}

        # Limit size of the error
        self.message = message[:1000]
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload
        self.translate = False
        self.parallel = parallel


class AirflowMicroServiceException(PumpWoodException):
    """Raises from AirflowMicroService."""

    pass


exceptions_dict = {
    "PumpWoodException": PumpWoodException,
    "PumpWoodDataLoadingException": PumpWoodDataLoadingException,
    "PumpWoodDatabaseError": PumpWoodDatabaseError,
    "PumpWoodDataTransformationException": PumpWoodDataTransformationException,
    "PumpWoodWrongParameters": PumpWoodWrongParameters,
    "PumpWoodObjectSavingException": PumpWoodObjectSavingException,
    "PumpWoodObjectDeleteException": PumpWoodObjectDeleteException,
    "PumpWoodActionArgsException": PumpWoodActionArgsException,
    "PumpWoodUnauthorized": PumpWoodUnauthorized,
    "PumpWoodForbidden": PumpWoodForbidden,
    "PumpWoodObjectDoesNotExist": PumpWoodObjectDoesNotExist,
    "PumpWoodQueryException": PumpWoodQueryException,
    "PumpWoodIntegrityError": PumpWoodIntegrityError,
    "PumpWoodNotImplementedError": PumpWoodNotImplementedError,
    "PumpWoodMicroserviceUnavailableError":
        PumpWoodMicroserviceUnavailableError,
    "PumpWoodMFAError": PumpWoodMFAError,
    "PumpWoodOtherException": PumpWoodOtherException,
    "AirflowMicroServiceException": AirflowMicroServiceException,
    "PumpWoodUniqueDatabaseError": PumpWoodUniqueDatabaseError
}
"""
Dictionary used by backends/microservice to treat Pumpwood exceptions and
re-raise them exception.
"""


def raise_pumpwood_exception(exception_name: str, message: str,
                             payload: dict = None, status_code: int = None,
                             translate: bool = False, parallel: bool = False):
    """Raise a PumpWood exception based on its name.

    Args:
        exception_name (str):
            Name of the exception to be retrieved and raised.
        message (str):
            The error message associated with the exception.
        payload (dict):
            A dictionary containing additional data for the exception.
            Defaults to None.
        status_code (int):
            HTTP status code to be returned. Defaults to None.
        translate (bool):
            Whether the message should be translated. Defaults to False.
        parallel (bool):
            If the exception happened during parallel processing.
            Defaults to False.

    Returns:
        None: This function does not return as it always raises an exception.

    Raises:
        PumpWoodOtherException:
            If the specified exception_name is not found in the registry.
        PumpWoodException:
            The specific exception mapped to the exception_name.
    """
    # Initialize payload to avoid mutable default issues
    if payload is None:
        payload = {}

    pumpwood_exception = exceptions_dict.get(exception_name)
    if pumpwood_exception is None:
        msg = (
            "exception_name [{exception_name}] not found in PumpWood "
            "Exceptions. Check implementation")
        logger.error(
            msg.format(exception_name=exception_name))
        raise PumpWoodOtherException(
            msg.format(exception_name=exception_name),
            payload=payload, status_code=status_code,
            translate=translate, parallel=parallel)
    else:
        raise pumpwood_exception(
            message=message, payload=payload, status_code=status_code,
            translate=translate, parallel=parallel)


