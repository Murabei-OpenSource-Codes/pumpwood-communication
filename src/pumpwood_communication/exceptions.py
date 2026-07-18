"""Define PumpWood exceptions to be treated as API errors.

Define specific errors for the PumpWood platform. These errors are handled
explicitly and do not result in default 500 responses.
"""
from typing import Any
from loguru import logger


class PumpWoodException(Exception): # NOQA
    """Special exception used in PumpWood systems.

    It permits handling raises in applications by serializing responses
    with ``to_dict`` and exposing the HTTP status as ``status_code``.
    """

    status_code: int = 400
    """PumpWoodException will return status 400 on Pumpwood backend."""

    message: str
    """Message associated with raise."""

    payload: dict
    """Dictionary payload returned by ``to_dict`` and used to format
       the message string."""

    i8n_object: None
    """I8n object used to translate the message."""

    was_translated: bool
    """If the message was translated."""

    tag: str
    """Tag used to disambiguate translation context."""

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
                 status_code: int = None, tag: str = '',
                 parallel: bool = False, i8n_object: None = None,
                 was_translated: bool = False):
        """Initialize the PumpWood exception.

        Args:
            message (str):
                Message formatted with payload data using ``{key}``
                placeholders.
            payload (dict):
                Payload data passed as a dictionary. Returned in
                ``to_dict`` and used to format the message.
                Defaults to None.
            status_code (int):
                HTTP status code override. Defaults to None.
            i8n_object (None):
                I8n object used to translate the message.
                Defaults to None.
            tag (str):
                Tag used to disambiguate translation context.
                Defaults to empty string.
            parallel (bool):
                Whether the error occurred during parallel work.
                Defaults to False.
        """
        Exception.__init__(self)

        # Initialize payload to avoid mutable default issues
        if payload is None:
            payload = {}

        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload
        self.i8n_object = i8n_object
        self.was_translated = was_translated
        self.tag = tag
        self.parallel = parallel

    def format_message(self) -> str:
        """Format exception message using payload data.

        Substitute placeholders at exception message with payload.

        Returns:
            str:
                Message with placeholders substituted from payload data.
        """
        try:
            # If i8n_object is not None and was_translated is False,
            # use it to translate the message
            message = self.message
            if (self.i8n_object is not None) and (not self.was_translated):
                message = self.i8n_object.t(
                    sentence=self.message, tag=self.tag)
            return message.format(**self.payload)
        except Exception:
            return self.message + "\n** format error **"

    def to_dict(self) -> dict[str, Any]:
        """Serialize exception object for API response.

        Returns:
            dict[str, Any]:
                Dictionary with keys:
            - **payload [dict]:** Payload associated with the raise.
            - **type [str]:** Name of the exception class.
            - **message_not_fmt [str]:** Message without payload
                substitution.
            - **message [str]:** Message formatted with payload data.
            - **status_code [int]:** HTTP status code for the exception.
            - **translate [bool]:** Whether the message should be
                translated.
            - **tag [str]:** Tag used to disambiguate translation
                context.
            - **parallel [bool]:** Whether the error was from parallel
                work.
        """
        message_fmt = self.format_message()
        rv = {
            "__error__": 'PumpWoodException',
            "type": self.__class__.__name__,
            "payload": self.payload,
            "message_not_fmt": self.message,
            "message": message_fmt,
            "status_code": self.status_code,
            "was_translated": self.was_translated,
            "tag": self.tag,
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
    """Invalid or missing request parameters."""

    pass


class PumpWoodObjectSavingException(PumpWoodException):
    """Problem when saving object data."""

    pass


class PumpWoodObjectDeleteException(PumpWoodException):
    """Problem when deleting object data."""

    pass


class PumpWoodActionArgsException(PumpWoodException):
    """Missing arguments to perform action."""

    pass


class PumpWoodUnauthorized(PumpWoodException):
    """User is unauthorized to perform the action."""

    status_code = 401


class PumpWoodForbidden(PumpWoodException):
    """Action is not permitted."""

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
    """Feature or operation is not implemented."""

    pass


class PumpWoodMicroserviceUnavailableError(PumpWoodException):
    """Microservice is unavailable or was not deployed."""

    pass


class PumpWoodMFAError(PumpWoodException):
    """Problem when using MFA."""

    pass


class PumpWoodJSONLoadError(PumpWoodException):
    """Problem loading JSON data from a request."""

    pass


class PumpWoodCacheError(PumpWoodException):
    """Problem using the PumpWood cache."""

    pass


class PumpWoodOtherException(PumpWoodException):
    """Unhandled or unmapped server error."""

    status_code = 500

    def __init__(self, message: str, payload: dict = None,
                 status_code: int = None, was_translated: bool = False,
                 tag: str = '', parallel: bool = False):
        """Initialize PumpWoodOtherException.

        Args:
            message (str):
                Message formatted with payload data using ``{key}``
                placeholders. Truncated to 1000 characters.
            payload (dict):
                Payload data passed as a dictionary. Returned in
                ``to_dict`` and used to format the message.
                Defaults to None.
            was_translated (bool):
                If the message was translated. Defaults to False.
            tag (str):
                Tag used to disambiguate translation context.
                Defaults to empty string.
            status_code (int):
                Change the default status code of the exception.
                Defaults to None.
            parallel (bool):
                Whether the error occurred during parallel work.
                Defaults to False.
        """
        Exception.__init__(self)

        # Initialize payload to avoid mutable default issues
        if payload is None:
            payload = {}

        # Limit size of the error, it is expected that other exceptions
        # may have long text from kong or other between services
        self.message = message[:1000]

        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

        # Other exceptions are never translated are never translated
        self.was_translated = False
        self.tag = tag
        self.parallel = parallel

    def format_message(self) -> str:
        """Return the message without formatting.
        
        Other exceptions are never translated, so the message is not formatted
        and returned as is.
        """
        return self.message
    

class AirflowMicroServiceException(PumpWoodException):
    """Exception raised from AirflowMicroService."""

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
    "PumpWoodJSONLoadError": PumpWoodJSONLoadError,
    "PumpWoodCacheError": PumpWoodCacheError,
    "PumpWoodOtherException": PumpWoodOtherException,
    "AirflowMicroServiceException": AirflowMicroServiceException,
    "PumpWoodUniqueDatabaseError": PumpWoodUniqueDatabaseError
}
"""
Dictionary mapping exception class names to types.

Used by backends and microservices to re-raise PumpWood exceptions.
"""


def raise_pumpwood_exception(exception_name: str, message: str,
                             payload: dict = None, status_code: int = None,
                             translate: bool = False, tag: str = '',
                             parallel: bool = False):
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
        tag (str):
            Tag used to disambiguate translation context.
            Defaults to empty string.
        parallel (bool):
            If the exception happened during parallel processing.
            Defaults to False.

    Returns:
        None:
            This function does not return; it always raises an exception.

    Raises:
        PumpWoodOtherException:
            If ``exception_name`` is not found in the registry.
        PumpWoodException:
            The specific exception mapped to ``exception_name``.
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
            tag=tag, parallel=parallel)
    else:
        raise pumpwood_exception(
            message=message, payload=payload, status_code=status_code,
            translate=translate, tag=tag, parallel=parallel)


def raise_from_dict(exception_dict: dict):
    """Raise a PumpWood exception from a serialized error dict.

    Accepts output from `PumpWoodException.to_dict()` or compatible
    payloads using `type` as the exception class name.

    Args:
        exception_dict (dict):
            Serialized exception data. Expected keys are `type` (or
            legacy `exception_name`), `message_not_fmt`, `payload`,
            `status_code`, `translate`, `tag`, and `parallel`.

    Returns:
        None:
            This function does not return as it always raises an
            exception.

    Raises:
        PumpWoodOtherException:
            If the specified exception type is not found in the
            registry.
        PumpWoodException:
            The specific exception mapped to the exception type.
    """
    exception_name = exception_dict.get("type") or exception_dict.get(
        "exception_name")
    message_not_fmt = exception_dict.get("message_not_fmt")
    payload = exception_dict.get("payload")
    status_code = exception_dict.get("status_code")
    translate = exception_dict.get("translate", False)
    tag = exception_dict.get("tag", '')
    parallel = exception_dict.get("parallel", False)

    raise_pumpwood_exception(
        exception_name=exception_name,
        message=message_not_fmt, payload=payload, status_code=status_code,
        translate=translate, tag=tag, parallel=parallel)
