"""
Define PumpWood exceptions to be treated as API errors.

Define especific errors for PumpWood plataform. These errors will be treated
and will not result in default 500 errors
"""


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
    """
    Dictionary payload that will be returned by to_dict funcion and format
    message string.
    """

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

    def __init__(self, message: str, payload: dict = {}, status_code=None):
        """__init__.

        Args:
            message:
                Message that will be formated using payload
                information using `{key}` to replace information.
            payload:
                Payload data passed as a dictionary, it will be returned
                in payload at `to_dict` funcion and used to format message.
            status_code:
                Change the default status code of the exception.
        """
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def format_message(self) -> str:
        """Format exception message using payload data.

        Substitute placeholders at exception message with payload.

        Returns:
            Return a string of message with placeholders substituted with
            payload data.
        """
        try:
            return self.message.format(**self.payload)
        except Exception:
            return self.message + "\n** format error **"

    def to_dict(self) -> dict:
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
            "payload": self.payload,
            "type": self.__class__.__name__,
            "message_not_fmt": self.message,
            "message": message_fmt}
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


class PumpWoodOtherException(PumpWoodException):
    """Other untreated error on server."""

    status_code = 500

    def __repr__(self):
        """__repr__."""
        template = "{class_name}[status_code={status_code}]: " + \
            "{message}\nerror payload={payload}"
        return template.format(
            class_name=self.__class__.__name__,
            status_code=self.status_code, message=self.message,
            payload=self.payload,)

    def __str__(self):
        """__str__."""
        template = "{class_name}[status_code={status_code}]: " + \
            "{message}\nerror payload={payload}"
        return template.format(
            class_name=self.__class__.__name__,
            status_code=self.status_code, message=self.message,
            payload=self.payload,)

    def __init__(self, message: str, payload: dict = {}, status_code=None):
        """__init__."""
        Exception.__init__(self)
        # Limit size of the error
        self.message = message[:1000]
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        """Serialize exception to dictionary."""
        rv = {
            "payload": self.payload,
            "type": self.__class__.__name__,
            "message": self.message}
        return rv


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
