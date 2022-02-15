"""
Define PumpWood exceptions to be treated as API errors.

Define especific errors for PumpWood plataform. These errors will be treated
and will not result in default 500 errors
"""


class PumpWoodException(Exception):
    status_code = 400

    def __repr__(self):
        template = "{class_name}[status_code={status_code}]: " + \
            "{message}\nerror payload={payload}"
        return template.format(
            class_name=self.__class__.__name__,
            status_code=self.status_code, message=self.message,
            payload=self.payload,)

    def __str__(self):
        template = "{class_name}[status_code={status_code}]: " + \
            "{message}\nerror payload={payload}"
        return template.format(
            class_name=self.__class__.__name__,
            status_code=self.status_code, message=self.message,
            payload=self.payload,)

    def __init__(self, message: str, payload: dict = {}, status_code=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = {
            "payload": self.payload,
            "type": self.__class__.__name__,
            "message": self.message}
        return rv


class PumpWoodDataLoadingException(PumpWoodException):
    """Problem when loading data at dataloaders and to_load models."""

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
    """Problem when loading data at dataloaders and to_load models."""

    pass


class PumpWoodIntegrityError(PumpWoodException):
    """Problem when saving data due to IntegrityError."""

    pass


class PumpWoodNotImplementedError(PumpWoodException):
    """Problem when saving data due to NotImplementedError."""

    pass


exceptions_dict = {
    "PumpWoodException": PumpWoodException,
    "PumpWoodDataLoadingException": PumpWoodDataLoadingException,
    "PumpWoodDataTransformationException": PumpWoodDataTransformationException,
    "PumpWoodObjectSavingException": PumpWoodObjectSavingException,
    "PumpWoodActionArgsException": PumpWoodActionArgsException,
    "PumpWoodUnauthorized": PumpWoodUnauthorized,
    "PumpWoodForbidden": PumpWoodForbidden,
    "PumpWoodObjectDoesNotExist": PumpWoodObjectDoesNotExist,
    "PumpWoodQueryException": PumpWoodQueryException,
    "PumpWoodIntegrityError": PumpWoodIntegrityError,
    "PumpWoodWrongParameters": PumpWoodWrongParameters,
    "PumpWoodNotImplementedError": PumpWoodNotImplementedError,
}
