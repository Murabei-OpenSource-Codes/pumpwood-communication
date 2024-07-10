# Module pumpwood_communication.exceptions

Define PumpWood exceptions to be treated as API errors.

Define especific errors for PumpWood plataform. These errors will be treated
and will not result in default 500 errors

??? example "View Source"
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

                try:

                    message_fmt = self.message.format(**self.payload)

                except Exception:

                    message_fmt = self.message + "\n** format error **"

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

            """Problem when saving data due to NotImplementedError."""

            status_code = 500

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

                # Limit size of the error

                self.message = message[:1000]

                if status_code is not None:

                    self.status_code = status_code

                self.payload = payload

            def to_dict(self):

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

            "PumpWoodOtherException": PumpWoodOtherException,

            "PumpWoodObjectDeleteException": PumpWoodObjectDeleteException,

            "AirflowMicroServiceException": AirflowMicroServiceException,

            "PumpWoodMicroserviceUnavailableError":

                PumpWoodMicroserviceUnavailableError

        }

## Variables

```python3
exceptions_dict
```

## Classes

### AirflowMicroServiceException

```python3
class AirflowMicroServiceException(
    message: str,
    payload: dict = {},
    status_code=None
)
```

Raises from AirflowMicroService.

??? example "View Source"
        class AirflowMicroServiceException(PumpWoodException):

            """Raises from AirflowMicroService."""

            pass

------

#### Ancestors (in MRO)

* pumpwood_communication.exceptions.PumpWoodException
* builtins.Exception
* builtins.BaseException

#### Class variables

```python3
args
```

```python3
status_code
```

#### Methods

    
#### to_dict

```python3
def to_dict(
    self
)
```

??? example "View Source"
            def to_dict(self):

                try:

                    message_fmt = self.message.format(**self.payload)

                except Exception:

                    message_fmt = self.message + "\n** format error **"

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message_not_fmt": self.message,

                    "message": message_fmt}

                return rv

    
#### with_traceback

```python3
def with_traceback(
    ...
)
```

Exception.with_traceback(tb) --

set self.__traceback__ to tb and return self.

### PumpWoodActionArgsException

```python3
class PumpWoodActionArgsException(
    message: str,
    payload: dict = {},
    status_code=None
)
```

Missing arguments to perform action.

??? example "View Source"
        class PumpWoodActionArgsException(PumpWoodException):

            """Missing arguments to perform action."""

            pass

------

#### Ancestors (in MRO)

* pumpwood_communication.exceptions.PumpWoodException
* builtins.Exception
* builtins.BaseException

#### Class variables

```python3
args
```

```python3
status_code
```

#### Methods

    
#### to_dict

```python3
def to_dict(
    self
)
```

??? example "View Source"
            def to_dict(self):

                try:

                    message_fmt = self.message.format(**self.payload)

                except Exception:

                    message_fmt = self.message + "\n** format error **"

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message_not_fmt": self.message,

                    "message": message_fmt}

                return rv

    
#### with_traceback

```python3
def with_traceback(
    ...
)
```

Exception.with_traceback(tb) --

set self.__traceback__ to tb and return self.

### PumpWoodDataLoadingException

```python3
class PumpWoodDataLoadingException(
    message: str,
    payload: dict = {},
    status_code=None
)
```

Problem when loading data at dataloaders and to_load models.

??? example "View Source"
        class PumpWoodDataLoadingException(PumpWoodException):

            """Problem when loading data at dataloaders and to_load models."""

            pass

------

#### Ancestors (in MRO)

* pumpwood_communication.exceptions.PumpWoodException
* builtins.Exception
* builtins.BaseException

#### Class variables

```python3
args
```

```python3
status_code
```

#### Methods

    
#### to_dict

```python3
def to_dict(
    self
)
```

??? example "View Source"
            def to_dict(self):

                try:

                    message_fmt = self.message.format(**self.payload)

                except Exception:

                    message_fmt = self.message + "\n** format error **"

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message_not_fmt": self.message,

                    "message": message_fmt}

                return rv

    
#### with_traceback

```python3
def with_traceback(
    ...
)
```

Exception.with_traceback(tb) --

set self.__traceback__ to tb and return self.

### PumpWoodDataTransformationException

```python3
class PumpWoodDataTransformationException(
    message: str,
    payload: dict = {},
    status_code=None
)
```

Problem when transforming model data.

??? example "View Source"
        class PumpWoodDataTransformationException(PumpWoodException):

            """Problem when transforming model data."""

            pass

------

#### Ancestors (in MRO)

* pumpwood_communication.exceptions.PumpWoodException
* builtins.Exception
* builtins.BaseException

#### Class variables

```python3
args
```

```python3
status_code
```

#### Methods

    
#### to_dict

```python3
def to_dict(
    self
)
```

??? example "View Source"
            def to_dict(self):

                try:

                    message_fmt = self.message.format(**self.payload)

                except Exception:

                    message_fmt = self.message + "\n** format error **"

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message_not_fmt": self.message,

                    "message": message_fmt}

                return rv

    
#### with_traceback

```python3
def with_traceback(
    ...
)
```

Exception.with_traceback(tb) --

set self.__traceback__ to tb and return self.

### PumpWoodDatabaseError

```python3
class PumpWoodDatabaseError(
    message: str,
    payload: dict = {},
    status_code=None
)
```

Errors raised by Postgres and not treated by other handlers.

??? example "View Source"
        class PumpWoodDatabaseError(PumpWoodException):

            """Errors raised by Postgres and not treated by other handlers."""

            pass

------

#### Ancestors (in MRO)

* pumpwood_communication.exceptions.PumpWoodException
* builtins.Exception
* builtins.BaseException

#### Class variables

```python3
args
```

```python3
status_code
```

#### Methods

    
#### to_dict

```python3
def to_dict(
    self
)
```

??? example "View Source"
            def to_dict(self):

                try:

                    message_fmt = self.message.format(**self.payload)

                except Exception:

                    message_fmt = self.message + "\n** format error **"

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message_not_fmt": self.message,

                    "message": message_fmt}

                return rv

    
#### with_traceback

```python3
def with_traceback(
    ...
)
```

Exception.with_traceback(tb) --

set self.__traceback__ to tb and return self.

### PumpWoodException

```python3
class PumpWoodException(
    message: str,
    payload: dict = {},
    status_code=None
)
```

Common base class for all non-exit exceptions.

??? example "View Source"
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

                try:

                    message_fmt = self.message.format(**self.payload)

                except Exception:

                    message_fmt = self.message + "\n** format error **"

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message_not_fmt": self.message,

                    "message": message_fmt}

                return rv

------

#### Ancestors (in MRO)

* builtins.Exception
* builtins.BaseException

#### Descendants

* pumpwood_communication.exceptions.PumpWoodDataLoadingException
* pumpwood_communication.exceptions.PumpWoodDatabaseError
* pumpwood_communication.exceptions.PumpWoodDataTransformationException
* pumpwood_communication.exceptions.PumpWoodWrongParameters
* pumpwood_communication.exceptions.PumpWoodObjectSavingException
* pumpwood_communication.exceptions.PumpWoodObjectDeleteException
* pumpwood_communication.exceptions.PumpWoodActionArgsException
* pumpwood_communication.exceptions.PumpWoodUnauthorized
* pumpwood_communication.exceptions.PumpWoodForbidden
* pumpwood_communication.exceptions.PumpWoodObjectDoesNotExist
* pumpwood_communication.exceptions.PumpWoodQueryException
* pumpwood_communication.exceptions.PumpWoodIntegrityError
* pumpwood_communication.exceptions.PumpWoodNotImplementedError
* pumpwood_communication.exceptions.PumpWoodMicroserviceUnavailableError
* pumpwood_communication.exceptions.PumpWoodMFAError
* pumpwood_communication.exceptions.PumpWoodOtherException
* pumpwood_communication.exceptions.AirflowMicroServiceException

#### Class variables

```python3
args
```

```python3
status_code
```

#### Methods

    
#### to_dict

```python3
def to_dict(
    self
)
```

??? example "View Source"
            def to_dict(self):

                try:

                    message_fmt = self.message.format(**self.payload)

                except Exception:

                    message_fmt = self.message + "\n** format error **"

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message_not_fmt": self.message,

                    "message": message_fmt}

                return rv

    
#### with_traceback

```python3
def with_traceback(
    ...
)
```

Exception.with_traceback(tb) --

set self.__traceback__ to tb and return self.

### PumpWoodForbidden

```python3
class PumpWoodForbidden(
    message: str,
    payload: dict = {},
    status_code=None
)
```

Action not permited.

??? example "View Source"
        class PumpWoodForbidden(PumpWoodException):

            """Action not permited."""

            status_code = 403

------

#### Ancestors (in MRO)

* pumpwood_communication.exceptions.PumpWoodException
* builtins.Exception
* builtins.BaseException

#### Class variables

```python3
args
```

```python3
status_code
```

#### Methods

    
#### to_dict

```python3
def to_dict(
    self
)
```

??? example "View Source"
            def to_dict(self):

                try:

                    message_fmt = self.message.format(**self.payload)

                except Exception:

                    message_fmt = self.message + "\n** format error **"

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message_not_fmt": self.message,

                    "message": message_fmt}

                return rv

    
#### with_traceback

```python3
def with_traceback(
    ...
)
```

Exception.with_traceback(tb) --

set self.__traceback__ to tb and return self.

### PumpWoodIntegrityError

```python3
class PumpWoodIntegrityError(
    message: str,
    payload: dict = {},
    status_code=None
)
```

Problem when saving data due to IntegrityError.

??? example "View Source"
        class PumpWoodIntegrityError(PumpWoodException):

            """Problem when saving data due to IntegrityError."""

            pass

------

#### Ancestors (in MRO)

* pumpwood_communication.exceptions.PumpWoodException
* builtins.Exception
* builtins.BaseException

#### Class variables

```python3
args
```

```python3
status_code
```

#### Methods

    
#### to_dict

```python3
def to_dict(
    self
)
```

??? example "View Source"
            def to_dict(self):

                try:

                    message_fmt = self.message.format(**self.payload)

                except Exception:

                    message_fmt = self.message + "\n** format error **"

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message_not_fmt": self.message,

                    "message": message_fmt}

                return rv

    
#### with_traceback

```python3
def with_traceback(
    ...
)
```

Exception.with_traceback(tb) --

set self.__traceback__ to tb and return self.

### PumpWoodMFAError

```python3
class PumpWoodMFAError(
    message: str,
    payload: dict = {},
    status_code=None
)
```

Problem when using MFA.

??? example "View Source"
        class PumpWoodMFAError(PumpWoodException):

            """Problem when using MFA."""

            pass

------

#### Ancestors (in MRO)

* pumpwood_communication.exceptions.PumpWoodException
* builtins.Exception
* builtins.BaseException

#### Class variables

```python3
args
```

```python3
status_code
```

#### Methods

    
#### to_dict

```python3
def to_dict(
    self
)
```

??? example "View Source"
            def to_dict(self):

                try:

                    message_fmt = self.message.format(**self.payload)

                except Exception:

                    message_fmt = self.message + "\n** format error **"

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message_not_fmt": self.message,

                    "message": message_fmt}

                return rv

    
#### with_traceback

```python3
def with_traceback(
    ...
)
```

Exception.with_traceback(tb) --

set self.__traceback__ to tb and return self.

### PumpWoodMicroserviceUnavailableError

```python3
class PumpWoodMicroserviceUnavailableError(
    message: str,
    payload: dict = {},
    status_code=None
)
```

Problem when trying to use a microservice that was not deployied.

??? example "View Source"
        class PumpWoodMicroserviceUnavailableError(PumpWoodException):

            """Problem when trying to use a microservice that was not deployied."""

            pass

------

#### Ancestors (in MRO)

* pumpwood_communication.exceptions.PumpWoodException
* builtins.Exception
* builtins.BaseException

#### Class variables

```python3
args
```

```python3
status_code
```

#### Methods

    
#### to_dict

```python3
def to_dict(
    self
)
```

??? example "View Source"
            def to_dict(self):

                try:

                    message_fmt = self.message.format(**self.payload)

                except Exception:

                    message_fmt = self.message + "\n** format error **"

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message_not_fmt": self.message,

                    "message": message_fmt}

                return rv

    
#### with_traceback

```python3
def with_traceback(
    ...
)
```

Exception.with_traceback(tb) --

set self.__traceback__ to tb and return self.

### PumpWoodNotImplementedError

```python3
class PumpWoodNotImplementedError(
    message: str,
    payload: dict = {},
    status_code=None
)
```

Problem when saving data due to NotImplementedError.

??? example "View Source"
        class PumpWoodNotImplementedError(PumpWoodException):

            """Problem when saving data due to NotImplementedError."""

            pass

------

#### Ancestors (in MRO)

* pumpwood_communication.exceptions.PumpWoodException
* builtins.Exception
* builtins.BaseException

#### Class variables

```python3
args
```

```python3
status_code
```

#### Methods

    
#### to_dict

```python3
def to_dict(
    self
)
```

??? example "View Source"
            def to_dict(self):

                try:

                    message_fmt = self.message.format(**self.payload)

                except Exception:

                    message_fmt = self.message + "\n** format error **"

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message_not_fmt": self.message,

                    "message": message_fmt}

                return rv

    
#### with_traceback

```python3
def with_traceback(
    ...
)
```

Exception.with_traceback(tb) --

set self.__traceback__ to tb and return self.

### PumpWoodObjectDeleteException

```python3
class PumpWoodObjectDeleteException(
    message: str,
    payload: dict = {},
    status_code=None
)
```

Raise for errors in object deserialization.

??? example "View Source"
        class PumpWoodObjectDeleteException(PumpWoodException):

            """Raise for errors in object deserialization."""

            pass

------

#### Ancestors (in MRO)

* pumpwood_communication.exceptions.PumpWoodException
* builtins.Exception
* builtins.BaseException

#### Class variables

```python3
args
```

```python3
status_code
```

#### Methods

    
#### to_dict

```python3
def to_dict(
    self
)
```

??? example "View Source"
            def to_dict(self):

                try:

                    message_fmt = self.message.format(**self.payload)

                except Exception:

                    message_fmt = self.message + "\n** format error **"

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message_not_fmt": self.message,

                    "message": message_fmt}

                return rv

    
#### with_traceback

```python3
def with_traceback(
    ...
)
```

Exception.with_traceback(tb) --

set self.__traceback__ to tb and return self.

### PumpWoodObjectDoesNotExist

```python3
class PumpWoodObjectDoesNotExist(
    message: str,
    payload: dict = {},
    status_code=None
)
```

Object not found in database.

??? example "View Source"
        class PumpWoodObjectDoesNotExist(PumpWoodException):

            """Object not found in database."""

            status_code = 404

------

#### Ancestors (in MRO)

* pumpwood_communication.exceptions.PumpWoodException
* builtins.Exception
* builtins.BaseException

#### Class variables

```python3
args
```

```python3
status_code
```

#### Methods

    
#### to_dict

```python3
def to_dict(
    self
)
```

??? example "View Source"
            def to_dict(self):

                try:

                    message_fmt = self.message.format(**self.payload)

                except Exception:

                    message_fmt = self.message + "\n** format error **"

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message_not_fmt": self.message,

                    "message": message_fmt}

                return rv

    
#### with_traceback

```python3
def with_traceback(
    ...
)
```

Exception.with_traceback(tb) --

set self.__traceback__ to tb and return self.

### PumpWoodObjectSavingException

```python3
class PumpWoodObjectSavingException(
    message: str,
    payload: dict = {},
    status_code=None
)
```

Raise for errors in object deserialization.

??? example "View Source"
        class PumpWoodObjectSavingException(PumpWoodException):

            """Raise for errors in object deserialization."""

            pass

------

#### Ancestors (in MRO)

* pumpwood_communication.exceptions.PumpWoodException
* builtins.Exception
* builtins.BaseException

#### Class variables

```python3
args
```

```python3
status_code
```

#### Methods

    
#### to_dict

```python3
def to_dict(
    self
)
```

??? example "View Source"
            def to_dict(self):

                try:

                    message_fmt = self.message.format(**self.payload)

                except Exception:

                    message_fmt = self.message + "\n** format error **"

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message_not_fmt": self.message,

                    "message": message_fmt}

                return rv

    
#### with_traceback

```python3
def with_traceback(
    ...
)
```

Exception.with_traceback(tb) --

set self.__traceback__ to tb and return self.

### PumpWoodOtherException

```python3
class PumpWoodOtherException(
    message: str,
    payload: dict = {},
    status_code=None
)
```

Problem when saving data due to NotImplementedError.

??? example "View Source"
        class PumpWoodOtherException(PumpWoodException):

            """Problem when saving data due to NotImplementedError."""

            status_code = 500

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

                # Limit size of the error

                self.message = message[:1000]

                if status_code is not None:

                    self.status_code = status_code

                self.payload = payload

            def to_dict(self):

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message": self.message}

                return rv

------

#### Ancestors (in MRO)

* pumpwood_communication.exceptions.PumpWoodException
* builtins.Exception
* builtins.BaseException

#### Class variables

```python3
args
```

```python3
status_code
```

#### Methods

    
#### to_dict

```python3
def to_dict(
    self
)
```

??? example "View Source"
            def to_dict(self):

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message": self.message}

                return rv

    
#### with_traceback

```python3
def with_traceback(
    ...
)
```

Exception.with_traceback(tb) --

set self.__traceback__ to tb and return self.

### PumpWoodQueryException

```python3
class PumpWoodQueryException(
    message: str,
    payload: dict = {},
    status_code=None
)
```

Problem when querying data, like wrong fields or operators.

??? example "View Source"
        class PumpWoodQueryException(PumpWoodException):

            """Problem when querying data, like wrong fields or operators."""

            pass

------

#### Ancestors (in MRO)

* pumpwood_communication.exceptions.PumpWoodException
* builtins.Exception
* builtins.BaseException

#### Class variables

```python3
args
```

```python3
status_code
```

#### Methods

    
#### to_dict

```python3
def to_dict(
    self
)
```

??? example "View Source"
            def to_dict(self):

                try:

                    message_fmt = self.message.format(**self.payload)

                except Exception:

                    message_fmt = self.message + "\n** format error **"

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message_not_fmt": self.message,

                    "message": message_fmt}

                return rv

    
#### with_traceback

```python3
def with_traceback(
    ...
)
```

Exception.with_traceback(tb) --

set self.__traceback__ to tb and return self.

### PumpWoodUnauthorized

```python3
class PumpWoodUnauthorized(
    message: str,
    payload: dict = {},
    status_code=None
)
```

User Unauthorized to perform action.

??? example "View Source"
        class PumpWoodUnauthorized(PumpWoodException):

            """User Unauthorized to perform action."""

            status_code = 401

------

#### Ancestors (in MRO)

* pumpwood_communication.exceptions.PumpWoodException
* builtins.Exception
* builtins.BaseException

#### Class variables

```python3
args
```

```python3
status_code
```

#### Methods

    
#### to_dict

```python3
def to_dict(
    self
)
```

??? example "View Source"
            def to_dict(self):

                try:

                    message_fmt = self.message.format(**self.payload)

                except Exception:

                    message_fmt = self.message + "\n** format error **"

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message_not_fmt": self.message,

                    "message": message_fmt}

                return rv

    
#### with_traceback

```python3
def with_traceback(
    ...
)
```

Exception.with_traceback(tb) --

set self.__traceback__ to tb and return self.

### PumpWoodWrongParameters

```python3
class PumpWoodWrongParameters(
    message: str,
    payload: dict = {},
    status_code=None
)
```

Raise for errors in object deserialization.

??? example "View Source"
        class PumpWoodWrongParameters(PumpWoodException):

            """Raise for errors in object deserialization."""

            pass

------

#### Ancestors (in MRO)

* pumpwood_communication.exceptions.PumpWoodException
* builtins.Exception
* builtins.BaseException

#### Class variables

```python3
args
```

```python3
status_code
```

#### Methods

    
#### to_dict

```python3
def to_dict(
    self
)
```

??? example "View Source"
            def to_dict(self):

                try:

                    message_fmt = self.message.format(**self.payload)

                except Exception:

                    message_fmt = self.message + "\n** format error **"

                rv = {

                    "payload": self.payload,

                    "type": self.__class__.__name__,

                    "message_not_fmt": self.message,

                    "message": message_fmt}

                return rv

    
#### with_traceback

```python3
def with_traceback(
    ...
)
```

Exception.with_traceback(tb) --

set self.__traceback__ to tb and return self.