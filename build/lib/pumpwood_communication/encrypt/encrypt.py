"""Module with classes and functions associated with data encryption."""
import os
import base64
import orjson
from loguru import logger
from cryptography.fernet import Fernet
from pumpwood_communication.exceptions import (
    PumpWoodOtherException, PumpWoodNotImplementedError)
from pumpwood_communication.serializers import pumpJsonDump


class PumpwoodCryptography:
    """Pumpwood data encryption class."""

    _fernet_object: Fernet
    """Fernet object."""

    def __init__(self, fernet_key: str = None):
        """__init__.

        Raises:
            PumpWoodOtherException:
                Raise PumpWoodOtherException error if Fernet object could not
                be correctly configured.
        """
        if fernet_key is None:
            fernet_key = os.getenv('PUMPWOOD_COMUNICATION__CRYPTO_FERNET_KEY')
            if fernet_key is None:
                log_msg = (
                    'PUMPWOOD_COMUNICATION__CRYPTO_FERNET_KEY is not set, '
                    'PumpwoodCryptography encription is disable and will '
                    'raise error if used')
                logger.info(log_msg)
            else:
                try:
                    self._fernet_object = Fernet(fernet_key)
                except Exception as e:
                    error_str = str(e)
                    msg = (
                        'Fernet is not correctly cofigured, error when '
                        'creating PumpwoodCryptography object. '
                        'Error: {erro_msg}')
                    raise PumpWoodOtherException(
                        message=msg, payload={'erro_msg': error_str})

    def _check_if_configured(self) -> bool:
        """Check if PumpwoodCryptography is configured.

        Returns:
            Returns true.

        Raises:
            PumpWoodOtherException:
                Raise PumpWoodOtherException if object was not configured
                (Fernet key was not set).
        """
        if self._fernet_object is None:
            msg = (
                'PumpwoodCryptography is not configured, fernet key was not '
                'passed as argument on object creation and env variable '
                '`PUMPWOOD_COMUNICATION__CRYPTO_FERNET_KEY` was not set')
            raise PumpWoodOtherException(message=msg)
        return True

    def encrypt(self, value: any) -> str:
        """Encrypt value using object Fernet Key.

        It will serialize the data to JSON and if bytes it will be converted to
        base64. Data will then be encrypted using the fernet key.

        Args:
            value (any):
                Value that will be encrypted. It is possible to encrypt
                python objects and bytes.

        Returns:
            Return a string with encripted information using objects Fernet
            Key.
        """
        self._check_if_configured()
        encoded_value = None
        # If type is bytes, convert to a dictinary that will be used when
        # decrypting data to convert information back to bytes again
        if type(value) is bytes:
            # Convert bytes to base64 before encription
            encoded_base64 = base64.b64encode(value).decode('utf-8')
            encoded_value = pumpJsonDump({
                '__type__': 'bytes',
                '__base64__': encoded_base64,
                '__PumpwoodCryptography__': True})
        else:
            encoded_value = pumpJsonDump(value)
        encrypted_data = self._fernet_object.encrypt(encoded_value)
        return encrypted_data.decode('utf-8')

    def decrypt(self, value: str) -> any:
        """Decrypt value using object Fernet Key.

        Args:
            value (str):
                String value that will be decripted.

        Returns:
            Return the encrypted object.

        Raise:
            PumpWoodNotImplementedError:
                Raise this error if the encrypted data is a dictinary with
                key `__PumpwoodCryptography__` is equal to `True`, but the
                key `__type__` indicates
        """
        self._check_if_configured()
        if value is None:
            return value

        decrypted_value = self._fernet_object.decrypt(value.encode('utf-8'))
        python_obj = orjson.loads(decrypted_value)
        if type(python_obj) is not dict:
            return python_obj

        # Dictionary data with `__PumpwoodCryptography__` key indicates
        # that the information was treated on encryption
        is_PumpwoodCryptography = python_obj.get(
            '__PumpwoodCryptography__', False)
        if not is_PumpwoodCryptography:
            return python_obj

        # __type__ will indicated the type of the data that was encrypted,
        # this will be used to correctly undo the encryption
        obj_type = python_obj.get('__type__')
        if obj_type == 'bytes':
            return base64.b64decode(python_obj['__base64__'])

        msg = (
            "Object is encrypted using PumpwoodCryptography, but type "
            "[{obj_type}] could not be recognized. Check if the version of "
            "Pumpwood Communication used at encryption is compatible")
        raise PumpWoodNotImplementedError(message=msg, payload={
            'obj_type': obj_type})
