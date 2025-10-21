"""Module with classes and functions associated with data encryption."""
import os
import base64
from loguru import logger
from cryptography.fernet import Fernet
from pumpwood_communication.exceptions import PumpWoodOtherException
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

        Returns:
            Return a string with encripted information using objects Fernet
            Key.
        """
        encoded_value = None
        if type(value) is bytes:
            # Convert bytes to base64 before encription
            encoded_value = base64.b64encode(value)
        else:
            encoded_value = pumpJsonDump(value)
        encrypted_base64 = self.fernet_obj.encrypt(encoded_value)
        return encrypted_base64.decode('utf-8')

    def decrypt(self, value: str, is_bytes: bool = False) -> any:
        """Decrypt value using object Fernet Key."""
        if value is None:
            return value
