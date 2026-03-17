"""Module for pumpwood internals calls."""
from .general import ABCSystemMicroservice
from .permission import ABCPermissionMicroservice

__docformat__ = "google"
__all__ = [
    ABCSystemMicroservice,ABCPermissionMicroservice
]
