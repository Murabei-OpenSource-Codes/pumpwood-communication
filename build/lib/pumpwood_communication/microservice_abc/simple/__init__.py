"""
Facilitate communication with Pumpowood backend.

This packages facilitates the communication with end-points with Pumpwood
pattern and helps with authentication.

Source-code at Github:<br>
https://github.com/Murabei-OpenSource-Codes/pumpwood-communication
"""

__docformat__ = "google"
from .batch import ABCSimpleBatchMicroservice
from .permission import ABCPermissionMicroservice

__all__ = [
    ABCSimpleBatchMicroservice, ABCPermissionMicroservice]
