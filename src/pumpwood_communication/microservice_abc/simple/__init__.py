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
from .retrieve import ABCSimpleRetriveMicroservice
from .delete import ABCSimpleDeleteMicroservice
from .save import ABCSimpleSaveMicroservice
from .list import ABCSimpleListMicroservice
from .dimensions import ABCSimpleDimensionMicroservice

__all__ = [
    ABCSimpleBatchMicroservice, ABCPermissionMicroservice,
    ABCSimpleRetriveMicroservice, ABCSimpleDeleteMicroservice,
    ABCSimpleSaveMicroservice, ABCSimpleListMicroservice,
    ABCSimpleDimensionMicroservice]
