"""Module for parallel requests."""
from .action import ABCParallelActionMicroservice
from .delete import ABCParallelDeleteMicroservice
from .list import ABCParallelListMicroservice
from .retrieve import ABCParallelRetriveMicroservice
from .save import ABCParallelSaveMicroservice


__docformat__ = "google"


__all__ = [
    ABCParallelActionMicroservice,
    ABCParallelDeleteMicroservice,
    ABCParallelListMicroservice,
    ABCParallelRetriveMicroservice,
    ABCParallelSaveMicroservice
]
