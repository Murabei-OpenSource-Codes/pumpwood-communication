"""Parallel Pumpwood microservice helpers.

Exports ABC mixins for parallel HTTP helpers. ``ParallelTaskErrorHandler``,
``ParallelErrorHandlerInput``, ``ParallelErrorSentinel``, and
``partition_parallel_results`` support optional partial-failure handling on
``ABCParallelBaseMicroservice.parallel_call``.
"""
from .action import ABCParallelActionMicroservice
from .delete import ABCParallelDeleteMicroservice
from .list import ABCParallelListMicroservice
from .retrieve import ABCParallelRetriveMicroservice
from .save import ABCParallelSaveMicroservice
from .batch import ABCParallelBatchMicroservice
from .error_handler import (
    ParallelErrorSentinel, ParallelErrorHandlerInput,
    ParallelTaskErrorHandler,
    coerce_parallel_task_error_handler, is_parallel_error_sentinel,
    partition_parallel_results)


__docformat__ = "google"


__all__ = [
    ABCParallelActionMicroservice,
    ABCParallelDeleteMicroservice,
    ABCParallelListMicroservice,
    ABCParallelRetriveMicroservice,
    ABCParallelSaveMicroservice,
    ABCParallelBatchMicroservice,
    ParallelErrorSentinel,
    ParallelErrorHandlerInput,
    ParallelTaskErrorHandler,
    is_parallel_error_sentinel,
    partition_parallel_results,
    coerce_parallel_task_error_handler,
]
