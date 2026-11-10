"""Sentinel values for failed parallel tasks.

``parallel_call`` (in ``ABCParallelBaseMicroservice``) can take an
``error_handler`` callback. That callback is not the HTTP
``PumpWoodMicroServiceBase.error_handler`` used on responses.
"""
import inspect
from dataclasses import dataclass
from typing import Any, Callable

from pumpwood_communication.exceptions import PumpWoodWrongParameters

_REQUIRED_HANDLER_PARAMS = frozenset({"index", "args", "error"})


class ParallelTaskErrorHandler:
    """Validates and wraps a per-task parallel ``error_handler`` callback.

    Not the HTTP ``PumpWoodMicroServiceBase.error_handler``. Instantiate
    with a callable that accepts ``index``, ``args``, and ``error`` (by
    name). ``parallel_call`` also accepts a bare callable and wraps it.
    """

    def __init__(self, handler: Callable[..., Exception | None]) -> None:
        """Wrap ``handler`` after checking its parameter names.

        Args:
            handler (Callable[..., Exception | None]):
                Called as ``handler(index=..., args=..., error=...)``.
                Return ``None`` for a handled failure, an ``Exception`` to
                abort with that error, or raise to abort.

        Raises:
            PumpWoodWrongParameters:
                If ``handler`` is not callable or lacks required parameters.
        """
        self._validate_handler(handler)
        self._handler = handler

    @property
    def handler(self) -> Callable[..., Exception | None]:
        """Underlying callback."""
        return self._handler

    @staticmethod
    def _validate_handler(handler: Callable[..., Any]) -> None:
        """Ensure ``handler`` can receive index, args, and error."""
        if not callable(handler):
            msg = (
                "parallel error handler must be callable. "
                "Received type [{type}]")
            raise PumpWoodWrongParameters(
                message=msg,
                payload={"type": type(handler).__name__})

        sig = inspect.signature(handler)
        has_var_kw = any(
            p.kind == inspect.Parameter.VAR_KEYWORD
            for p in sig.parameters.values())
        if has_var_kw:
            return

        names = set(sig.parameters.keys())
        missing = _REQUIRED_HANDLER_PARAMS - names
        if missing:
            msg = (
                "parallel error handler missing parameters: {missing}. "
                "Required: index, args, error.")
            raise PumpWoodWrongParameters(
                message=msg,
                payload={
                    "missing": sorted(missing),
                    "received": sorted(names)})

    def __call__(
            self, *,
            index: int,
            args: dict[str, Any],
            error: Exception) -> Exception | None:
        """Invoke the wrapped handler.

        Args:
            index (int): Task index in the parallel batch.
            args (dict[str, Any]): Keyword arguments for that task.
            error (Exception): Normalized failure for that task.

        Returns:
            Exception | None:
                Whatever the wrapped handler returns (see class docstring).
        """
        return self._handler(index=index, args=args, error=error)


ParallelErrorHandlerInput = (
    ParallelTaskErrorHandler | Callable[..., Exception | None] | None
)


def coerce_parallel_task_error_handler(
        error_handler: ParallelErrorHandlerInput) -> (
            ParallelTaskErrorHandler | None):
    """Normalize ``error_handler`` for ``parallel_call``.

    Args:
        error_handler (ParallelErrorHandlerInput):
            ``None``, a ``ParallelTaskErrorHandler``, or a bare callable.

    Returns:
        ParallelTaskErrorHandler | None:
            Wrapped handler, or ``None`` when no handler was given.

    Raises:
        PumpWoodWrongParameters:
            If a bare callable fails signature validation.
    """
    if error_handler is None:
        return None
    if isinstance(error_handler, ParallelTaskErrorHandler):
        return error_handler
    return ParallelTaskErrorHandler(error_handler)


@dataclass(frozen=True)
class ParallelErrorSentinel:
    """Marks one handled failure in a ``parallel_call`` result list.

    Inserted when the parallel ``error_handler`` returns ``None``: the
    batch continues and the original task exception is stored on this
    object. With ``filter_errors=False`` on ``parallel_call``, handled
    failures appear as ``ParallelErrorSentinel`` instances in the
    ``errors`` list (see ``partition_parallel_results``).
    """

    index: int
    """Index of the task in ``function_args``."""
    args: dict[str, Any]
    """Keyword arguments passed to the failed call."""
    error: Exception
    """Normalized task exception (often ``PumpWoodException``)."""


def is_parallel_error_sentinel(value: Any) -> bool:
    """Return whether ``value`` is a ``ParallelErrorSentinel``."""
    return isinstance(value, ParallelErrorSentinel)


def partition_parallel_results(
        results: list[Any]) -> dict[str, list[Any]]:
    """Split ordered ``parallel_call`` slots into successes and failures.

    Args:
        results (list[Any]):
            One entry per task (success value or ``ParallelErrorSentinel``).

    Returns:
        dict[str, list[Any]]:
            ``result``: success values in task order. ``errors``: list of
            ``ParallelErrorSentinel`` objects (not converted to dicts or
            DataFrames).
    """
    successes = []
    errors = []
    for item in results:
        if is_parallel_error_sentinel(item):
            errors.append(item)
        else:
            successes.append(item)
    return {"result": successes, "errors": errors}
