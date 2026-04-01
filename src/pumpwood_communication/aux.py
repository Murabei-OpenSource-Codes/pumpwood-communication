"""General auxiliary functions for Pumpwood Communications."""
import importlib
from typing import Any, Callable


def import_function_by_string(module: str | Any) -> Callable:
    """Help importing a function using a string or function if not string."""
    if not isinstance(module, str):
        return module

    module_name, function_name = module.rsplit('.', 1)
    module = importlib.import_module(module_name)
    func = getattr(module, function_name)
    return func
