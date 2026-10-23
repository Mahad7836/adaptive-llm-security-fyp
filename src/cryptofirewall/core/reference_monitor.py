from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .capabilities import get_task_capability


class UnauthorizedActionError(Exception):
    """Raised when a tool call exceeds the current task capability."""


def authorize_tool_call(
    task_id: str,
    function: str,
    kwargs: Mapping[str, Any],
) -> bool:
    """Deterministically authorize a tool call against the task capability manifest.

    Fails closed for unknown tasks, disallowed tools, or constrained arguments
    that do not exactly match the authorized values.
    """
    capability = get_task_capability(task_id)
    allowed_tools = capability["allowed_tools"]

    if function not in allowed_tools:
        raise UnauthorizedActionError(
            f"Tool '{function}' is not authorized for task '{task_id}'."
        )

    constraints = capability.get("tool_constraints", {}).get(function)
    if constraints is not None:
        for key, expected_value in constraints.items():
            actual_value = kwargs.get(key)
            if actual_value != expected_value:
                raise UnauthorizedActionError(
                    f"Tool '{function}' argument '{key}' is unauthorized for task '{task_id}': "
                    f"expected {expected_value!r}, got {actual_value!r}."
                )

    return True
