from __future__ import annotations

from typing import Any

from .egress import ALLOWLIST_POLICY, UnauthorizedFlowError
from .taint_registry import TaintRegistry, TaintRecord


def _find_taint_matches(value: Any, registry: TaintRegistry) -> tuple[TaintRecord, ...]:
    matches: list[TaintRecord] = []

    if isinstance(value, str):
        matches.extend(registry.find_matches(value))
    elif isinstance(value, dict):
        for nested in value.values():
            matches.extend(_find_taint_matches(nested, registry))
    elif isinstance(value, (list, tuple, set)):
        for nested in value:
            matches.extend(_find_taint_matches(nested, registry))

    return tuple(matches)


def authorize_information_flow(destination: str, payload: Any, registry: TaintRegistry) -> tuple[TaintRecord, ...]:
    matches = _find_taint_matches(payload, registry)

    if not matches:
        return ()

    allowed_labels = ALLOWLIST_POLICY.get(destination, set())

    for record in matches:
        if not record.tainted.verify_integrity():
            raise UnauthorizedFlowError(
                f"Taint integrity verification failed for value from {record.source_tool} at {record.path}."
            )

        if record.label not in allowed_labels:
            raise UnauthorizedFlowError(
                f"Label {record.label!r} from {record.source_tool} at {record.path} is not authorized for destination {destination!r}."
            )

    return matches
