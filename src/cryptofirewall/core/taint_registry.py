from __future__ import annotations

from dataclasses import dataclass
import unicodedata
from typing import Any

from .crypto_tracker import TaintedString


@dataclass(frozen=True)
class TaintRecord:
    value: str
    label: str
    source_tool: str
    path: str
    tainted: TaintedString


class TaintRegistry:
    """Trusted sidecar metadata for values returned by source tools."""

    def __init__(self) -> None:
        self._records: list[TaintRecord] = []

    @property
    def records(self) -> tuple[TaintRecord, ...]:
        return tuple(self._records)

    def register_value(self, value: str, label: str, source_tool: str, path: str) -> None:
        self._records.append(
            TaintRecord(
                value=value,
                label=label,
                source_tool=source_tool,
                path=path,
                tainted=TaintedString(value, label),
            )
        )

    @staticmethod
    def _normalize_for_matching(value: str) -> str:
        value = unicodedata.normalize("NFKC", value).casefold()
        return " ".join(value.split())

    def find_matches(self, value: str) -> tuple[TaintRecord, ...]:
        """Return taint records whose normalized values occur in an outbound string."""
        if not isinstance(value, str) or not value:
            return ()

        normalized_value = self._normalize_for_matching(value)

        return tuple(
            record
            for record in self._records
            if record.value
            and self._normalize_for_matching(record.value) in normalized_value
        )

    def register_result(self, result: Any, label: str, source_tool: str, path: str = "result") -> None:
        if isinstance(result, str):
            self.register_value(result, label, source_tool, path)
            return

        if isinstance(result, dict):
            for key, value in result.items():
                self.register_result(value, label, source_tool, f"{path}.{key}")
            return

        if isinstance(result, (list, tuple)):
            for index, value in enumerate(result):
                self.register_result(value, label, source_tool, f"{path}[{index}]")
            return

        if hasattr(result, "model_dump"):
            self.register_result(result.model_dump(), label, source_tool, path)
