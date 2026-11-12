from __future__ import annotations

from typing import Protocol

from agentdojo.base_tasks import BaseInjectionTask, BaseUserTask


class SwarmSecAttacker(Protocol):
    """Interface for agents that create AgentDojo injection mappings."""

    name: str

    def generate(
        self,
        user_task: BaseUserTask,
        injection_task: BaseInjectionTask,
    ) -> dict[str, str]:
        """Return injection-vector IDs and their benchmark payloads."""
        ...
